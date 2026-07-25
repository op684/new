/**
 * Getting bytes onto the console outside of the ps4debug protocol:
 *  - the GoldHEN payload loader on port 9090 (raw ELF/BIN, executed on close)
 *  - the GoldHEN FTP server on port 2121 (anonymous, used to drop .prx plugins)
 */

import net from "node:net";
import { FTP_PORT, PAYLOAD_PORT } from "./protocol.js";

const CONNECT_TIMEOUT_MS = 10_000;

function connect(host: string, port: number, timeoutMs = CONNECT_TIMEOUT_MS): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host, port });
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error(`timed out connecting to ${host}:${port}`));
    }, timeoutMs);
    sock.once("connect", () => {
      clearTimeout(timer);
      sock.setNoDelay(true);
      resolve(sock);
    });
    sock.once("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`could not connect to ${host}:${port}: ${err.message}`));
    });
  });
}

/**
 * Send a payload (ps4debug.bin, goldhen.bin, …) to the loader. The loader runs
 * the blob once the socket closes, so there is nothing to read back.
 */
export async function sendPayload(host: string, payload: Buffer, port = PAYLOAD_PORT): Promise<void> {
  const sock = await connect(host, port);
  try {
    await new Promise<void>((resolve, reject) => {
      sock.write(payload, (err) => (err ? reject(err) : resolve()));
    });
  } finally {
    await new Promise<void>((resolve) => sock.end(resolve));
  }
}

/** Minimal line-oriented FTP control channel. */
class FtpControl {
  private buffered = "";
  private pending: { resolve: (line: string) => void; reject: (e: Error) => void }[] = [];

  constructor(private readonly socket: net.Socket) {
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      this.buffered += chunk;
      this.pump();
    });
    socket.on("error", (err) => this.pending.splice(0).forEach((p) => p.reject(err)));
  }

  private pump(): void {
    // FTP replies may be multi-line ("220-…" continuation); a reply is complete
    // when a line starts with three digits followed by a space.
    while (this.pending.length) {
      const match = this.buffered.match(/^(?:.*\r?\n)*?(\d{3} [^\r\n]*)\r?\n/);
      if (!match) return;
      const end = match.index! + match[0].length;
      const reply = this.buffered.slice(0, end);
      this.buffered = this.buffered.slice(end);
      this.pending.shift()!.resolve(reply.trim());
    }
  }

  reply(): Promise<string> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out waiting for an FTP reply")), 15_000);
      this.pending.push({
        resolve: (l) => {
          clearTimeout(timer);
          resolve(l);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.pump();
    });
  }

  /** Write a command without queuing a reply waiter. */
  write(line: string): void {
    this.socket.write(`${line}\r\n`);
  }

  async send(line: string): Promise<string> {
    const promise = this.reply();
    this.write(line);
    return promise;
  }

  close(): void {
    this.socket.destroy();
  }
}

/** The reply code is the leading three digits of the final line. */
export function replyCode(reply: string): number {
  const lines = reply.trim().split(/\r?\n/);
  return Number.parseInt(lines[lines.length - 1]!.slice(0, 3), 10);
}

function expect(reply: string, ...codes: number[]): string {
  if (!codes.includes(replyCode(reply))) {
    throw new Error(`FTP server replied "${reply}", expected one of ${codes.join("/")}`);
  }
  return reply;
}

/** Parse a PASV reply of the form `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`. */
export function parsePasv(reply: string): { host: string; port: number } {
  const m = reply.match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/);
  if (!m) throw new Error(`could not parse PASV reply: ${reply}`);
  const n = m.slice(1).map(Number);
  return { host: n.slice(0, 4).join("."), port: n[4]! * 256 + n[5]! };
}

/**
 * Upload `data` to `remotePath` over GoldHEN's FTP server, creating parent
 * directories as needed. GoldHEN's FTP accepts anonymous logins.
 */
export async function ftpUpload(
  host: string,
  remotePath: string,
  data: Buffer,
  port = FTP_PORT,
): Promise<void> {
  const control = new FtpControl(await connect(host, port));
  try {
    expect(await control.reply(), 220);
    if (replyCode(await control.send("USER anonymous")) === 331) {
      expect(await control.send("PASS anonymous"), 230, 202);
    }
    expect(await control.send("TYPE I"), 200);

    // Best-effort mkdir -p; 550 just means the directory already exists.
    const parts = remotePath.split("/").filter(Boolean);
    let dir = "";
    for (const part of parts.slice(0, -1)) {
      dir += `/${part}`;
      await control.send(`MKD ${dir}`);
    }

    const pasv = parsePasv(expect(await control.send("PASV"), 227));
    const dataSock = await connect(pasv.host === "0.0.0.0" ? host : pasv.host, pasv.port);
    const storeReply = control.reply();
    control.write(`STOR ${remotePath}`);
    await new Promise<void>((resolve, reject) => {
      dataSock.write(data, (err) => (err ? reject(err) : resolve()));
    });
    await new Promise<void>((resolve) => dataSock.end(resolve));
    const first = await storeReply;
    // 150 = opening data connection, followed by 226 = transfer complete.
    if (replyCode(first) === 150) expect(await control.reply(), 226, 250);
    else expect(first, 226, 250);
  } finally {
    control.close();
  }
}
