/**
 * Async TCP client for the ps4debug command server.
 *
 * One connection is kept alive for the life of the process and every command is
 * serialised through a queue — the console's server is strictly request/response
 * and interleaving two commands corrupts the stream.
 */

import net from "node:net";
import {
  Cmd,
  HEADER_SIZE,
  PACKET_MAGIC,
  PROC_INFO_SIZE,
  Ps4DebugError,
  Status,
  buildHeader,
  parseProcInfo,
  parseProcList,
  parseProcMaps,
  type ProcEntry,
  type ProcInfo,
  type ProcMap,
} from "./protocol.js";

const DEFAULT_TIMEOUT_MS = 15_000;
/** ps4debug refuses reads larger than this in one shot; we chunk transparently. */
export const MAX_CHUNK = 0x8000;

export interface Ps4DebugOptions {
  host: string;
  port?: number;
  timeoutMs?: number;
}

/** Reads an exact number of bytes off a socket, buffering partial arrivals. */
class SocketReader {
  private buffered: Buffer = Buffer.alloc(0);
  private waiter?: { need: number; resolve: (b: Buffer) => void; reject: (e: Error) => void };

  constructor(private readonly socket: net.Socket) {
    socket.on("data", (chunk) => {
      this.buffered = Buffer.concat([this.buffered, chunk]);
      this.pump();
    });
    socket.on("error", (err) => this.fail(err));
    socket.on("close", () => this.fail(new Error("connection closed by the console")));
  }

  private pump(): void {
    const waiter = this.waiter;
    if (!waiter || this.buffered.length < waiter.need) return;
    this.waiter = undefined;
    const out = this.buffered.subarray(0, waiter.need);
    this.buffered = this.buffered.subarray(waiter.need);
    waiter.resolve(out);
  }

  private fail(err: Error): void {
    const waiter = this.waiter;
    this.waiter = undefined;
    waiter?.reject(err);
  }

  read(need: number, timeoutMs: number): Promise<Buffer> {
    if (need === 0) return Promise.resolve(Buffer.alloc(0));
    return new Promise<Buffer>((resolve, reject) => {
      if (this.waiter) {
        reject(new Error("concurrent read on the ps4debug socket"));
        return;
      }
      const timer = setTimeout(() => {
        this.waiter = undefined;
        reject(
          new Error(
            `timed out after ${timeoutMs}ms waiting for ${need} bytes from the console — ` +
              `is ps4debug still running? Re-inject the payload and retry.`,
          ),
        );
      }, timeoutMs);
      this.waiter = {
        need,
        resolve: (b) => {
          clearTimeout(timer);
          resolve(b);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      };
      this.pump();
    });
  }
}

export class Ps4Debug {
  private socket?: net.Socket;
  private reader?: SocketReader;
  private queue: Promise<unknown> = Promise.resolve();
  private readonly timeoutMs: number;

  readonly host: string;
  readonly port: number;

  constructor(opts: Ps4DebugOptions) {
    this.host = opts.host;
    this.port = opts.port ?? 744;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  get connected(): boolean {
    return !!this.socket && !this.socket.destroyed;
  }

  async connect(): Promise<void> {
    if (this.connected) return;
    this.socket = await new Promise<net.Socket>((resolve, reject) => {
      const sock = net.createConnection({ host: this.host, port: this.port });
      const timer = setTimeout(() => {
        sock.destroy();
        reject(
          new Error(
            `could not reach ps4debug at ${this.host}:${this.port} within ${this.timeoutMs}ms — ` +
              `check the console is awake, on the same network, and that the ps4debug payload ` +
              `has been sent to port 9090`,
          ),
        );
      }, this.timeoutMs);
      sock.once("connect", () => {
        clearTimeout(timer);
        sock.setNoDelay(true);
        resolve(sock);
      });
      sock.once("error", (err) => {
        clearTimeout(timer);
        reject(new Error(`could not reach ps4debug at ${this.host}:${this.port}: ${err.message}`));
      });
    });
    this.socket.on("close", () => {
      this.socket = undefined;
      this.reader = undefined;
    });
    this.reader = new SocketReader(this.socket);
  }

  disconnect(): void {
    this.socket?.destroy();
    this.socket = undefined;
    this.reader = undefined;
  }

  /** Serialises `fn` behind every previously issued command. */
  private run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    // Keep the chain alive even if this command rejects.
    this.queue = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  private async write(buf: Buffer): Promise<void> {
    const socket = this.socket;
    if (!socket) throw new Error("not connected — call ps4_connect first");
    await new Promise<void>((resolve, reject) => {
      socket.write(buf, (err) => (err ? reject(err) : resolve()));
    });
  }

  private async recv(n: number): Promise<Buffer> {
    if (!this.reader) throw new Error("not connected — call ps4_connect first");
    return this.reader.read(n, this.timeoutMs);
  }

  private async expectStatus(cmd: Cmd): Promise<void> {
    const status = (await this.recv(4)).readUInt32LE(0) >>> 0;
    if (status !== (Status.SUCCESS >>> 0)) throw new Ps4DebugError(cmd, status);
  }

  /**
   * Send a command with a fixed argument blob and read the status word.
   * `extra` (e.g. the body of a write) is sent after the status check, matching
   * ps4debug's two-phase transfer for bulk commands.
   */
  private async command(cmd: Cmd, payload?: Buffer): Promise<void> {
    await this.connect();
    const body = payload ?? Buffer.alloc(0);
    await this.write(Buffer.concat([buildHeader(cmd, body.length), body]));
    await this.expectStatus(cmd);
  }

  // ---------------------------------------------------------------- general

  async version(): Promise<string> {
    return this.run(async () => {
      await this.connect();
      await this.write(buildHeader(Cmd.VERSION, 0));
      const len = (await this.recv(4)).readUInt32LE(0);
      return (await this.recv(len)).toString("utf8");
    });
  }

  async processes(): Promise<ProcEntry[]> {
    return this.run(async () => {
      await this.command(Cmd.PROC_LIST);
      const len = (await this.recv(4)).readUInt32LE(0);
      const body = await this.recv(len * 36);
      const framed = Buffer.concat([Buffer.alloc(4), body]);
      framed.writeUInt32LE(len, 0);
      return parseProcList(framed);
    });
  }

  async processInfo(pid: number): Promise<ProcInfo> {
    return this.run(async () => {
      const arg = Buffer.alloc(4);
      arg.writeUInt32LE(pid, 0);
      await this.command(Cmd.PROC_INFO, arg);
      return parseProcInfo(await this.recv(PROC_INFO_SIZE));
    });
  }

  async maps(pid: number): Promise<ProcMap[]> {
    return this.run(async () => {
      const arg = Buffer.alloc(4);
      arg.writeUInt32LE(pid, 0);
      await this.command(Cmd.PROC_MAPS, arg);
      const count = (await this.recv(4)).readUInt32LE(0);
      const body = await this.recv(count * 58);
      const framed = Buffer.concat([Buffer.alloc(4), body]);
      framed.writeUInt32LE(count, 0);
      return parseProcMaps(framed);
    });
  }

  // ----------------------------------------------------------------- memory

  async readMemory(pid: number, address: bigint, length: number): Promise<Buffer> {
    const chunks: Buffer[] = [];
    for (let done = 0; done < length; done += MAX_CHUNK) {
      const size = Math.min(MAX_CHUNK, length - done);
      chunks.push(await this.readChunk(pid, address + BigInt(done), size));
    }
    return Buffer.concat(chunks);
  }

  private readChunk(pid: number, address: bigint, length: number): Promise<Buffer> {
    return this.run(async () => {
      const arg = Buffer.alloc(16);
      arg.writeUInt32LE(pid, 0);
      arg.writeBigUInt64LE(address, 4);
      arg.writeUInt32LE(length, 12);
      await this.command(Cmd.PROC_READ, arg);
      return this.recv(length);
    });
  }

  async writeMemory(pid: number, address: bigint, data: Buffer): Promise<void> {
    for (let done = 0; done < data.length; done += MAX_CHUNK) {
      const slice = data.subarray(done, Math.min(done + MAX_CHUNK, data.length));
      await this.writeChunk(pid, address + BigInt(done), slice);
    }
  }

  private writeChunk(pid: number, address: bigint, data: Buffer): Promise<void> {
    return this.run(async () => {
      const arg = Buffer.alloc(16);
      arg.writeUInt32LE(pid, 0);
      arg.writeBigUInt64LE(address, 4);
      arg.writeUInt32LE(data.length, 12);
      await this.command(Cmd.PROC_WRITE, arg);
      await this.write(data);
      await this.expectStatus(Cmd.PROC_WRITE);
    });
  }

  async allocate(pid: number, length: number): Promise<bigint> {
    return this.run(async () => {
      const arg = Buffer.alloc(8);
      arg.writeUInt32LE(pid, 0);
      arg.writeUInt32LE(length, 4);
      await this.command(Cmd.PROC_ALLOC, arg);
      return (await this.recv(8)).readBigUInt64LE(0);
    });
  }

  async free(pid: number, address: bigint, length: number): Promise<void> {
    return this.run(async () => {
      const arg = Buffer.alloc(16);
      arg.writeUInt32LE(pid, 0);
      arg.writeBigUInt64LE(address, 4);
      arg.writeUInt32LE(length, 12);
      await this.command(Cmd.PROC_FREE, arg);
    });
  }

  async protect(pid: number, address: bigint, length: bigint, prot: number): Promise<void> {
    return this.run(async () => {
      const arg = Buffer.alloc(24);
      arg.writeUInt32LE(pid, 0);
      arg.writeBigUInt64LE(address, 4);
      arg.writeBigUInt64LE(length, 12);
      arg.writeUInt32LE(prot, 20);
      await this.command(Cmd.PROC_PROTECT, arg);
    });
  }

  // -------------------------------------------------------------------- rpc

  /** Injects the RPC stub into the target and returns its address. */
  async installRpc(pid: number): Promise<bigint> {
    return this.run(async () => {
      const arg = Buffer.alloc(4);
      arg.writeUInt32LE(pid, 0);
      await this.command(Cmd.PROC_INSTALL, arg);
      return (await this.recv(8)).readBigUInt64LE(0);
    });
  }

  /** Calls `address` in the target with up to six integer arguments; returns rax. */
  async call(pid: number, stub: bigint, address: bigint, args: bigint[]): Promise<bigint> {
    if (args.length > 6) {
      throw new Error(
        `ps4debug RPC passes arguments in registers and supports at most 6; got ${args.length}. ` +
          `Write extra arguments into memory with ps4_write_memory and pass a pointer.`,
      );
    }
    return this.run(async () => {
      const arg = Buffer.alloc(68);
      arg.writeUInt32LE(pid, 0);
      arg.writeBigUInt64LE(stub, 4);
      arg.writeBigUInt64LE(address, 12);
      for (let i = 0; i < args.length; i++) arg.writeBigUInt64LE(args[i]!, 20 + i * 8);
      await this.command(Cmd.PROC_CALL, arg);
      const resp = await this.recv(12);
      return resp.readBigUInt64LE(4);
    });
  }

  /** Loads and runs an ELF inside the target process. */
  async loadElf(pid: number, elf: Buffer): Promise<void> {
    return this.run(async () => {
      const arg = Buffer.alloc(8);
      arg.writeUInt32LE(pid, 0);
      arg.writeUInt32LE(elf.length, 4);
      await this.command(Cmd.PROC_ELF, arg);
      await this.write(elf);
      await this.expectStatus(Cmd.PROC_ELF);
    });
  }

  // ---------------------------------------------------------------- console

  async notify(message: string, messageType = 222): Promise<void> {
    return this.run(async () => {
      const text = Buffer.from(`${message}\0`, "utf8");
      const arg = Buffer.alloc(8);
      arg.writeUInt32LE(messageType, 0);
      arg.writeUInt32LE(text.length, 4);
      await this.command(Cmd.CONSOLE_NOTIFY, arg);
      await this.write(text);
    });
  }

  async kernelBase(): Promise<bigint> {
    return this.run(async () => {
      await this.command(Cmd.KERN_BASE);
      return (await this.recv(8)).readBigUInt64LE(0);
    });
  }

  /**
   * Escape hatch: send an arbitrary command and read back `responseBytes`.
   * Useful for the handful of ps4debug opcodes this client does not model.
   */
  async raw(cmd: number, payload: Buffer, responseBytes: number): Promise<Buffer> {
    return this.run(async () => {
      await this.connect();
      const header = Buffer.alloc(HEADER_SIZE);
      header.writeUInt32LE(PACKET_MAGIC, 0);
      header.writeUInt32LE(cmd >>> 0, 4);
      header.writeUInt32LE(payload.length, 8);
      await this.write(Buffer.concat([header, payload]));
      await this.expectStatus(cmd as Cmd);
      return responseBytes > 0 ? this.recv(responseBytes) : Buffer.alloc(0);
    });
  }
}
