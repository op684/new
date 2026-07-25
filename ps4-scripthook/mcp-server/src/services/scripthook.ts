/**
 * Client for the OrbisScriptHook control channel.
 *
 * The plugin (see ../../plugin/orbis/ipc.cpp) listens on TCP 9028 inside the
 * game process and speaks length-prefixed JSON:
 *
 *   request:  u32 length (LE) | UTF-8 JSON object
 *   response: u32 length (LE) | UTF-8 JSON object
 *
 * Requests that touch the game are queued and executed on the script thread at
 * the next tick, so `native` calls are safe with respect to RAGE's threading.
 */

import net from "node:net";
import { SCRIPTHOOK_PORT } from "./protocol.js";

export type NativeReturnType = "void" | "int" | "bool" | "float" | "string" | "vector3" | "pointer";

export interface NativeArg {
  type: "int" | "float" | "bool" | "string" | "pointer";
  value: number | string | boolean;
}

export interface ScriptHookRequest {
  op:
    | "ping"
    | "status"
    | "native"
    | "resolve"
    | "list_scripts"
    | "load_script"
    | "unload_script"
    | "log";
  [key: string]: unknown;
}

export interface ScriptHookResponse {
  ok: boolean;
  error?: string;
  [key: string]: unknown;
}

const TIMEOUT_MS = 20_000;

export class ScriptHookClient {
  constructor(
    private readonly host: string,
    private readonly port: number = SCRIPTHOOK_PORT,
  ) {}

  /**
   * One request per connection. The plugin's listener is deliberately simple
   * (single-threaded accept loop) and keeping sockets open would block it.
   */
  async request(payload: ScriptHookRequest): Promise<ScriptHookResponse> {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    const frame = Buffer.alloc(4 + body.length);
    frame.writeUInt32LE(body.length, 0);
    body.copy(frame, 4);

    const socket = await this.connect();
    try {
      await new Promise<void>((resolve, reject) =>
        socket.write(frame, (err) => (err ? reject(err) : resolve())),
      );
      const raw = await this.readFrame(socket);
      let parsed: ScriptHookResponse;
      try {
        parsed = JSON.parse(raw.toString("utf8")) as ScriptHookResponse;
      } catch {
        throw new Error(`OrbisScriptHook returned malformed JSON: ${raw.toString("utf8").slice(0, 200)}`);
      }
      if (!parsed.ok && parsed.error) {
        throw new Error(`OrbisScriptHook rejected "${payload.op}": ${parsed.error}`);
      }
      return parsed;
    } finally {
      socket.destroy();
    }
  }

  private connect(): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const sock = net.createConnection({ host: this.host, port: this.port });
      const timer = setTimeout(() => {
        sock.destroy();
        reject(
          new Error(
            `OrbisScriptHook did not answer on ${this.host}:${this.port} — the plugin is not ` +
              `loaded. Check /data/GoldHEN/plugins.ini has an entry for this title id and that ` +
              `the game was restarted after installing the .prx.`,
          ),
        );
      }, TIMEOUT_MS);
      sock.once("connect", () => {
        clearTimeout(timer);
        sock.setNoDelay(true);
        resolve(sock);
      });
      sock.once("error", (err) => {
        clearTimeout(timer);
        reject(new Error(`OrbisScriptHook connection failed: ${err.message}`));
      });
    });
  }

  private readFrame(socket: net.Socket): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      let buffered = Buffer.alloc(0);
      const timer = setTimeout(
        () => reject(new Error("timed out waiting for an OrbisScriptHook reply")),
        TIMEOUT_MS,
      );
      const done = (fn: () => void) => {
        clearTimeout(timer);
        fn();
      };
      socket.on("data", (chunk) => {
        buffered = Buffer.concat([buffered, chunk]);
        if (buffered.length < 4) return;
        const length = buffered.readUInt32LE(0);
        if (buffered.length < 4 + length) return;
        done(() => resolve(buffered.subarray(4, 4 + length)));
      });
      socket.on("error", (err) => done(() => reject(err)));
      socket.on("close", () =>
        done(() => reject(new Error("OrbisScriptHook closed the connection early"))),
      );
    });
  }
}
