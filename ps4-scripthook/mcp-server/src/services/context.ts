/**
 * Shared connection state for every tool: one console, one ps4debug socket, one
 * remembered "current game process" so callers do not have to pass a pid around.
 */

import { Ps4Debug } from "./ps4debug.js";
import { ScriptHookClient } from "./scripthook.js";
import { findGameProcess, type GameProcess } from "./gta.js";
import { PS4DEBUG_PORT, SCRIPTHOOK_PORT } from "./protocol.js";

export class ConsoleContext {
  private client?: Ps4Debug;
  private game?: GameProcess;
  host?: string;
  debugPort = PS4DEBUG_PORT;
  scriptHookPort = SCRIPTHOOK_PORT;

  configure(host: string, debugPort = PS4DEBUG_PORT, scriptHookPort = SCRIPTHOOK_PORT): void {
    if (this.host !== host || this.debugPort !== debugPort) {
      this.client?.disconnect();
      this.client = undefined;
      this.game = undefined;
    }
    this.host = host;
    this.debugPort = debugPort;
    this.scriptHookPort = scriptHookPort;
  }

  requireHost(): string {
    if (!this.host) {
      throw new Error(
        "no console configured — call ps4_connect with your PS4's IP address first " +
          "(or start the server with PS4_HOST set)",
      );
    }
    return this.host;
  }

  async api(): Promise<Ps4Debug> {
    const host = this.requireHost();
    if (!this.client) this.client = new Ps4Debug({ host, port: this.debugPort });
    await this.client.connect();
    return this.client;
  }

  scriptHook(): ScriptHookClient {
    return new ScriptHookClient(this.requireHost(), this.scriptHookPort);
  }

  /** Resolve a pid: explicit wins, otherwise the cached/detected game process. */
  async resolvePid(pid?: number): Promise<number> {
    if (pid !== undefined) return pid;
    return (await this.gameProcess()).pid;
  }

  async gameProcess(refresh = false): Promise<GameProcess> {
    if (this.game && !refresh) return this.game;
    this.game = await findGameProcess(await this.api());
    return this.game;
  }

  reset(): void {
    this.client?.disconnect();
    this.client = undefined;
    this.game = undefined;
  }
}

export const consoleContext = new ConsoleContext();
