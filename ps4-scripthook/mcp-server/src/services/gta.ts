/**
 * GTA V / RAGE-specific helpers layered on top of the raw ps4debug client.
 */

import type { Ps4Debug } from "./ps4debug.js";
import type { ProcMap } from "./protocol.js";

/**
 * Every PS4 game process is called `eboot.bin`; the CUSA title id from
 * CMD_PROC_INFO is what actually identifies the game. These are the GTA V
 * region SKUs commonly reported by the homebrew community — treat the list as a
 * hint only. `findGameProcess` always prefers live detection over this table.
 */
export const KNOWN_GTAV_TITLE_IDS = new Set([
  "CUSA00411",
  "CUSA00419",
  "CUSA00420",
  "CUSA00880",
  "CUSA01014",
  "CUSA01045",
]);

export const GAME_PROCESS_NAME = "eboot.bin";

export interface GameProcess {
  pid: number;
  titleId: string;
  path: string;
  /** True when the title id is in the known-GTAV table. */
  recognised: boolean;
}

export async function findGameProcess(api: Ps4Debug): Promise<GameProcess> {
  const procs = await api.processes();
  const candidates = procs.filter((p) => p.name === GAME_PROCESS_NAME);
  if (!candidates.length) {
    throw new Error(
      "no game process found — a game must be running and in the foreground. " +
        `Processes seen: ${procs.map((p) => p.name).join(", ") || "(none)"}`,
    );
  }
  const infos = [];
  for (const candidate of candidates) {
    try {
      infos.push(await api.processInfo(candidate.pid));
    } catch {
      // A process can exit between the list and the info query; ignore it.
    }
  }
  const gta = infos.find((info) => KNOWN_GTAV_TITLE_IDS.has(info.titleId));
  const chosen = gta ?? infos[0];
  if (!chosen) throw new Error("found eboot.bin but could not read its process info");
  return {
    pid: chosen.pid,
    titleId: chosen.titleId,
    path: chosen.path,
    recognised: KNOWN_GTAV_TITLE_IDS.has(chosen.titleId),
  };
}

export interface ModuleRange {
  name: string;
  start: bigint;
  end: bigint;
  size: bigint;
}

/**
 * The main executable's code segment. ps4debug reports the eboot's segments with
 * the name `executable`; we take the first executable-protection entry, which is
 * `.text` and the only region worth signature-scanning.
 */
export async function findExecutableSegment(api: Ps4Debug, pid: number): Promise<ModuleRange> {
  const maps = await api.maps(pid);
  const exec = maps.filter((m) => (m.prot & 4) !== 0);
  const named = exec.find((m) => m.name.toLowerCase().includes("executable"));
  const chosen = named ?? largest(exec);
  if (!chosen) {
    throw new Error(
      `process ${pid} has no executable memory regions — is the pid correct? ` +
        `Use ps4_list_processes to check.`,
    );
  }
  return { name: chosen.name || "executable", start: chosen.start, end: chosen.end, size: chosen.size };
}

function largest(maps: ProcMap[]): ProcMap | undefined {
  return maps.reduce<ProcMap | undefined>(
    (best, m) => (!best || m.size > best.size ? m : best),
    undefined,
  );
}

/**
 * Jenkins one-at-a-time hash, lowercased — RAGE's `joaat`.
 *
 * This is the hash the *game* uses for strings: model names ("adder"),
 * animation dictionaries, weapon names, and everything GET_HASH_KEY returns. It
 * is stable across platforms and builds, so it is safe to compute host-side.
 *
 * It is NOT how GTA V native hashes work. Native hashes in the public database
 * (GET_PLAYER_PED = 0x43A66C31 on b323) are not joaat of the native's name, and
 * they are rotated again on every game build. Mapping a native name to the hash
 * *this* build uses requires a crossmap — see docs/natives.md.
 */
export function joaat(input: string): number {
  let hash = 0;
  const text = input.toLowerCase();
  for (let i = 0; i < text.length; i++) {
    hash = (hash + text.charCodeAt(i)) >>> 0;
    hash = (hash + (hash << 10)) >>> 0;
    hash = (hash ^ (hash >>> 6)) >>> 0;
  }
  hash = (hash + (hash << 3)) >>> 0;
  hash = (hash ^ (hash >>> 11)) >>> 0;
  hash = (hash + (hash << 15)) >>> 0;
  return hash >>> 0;
}

/**
 * Signatures for the RAGE script-engine structures OrbisScriptHook needs.
 *
 * IMPORTANT: these are the well-known *PC* signatures. The PS4 build is the same
 * engine compiled by the same toolchain family for the same ISA, so the shapes
 * survive, but the exact byte sequences will not all match. They are here as
 * scan seeds: run `gta_scan_pattern` with each, see which land, and refine
 * against your own dump. Anything that resolves should be recorded in
 * `plugin/orbis/game_offsets.h` so the on-console plugin stops guessing.
 */
export const SCAN_SEEDS: { id: string; what: string; pattern: string; note: string }[] = [
  {
    id: "native_registration_table",
    what: "rage::scrEngine native registration table",
    pattern: "76 32 48 8B 53 40 48 8D 0D",
    note: "Leads to the linked list of scrNativeRegistration blocks (hash + handler pairs).",
  },
  {
    id: "get_native_handler",
    what: "rage::scrEngine::GetNativeHandler",
    pattern: "48 89 5C 24 ?? 57 48 83 EC 20 8B D9 8B FA",
    note: "Preferred entry point: call it with a joaat hash to get a handler pointer.",
  },
  {
    id: "script_thread_tick",
    what: "GtaThread / scrThread::Run dispatcher",
    pattern: "80 B9 ?? ?? ?? ?? ?? 8B FA 48 8B D9 74 ??",
    note: "Hook target for running mod scripts on the game's own script thread.",
  },
  {
    id: "world_ped_pool",
    what: "CPed pool pointer",
    pattern: "4C 8B 0D ?? ?? ?? ?? 44 8B C1 49 8B 41 ??",
    note: "RIP-relative operand at +3 points at the pool; needed by worldGetAllPeds().",
  },
  {
    id: "script_globals",
    what: "scrProgram global block table",
    pattern: "4C 8D 05 ?? ?? ?? ?? 4D 8B 08 4D 85 C9 74 ??",
    note: "Backs getGlobalPtr(); the operand at +3 is the global block array.",
  },
];
