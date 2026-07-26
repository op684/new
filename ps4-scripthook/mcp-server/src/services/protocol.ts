/**
 * ps4debug wire protocol.
 *
 * ps4debug is a payload (GoldHEN ships a fork) that opens a TCP command server
 * on the console. Every request is a 12-byte little-endian header followed by an
 * optional fixed-size argument blob; every response begins with a 4-byte status
 * word, then command-specific data.
 *
 *   header: magic:u32 | cmd:u32 | datalen:u32
 *
 * Constants below match the GoldHEN/jogolden ps4debug `protocol.h` and the
 * reference C# client (`PS4DBG.cs`). Anything I was not able to verify against a
 * primary source is called out in a comment; use `ps4_raw_command` from the MCP
 * layer if you need to poke a command that is not modelled here.
 */

export const PACKET_MAGIC = 0xffaabbcc;

/** Main command server. */
export const PS4DEBUG_PORT = 744;
/** Async debugger event channel (breakpoint/exception callbacks). */
export const PS4DEBUG_EVENT_PORT = 755;
/** UDP broadcast discovery. */
export const PS4DEBUG_BROADCAST_PORT = 1010;
/** GoldHEN payload loader — raw ELF/BIN dumped onto this socket gets executed. */
export const PAYLOAD_PORT = 9090;
/** GoldHEN FTP server (anonymous). */
export const FTP_PORT = 2121;
/** OrbisScriptHook plugin control channel (see ../../plugin/orbis/ipc.cpp). */
export const SCRIPTHOOK_PORT = 9028;

export const HEADER_SIZE = 12;

export enum Cmd {
  VERSION = 0xbd000001,

  PROC_LIST = 0xbdaa0001,
  PROC_READ = 0xbdaa0002,
  PROC_WRITE = 0xbdaa0003,
  PROC_MAPS = 0xbdaa0004,
  /** Installs the RPC stub into the target; returns the stub address. */
  PROC_INSTALL = 0xbdaa0005,
  PROC_CALL = 0xbdaa0006,
  /** Load + run an ELF inside the target process. */
  PROC_ELF = 0xbdaa0007,
  PROC_PROTECT = 0xbdaa0008,
  PROC_SCAN = 0xbdaa0009,
  PROC_INFO = 0xbdaa000a,
  PROC_ALLOC = 0xbdaa000b,
  PROC_FREE = 0xbdaa000c,

  DEBUG_ATTACH = 0xbdbb0001,
  DEBUG_DETACH = 0xbdbb0002,
  DEBUG_BREAKPT = 0xbdbb0003,
  DEBUG_WATCHPT = 0xbdbb0004,
  DEBUG_THREADS = 0xbdbb0005,
  DEBUG_STOPTHR = 0xbdbb0006,
  DEBUG_RESUMETHR = 0xbdbb0007,
  DEBUG_GETREGS = 0xbdbb0008,
  DEBUG_SETREGS = 0xbdbb0009,
  DEBUG_STOPGO = 0xbdbb000e,
  DEBUG_THRINFO = 0xbdbb000f,
  DEBUG_SINGLESTEP = 0xbdbb0010,

  KERN_BASE = 0xbdcc0001,
  KERN_READ = 0xbdcc0002,
  KERN_WRITE = 0xbdcc0003,

  CONSOLE_REBOOT = 0xbddd0001,
  CONSOLE_END = 0xbddd0002,
  CONSOLE_PRINT = 0xbddd0003,
  CONSOLE_NOTIFY = 0xbddd0004,
  CONSOLE_INFO = 0xbddd0005,
}

export enum Status {
  SUCCESS = 0x80000000,
  ERROR = 0xf0000001,
  TOO_MUCH_DATA = 0xf0000002,
  DATA_NULL = 0xf0000003,
  ALREADY_DEBUG = 0xf0000004,
  INVALID_INDEX = 0xf0000005,
}

const STATUS_TEXT: Record<number, string> = {
  [Status.SUCCESS]: "success",
  [Status.ERROR]: "generic error — the console rejected the command",
  [Status.TOO_MUCH_DATA]: "too much data — split the request into smaller chunks",
  [Status.DATA_NULL]: "no data — the requested region is empty or unreadable",
  [Status.ALREADY_DEBUG]: "a debugger is already attached to that process",
  [Status.INVALID_INDEX]: "invalid index (bad pid, thread id or breakpoint slot)",
};

export function describeStatus(status: number): string {
  return STATUS_TEXT[status >>> 0] ?? `unknown status 0x${(status >>> 0).toString(16)}`;
}

export class Ps4DebugError extends Error {
  constructor(
    readonly cmd: Cmd,
    readonly status: number,
  ) {
    super(
      `ps4debug command ${Cmd[cmd] ?? `0x${cmd.toString(16)}`} failed: ${describeStatus(status)}`,
    );
    this.name = "Ps4DebugError";
  }
}

/** Fixed argument-blob sizes, keyed by command. Used to sanity-check callers. */
export const CMD_PAYLOAD_SIZE: Partial<Record<Cmd, number>> = {
  [Cmd.PROC_READ]: 16,
  [Cmd.PROC_WRITE]: 16,
  [Cmd.PROC_MAPS]: 4,
  [Cmd.PROC_INSTALL]: 4,
  [Cmd.PROC_CALL]: 68,
  [Cmd.PROC_ELF]: 8,
  [Cmd.PROC_PROTECT]: 24,
  [Cmd.PROC_SCAN]: 13,
  [Cmd.PROC_INFO]: 4,
  [Cmd.PROC_ALLOC]: 8,
  [Cmd.PROC_FREE]: 16,
  [Cmd.KERN_READ]: 12,
  [Cmd.KERN_WRITE]: 12,
  [Cmd.CONSOLE_NOTIFY]: 8,
  [Cmd.CONSOLE_PRINT]: 4,
};

export function buildHeader(cmd: Cmd, dataLen: number): Buffer {
  const header = Buffer.alloc(HEADER_SIZE);
  header.writeUInt32LE(PACKET_MAGIC, 0);
  header.writeUInt32LE(cmd >>> 0, 4);
  header.writeUInt32LE(dataLen >>> 0, 8);
  return header;
}

export interface ParsedHeader {
  magic: number;
  cmd: number;
  dataLen: number;
}

export function parseHeader(buf: Buffer): ParsedHeader {
  if (buf.length < HEADER_SIZE) {
    throw new Error(`short header: got ${buf.length} bytes, need ${HEADER_SIZE}`);
  }
  return {
    magic: buf.readUInt32LE(0),
    cmd: buf.readUInt32LE(4),
    dataLen: buf.readUInt32LE(8),
  };
}

/** Entry of a CMD_PROC_LIST response: char name[32]; uint32 pid. */
export const PROC_LIST_ENTRY_SIZE = 36;
/** Entry of a CMD_PROC_MAPS response: char name[32]; u64 start,end,offset; u16 prot. */
export const PROC_MAP_ENTRY_SIZE = 58;
/** CMD_PROC_INFO response: pid, name[32], path[64], titleid[16], contentid[64]. */
export const PROC_INFO_SIZE = 188;

export interface ProcEntry {
  name: string;
  pid: number;
}

export interface ProcMap {
  name: string;
  start: bigint;
  end: bigint;
  offset: bigint;
  prot: number;
  size: bigint;
}

export interface ProcInfo {
  pid: number;
  name: string;
  path: string;
  titleId: string;
  contentId: string;
}

function cstr(buf: Buffer, offset: number, length: number): string {
  const slice = buf.subarray(offset, offset + length);
  const nul = slice.indexOf(0);
  return slice.subarray(0, nul === -1 ? slice.length : nul).toString("utf8");
}

export function parseProcList(data: Buffer): ProcEntry[] {
  const count = data.readUInt32LE(0);
  const entries: ProcEntry[] = [];
  for (let i = 0; i < count; i++) {
    const base = 4 + i * PROC_LIST_ENTRY_SIZE;
    if (base + PROC_LIST_ENTRY_SIZE > data.length) break;
    entries.push({ name: cstr(data, base, 32), pid: data.readUInt32LE(base + 32) });
  }
  return entries;
}

export function parseProcMaps(data: Buffer): ProcMap[] {
  const count = data.readUInt32LE(0);
  const maps: ProcMap[] = [];
  for (let i = 0; i < count; i++) {
    const base = 4 + i * PROC_MAP_ENTRY_SIZE;
    if (base + PROC_MAP_ENTRY_SIZE > data.length) break;
    const start = data.readBigUInt64LE(base + 32);
    const end = data.readBigUInt64LE(base + 40);
    maps.push({
      name: cstr(data, base, 32),
      start,
      end,
      offset: data.readBigUInt64LE(base + 48),
      prot: data.readUInt16LE(base + 56),
      size: end - start,
    });
  }
  return maps;
}

export function parseProcInfo(data: Buffer): ProcInfo {
  return {
    pid: data.readUInt32LE(0),
    name: cstr(data, 4, 32),
    path: cstr(data, 36, 64),
    titleId: cstr(data, 100, 16),
    contentId: cstr(data, 116, 64),
  };
}

/** Render a FreeBSD vm_prot_t bitmask the way `procfs` would. */
export function formatProt(prot: number): string {
  return `${prot & 1 ? "r" : "-"}${prot & 2 ? "w" : "-"}${prot & 4 ? "x" : "-"}`;
}

export function protFromString(s: string): number {
  let prot = 0;
  if (s.includes("r")) prot |= 1;
  if (s.includes("w")) prot |= 2;
  if (s.includes("x")) prot |= 4;
  return prot;
}
