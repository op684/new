/**
 * Host-side signature scanning.
 *
 * The console has no scanner of its own that we can drive remotely, so we pull
 * memory down in windows and match locally. That is slow over Wi-Fi but it is
 * exactly what you want while reverse-engineering: patterns can be iterated on
 * without rebuilding and re-deploying anything to the PS4.
 */

import type { Ps4Debug } from "./ps4debug.js";

export interface PatternByte {
  /** -1 means "wildcard". */
  value: number;
}

/** Parse an IDA-style signature: `48 8B 05 ?? ?? ?? ?? 48 85 C0`. */
export function parsePattern(pattern: string): number[] {
  const tokens = pattern.trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) throw new Error("empty pattern");
  return tokens.map((token) => {
    if (token === "?" || token === "??") return -1;
    if (!/^[0-9a-fA-F]{2}$/.test(token)) {
      throw new Error(
        `invalid pattern token "${token}" — expected a two-digit hex byte or "??" wildcard`,
      );
    }
    return Number.parseInt(token, 16);
  });
}

/** Find every offset in `haystack` matching `needle` (with -1 wildcards). */
export function findPattern(haystack: Buffer, needle: number[]): number[] {
  const hits: number[] = [];
  const last = haystack.length - needle.length;
  outer: for (let i = 0; i <= last; i++) {
    for (let j = 0; j < needle.length; j++) {
      const want = needle[j]!;
      if (want !== -1 && haystack[i + j] !== want) continue outer;
    }
    hits.push(i);
  }
  return hits;
}

export interface ScanOptions {
  pid: number;
  start: bigint;
  end: bigint;
  pattern: string;
  /** Stop after this many hits. */
  limit?: number;
  /** Window size per ps4debug read. */
  windowSize?: number;
}

const DEFAULT_WINDOW = 0x8000;

/**
 * Scan `[start, end)` in the target process. Windows overlap by `pattern.length-1`
 * bytes so a match straddling a window boundary is still found.
 */
export async function scanRange(api: Ps4Debug, opts: ScanOptions): Promise<bigint[]> {
  const needle = parsePattern(opts.pattern);
  const limit = opts.limit ?? 16;
  const window = opts.windowSize ?? DEFAULT_WINDOW;
  const overlap = needle.length - 1;
  const hits: bigint[] = [];

  for (let cursor = opts.start; cursor < opts.end; ) {
    const remaining = Number(opts.end - cursor);
    const size = Math.min(window, remaining);
    let chunk: Buffer;
    try {
      chunk = await api.readMemory(opts.pid, cursor, size);
    } catch {
      // Unmapped holes are normal inside a module's address range; skip the window.
      cursor += BigInt(size);
      continue;
    }
    for (const offset of findPattern(chunk, needle)) {
      hits.push(cursor + BigInt(offset));
      if (hits.length >= limit) return hits;
    }
    if (size <= overlap) break;
    cursor += BigInt(size - overlap);
  }
  return hits;
}

/**
 * Resolve a RIP-relative operand. `at` points at the 4-byte displacement,
 * `instructionEnd` is the address of the next instruction.
 */
export function resolveRipRelative(
  displacement: number,
  instructionEnd: bigint,
): bigint {
  return BigInt.asUintN(64, instructionEnd + BigInt(displacement));
}
