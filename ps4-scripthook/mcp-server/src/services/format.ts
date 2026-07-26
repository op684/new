/** Shared response shaping: hex dumps, truncation, and the tool result envelope. */

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

/** Above this, responses get truncated with an explicit note. */
export const CHARACTER_LIMIT = 25_000;

export enum ResponseFormat {
  MARKDOWN = "markdown",
  JSON = "json",
}

export function hex(value: bigint | number, pad = 0): string {
  return `0x${value.toString(16).toUpperCase().padStart(pad, "0")}`;
}

/** classic 16-bytes-per-line dump with ASCII gutter. */
export function hexDump(data: Buffer, baseAddress: bigint): string {
  const lines: string[] = [];
  for (let offset = 0; offset < data.length; offset += 16) {
    const row = data.subarray(offset, offset + 16);
    const bytes = [...row].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    const addr = (baseAddress + BigInt(offset)).toString(16).toUpperCase().padStart(16, "0");
    lines.push(`${addr}  ${bytes.padEnd(47)}  |${ascii}|`);
  }
  return lines.join("\n");
}

export interface Truncatable {
  truncated?: boolean;
  truncation_message?: string;
}

/**
 * Build a tool result. Long text is cut at CHARACTER_LIMIT with a message that
 * tells the caller how to ask for less.
 */
export function toolResult<T extends object>(
  text: string,
  structured: T,
  narrowingHint = "narrow the range or lower the limit",
): CallToolResult {
  let body = text;
  let payload: T & Truncatable = structured;
  if (body.length > CHARACTER_LIMIT) {
    body = `${body.slice(0, CHARACTER_LIMIT)}\n\n… truncated at ${CHARACTER_LIMIT} characters — ${narrowingHint}.`;
    payload = {
      ...structured,
      truncated: true,
      truncation_message: `Response truncated at ${CHARACTER_LIMIT} characters; ${narrowingHint}.`,
    };
  }
  return {
    content: [{ type: "text", text: body }],
    structuredContent: payload as unknown as Record<string, unknown>,
  };
}

export function errorResult(error: unknown): CallToolResult {
  const message = error instanceof Error ? error.message : String(error);
  return {
    content: [{ type: "text", text: `Error: ${message}` }],
    isError: true,
  };
}

/** Wrap a tool handler so thrown errors become readable, non-fatal results. */
export function guarded<A>(fn: (args: A) => Promise<CallToolResult>) {
  return async (args: A): Promise<CallToolResult> => {
    try {
      return await fn(args);
    } catch (error) {
      return errorResult(error);
    }
  };
}

/** Accept "0x1234", "1234", or a decimal number and return a BigInt. */
export function toAddress(input: string | number): bigint {
  if (typeof input === "number") return BigInt(input);
  const text = input.trim();
  if (/^0x[0-9a-f]+$/i.test(text)) return BigInt(text);
  if (/^[0-9]+$/.test(text)) return BigInt(text);
  if (/^[0-9a-f]+$/i.test(text)) return BigInt(`0x${text}`);
  throw new Error(`"${input}" is not a valid address — use 0x-prefixed hex or a decimal number`);
}

/** Decode "48 8B 05" / "488b05" / base64: (prefixed) into raw bytes. */
export function toBytes(input: string): Buffer {
  const text = input.trim();
  if (text.startsWith("base64:")) return Buffer.from(text.slice(7), "base64");
  const compact = text.replace(/[\s,]|0x/gi, "");
  if (!/^[0-9a-f]*$/i.test(compact) || compact.length % 2 !== 0) {
    throw new Error(
      `"${input}" is not valid hex — pass bytes as "DE AD BE EF", "deadbeef", or "base64:<data>"`,
    );
  }
  return Buffer.from(compact, "hex");
}
