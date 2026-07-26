/**
 * Round-trips the ps4debug client against an in-process mock of the console's
 * command server. This is the only part of the stack that can be verified
 * without hardware, so it is verified thoroughly: every packet the client emits
 * is decoded and asserted on by the mock.
 */

import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

import { Ps4Debug } from "../dist/services/ps4debug.js";
import {
  Cmd,
  PACKET_MAGIC,
  Status,
  parseProcList,
  parseProcMaps,
  formatProt,
  protFromString,
} from "../dist/services/protocol.js";
import { findPattern, parsePattern } from "../dist/services/scan.js";
import { joaat } from "../dist/services/gta.js";
import { toAddress, toBytes, hexDump } from "../dist/services/format.js";
import { parsePasv, replyCode } from "../dist/services/transfer.js";

const SUCCESS = Buffer.alloc(4);
SUCCESS.writeUInt32LE(Status.SUCCESS >>> 0, 0);

/** Fixed 32-byte name field. */
function name32(text) {
  const buf = Buffer.alloc(32);
  buf.write(text, 0, "utf8");
  return buf;
}

/**
 * Mock console. Handles one command at a time, recording what it saw so tests
 * can assert on the exact bytes the client produced.
 */
function startMockConsole(handlers) {
  const seen = [];
  const server = net.createServer((socket) => {
    let buffered = Buffer.alloc(0);
    let expecting = null;

    const pump = async () => {
      for (;;) {
        if (expecting) {
          if (buffered.length < expecting.bytes) return;
          const body = buffered.subarray(0, expecting.bytes);
          buffered = buffered.subarray(expecting.bytes);
          const resume = expecting.resume;
          expecting = null;
          await resume(body);
          continue;
        }
        if (buffered.length < 12) return;
        const magic = buffered.readUInt32LE(0);
        assert.equal(magic >>> 0, PACKET_MAGIC >>> 0, "bad packet magic");
        const cmd = buffered.readUInt32LE(4);
        const dataLen = buffered.readUInt32LE(8);
        if (buffered.length < 12 + dataLen) return;
        const payload = buffered.subarray(12, 12 + dataLen);
        buffered = buffered.subarray(12 + dataLen);
        seen.push({ cmd, payload: Buffer.from(payload) });
        const handler = handlers[cmd];
        assert.ok(handler, `mock console got an unhandled command 0x${cmd.toString(16)}`);
        await handler({
          payload,
          send: (buf) => socket.write(buf),
          ok: () => socket.write(SUCCESS),
          // Read a follow-up body (used by the two-phase write/elf commands).
          expect: (bytes) => new Promise((resolve) => {
            expecting = { bytes, resume: async (body) => resolve(body) };
            // Re-enter the loop so already-buffered bytes are consumed.
            queueMicrotask(pump);
          }),
        });
      }
    };

    socket.on("data", (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      pump().catch((err) => {
        socket.destroy();
        throw err;
      });
    });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: server.address().port, seen });
    });
  });
}

test("version, process list and process info round-trip", async () => {
  const mock = await startMockConsole({
    [Cmd.VERSION]: ({ send }) => {
      const text = Buffer.from("ps4debug 1.1.19", "utf8");
      const len = Buffer.alloc(4);
      len.writeUInt32LE(text.length, 0);
      send(Buffer.concat([len, text]));
    },
    [Cmd.PROC_LIST]: ({ ok, send }) => {
      ok();
      const count = Buffer.alloc(4);
      count.writeUInt32LE(2, 0);
      const pid1 = Buffer.alloc(4);
      pid1.writeUInt32LE(76, 0);
      const pid2 = Buffer.alloc(4);
      pid2.writeUInt32LE(112, 0);
      send(Buffer.concat([count, name32("SceShellCore"), pid1, name32("eboot.bin"), pid2]));
    },
    [Cmd.PROC_INFO]: ({ payload, ok, send }) => {
      assert.equal(payload.readUInt32LE(0), 112);
      ok();
      const info = Buffer.alloc(188);
      info.writeUInt32LE(112, 0);
      info.write("eboot.bin", 4);
      info.write("/mnt/sandbox/CUSA00419_000/app0/eboot.bin", 36);
      info.write("CUSA00419", 100);
      info.write("EP1004-CUSA00419_00-GTAVAPP000000001", 116);
      send(info);
    },
  });

  const api = new Ps4Debug({ host: "127.0.0.1", port: mock.port, timeoutMs: 4000 });
  assert.equal(await api.version(), "ps4debug 1.1.19");

  const procs = await api.processes();
  assert.deepEqual(procs, [
    { name: "SceShellCore", pid: 76 },
    { name: "eboot.bin", pid: 112 },
  ]);

  const info = await api.processInfo(112);
  assert.equal(info.titleId, "CUSA00419");
  assert.equal(info.name, "eboot.bin");
  assert.match(info.path, /CUSA00419/);

  api.disconnect();
  mock.server.close();
});

test("memory read is chunked and write is two-phase", async () => {
  const REGION_BASE = 0x0000000000400000n;
  const region = Buffer.alloc(0x12000);
  for (let i = 0; i < region.length; i++) region[i] = i & 0xff;
  const writes = [];

  const mock = await startMockConsole({
    [Cmd.PROC_READ]: ({ payload, ok, send }) => {
      const addr = payload.readBigUInt64LE(4);
      const len = payload.readUInt32LE(12);
      assert.ok(len <= 0x8000, `client asked for ${len} bytes in one read`);
      ok();
      const offset = Number(addr - REGION_BASE);
      send(region.subarray(offset, offset + len));
    },
    [Cmd.PROC_WRITE]: async ({ payload, ok, expect }) => {
      const addr = payload.readBigUInt64LE(4);
      const len = payload.readUInt32LE(12);
      ok();
      const body = await expect(len);
      writes.push({ addr, body: Buffer.from(body) });
      ok();
    },
  });

  const api = new Ps4Debug({ host: "127.0.0.1", port: mock.port, timeoutMs: 4000 });

  // 0x12000 bytes forces three chunked reads (0x8000 + 0x8000 + 0x2000).
  const data = await api.readMemory(112, REGION_BASE, region.length);
  assert.equal(data.length, region.length);
  assert.ok(data.equals(region), "chunked read reassembled out of order");

  await api.writeMemory(112, REGION_BASE + 0x10n, Buffer.from([0x90, 0x90, 0xc3]));
  assert.equal(writes.length, 1);
  assert.equal(writes[0].addr, REGION_BASE + 0x10n);
  assert.deepEqual([...writes[0].body], [0x90, 0x90, 0xc3]);

  api.disconnect();
  mock.server.close();
});

test("rpc install and call encode a 68-byte argument blob", async () => {
  let callPayload;
  const mock = await startMockConsole({
    [Cmd.PROC_INSTALL]: ({ ok, send }) => {
      ok();
      const stub = Buffer.alloc(8);
      stub.writeBigUInt64LE(0x9000n, 0);
      send(stub);
    },
    [Cmd.PROC_CALL]: ({ payload, ok, send }) => {
      callPayload = Buffer.from(payload);
      ok();
      const resp = Buffer.alloc(12);
      resp.writeUInt32LE(112, 0);
      resp.writeBigUInt64LE(0xdeadbeefn, 4);
      send(resp);
    },
  });

  const api = new Ps4Debug({ host: "127.0.0.1", port: mock.port, timeoutMs: 4000 });
  const stub = await api.installRpc(112);
  assert.equal(stub, 0x9000n);

  const rax = await api.call(112, stub, 0x401000n, [1n, 2n, 3n]);
  assert.equal(rax, 0xdeadbeefn);
  assert.equal(callPayload.length, 68, "PROC_CALL blob must be 68 bytes");
  assert.equal(callPayload.readUInt32LE(0), 112);
  assert.equal(callPayload.readBigUInt64LE(4), 0x9000n);
  assert.equal(callPayload.readBigUInt64LE(12), 0x401000n);
  assert.equal(callPayload.readBigUInt64LE(20), 1n);
  assert.equal(callPayload.readBigUInt64LE(28), 2n);
  assert.equal(callPayload.readBigUInt64LE(36), 3n);

  await assert.rejects(
    () => api.call(112, stub, 0x401000n, [1n, 2n, 3n, 4n, 5n, 6n, 7n]),
    /at most 6/,
  );

  api.disconnect();
  mock.server.close();
});

test("a failure status becomes a descriptive error", async () => {
  const mock = await startMockConsole({
    [Cmd.PROC_READ]: ({ send }) => {
      const status = Buffer.alloc(4);
      status.writeUInt32LE(Status.DATA_NULL >>> 0, 0);
      send(status);
    },
  });

  const api = new Ps4Debug({ host: "127.0.0.1", port: mock.port, timeoutMs: 4000 });
  await assert.rejects(() => api.readMemory(112, 0xdead0000n, 16), /unreadable|no data/i);
  api.disconnect();
  mock.server.close();
});

test("proc maps parse into ranges with protection flags", () => {
  const count = Buffer.alloc(4);
  count.writeUInt32LE(1, 0);
  const entry = Buffer.alloc(58);
  name32("executable").copy(entry, 0);
  entry.writeBigUInt64LE(0x400000n, 32);
  entry.writeBigUInt64LE(0x2400000n, 40);
  entry.writeBigUInt64LE(0n, 48);
  entry.writeUInt16LE(5, 56); // r-x
  const maps = parseProcMaps(Buffer.concat([count, entry]));
  assert.equal(maps.length, 1);
  assert.equal(maps[0].name, "executable");
  assert.equal(maps[0].size, 0x2000000n);
  assert.equal(formatProt(maps[0].prot), "r-x");
  assert.equal(protFromString("rwx"), 7);
});

test("proc list tolerates a truncated tail", () => {
  const count = Buffer.alloc(4);
  count.writeUInt32LE(3, 0);
  const pid = Buffer.alloc(4);
  pid.writeUInt32LE(9, 0);
  const parsed = parseProcList(Buffer.concat([count, name32("a"), pid]));
  assert.equal(parsed.length, 1, "a short response must not throw");
});

test("pattern parsing and matching handle wildcards", () => {
  assert.deepEqual(parsePattern("48 8B ?? C3"), [0x48, 0x8b, -1, 0xc3]);
  assert.throws(() => parsePattern("48 ZZ"), /invalid pattern token/);
  assert.throws(() => parsePattern("   "), /empty pattern/);

  const haystack = Buffer.from([0x48, 0x8b, 0x05, 0xc3, 0x00, 0x48, 0x8b, 0x99, 0xc3]);
  assert.deepEqual(findPattern(haystack, parsePattern("48 8B ?? C3")), [0, 5]);
  assert.deepEqual(findPattern(haystack, parsePattern("48 8B 05 C3")), [0]);
  assert.deepEqual(findPattern(haystack, parsePattern("FF FF")), []);
});

test("joaat matches a reference implementation", () => {
  // Cross-checked against an independent implementation of Jenkins
  // one-at-a-time. NOTE: these are RAGE *string* hashes (GET_HASH_KEY), not
  // GTA V native hashes — natives are not joaat of their public names.
  assert.equal(joaat("GET_PLAYER_PED") >>> 0, 0x6e31e993);
  assert.equal(joaat("SET_ENTITY_COORDS") >>> 0, 0xdf70b41b);
  assert.equal(joaat("adder") >>> 0, joaat("ADDER") >>> 0, "hashing must be case-insensitive");
  assert.equal(joaat("") >>> 0, 0);
});

test("address and byte parsing accept the documented forms", () => {
  assert.equal(toAddress("0x400000"), 0x400000n);
  // Bare digit strings are decimal, matching the documented behaviour.
  assert.equal(toAddress("400000"), 400000n);
  // Bare strings containing hex letters are unambiguous and read as hex.
  assert.equal(toAddress("4a0000"), 0x4a0000n);
  assert.equal(toAddress(1024), 1024n);
  assert.throws(() => toAddress("nope"), /not a valid address/);

  assert.deepEqual([...toBytes("90 90 C3")], [0x90, 0x90, 0xc3]);
  assert.deepEqual([...toBytes("9090c3")], [0x90, 0x90, 0xc3]);
  assert.deepEqual([...toBytes("base64:kJDD")], [0x90, 0x90, 0xc3]);
  assert.throws(() => toBytes("90 9"), /not valid hex/);
});

test("hex dump renders 16 bytes per line with an ascii gutter", () => {
  const dump = hexDump(Buffer.from("ABCD"), 0x400000n);
  assert.match(dump, /^0000000000400000 {2}41 42 43 44 +\|ABCD\|$/);

  const two = hexDump(Buffer.alloc(20), 0x400000n).split("\n");
  assert.equal(two.length, 2, "20 bytes must wrap onto a second line");
  assert.ok(two[1].startsWith("0000000000400010"), "the second line must be 16 bytes further on");
});

test("ftp helpers parse passive replies and reply codes", () => {
  assert.deepEqual(parsePasv("227 Entering Passive Mode (192,168,1,42,195,80)"), {
    host: "192.168.1.42",
    port: 195 * 256 + 80,
  });
  assert.throws(() => parsePasv("227 nope"), /could not parse/);
  assert.equal(replyCode("220-hello\r\n220 ready"), 220);
  assert.equal(replyCode("550 nope"), 550);
});
