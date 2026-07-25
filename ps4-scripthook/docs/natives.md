# Native hashes on an unmapped build

This is the hardest part of the project, so it is worth being precise about why.

## Why you cannot just use the PC hashes

Three separate things get called "the hash" and conflating them wastes days:

1. **`joaat(name)`** — Jenkins one-at-a-time, lowercased. This is what `GET_HASH_KEY` computes and
   what model names, weapon names and animation dictionaries hash to. It is stable across every
   platform and build. `gta_joaat` computes it locally, and `osh::joaat()` computes it in the
   plugin.

2. **The native hash in the public database** — e.g. `GET_PLAYER_PED = 0x43A66C31`. This is *not*
   `joaat("GET_PLAYER_PED")`, which is `0x6E31E993`. The public names were recovered separately
   from the hashes; there is no function mapping one to the other.

3. **The native hash *this build* uses** — Rockstar rotated the native table between game builds,
   so the same native has different hashes on different versions. A table mapping one build's
   hashes to another's is called a crossmap.

So: a native name cannot be turned into a hash by computation. It has to come from a table.

## What the plugin does about it

`Crossmap` (`plugin/orbis/crossmap.h`) holds name → hash for the build you are running on. It is
populated from two places:

- A tiny built-in set of b323 PC hashes, purely as a smoke test. If those resolve on your console,
  your build shares b323's table and you have got off lightly. `scripthook_log` tells you either
  way.
- `/data/GoldHEN/scripthook/natives.txt`, one `NAME=0xHASH` per line, `#` for comments. Entries
  here override the built-ins. This is the file you will actually maintain, and it is read at
  plugin load, so adding natives needs no rebuild — just re-upload and restart the game.

```
# /data/GoldHEN/scripthook/natives.txt
PLAYER_PED_ID        = 0xD80958FC
SET_ENTITY_INVINCIBLE= 0x3882114B
GET_ENTITY_COORDS    = 0x3FEF770D
```

Scripts written against `nativeByName()` are therefore build-independent: only the text file
changes when you move to another build.

## Producing a crossmap

Three approaches, cheapest first.

### 1. Try an existing one

If the console's build corresponds to a PC build that has a published crossmap, the mapping may
already exist. Confirm before trusting it: pick five natives, resolve each hash through
`scripthook_resolve` (or `scripthook_call_native` with a harmless read-only native like
`PLAYER_ID`), and check the answers are sane. A crossmap that is wrong in a few entries is worse
than none — those entries call arbitrary handlers.

### 2. Walk the registration table and match by arity and behaviour

Once `native_registration_table` resolves, the plugin has every hash and handler pair on the
console. That gives you the complete set of hashes for the build; what is missing is which name
goes with which. Two signals narrow it fast:

- **Handler shape.** Many natives are one-line handlers whose disassembly is distinctive — a
  single field read at a fixed offset, a call to a known engine function, a constant return.
- **Order.** Natives are registered in blocks in a stable order that tends to survive between
  builds. Aligning your table against a known build's table by position identifies large runs at
  once.

`ps4_read_memory` over the handler addresses gives you the bytes to compare.

### 3. Behavioural probing

For the handful you actually need, call a candidate hash with known-safe arguments through
`scripthook_call_native` and see if the return value matches what the named native should do.
`PLAYER_ID` returning a small integer, `GET_ENTITY_HEALTH` on the player ped returning something
near 200 — that kind of check. Slow, but decisive, and it is how you confirm the results of the
other two methods.

## A caution

An unresolved native is safe: `Game::invoke` logs and returns false, and the call is skipped. A
*wrongly* resolved native is not — it jumps into a handler that expects different arguments. When
you are unsure about an entry, leave it out of `natives.txt` rather than guessing.
