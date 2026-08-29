# rex -- reference

Everything the quickstart doesn't cover. `rex --help` prints the same command
list from the module docstring.

## Contents

- [Configuration keys](#configuration-keys)
- [Target layout](#target-layout)
- [Corpus generation (`rex shards`)](#corpus-generation-rex-shards)
- [Command reference](#command-reference)
- [The `ann` badge legend](#the-ann-badge-legend)
- [Registry file formats](#registry-file-formats)
- [MEMORY-MAP.md format](#memory-mapmd-format)
- [Headers integration](#headers-integration)
- [Getting `uncompressed_main`](#getting-uncompressed_main)
- [Gotchas](#gotchas)

## Configuration keys

Resolution order: **env > `~/.rexrc` > default**. `~/.rexrc` is `KEY=VALUE`
lines, `#` comments. Explicit config is law: set-and-invalid → immediate
error, no silent fallback.

| key | default | meaning |
|---|---|---|
| `REX_ROOT` | -- (**required**) | target dir (any layout matching below) |
| `REX_BIN` | `main-binary/uncompressed_main` | raw binary, relative to ROOT |
| `REX_DUMPERS` | `$REX_ROOT/dumpers` | dir with the dump `.java` files |
| `REX_GHIDRA_PROJ` | `$REX_ROOT/ghidra-project` | Ghidra project dir |
| `REX_GPR` | first `.gpr` found in the project dir | project file name inside it |
| `REX_PROGRAM` | `uncompressed_main` | program name inside the Ghidra project |
| `REX_BASE` | `0x7100000000` | NSO VA base |
| `REX_HEADERS` | -- | headers `include/` dir (see below) |
| `GHIDRA_HOME` | homebrew 12.1.2 | Ghidra install |

## Target layout

```
<target>/                      ← REX_ROOT
  main-binary/uncompressed_main    raw binary (REX_BIN)
  ghidra-project/<name>.gpr          Ghidra project (REX_GHIDRA_PROJ/REX_GPR)
  dumpers/*.java                   FullDecompDump/FullAsmDump (REX_DUMPERS)
  data/decomp-full/                ← generated: shards + functions.tsv
  data/asm-full/                   ← generated: shards + functions.tsv
  data/*.json                      optional registries (see formats below)
  notes/MEMORY-MAP.md              optional: offset owners (feeds ann)
```

Bootstrap: `mkdir -p <target> && cp -r ~/rex/dumpers <target>/` --
the rex copy is canonical; `REX_DUMPERS` may point straight at it.

## Corpus generation (`rex shards`)

```
rex shards [all|decomp|asm] [--force]
```

Pipeline per dumper: clear OSGi cache → `javac` with Ghidra's full jar
classpath → install `.java`+`.class` into the user's
`ghidra_*/Extensions/SwitchLoader/ghidra_scripts/` (under the Ghidra user
settings dir: `~/Library/ghidra` on macOS, `~/.ghidra` elsewhere) → run
`analyzeHeadless <proj> -process <program> -noanalysis -postScript <Dumper>`
from a neutral cwd (`/tmp`) → fail on `SCRIPT ERROR` in the log.

- decomp: minutes-scale for tens of thousands of functions, has **RESUME**
  (existing `ok` entries in `functions.tsv` are skipped); `--force` ignores it
- asm: ~100 s
- the subprocess gets `REX_ROOT` injected into its env (Java doesn't read
  `~/.rexrc`)

Output: `data/{decomp,asm}-full/shard-NNN.txt` (500 functions per shard) +
`functions.tsv`. Shard numbering is identical across both corpora -- a hard
requirement of `shard_resolve`.

## Command reference

VA arguments accept `0x7100...`, bare hex, `FUN_...`, `thunk_FUN_...`, and
registry short names (`rex ann PlayerMove`).

| command | what it does |
|---|---|
| `fn <va>` | function containing the VA (+offset); warns on GAP |
| `fn -r A..B` | catalogued functions with start in range |
| `body <va> [-a]` | decomp (or asm) body; mid-function → whole container; GAP → in-place dis |
| `ann <va>` | decomp + annotations (MEMORY-MAP, registries, headers, notes) |
| `callers <va>` | all BL sites targeting it, bounds-checked (GAP hits discarded) |
| `offset <imm> [-w\|-l] [-m SUB] [-r A..B]` | instructions touching `[reg, #imm]` (default stores; `-l` loads); all widths, stp/ldp, writeback; `-m` filters mnemonic, `-r` VA range |
| `bit <off> <bit> [-r A..B]` | writers that SET/CLEAR/TOGGLE the bit, with the immediate def |
| `vtable <va\|name> [-n N] [-j\|-l]` | vtable dump via relocations (slots→functions) |
| `vtable-callers <va\|name>` | per slot: exact BL callers + BLR dispatch candidates |
| `blr <site>` / `blr -l` | resolve a virtual dispatch site / global BLR stats |
| `ctor <va\|name> [-l]` | static ctor chain: holders → vtables installed |
| `reloc <va> [-n N]` | NSO relocation entries from VA |
| `reloc -a <va>` | reverse: which vtable slots hold this function |
| `ptr <va>` | resolve a .data/.rodata qword (function/vtable/global/string) |
| `adrp <va>` | ADRP+ADD/LDR materializations of the VA |
| `xref <va\|name>` | every corpus reference (file:line + function) |
| `rodata <va> [-t T] [-n N]` | decode a table (i32/u32/f32/f64/…/hex; u64 → FUN_) |
| `str <va>` / `str -f <sub>` | C-string at VA / reverse substring search |
| `dis <va> [-n N]` / `dis <a> <b>` | in-place / range disassembly (capstone) |
| `headers <offset\|Struct>` | field at offset across all structs, or struct dump |
| `shards [all\|decomp\|asm] [--force]` | generate the corpus (above) |

## The `ann` badge legend

| badge | meaning |
|---|---|
| `+0x1e4=Director: ...` | owner confirmed by the line's own context |
| `+0x1e4≈Owner: ...` | heuristic single owner (confirm the base object) |
| `+0x1e4=? A ... \| B ...` | ambiguous -- multiple owners have this offset |
| trailing `?` | source status UNCONFIRMED/PARTIAL |
| `hdr:Struct.field` | from the C++ headers (REX_HEADERS), when MEMORY-MAP doesn't cover |
| `⭐ note` | curated note from `function-notes.json` |

## Registry file formats

All registries are optional; missing files just disable that feature. A
top-level `"_comment"` key is ignored everywhere. VAs are hex strings
**without** `0x` prefix.

```jsonc
// data/function-names.json -- short names, usable wherever a VA is
{"7100172ab0": "PlayerMove", "71001728fc": "StepUpdate"}

// data/globals.json -- DAT_ symbols → names
{"KartDirectorHolder": {"va": "7101300398", "tag": "holder", "value": "0x71011b2fe0"}}

// data/enums.json -- known values/masks, annotated in ann comparisons
{"control_byte": {"field": "Player+0x78 (low byte)",
                  "values": {"1": "idle", "5": "drift"},
                  "bits": {"0x200": "mini-turbo L1"}}}

// data/vtables.json -- curated vtable registry; slots=0 → auto-detect
{"vt_player": {"va": "71011b2fe0", "slots": 80}}

// data/ctors.json -- named ctors
{"PlayerCtor": {"va": "710017ff78"}}

// data/function-notes.json -- one-line curated notes (⭐ in ann)
{"7100003208": "RaceDirector::calc [CONFIRMED]"}
```

## MEMORY-MAP.md format

Sections name the owner object; table rows carry the offsets:

```markdown
## Player (0x1AD8)

| Offset | Type | Meaning | Status | Source |
|--------|------|---------|--------|--------|
| +0x078 | u32  | control bitfield | RUNTIME | player-runtime-offsets |
```

Any `## <name>` applies to all rows until the next `##`. `ann` matches the
owner against the decomp line when it can (better disambiguation).

## Headers integration

`REX_HEADERS` → a dir of `.hpp` files whose fields carry `//0xNN` offset comments:

```cpp
class Player {
    uint32_t mCoins; //0x1E4
};
```

Offsets come from the comments (declared packing, no guessing). Then:

```
rex headers 0x1e4        # every struct with a field at +0x1e4
rex headers Player        # full struct dump
rex ann <va>             # hdr:Struct.field badges on uncovered offsets
```

## Getting `uncompressed_main`

You need the game dump (update NSP carries the newest code), `prod.keys` +
`title.keys` (dumped from a hacked Switch via Lockpick_RCM), and hactool
(the borntohonk fork builds on macOS: `brew install capstone`, fix
`config.mk` include/lib paths) or nstool.

```bash
# 1. PROGRAM NCA out of the update NSP (nstool, or hac.py from
#    borntohonk/Switch-Ghidra-Guides) -- the big one with an ExeFS
# 2. ExeFS out of the NCA (titlekey decrypts):
hactool -k prod.keys --titlekey <TITLEKEY> -t nca \
  --exefsdir <target>/main-binary/
#    → main, main.npdm, rtld, sdk, subsdk0
# 3. Decompress the main NSO -- this is the file rex reads:
hactool -t nso <target>/main-binary/main \
  --uncompressed=<target>/main-binary/uncompressed_main
```

Note the Build ID -- it identifies
the version across your docs.

Then import into Ghidra once via GUI: `ghidraRun` → **File → New Project**
(non-shared) at `<target>/ghidra-project/` → **File → Import File** →
`uncompressed_main` → format **Nintendo Switch Binary** (SwitchLoader) →
analyzers default + **Switch IPC** → save. After that everything is
headless. See the README's Dependencies section for installing Ghidra +
SwitchLoader.

## Gotchas

- **OSGi**: new Java scripts only load from the user's
  `Extensions/SwitchLoader/ghidra_scripts/`. A stale copy with a hardcoded
  path there silently hijacks the dump -- `rex shards` always overwrites
  with a fresh compiled pair.
- **`analyzeHeadless` exits 0 even on SCRIPT ERROR** -- rex greps the log and
  fails for real.
- **Headless cwd must be neutral** (`/tmp`): OSGi picks the cwd's raw
  `.java` over the compiled pair → `ClassNotFoundException`.
- **`callers` = 0 ≠ orphan**: may be a `b` tail-call -- re-check with a raw
  BL grep over the asm corpus.
- **`-scriptPath` is broken** in Ghidra 12.1.2 (OSGi/Felix won't resolve
  bundles from arbitrary paths) -- that's why the install step exists.
