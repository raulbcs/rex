# rex

Static-analysis toolkit for Switch games (NSO binaries): raw binary + Ghidra
corpus + C++ headers, queried through one CLI.

Ask it things like *which function contains this address*, *who calls it*,
*who writes to this struct offset*, *what vtable is this* — without opening
Ghidra again. It also **generates the corpus** (decomp + asm dumps of every
function) from an existing Ghidra project.

```
$ rex callers CoinAdd
  0x710018a9b8  DriftInput+0x644
  0x71002631b0  FUN_71002630ec+0xc4
  ...
$ rex headers 0x1e4
  KartVehicle    +0x01e4  uint32_t  mDriftCounter
```

## Quickstart

```bash
# 1. point rex at your target (once)
echo 'REX_ROOT=/path/to/target' >> ~/.rexrc

# 2. generate the corpus from your Ghidra project (~7 min the first time)
uv run python ~/projects/rex/rex.py shards

# 3. analyze
uv run python ~/projects/rex/rex.py fn 0x7100176474     # what function is this?
uv run python ~/projects/rex/rex.py ann 0x7100174778    # annotated decomp
```

Prerequisites for step 2: a Ghidra project with the game binary already
imported and analyzed (one-time, via GUI — see below), plus `uv`, `javac`,
and Ghidra 12.x installed.

## New project, from zero

**1. Get the binary.** From your game dump: the update NSP is enough (it has
the newest code). With `prod.keys`/`title.keys` and hactool:

```bash
hactool -k prod.keys --titlekey <TITLEKEY> -t nca --exefsdir main-binary/
hactool -t nso main-binary/main --uncompressed=main-binary/uncompressed_main
```

**2. Import into Ghidra (once, GUI).** `ghidraRun` → Import File →
`uncompressed_main` → format **Nintendo Switch Binary** (needs the
SwitchLoader extension) → analyze → save under `<target>/ghidra-project/`.
Headless can't load the extension on its own, so this step is manual — but
only once.

**3. Lay out the target.**

```
<target>/                          ← this is REX_ROOT
  main-binary/uncompressed_main
  ghidra-project/                  ← from step 2
  dumpers/                         ← cp -r ~/projects/rex/dumpers .
  data/                            ← generated (shards land here)
```

**4. Configure & generate.** Put `REX_ROOT` in `~/.rexrc` (or export it),
then `rex shards`. Done — everything else is reading.

## What to query

```bash
rex fn 0x7100176474          # which function contains this VA
rex body <va> [-a]           # decomp (or asm) body
rex ann <va>                 # body + semantic annotations  ← use this first
rex callers <va|name>        # all BL callers
rex offset 0x1e4 -w          # who writes to this struct offset
rex vtable <va|name>         # dump a vtable (via relocations)
rex xref <va|name>           # every reference in the corpus
rex headers 0x1e4            # which struct has a field here (C++ headers)
```

Every command that takes a VA also takes a short name (`rex ann DriftCalc`).

## Making it yours

- **`~/.rexrc`** — all config lives there (or env vars, which win). Keys and
  defaults: `rexconfig.py`. The one required key is `REX_ROOT`.
- **Annotations** — the more you feed it, the smarter `ann` gets: a
  `notes/MEMORY-MAP.md` with offset owners, `data/*.json` registries (short
  names, globals, enums, vtables), and `REX_HEADERS` pointing at C++ headers
  with offset comments (MK8DX-Headers style).
- **Config is law** — if you set something and it's invalid, rex errors out
  immediately instead of silently falling back.

Deep reference — every command, registry file formats, badge legend, and the
gotchas (OSGi cache, lying headless exit codes) — lives in
[docs/REFERENCE.md](docs/REFERENCE.md).

## mk8dx-re

The main repo ships a shim (`03-analysis/scripts/rex.py`) that sets
`REX_ROOT` to itself and loads rex from here — its regen pipeline and
docs keep working with zero configuration.
