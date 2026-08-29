# rex 🦖

**rex** -- short for **RE EXamine**. Every command is an act of examining:
`rex fn`, `rex ann`, `rex xref` -- reverse engineering, one question at a
time. (The dinosaur is the mascot. Rawr.)

> **Educational purposes only.** Personal study of reverse engineering on
> games I own. Not affiliated with or endorsed by any rights holder. No
> copyrighted assets (game code, keys, dumps) are or will be hosted here --
> the repo contains only original analysis tooling.

Static-analysis toolkit for Switch games (NSO binaries): raw binary + Ghidra
corpus + C++ headers, queried through one CLI.

Developed and battle-tested on **Mario Kart 8 Deluxe** (v3.0.5, ~33k
functions): every feature here exists because a real analysis question
needed it. The tool is game-agnostic, but that's where it proved itself.

Ask it things like *which function contains this address*, *who calls it*,
*who writes to this struct offset*, *what vtable is this* -- without opening
Ghidra again. It also **generates the corpus** (decomp + asm dumps of every
function) from an existing Ghidra project.

```
$ rex callers PlayerAdd
  0x710018a9b8  InputUpdate+0x644
  0x71002631b0  FUN_71002630ec+0xc4
  ...
$ rex headers 0x1e4
  Player         +0x01e4  uint32_t  mCoins
```

## Quickstart

```bash
# 1. point rex at your target (once)
echo 'REX_ROOT=/path/to/target' >> ~/.rexrc

# 2. generate the corpus from your Ghidra project (~7 min the first time)
uv run python ~/rex/rex.py shards

# 3. analyze
uv run python ~/rex/rex.py fn 0x7100176474     # what function is this?
uv run python ~/rex/rex.py ann 0x7100174778    # annotated decomp
```

Prerequisites for step 2: a Ghidra project with the game binary already
imported and analyzed (one-time, via GUI -- see below), plus `uv`, `javac`,
and Ghidra 12.x installed.

## Dependencies

| tool | version used | what for |
|---|---|---|
| **Ghidra** | 12.1.2 (Homebrew) | imports/analyzes the binary; headless runs the dumpers |
| **SwitchLoader** | [borntohonk/Ghidra-Switch-Loader](https://github.com/borntohonk/Ghidra-Switch-Loader) @ `2c9357f` (ext v1.6.1) | Ghidra extension: understands NSO/NRO binaries |
| **Java JDK** | 21 (`javac` included) | Ghidra itself + compiling the dumpers |
| **uv** | any recent | runs rex (`uv run python`) |
| hactool / nstool | hactool 1.x (same author's [fork](https://github.com/borntohonk/hactool), builds on macOS) or nstool 1.9.2 | one-time extraction: game dump → NCA → ExeFS → decompressed NSO (needs `prod.keys`/`title.keys` from your console) |

Who invokes what:

- **rex itself is pure stdlib Python** -- `uv` is just the runner convention.
- **rex only ever spawns two external tools**, and only during `rex shards`:
  `javac` (to compile the dumpers) and Ghidra's `analyzeHeadless` (to run them).
- **SwitchLoader is loaded by Ghidra, not by rex** -- it's needed at the
  one-time GUI import. rex merely borrows the extension's `ghidra_scripts/`
  directory to install the dumpers (the only place Ghidra's OSGi will load
  them from).
- **hactool / nstool are never called by rex** -- you run them yourself,
  once, to produce the binary.

Setup (one-time):

```bash
# 1. Ghidra 12.x + JDK 21
#    Any OS: download from ghidra-sre.org and unzip, then set GHIDRA_HOME.
#    macOS shortcut: brew install ghidra openjdk@21
#    (Homebrew path: /opt/homebrew/Cellar/ghidra/<ver>/libexec)

# 2. SwitchLoader extension -- clone & build against your Ghidra
#    (needs JDK 21 and the gradle wrapper; works on any OS):
git clone https://github.com/borntohonk/Ghidra-Switch-Loader
cd Ghidra-Switch-Loader
git checkout 2c9357f        # commit validated with Ghidra 12.1.2
./gradlew -PGHIDRA_INSTALL_DIR=/path/to/ghidra
# -> produces dist/SwitchLoader-<ver>-Ghidra_<ver>.zip

# 3. Install it (either way):
#    a) Ghidra GUI: File -> Install Extensions -> (+) -> the zip, restart when
#       prompted. (Needs a writable Ghidra install or user extensions dir.)
#    b) Manual: unzip into <GHIDRA_INSTALL_DIR>/Extensions/Ghidra/
#       (that's how this setup was validated)

# 4. uv (any OS): https://docs.astral.sh/uv/getting-started/installation/
#    macOS shortcut: brew install uv

# 5. hactool (any OS, build from source): https://github.com/borntohonk/hactool
#    nstool alternative (prebuilt binaries): https://github.com/jakcron/nstool
```

Capstone (`brew install capstone`, or your distro's `libcapstone-dev`) is
only needed to compile hactool from source.

## New project, from zero

**1. Get the binary.** From your game dump: the update NSP is enough (it has
the newest code). With `prod.keys`/`title.keys` and hactool:

```bash
hactool -k prod.keys --titlekey <TITLEKEY> -t nca --exefsdir main-binary/
hactool -t nso main-binary/main --uncompressed=main-binary/uncompressed_main
```

**2. Import into Ghidra (one time, via GUI).**

Headless can't load the SwitchLoader extension on its own, so the first
import is manual. Only once -- after this, everything runs headless.

1. Launch Ghidra: `ghidraRun`
2. Create the project: **File → New Project → Non-Shared Project**
   - Project directory: `<target>/ghidra-project/`
   - Project name: anything (e.g. `game`)
3. Import the binary: **File → Import File** → `uncompressed_main`
   - Format: **Nintendo Switch Binary**
   - Don't see that format in the list? SwitchLoader isn't installed --
     go back to Dependencies.
4. Analyze: accept the defaults, additionally enable the **Switch IPC**
   analyzer, and let it run. Expect roughly 30 minutes for a 19 MB NSO.
5. Save the project.

**3. Lay out the target.**

```bash
mkdir -p <target>/ghidra-project <target>/main-binary
cp -r ~/rex/dumpers <target>/
```

Which gives you:

```
<target>/
  main-binary/uncompressed_main    # the raw binary (step 1)
  ghidra-project/                  # the Ghidra project (step 2)
  dumpers/                         # the corpus dumpers (copied from rex)
  data/                            # created by rex shards
```

This whole directory is what `REX_ROOT` points to.

**4. Configure & generate.** Put `REX_ROOT` in `~/.rexrc` (or export it),
then `rex shards`. Done -- everything else is reading.

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

Every command that takes a VA also takes a short name (`rex ann PlayerMove`).

## Making it yours

- **`~/.rexrc`** -- all config lives there (or env vars, which win). Keys and
  defaults: `rexconfig.py`. The one required key is `REX_ROOT`.
- **Annotations** -- the more you feed it, the smarter `ann` gets: a
  `notes/MEMORY-MAP.md` mapping struct offsets to meanings (any project's
  notes work -- rex only parses the table format), `data/*.json` registries
  (short names, globals, enums, vtables), and `REX_HEADERS` pointing at any
  C++ headers that carry `//0xNN` offset comments.
- **Config is law** -- if you set something and it's invalid, rex errors out
  immediately instead of silently falling back.

Deep reference -- every command, registry file formats, badge legend, and the
gotchas (OSGi cache, lying headless exit codes) -- lives in
[docs/REFERENCE.md](docs/REFERENCE.md).

## Legal

This repository contains **no Nintendo assets** -- no game code, no keys, no
dumps; only original analysis tooling. To use it you are expected to **own
the game** and dump **your own console's keys and your own copy** (e.g. via
Lockpick_RCM). Do not ask for or share copyrighted material here. This
project is not affiliated with or endorsed by Nintendo; it exists for
interoperability research and personal study.
