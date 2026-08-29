"""rexconfig -- rex configuration: env > ~/.rexrc. No project paths in code.

~/.rexrc format is KEY=VALUE (# comments). Keys:
  REX_ROOT          target data root (e.g. /path/project/03-analysis) -- REQUIRED
  REX_HEADERS       headers include/ dir with .hpp (rex headers / ann badge)
  REX_DUMPERS       dumpers .java dir (default $REX_ROOT/dumpers)
  REX_GHIDRA_PROJ   Ghidra project dir (default $REX_ROOT/ghidra-project)
  REX_PROGRAM       program name inside the Ghidra project (default uncompressed_main)
  REX_BIN           raw binary, relative to ROOT (default main-binary/uncompressed_main)
  REX_BASE          NSO VA base in hex (default 0x7100000000)
  GHIDRA_HOME       Ghidra install (default: homebrew 12.1.2)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_REXRC = Path.home() / ".rexrc"


def _rexrc() -> dict[str, str]:
    if not _REXRC.exists():
        return {}
    out: dict[str, str] = {}
    for line in _REXRC.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def cfg(key: str, default: str | None = None) -> str | None:
    """env takes precedence over ~/.rexrc, which takes precedence over default."""
    v = os.environ.get(key)
    if v:
        return v
    return _rexrc().get(key, default)


def root() -> Path:
    """REX_ROOT (env or ~/.rexrc) -- or exit with a clear instruction."""
    r = cfg("REX_ROOT")
    if not r:
        print("ERROR: REX_ROOT not configured -- no guessing project paths.\n"
              "  export REX_ROOT=/path/to/target/03-analysis   (or create ~/.rexrc):\n"
              "    REX_ROOT=/path/03-analysis\n"
              "  (a project-local shim can configure this automatically)",
              file=sys.stderr)
        sys.exit(2)
    p = Path(r).expanduser()
    if not p.is_dir():
        print(f"ERROR: REX_ROOT does not exist: {p}", file=sys.stderr)
        sys.exit(2)
    return p
