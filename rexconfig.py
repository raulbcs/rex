"""rexconfig — configuração do rex: env > ~/.rexrc. Nenhum path de projeto no código.

~/.rexrc formato KEY=VALUE (# comenta). Chaves:
  REX_ROOT          root de dados do alvo (ex.: /path/proj/03-analysis) — OBRIGATÓRIO
  REX_HEADERS       dir include/ dos headers .hpp (rex headers / badge ann)
  REX_DUMPERS       dir dos dumpers .java (default $REX_ROOT/dumpers)
  REX_GHIDRA_PROJ   dir do projeto Ghidra (default $REX_ROOT/ghidra-project)
  REX_PROGRAM       nome do programa no projeto Ghidra (default uncompressed_main)
  REX_BIN           binário cru relativo ao ROOT (default main-binary/uncompressed_main)
  REX_BASE          VA base do NSO em hex (default 0x7100000000)
  GHIDRA_HOME       install do Ghidra (default: homebrew 12.1.2)
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
    """env tem precedência sobre ~/.rexrc, que tem sobre o default."""
    v = os.environ.get(key)
    if v:
        return v
    return _rexrc().get(key, default)


def root() -> Path:
    """REX_ROOT (env ou ~/.rexrc) — ou encerra com instrução clara."""
    r = cfg("REX_ROOT")
    if not r:
        print("ERRO: REX_ROOT não configurado — nada de adivinhar path de projeto.\n"
              "  export REX_ROOT=/caminho/do/alvo/03-analysis   (ou crie ~/.rexrc):\n"
              "    REX_ROOT=/caminho/03-analysis\n"
              "  (o shim do mk8dx-re configura isso automaticamente)",
              file=sys.stderr)
        sys.exit(2)
    p = Path(r).expanduser()
    if not p.is_dir():
        print(f"ERRO: REX_ROOT não existe: {p}", file=sys.stderr)
        sys.exit(2)
    return p
