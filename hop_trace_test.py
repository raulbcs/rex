#!/usr/bin/env python3
"""Teste top-down do hop: quem ESCREVE vel_y/pos_y no caminho do kart.

A hipótese testada: o hop (input ZR → drift/hop) acaba gravando velocidade/
posição vertical em algum lugar do caminho input→hop→física — apesar de o
KartUnit::calc (case 0x04) ser "zero-física".

Para cada offset CANDIDATO de vertical (vel_y/pos_y das representações de
corpo), lista todos os writers no binário e destaca os que caem nos ranges
de kart/hop/drift/input. Se o hop realmente ergue o kart, deve existir um
writer vertical no caminho do hop que a análise do calc não cobre.

Ranges de interesse (domínio kart/veículo):
  [0x71000d0000, 0x71000ecfff]  KartUnit
  [0x7100160000, 0x710019ffff]  KartVehicleMove/drift/hop/boost/wrapper
  [0x71001a0000, 0x71001bffff]  drift engage / boost slots

Uso: cd ~/projects/rex && python3 hop_trace_test.py [--all]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rex  # noqa: E402

# (label, offset, é float, nota)
CANDIDATES = [
    # 0x1900B scene/collision body (kartunit-runtime-offsets §147)
    ("body0x1900B pos_y", 0x64, "float pos Y (0x60 XYZ)"),
    ("body0x1900B vel_y", 0xB4, "float vel Y (0x0B0 XYZ)"),
    ("body0x1900B wheel0 posY", 0xA4, "raycast roda 0 (+0x0A0)"),
    ("body0x1900B wheel1 posY", 0xE4, "raycast roda 1 (+0x0E0)"),
    ("body0x1900B wheel2 posY", 0x124, "raycast roda 2 (+0x120)"),
    # position-pipeline physics body (position-pipeline.md §9)
    ("pp body vel_y", 0x3C, "vel Y (Eq 2: pos_y 0x164 -= vel 0x3C*0.25)"),
    ("pp body pos_y", 0x164, "pos Y after quarter-steps"),
    ("pp body pos_y_coll", 0x2B, "pos Y collision-resolved"),
]

KART_RANGES = [
    (0x71000D0000, 0x71000ECFFF),
    (0x7100160000, 0x710019FFFF),
    (0x71001A0000, 0x71001BFFFF),
]


def in_kart(va: int) -> str:
    for a, b in KART_RANGES:
        if a <= va <= b:
            return f"KART[{a:#x}-{b:#x}]"
    return ""


def main() -> None:
    only_kart = "--all" not in sys.argv
    print("=== Teste top-down do hop: writers de vertical no domínio kart ===")
    if only_kart:
        print("  (filtro: só ranges de kart; use --all p/ ver todos os writers)")
    for label, off, note in CANDIDATES:
        print(f"\n--- {label}  (offset +0x{off:X})  {note} ---")
        # cmd_offset(imm, load=False) = stores
        hits = 0
        for va, mi in rex._scan_mem(off, load=False):
            tag = in_kart(va)
            if only_kart and not tag:
                continue
            hits += 1
            m = f"{mi['mnem']} {mi['rt']}"
            wb = mi.get("wb")
            mem = f"[x{mi['rn']},#{mi['off']:#x}]" + ("!" if wb == "pre" else "")
            print(f"  {va:#x}  {m},{mem}  <{rex.name_of(va)}>  {tag}")
        print(f"  # {hits} writers{' (kart domain)' if only_kart else ''}")
    print("\n=== Interpretação ===")
    print("Se houver writer vertical num range de kart/hop/input → o lift do hop")
    print("tem fonte estática de verdade (mecanismo). Se não houver nenhum →")
    print("confirma que o lift vem de matriz roda→corpo (suspensão), número via peek.")


if __name__ == "__main__":
    main()
