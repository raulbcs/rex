#!/usr/bin/env python3
"""headers_parser -- C++ header structs (.hpp) in the MK8DX-Headers style.

Parses `class/struct X { type field; //0xNN ... };` with explicit offsets in
comments (the MK8DX-Headers convention -- declared packing, no guessing).
Enums, methods, statics and nested structs are ignored (data layout only).

Usage (library):
    from headers_parser import HeadersDB
    db = HeadersDB("/path/to/headers/include")
    db.structs["KartVehicle"]                    # -> Struct(name, size, fields)
    db.field_at("KartVehicle", 0x1e4)            # -> Field | None
    db.owners_at(0x1e4)                          # -> [(struct, field)] across structs

rex integrates this in `rex headers` (offset lookup) and `rex ann` (hdr: badge).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from pathlib import Path

# --------------------------------------------------------------------- modelo


@dataclass
class HField:
    offset: int
    type: str
    name: str
    note: str = ""


@dataclass
class HStruct:
    name: str
    file: str
    size: int          # last offset + size (or 0 if unknown)
    fields: list = dc_field(default_factory=list)

    def field_at(self, off: int) -> HField | None:
        for f in self.fields:
            if f.offset == off:
                return f
        return None


# --------------------------------------------------------------------- parsing

_RE_STRUCT = re.compile(
    r"(?:class|struct)\s+(\w+)\s*[^{;()]*\{")
_RE_FIELD = re.compile(
    r"^\s*((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:\s*[*&])?\s+)"
    r"([A-Za-z_]\w*(?:\[[^\]]*\])?)\s*;"
    r"(?:\s*//\s*(.*))?$")


def _skip_to_close(body: str, i: int) -> int:
    """Index after the '}' closing the block opened before i (brace counting)."""
    depth = 1
    while i < len(body) and depth:
        c = body[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return i


def parse_hpp(path: Path) -> list[HStruct]:
    out: list[HStruct] = []
    text = path.read_text(errors="replace").replace("\r\n", "\n")
    # methods/statics/nested: drop inner { ... } blocks of signatures
    # (keeps fields -- they have no {})
    for m in _RE_STRUCT.finditer(text):
        name = m.group(1)
        i = m.end()
        depth = 0
        fields: list[HField] = []
        # collects until the struct closes
        while i < len(text):
            c = text[i]
            if c == "{":
                # inner block (method/nested): skip entirely
                i = _skip_to_close(text, i + 1)
                continue
            if c == "}":
                break
            if c == ";":
                # FULL line (the offset is in the comment AFTER the ';')
                ls = text.rfind("\n", 0, i) + 1
                le = text.find("\n", i)
                if le == -1:
                    le = len(text)
                line = text[ls:le]
                fm = _RE_FIELD.match(line)
                if fm:
                    typ = fm.group(1).strip()
                    # skip static inline method returns etc
                    if typ.split()[0] in ("return", "static", "void", "friend", "using", "typedef", "enum"):
                        continue
                    fname = fm.group(2)
                    comment = (fm.group(3) or "").strip()
                    off_m = re.search(r"0[xX]([0-9a-fA-F]+)", comment)
                    if off_m:
                        fields.append(HField(
                            offset=int(off_m.group(1), 16),
                            type=typ, name=fname, note=comment))
                i += 1
                continue
            i += 1
        if fields:
            out.append(HStruct(name=name, file=str(path), size=0, fields=fields))
    return out


class HeadersDB:
    """Todas as structs dos headers, com lookup por nome e por offset."""

    def __init__(self, include_dir: str | Path):
        self.dir = Path(include_dir)
        self.structs: dict[str, HStruct] = {}
        self._by_offset: dict[int, list[tuple[HStruct, HField]]] = {}
        for p in sorted(self.dir.rglob("*.hpp")):
            for s in parse_hpp(p):
                if s.name in self.structs:
                    continue  # first declaration wins (include guard)
                self.structs[s.name] = s
                for f in s.fields:
                    self._by_offset.setdefault(f.offset, []).append((s, f))

    def field_at(self, struct: str, offset: int) -> HField | None:
        return self.structs[struct].field_at(offset)

    def owners_at(self, offset: int) -> list[tuple[HStruct, HField]]:
        return self._by_offset.get(offset, [])

    def summary(self) -> str:
        nf = sum(len(s.fields) for s in self.structs.values())
        return f"{len(self.structs)} structs, {nf} fields with offsets"


# quick sanity CLI
if __name__ == "__main__":
    import sys
    import rexconfig
    db = HeadersDB(sys.argv[1] if len(sys.argv) > 1 else
                   rexconfig.cfg("REX_HEADERS", ""))
    print(db.summary())
    for probe in ("KartVehicle", "KartUnit", "RaceInfo"):
        s = db.structs.get(probe)
        print(f"\n== {probe}: {len(s.fields) if s else 0} campos")
        if s:
            for f in s.fields[:6]:
                print(f"  +{f.offset:#05x}  {f.type:28s} {f.name}  {f.note[:40]}")
