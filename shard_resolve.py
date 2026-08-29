#!/usr/bin/env python3
"""Resolve functions from the corpus: address/name → shard, decomp/asm body.

Two independent corpora with distinct shard numbering:
  - decomp-full/: 500 functions/shard, 69 shards (shard-000..shard-068)
  - asm-full/:   1000 functions/shard, 35 shards (shard-000..shard-034)

Project docs use DECOMP shard numbers by default.
Known exceptions (asm): FUN_710012792c (CoinGet effect) documented as
shard-002 = asm shard-002 (correct decomp = shard-004).

Usage:
    from shard_resolve import ShardIndex
    idx = ShardIndex()                      # loads TSVs once

    # Resolve → ShardResult (decomp by default)
    idx.resolve(0x710004475c)                # -> ShardResult(name, shard, addr)
    idx.resolve('FUN_710004475c')            # -> same (by name)
    idx.resolve('shard-026')                 # -> first fn of shard-026
    idx.resolve('asm:shard-013')            # -> asm corpus, shard-013

    # Function body
    idx.load_decomp(0x710004475c)             # -> C body (str)
    idx.load_asm(0x710004475c)               # -> asm body (str)

    # Grep with context
    idx.search_decomp(0x710004475c, '0x9c')  # -> lines containing '0x9c'

    # Shard info
    idx.functions_in_shard(26)               # -> [(addr, name), ...] (decomp)
    idx.functions_in_shard(13, 'asm')        # -> [(addr, name), ...] (asm)

    # Both shards for a function
    idx.resolve_both(0x710004475c)           # -> (ShardResult, ShardResult)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# rex lives in ~/rex; corpus data lives in the TARGET -- configured
# via rexconfig (env > ~/.rexrc), no project paths in code.
import rexconfig

_DATA_DIR: Path | None = None


def _data_dir() -> Path:
    global _DATA_DIR
    if _DATA_DIR is None:
        _DATA_DIR = rexconfig.root() / 'data'
    return _DATA_DIR
DECOMP_FUNCS_PER_SHARD = 500
ASM_FUNCS_PER_SHARD = 500


@dataclass(frozen=True)
class ShardResult:
    addr: int
    name: str
    shard: int
    corpus: str  # 'decomp' or 'asm'

    @property
    def shard_file(self) -> str:
        return f'shard-{self.shard:03d}.txt'

    def __str__(self) -> str:
        return f'{self.name} @ {self.addr:#x}  {self.corpus}/{self.shard_file}'


class _CorpusIndex:
    """Index for a single corpus (decomp or asm)."""

    def __init__(self, tsv_path: Path, kind: str):
        self.kind = kind
        self.entries: list[int] = []
        self.names: dict[int, str] = {}
        self.shards: dict[int, int] = {}
        self.name_map: dict[str, int] = {}
        self.shard_fns: dict[int, list[tuple[int, str]]] = {}
        for line in tsv_path.read_text().splitlines()[1:]:
            cols = line.split('	')
            if len(cols) < 4:
                continue
            addr = int(cols[0], 16)
            name = cols[1]
            shard = int(cols[3])
            self.entries.append(addr)
            self.names[addr] = name
            self.shards[addr] = shard
            self.name_map[name.upper()] = addr
            self.shard_fns.setdefault(shard, []).append((addr, name))
        self.entries.sort()

    def resolve_addr(self, addr: int) -> int | None:
        """Exact match only. Returns None for addresses not in the corpus."""
        if addr in self.shards:
            return addr
        return None

    def resolve_name(self, name: str) -> int | None:
        return self.name_map.get(name.upper())

    def make_result(self, addr: int) -> ShardResult:
        return ShardResult(
            addr=addr,
            name=self.names.get(addr, f'FUN_{addr:x}'),
            shard=self.shards[addr],
            corpus=self.kind,
        )


class ShardIndex:
    def __init__(self, data_dir: Path | str | None = None):
        base = Path(data_dir) if data_dir else _data_dir()
        self._decomp_dir = base / 'decomp-full'
        self._asm_dir = base / 'asm-full'
        self.decomp = _CorpusIndex(self._decomp_dir / 'functions.tsv', 'decomp')
        self.asm = _CorpusIndex(self._asm_dir / 'functions.tsv', 'asm')

    def _pick_corpus(self, query: str) -> tuple[str, str] | None:
        """Parse 'asm:...' prefix. Returns (prefix_stripped, corpus) or None."""
        if query.startswith('asm:'):
            return query[4:], 'asm'
        if query.startswith('decomp:'):
            return query[7:], 'decomp'
        return None

    def resolve(self, query: int | str, corpus: str = 'decomp') -> ShardResult | None:
        """Resolve query para ShardResult no corpus especificado (default: decomp)."""
        idx = self.decomp if corpus == 'decomp' else self.asm
        addr = self._to_addr(query, idx) if isinstance(query, (int, str)) else None
        if addr is None:
            return None
        return idx.make_result(addr)

    def resolve_both(self, query: int | str) -> tuple[ShardResult | None, ShardResult | None]:
        """Resolve nos dois corpus. Retorna (decomp_result, asm_result)."""
        d_addr = self._to_addr(query, self.decomp)
        a_addr = self._to_addr(query, self.asm)
        d = self.decomp.make_result(d_addr) if d_addr is not None else None
        a = self.asm.make_result(a_addr) if a_addr is not None else None
        return d, a

    def _to_addr(self, query: int | str, idx: _CorpusIndex) -> int | None:
        if isinstance(query, int):
            return idx.resolve_addr(query)
        q = query.strip()
        # prefix override
        parsed = self._pick_corpus(q)
        if parsed:
            q_clean, corpus = parsed
            target = self.decomp if corpus == 'decomp' else self.asm
            return self._to_addr(q_clean, target)
        # name lookup
        if q.upper().startswith('FUN_') or q.upper().startswith('_') or q.upper().startswith('OPERATOR.'):
            addr = idx.resolve_name(q)
            if addr is not None:
                return addr
        # hex address
        if q.startswith('0x') or q.startswith('0X'):
            return idx.resolve_addr(int(q, 16))
        # shard reference
        m = re.match(r'^shard-(\d+)$', q)
        if m:
            n = int(m.group(1))
            fns = idx.shard_fns.get(n)
            if fns:
                return min(fns)[0]
        return None

    def functions_in_shard(self, shard: int, corpus: str = 'decomp') -> list[tuple[int, str]]:
        idx = self.decomp if corpus == 'decomp' else self.asm
        return idx.shard_fns.get(shard, [])

    def load_decomp(self, query: int | str) -> str | None:
        r = self.resolve(query, 'decomp')
        if r is None:
            return None
        return self._extract_fn_body(self._decomp_dir / r.shard_file, r.name, r.addr)

    def load_asm(self, query: int | str) -> str | None:
        r = self.resolve(query, 'asm')
        if r is None:
            return None
        return self._extract_fn_body(self._asm_dir / r.shard_file, r.name, r.addr)

    def search_decomp(self, query, pattern, context=0):
        body = self.load_decomp(query)
        if body is None:
            return []
        return self._search_body(body, pattern, context)

    def search_asm(self, query, pattern, context=0):
        body = self.load_asm(query)
        if body is None:
            return []
        return self._search_body(body, pattern, context)

    @staticmethod
    def _search_body(body: str, pattern: str, context: int) -> list[str]:
        lines = body.splitlines()
        pat = re.compile(pattern)
        hits = []
        for i, line in enumerate(lines):
            if pat.search(line):
                lo = max(0, i - context)
                hi = min(len(lines), i + context + 1)
                for j in range(lo, hi):
                    hits.append(lines[j])
                hits.append('  --')
        return hits

    @staticmethod
    def _extract_fn_body(shard_path: Path, name: str, addr: int) -> str | None:
        if not shard_path.exists():
            return None
        # decomp: '// ===== FUN_x @ addr =====' · asm: '// FUN_x @ addr' (sem =====)
        pat = re.compile(rf'^// (===== )?{re.escape(name)} @ {addr:x}( =====)?$')
        grab = False
        buf = []
        for raw in shard_path.read_text(errors='replace').splitlines():
            if raw.startswith('// ') and ' @ ' in raw and not raw.startswith('//   '):
                if re.match(r'^// (===== )?\S+ @ [0-9a-f]+( =====)?$', raw):
                    if grab:
                        return '\n'.join(buf)
                    grab = bool(pat.match(raw))
                    buf = [raw] if grab else []
            elif grab:
                buf.append(raw)
        if grab:
            return '\n'.join(buf)
        return None


def main():
    idx = ShardIndex()
    args = sys.argv[1:] or ['0x710004475c', 'FUN_710057420c', 'shard-026']
    for q in args:
        # Show both if no prefix
        d, a = idx.resolve_both(q)
        if d is None and a is None:
            print(f'{q!r} -> NAO ENCONTRADO')
            continue
        if d:
            print(f'  decomp: {d}')
        if a:
            print(f'  asm:    {a}')
        print()


if __name__ == '__main__':
    main()


__all__ = ['ShardIndex', 'ShardResult']
