#!/usr/bin/env python3
"""rex — faca suíça de RE MK8DX (binário cru + corpus).

Resolve as fricções recorrentes da análise estática:
  rex fn <va>              → qual função contém o endereço
  rex callers <va>         → todos os BL para o alvo (com nome da função caller)
  rex body <va> [-a]       → corpo no corpus (decomp; -a = asm)
  rex offset <imm> [-w|-l] [-m SUB] [-r A..B]
                           → instruções que acessam [reg, #imm] (default: STORES;
                             -w = writes (alias do default); -l = loads)
                             cobre str/ldr b/h/w/x/s/d/q, stp/ldp, stur/ldur e
                             pre/post-index writeback (str x,[x,#imm]! / [x],#imm)
                             (offset de struct com sinal; FP/SIMD com escala correta)
                             -m SUB: filtra pelo lado esquerdo renderizado
                               (ex.: -m 'stp s' só pairs FP; -m 'str s' só singles)
                             -r A..B: só VAs no range [A, B] (ex.: -r 0x7100160000..0x71001a0000)
  rex rodata <va> [-t T] [-n N]   → decodifica tabela em .rodata/.data
                            T: i32 (default) | u32 | f32 | f64 | i64 | u64
                               | i16 | u16 | i8 | u8 | hex  (u64 resolve → FUN_xxx)
  rex str <va>             → C-string no VA
  rex str -f <substr>      → busca REVERSA: VAs que contêm a substring
  rex vtable <va|nome> [-n N] [-j|-l] → dump da vtable via relocations
                               (slots→funções com nomes curtos; -n limita p/
                               blocos compactos sem RTTI; -j JSON; -l lista
                               as registradas em data/vtables.json)
  rex vtable-callers <va|nome> → inventário de call sites por slot de uma vtable:
                               BL callers diretos do alvo (exatos) + BLR sites cujo
                               slot-offset == offset do slot (dispatch virtual,
                               candidatos). Cobre o gargalo '0 BL callers' do NEXT.md.
  rex blr <site_va>          → resolve um dispatch virtual: slot-offset + quais
                               vtables curadas têm slot nesse offset
  rex blr -l                 → resumo global: total de BLR em .text, quantos com
                               slot-offset resolvido, top offsets por frequência
  rex ctor <va|nome> [-l]    → cadeia estática do ctor: holders -> vtables
                               instaladas por campo; new(size) e calls nomeados
  rex adrp <va>            → ADRP+ADD/LDR que materializam o VA no .text
  rex dis <va> [-n N]      → disassembly in loco (capstone via 'uv run --with
                             capstone'; fallback estrutural ret/nop/bl)
  rex dis <va1> <va2>      → range: disassembla de va1 até va2 (inclusivo)
  rex bit <off> <bit> [-r A..B] → stores de #off que SET/CLEAR/TOGGLE o bit, com o
                             def por imediato (orr/and/eor/mov) que o originou
                             (-r filtra por range de VA)
  rex reloc <va> [-n N] [-b B] → entradas da tabela de relocations do NSO
                             (R_AARCH64_RELATIVE) a partir do VA — resolve
                             vtables relocáveis: addend → nome da função
  rex reloc -a <va>        → REVERSO: slots que recebem este VA como addend
                           (= em quais vtables a função é método)
  rex ann <va>             → corpo decomp ANOTADO: offsets de struct com nome
                           semântico do MEMORY-MAP.md e chamadas com nota
                           curatorial (function-notes.json). Padrão: offset
                           conhecido em destaque [+0x184 = coins clamp 0..10]
                           OFF desconhecido fica limpo — foco no que sabe.
  rex ptr <va>            → resolve ponteiro em .data/.rodata: lê o qword no VA
                           e identifica o alvo (função/vtable/global/string)
  rex xref <va|nome>      → quem referencia um VA/global no corpus (decomp-full
                            + asm-full; DAT_/PTR_DAT_ + hex). lista arq:linha+fn
  rex fn -r A..B          → lista funções catalogadas com start em [A, B]
  rex headers <offset|Struct> → campo do MK8DX-Headers nesse offset (todas as
                            structs) ou dump da struct; badge hdr: no `ann`
                            (config REX_HEADERS = dir include/)
  rex shards [all|decomp|asm] [--force]
                          → GERA o corpus (shards) via Ghidra headless: limpa
                            cache OSGi, compila $REX_DUMPERS/ (default
                            $REX_ROOT/dumpers), instala em
                            Extensions/SwitchLoader e roda FullDecompDump
                            (~6min, RESUME) + FullAsmDump (~100s) com detecção
                            de SCRIPT ERROR. Saída em $REX_ROOT/data/

Args de VA aceitam '0x7100...', '7100...' ou 'FUN_7100...'/'thunk_FUN_...'.

Casos-edge: 'fn' AVISA quando o VA está em GAP (função órfã do dumper,
bounds-check via asm-full insns); 'body' distingue mid-function (dumpa a
contenedora) de gap (disassembla in loco com 'dis').

Paths relativos ao repo (03-analysis/). Python 3 stdlib only.
"""
from __future__ import annotations

import bisect
import json
import re
import struct
import sys
from pathlib import Path

# Config: env > ~/.rexrc — NENHUM path de projeto no código (rexconfig.py).
# ROOT é lazy: só resolve (e exige REX_ROOT) quando um comando precisa de dados.
import os
import rexconfig

_ROOT: Path | None = None


def _root() -> Path:
    global _ROOT
    if _ROOT is None:
        _ROOT = rexconfig.root()
    return _ROOT


def _cfg(key: str, default: str) -> str:
    return rexconfig.cfg(key, default) or default

BASE = 0x7100000000
HDR = 0x100            # text file offset = VA - BASE + HDR

# ---------------------------------------------------------------- indices

_DATA = None
TSV = None            # setado no _load() (depende de REX_ROOT)
ASM_TSV = None        # idem
BASE = int(_cfg("REX_BASE", "0x7100000000"), 16)   # VA base do NSO (config)
_FUNCS = None         # list[(addr, name)] sorted
_FUNCS_ADDRS = None   # list[int] sorted, paralelo a _FUNCS
_INSNS = None         # addr -> n. de instruções (asm-full; tamanho exato)


def _load():
    global _DATA, _FUNCS, _FUNCS_ADDRS, _INSNS
    if _DATA is not None:
        return
    global TSV, ASM_TSV
    ROOT = _root()
    BIN = _cfg("REX_BIN", "main-binary/uncompressed_main")
    BIN = ROOT / BIN if not BIN.startswith("/") else Path(BIN)
    _DATA = open(BIN, "rb").read()
    TSV = ROOT / "data" / "decomp-full" / "functions.tsv"
    ASM_TSV = ROOT / "data" / "asm-full" / "functions.tsv"
    _FUNCS, _FUNCS_ADDRS = [], []
    _INSNS = {}
    with open(TSV) as f:
        next(f)
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[0][0] in "0123456789abcdef":
                _FUNCS.append((int(parts[0], 16), parts[1]))
    try:
        with open(ASM_TSV) as f:
            next(f)
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 3 and parts[0][0] in "0123456789abcdef":
                    try:
                        _INSNS[int(parts[0], 16)] = int(parts[2])
                    except ValueError:
                        pass
    except FileNotFoundError:
        pass  # sem asm-full: fn_of sem bounds-check exato
    _FUNCS.sort()
    _FUNCS_ADDRS = [a for a, _ in _FUNCS]


def fn_of(va: int) -> tuple[int, str] | None:
    """Função que contém o VA."""
    _load()
    i = bisect.bisect_right(_FUNCS_ADDRS, va) - 1
    if i < 0:
        return None
    return _FUNCS[i]


def name_of(va: int) -> str:
    _load_names()
    f = fn_of(va)
    if f:
        short = (_NAMES_R or {}).get(f"{f[0]:x}")
        if short:
            return f"{short}+{va - f[0]:#x}" if va != f[0] else short
        return f"{f[1]}+{va - f[0]:#x}"
    return f"FUN_{va:x}"


# ---------------------------------------------------------------- NSO segments

def _segments():
    """[(mem_off, file_off, size)] do NSO (text/ro/data) — cached."""
    d = _DATA
    segs = []
    for off in (0x10, 0x20, 0x30):
        f_off, m_off, sz = struct.unpack_from("<III", d, off)
        segs.append((m_off, f_off, sz))
    return segs


def va_to_file(va: int) -> int | None:
    """Converte VA → file offset usando os segmentos (não só text)."""
    d = _DATA
    m = va - BASE
    # text segment tem file_off ≠ mem_off (header 0x100): usa mapping direto
    tm, tf, ts = struct.unpack_from("<III", d, 0x10)
    if tm <= m < tm + ts:
        return tf + (m - tm)
    for off in (0x20, 0x30):  # ro, data
        f_off, m_off, sz = struct.unpack_from("<III", d, off)
        if m_off <= m < m_off + sz:
            return f_off + (m - m_off)
    return None


# ---------------------------------------------------------------- comandos

def cmd_fn(va: int) -> None:
    _load()
    assert _FUNCS_ADDRS is not None  # populado por _load()
    f = fn_of(va)
    if not f:
        print(f"nenhuma função contém {va:#x}")
        return
    start, name = f
    off = va - start
    # bounds-check exato via asm-full (insns); sem asm-full, usa próxima função
    if _INSNS:
        end = start + _INSNS.get(start, 0) * 4
    else:
        i = bisect.bisect_right(_FUNCS_ADDRS, start)
        end = _FUNCS_ADDRS[i] if i < len(_FUNCS_ADDRS) else start + (1 << 30)
    if va >= end:
        print(f"AVISO: {va:#x} está em GAP (depois do fim de {name} @ {start:#x}, "
              f"tamanho {end - start:#x} — funcao nao catalogada ou dado)")
        print(f"  função anterior mais próxima: {name} @ {start:#x} (fim {end:#x})")
        return
    print(f"{name} @ {start:#x}  (VA {va:#x} = +{off:#x})")


def cmd_callers(target: int) -> None:
    _load()
    d = _DATA
    assert d is not None
    # varre só .text (literal pools em .rodata/.data e padding entre funções
    # decodificam como BL espúrio — falso-positivo histórico do callers)
    tm, tf, ts = struct.unpack_from("<III", d, 0x10)
    end = min(tf + ts, len(d)) & ~3
    hits: list[int] = []
    gaps: list[int] = []
    for i in range(end // 4):
        w = struct.unpack_from("<I", d, i * 4)[0]
        if (w & 0xFC000000) == 0x94000000:
            src = BASE + i * 4 - HDR
            imm = w & 0x3FFFFFF
            if imm & 0x2000000:
                imm -= 0x4000000
            if src + (imm << 2) == target:
                # bounds-check: BL só vale se src estiver DENTRO de função
                # catalogada (não em gap pós-fim — é dado/literal, não call)
                if _INSNS:
                    f = fn_of(src)
                    if f and src < f[0] + _INSNS.get(f[0], 0) * 4:
                        hits.append(src)
                    else:
                        gaps.append(src)
                else:
                    hits.append(src)
    if not hits:
        msg = f"0 BL callers de {target:#x}"
        if gaps:
            msg += f"  ({len(gaps)} em GAP descartados — provável literal/dado)"
        print(msg + " (exit 1)")
        sys.exit(1)
    _load_names()
    short = (_NAMES_R or {}).get(f"{target:x}")
    for h in hits:
        print(f"  {h:#x}  {name_of(h)}")
    if gaps:
        print(f"# {len(gaps)} hit(s) em GAP descartados: " +
              ", ".join(f"{g:#x}" for g in gaps))
    if short:
        print(f"# alvo: {short} ({target:#x})")


def _disasm(va: int, n: int) -> list[str]:
    """Disassemble n instructions at va. Capstone (via uv --with) se disponível;
    senão marcação estrutural mínima (ret/nop/bl/padding) — não é decompilação."""
    _load()
    assert _DATA is not None
    d = _DATA
    off = va - BASE + HDR
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        return [f"{ins.address:#x}: {ins.mnemonic:8s} {ins.op_str}"
                for ins in md.disasm(d[off:off + n * 4], va)]
    except ImportError:
        out = []
        for i in range(n):
            w = struct.unpack_from("<I", d, off + i * 4)[0]
            a = va + i * 4
            if w == 0xd65f03c0:
                s = "ret"
            elif w == 0xd503201f:
                s = "nop"
            elif (w & 0xFC000000) == 0x94000000:
                imm = w & 0x3FFFFFF
                imm = imm - 0x4000000 if imm & 0x2000000 else imm
                s = f"bl {a + (imm << 2):#x}"
            else:
                s = f".word {w:08x}  (capstone ausente: uv run --with capstone)"
            out.append(f"{a:#x}: {s}")
        return out


def cmd_dis(va: int, n: int) -> None:
    _load()
    for line in _disasm(va, n):
        print(f"  {line}")
    # contexto: função vizinha + limites
    f = fn_of(va)
    if f:
        start, name = f
        end = start + _INSNS.get(start, 0) * 4 if _INSNS else None
        where = "mid-function" if (end and start < va < end) else \
            ("GAP após" if va > start else "antes de")
        print(f"# {where} {name} @ {start:#x}" + (f" (fim {end:#x})" if end else ""))


# ------------------------------------------------------------- ann (anotação)

_MEMMAP = None          # {offset_int: [(objeto, significado, status)]}
_MEMMAP_NOTE = ""       # cabeçalho de aviso (ambiguidades)


def _load_memmap() -> None:
    """Parseia MEMORY-MAP.md → {offset: [(objeto, significado, status)]}.

    Fonte única: a tabela curada. Linhas '| +0x184 | u32 | ... | STATUS | font |'
    de qualquer seção (KartUnit, physics body, boost slot, RaceSystem, ...).
    """
    global _MEMMAP, _MEMMAP_NOTE
    if _MEMMAP is not None:
        return
    path = _root() / "notes" / "MEMORY-MAP.md"
    mapping: dict[int, list[tuple[str, str, str]]] = {}
    obj = "?"
    for line in path.read_text().splitlines():
        if line.startswith("## "):
            obj = line[3:].strip()
        m = re.match(r"^\|\s*\+(0x[0-9a-fA-F]+)\s*\|([^|]*)\|([^|]*)\|([^|]*)\|", line)
        if m:
            off = int(m.group(1), 16)
            typ = m.group(2).strip()
            sig = m.group(3).strip().strip("*")
            status = m.group(4).strip()
            # ignora separator/header de tabela
            if sig in ("Significado", "---") or set(sig) <= {"-", " "}:
                continue
            sig = re.sub(r"\s+", " ", sig)
            if typ and typ not in ("?", "---"):
                sig = f"{typ} {sig}" if not sig.startswith(typ) else sig
            mapping.setdefault(off, []).append((obj, sig, status))
    _MEMMAP = mapping
    amb = sum(1 for v in mapping.values() if len(v) > 1)
    _MEMMAP_NOTE = f"MEMmap: {len(mapping)} offsets, {amb} ambíguos (multi-owner)"


def _try_note(off: int, line: str, notes: list[str], seen: set[int]) -> None:
    """Adiciona anotação do offset se o MEMORY-MAP o conhece."""
    if off in seen or off < 0x40:   # offsets <0x40: onipresentes, alto risco de dono errado
        return
    ents = _MEMMAP.get(off) if _MEMMAP else None
    if not ents:
        return
    seen.add(off)
    # se a linha já nomeia o objeto (KartUnit/vehicle/etc), prioriza o match dele
    low = line.lower()
    chosen = None
    for obj, sig, status in ents:
        key = obj.lower().split()[0].strip("/")
        if key and len(key) > 3 and key in low:
            chosen = (obj, sig, status)
            break
    if chosen is None and len(ents) == 1:
        obj, sig, status = ents[0]
        # dono heurístico: marca como candidato (map é incompleto; +0x78 pode ser
        # de outro objeto na cadeia) — "?" lembra de confirmar o base object
        notes.append(f"+{off:#x}≈{obj.split()[0]}: {sig[:90]}")
        return
    if chosen is not None:
        obj, sig, status = chosen
        badge = "?" if status.upper() in ("UNCONFIRMED", "PARTIAL") else ""
        notes.append(f"+{off:#x}={obj.split()[0]}{badge}: {sig[:90]}")
    else:
        # ambíguo: mostra os 2 primeiros donos
        parts = [f"{o.split()[0]}: {s[:60]}" for o, s, _ in ents[:2]]
        notes.append(f"+{off:#x}=? {' | '.join(parts)}")


def _hdr_note(off: int, line: str, notes: list[str], seen: set[int]) -> None:
    """Badge hdr:Struct.field do MK8DX-Headers (quando o MEMORY-MAP não cobre)."""
    if off in seen or off < 0x40 or _HEADERS is None:
        return
    hits = _HEADERS.owners_at(off)
    if not hits:
        return
    low = line.lower()
    chosen = next(((s, f) for s, f in hits if s.name.lower() in low), None)
    s, f = chosen or (hits[0] if len(hits) == 1 else (None, None))
    if f is None:
        names = ", ".join(f"{s.name}.{f.name}" for s, f in hits[:2])
        notes.append(f"hdr:? {names}")
    else:
        seen.add(off)
        notes.append(f"hdr:{s.name}.{f.name} ({f.type})")


def _offset_notes(line: str) -> list[str]:
    """Notas de offset do MEMORY-MAP para uma linha de decomp (3 formas)."""
    notes: list[str] = []
    seen: set[int] = set()
    _load_headers()
    for m in re.finditer(r"\+\s*(0x[0-9a-fA-F]+)", line):
        off = int(m.group(1), 16)
        before = len(notes)
        _try_note(off, line, notes, seen)
        if len(notes) == before:
            _hdr_note(off, line, notes, seen)
    # param_1[N] → offset N*8 (indexação de ponteiro do decomp)
    for m in re.finditer(r"\bparam_\d+\[(\d+)\]", line):
        _try_note(int(m.group(1)) * 8, line, notes, seen)
    # *(tipo *)(x + N) com N DECIMAL (Ghidra renderiza decimal); ignora vtable `**(`
    if "**(" not in line:
        for m in re.finditer(r"\(\s*[a-z0-9_ ]+\s*\*\s*\)\s*\*\s*\([^)]*\+\s*(\d+)\s*\)", line):
            _try_note(int(m.group(1)), line, notes, seen)
    return notes


def _ann_line(line: str) -> str:
    """Uma linha de decomp com anotações no fim (não quebra a expressão)."""
    notes: list[str] = _offset_notes(line)
    # globals DAT_7100.../PTR_DAT_7100... → nome do registry + valor
    _load_globals()
    gr = _GLOBALS_R or {}
    for m in re.finditer(r"(?:PTR_)?DAT_([0-9a-fA-F]{9,12})", line):
        nm = gr.get(m.group(1).lower())
        if nm:
            ent = (_GLOBALS or {})[nm]
            val = f" = {ent['value']}" if ent.get("value") else ""
            notes.append(f"{nm}{val}")
    # enums: comparacoes/mascaras com valor conhecido — só valores DISTINCTIVOS
    # (>=0x10 ou mascara multi-bit); 0/1/2... pequenos sao onipresentes = ruido
    _load_enums()
    ev = _ENUM_VALS or {}
    for m in re.finditer(r"(?:==|!=|&|\band\b|\bor\b)\s*\(?\s*(0x[0-9a-fA-F]+|\d+)\s*\)?", line):
        try:
            v = int(m.group(1), 0)
        except ValueError:
            continue
        if v in ev and (v >= 0x10 or bin(v).count("1") >= 2):
            notes.append("state: " + " | ".join(ev[v][:2]))
    if not notes:
        return line
    return line.rstrip() + "   ⟦" + " · ".join(notes) + "⟧"


def cmd_ann(va: int, n_context: int = 0) -> None:
    """Corpo decomp com anotações semânticas inline."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))  # rex vive em ~/projects/rex
    from shard_resolve import ShardIndex
    idx = ShardIndex()
    body = idx.load_decomp(va)
    if body is None:
        f = fn_of(va)
        if f and f[0] < va:
            body = idx.load_decomp(f[0])
            print(f"# {va:#x} mid-function de {f[1]} @ {f[0]:#x} — corpo inteiro anotado")
        if body is None:
            print(f"não achou corpo de {va:#x} no corpus")
            sys.exit(1)
    _load_memmap()
    assert _MEMMAP is not None
    print(f"# {_MEMMAP_NOTE}")
    _load_names()
    short = (_NAMES_R or {}).get(f"{va:x}")
    if short:
        print(f"# {short} = {va:#x}")
    notes_path = _root() / "data" / "function-notes.json"
    fnote = ""
    if notes_path.exists():
        fn = json.loads(notes_path.read_text())
        note = fn.get(f"{va:x}", "")
        if note:
            fnote = f"  # ⭐ {note}"
    print(f"# FUN {va:#x}{fnote}")
    for line in body.splitlines():
        print(_ann_line(line))


def cmd_body(va: int, asm: bool) -> None:
    from shard_resolve import ShardIndex
    idx = ShardIndex()
    body = idx.load_asm(va) if asm else idx.load_decomp(va)
    if body is None:
        # nao e inicio catalogado: distingue mid-function de gap
        f = fn_of(va)
        if f:
            start, name = f
            if _INSNS:
                end = start + _INSNS.get(start, 0) * 4
            else:
                i = bisect.bisect_right(_FUNCS_ADDRS or [], start)
                addrs = _FUNCS_ADDRS or []
                end = addrs[i] if i < len(addrs) else start + (1 << 30)
            if start < va < end:
                print(f"# {va:#x} é mid-function de {name} @ {start:#x} (+{va - start:#x}); corpo inteiro:")
                body = idx.load_asm(start) if asm else idx.load_decomp(start)
                if body is not None:
                    print(body)
                    return
            else:
                print(f"# {va:#x} está em GAP (após {name} @ {start:#x}, fim {end:#x}) — "
                      f"função NÃO catalogada pelo dumper; disassemblando in loco:")
                cmd_dis(va, 64)
                return
        print(f"não achou corpo de {va:#x} no corpus (usar disasm.py)")
        sys.exit(1)
    print(body)


def _decode_mem(w: int) -> dict | None:
    """Decodifica STR/LDR (uimm, int+SIMD), STP/LDP e STUR/LDUR.

    Retorna {mnem, rt, rt2, rn, off} ou None. off é o offset de struct
    (com sinal em stur/stp). Corrige o bug histórico: imm12 de SIMD/FP
    (V=1) escala por size/16 igual ao int (str s em +0x368 era invisível).
    """
    g = w & 0x3B000000
    rn = (w >> 5) & 0x1F
    rt = w & 0x1F
    rt2 = (w >> 10) & 0x1F

    def _reg(cls: str, n: int) -> str:
        if n == 31 and cls in ("w", "x"):
            return cls + "zr"
        return f"{cls}{n}"

    if g in (0x39000000, 0x3D000000):            # unsigned offset (int/SIMD&FP)
        v = (w >> 26) & 1
        opc = (w >> 22) & 3
        size = (w >> 30) & 3
        if v == 0:
            scale = 1 << size
            if opc in (0b10, 0b11):              # ldrsb/ldrsh/ldrsw
                if opc == 0b11 and size == 2:
                    return None                  # PRFM
                mnem = "ldrs" + {0: "b", 1: "h", 2: "w"}[size]
                cls = "x" if opc == 0b10 else "w"
                return {"mnem": mnem, "rt": _reg(cls, rt), "rt2": None, "rn": rn,
                        "off": ((w >> 10) & 0xFFF) * scale}
            is_load = opc == 0b01
            mnem = ("ldr" if is_load else "str") + {0: "b", 1: "h", 2: "", 3: ""}[size]
            cls = "x" if size == 3 else "w"
        else:
            if opc in (0b10, 0b11):              # q-reg (escala 16; 10=store, 11=load)
                scale, cls = 16, "q"
            else:
                scale = 1 << size
                cls = {0: "b", 1: "h", 2: "s", 3: "d"}[size]
            is_load = opc & 1
            mnem = "ldr" if is_load else "str"   # sem sufixo: a classe do reg já diz a largura
        off = ((w >> 10) & 0xFFF) * scale
        return {"mnem": mnem, "rt": _reg(cls, rt), "rt2": None, "rn": rn, "off": off}
    if g in (0x29000000, 0x2D000000):            # pair (stp/ldp, 3 modos de indexing)
        opc = (w >> 30) & 3
        v = (w >> 26) & 1
        meta = {(0, 0): ("w", 4), (2, 0): ("x", 8), (0, 1): ("s", 4), (1, 1): ("d", 8), (2, 1): ("q", 16)}
        m = meta.get((opc, v))
        if m is None:
            return None
        cls, scale = m
        imm7 = (w >> 15) & 0x7F
        if imm7 & 0x40:
            imm7 -= 0x80
        pmode = (w >> 23) & 3                    # pairs: opc de indexing em bits 24:23 (10 signed, 11 pre, 01 post); bits 11:10 = parte do rt2
        pwb = {0b10: None, 0b11: "pre", 0b01: "post"}.get(pmode)
        return {"mnem": "ldp" if (w >> 22) & 1 else "stp",
                "rt": _reg(cls, rt), "rt2": _reg(cls, rt2),
                "rn": rn, "off": imm7 * scale, "wb": pwb}
    if g == 0x38000000:                          # unscaled (stur/ldur) + pre/post-index (writeback) + unprivileged (sttr/ldtr)
        mode = (w >> 10) & 3
        # mode: 00 = unscaled (stur/ldur), 01 = post-index (str [x],#imm),
        #       10 = unprivileged (sttr/ldtr), 11 = pre-index (str [x,#imm]!)
        if mode == 0b01:
            wb = "post"
        elif mode == 0b11:
            wb = "pre"
        else:
            wb = None
        v = (w >> 26) & 1
        opc = (w >> 22) & 3
        size = (w >> 30) & 3
        if mode == 0:
            stem = ("stur", "ldur"); sstem = "ldurs"
        elif mode == 2:
            stem = ("sttr", "ldtr"); sstem = "ldtrs"
        else:
            stem = ("str", "ldr"); sstem = "ldrs"
        if v == 0:
            if opc == 0b11:
                return None                      # PRFM/PRFUM
            suf = {0: "b", 1: "h", 2: "", 3: ""}[size]
            if opc == 0b10:                      # signed byte/half/word loads
                mnem = sstem + {0: "b", 1: "h", 2: "w"}[size]
                cls = "x" if size == 2 else "w"
            else:
                is_load = opc == 0b01
                mnem = (stem[1] if is_load else stem[0]) + suf
                cls = "x" if size == 3 else "w"
        else:
            if opc in (0b10, 0b11):              # q-reg (10=store, 11=load)
                cls = "q"
            else:
                cls = {0: "b", 1: "h", 2: "s", 3: "d"}[size]
            is_load = opc & 1
            mnem = stem[1] if is_load else stem[0]
        imm9 = (w >> 12) & 0x1FF
        if imm9 & 0x100:
            imm9 -= 0x200
        return {"mnem": mnem, "rt": _reg(cls, rt), "rt2": None, "rn": rn,
                "off": imm9, "wb": wb}
    return None


def _scan_mem(imm: int, load: bool):
    """Varre .text decodificando STR/LDR/etc com offset == imm. Yield (va, mi)."""
    _load()
    d = _DATA
    assert d is not None
    tm, tf, ts = struct.unpack_from("<III", d, 0x10)
    end = min(tf + ts, len(d)) & ~3
    words = struct.unpack_from(f"<{end // 4}I", d, 0)
    for i, w in enumerate(words):
        if ((w >> 27) & 7) not in (0b101, 0b111):   # fast reject: só grupos load/store
            continue
        mi = _decode_mem(w)
        if mi is None or mi["off"] != imm:
            continue
        if (mi["mnem"][:2] == "ld") != load:
            continue
        yield BASE + i * 4 - HDR, mi


def _parse_range(tok: str) -> tuple[int, int]:
    """'0xA..0xB' → (lo, hi) em VA; lados < BASE são tratados como offset de módulo."""
    lo_s, sep, hi_s = tok.partition("..")
    if not sep:
        raise ValueError(f"range inválido: {tok} (use A..B)")
    lo, hi = int(lo_s, 16), int(hi_s, 16)
    if lo < BASE:
        lo += BASE
    if hi < BASE:
        hi += BASE
    if lo > hi:
        raise ValueError(f"range com lo > hi: {tok}")
    return lo, hi


def cmd_offset(imm: int, load: bool, msub: str | None = None,
               rng: tuple[int, int] | None = None) -> None:
    by_mnem: dict[str, int] = {}
    count = total = 0
    for va, mi in _scan_mem(imm, load):
        total += 1
        pair = f",{mi['rt2']}" if mi["rt2"] else ""
        left = f"{mi['mnem']} {mi['rt']}{pair}"
        if msub and msub not in left:
            continue
        if rng and not (rng[0] <= va <= rng[1]):
            continue
        wb = mi.get("wb")
        if wb == "post":
            mem = f"[x{mi['rn']}],#{mi['off']:#x}"
        else:
            mem = f"[x{mi['rn']},#{mi['off']:#x}]" + ("!" if wb == "pre" else "")
        print(f"  {va:#x}  {left},{mem}  <{name_of(va)}>")
        by_mnem[mi["mnem"]] = by_mnem.get(mi["mnem"], 0) + 1
        count += 1
    detail = ", ".join(f"{m} ×{c}" for m, c in sorted(by_mnem.items(), key=lambda kv: -kv[1]))
    kind = "loads" if load else "stores"
    extra = []
    if msub:
        extra.append(f"filtro '{msub}'")
    if rng:
        extra.append(f"range {rng[0]:#x}..{rng[1]:#x}")
    if total and count != total:
        extra.append(f"{total - count} fora do filtro")
    print(f"# {count}/{total} {kind} de #{imm:#x}"
          + (f"  ({'; '.join(extra)})" if extra else "")
          + (f"  [{detail}]" if detail else ""))


# ---------------------------------------------------------------- bit query

def _decode_logimm(w: int):
    """AND/ORR/EOR/ANDS por imediato lógico → (nome, mask, rd, sf) ou None."""
    if ((w >> 23) & 0x3F) != 0b100100:
        return None
    sf = (w >> 31) & 1
    opc = (w >> 29) & 3
    n = (w >> 22) & 1
    immr = (w >> 16) & 0x3F
    imms = (w >> 10) & 0x3F
    rd = w & 0x1F
    width = 64 if sf else 32
    x = (n << 6) | ((~imms) & 0x3F)
    if x < 2:                       # len < 1 → UNDEFINED
        return None
    esize = 1 << (x.bit_length() - 1)
    if esize > width:
        return None
    levels = esize - 1
    if (imms & levels) == levels:
        return None
    s = (imms & levels) + 1
    welem = (1 << s) - 1
    r = immr % esize
    if r:
        welem = ((welem >> r) | (welem << (esize - r))) & ((1 << esize) - 1)
    mask = 0
    for i in range(width // esize):
        mask |= welem << (i * esize)
    return {0: "and", 1: "orr", 2: "eor", 3: "ands"}[opc], mask, rd, sf


def _decode_movwide(w: int):
    """MOVZ/MOVN/MOVK → (nome, val_16bits, lane_hw, rd, sf) ou None."""
    if ((w >> 23) & 0x3F) != 0b100101:
        return None
    sf = (w >> 31) & 1
    opc = (w >> 29) & 3
    hw = (w >> 21) & 3
    imm16 = (w >> 5) & 0xFFFF
    rd = w & 0x1F
    if opc == 0b01:
        return None                 # unallocated
    name = {0b00: "movn", 0b10: "movz", 0b11: "movk"}[opc]
    return name, imm16, hw, rd, sf


def _writes_reg(w: int) -> bool:
    """Heurística: palavra escreve em Rd (bits 4:0) — exclui branches."""
    if (w & 0x7C000000) in (0x14000000, 0x94000000):     # b / bl
        return False
    if (w & 0x7E000000) in (0x34000000, 0x36000000):     # cbz/cbnz, tbz/tbnz
        return False
    if (w & 0xFF000010) == 0x54000000:                    # b.cond (Rd colide)
        return False
    return True


def _def_verdict(w: int, rt: str, bit: int):
    """Classifica um def candidato de rt: ('def'|'pass'|'no', veredito)."""
    mi = _decode_mem(w)
    if mi:
        if mi["rt2"]:                                   # stp/ldp: pula
            return "no", None
        if mi["rt"] == rt:
            return ("def", "carregado da memória (ldr)") if mi["mnem"][:2] == "ld" else ("no", None)
        return "no", None                               # mem op n define rt
    li = _decode_logimm(w)
    if li:
        name, mask, rd, sf = li
        rds = ("xzr" if sf else "wzr") if rd == 31 else f"{'x' if sf else 'w'}{rd}"
        if rds != rt:
            return "no", None
        has = (mask >> bit) & 1
        if name == "orr":
            return ("def", "SET (orr imediato)") if has else ("pass", None)
        if name in ("and", "ands"):
            return ("pass", None) if has else ("def", "CLEAR (and imediato)")
        if name == "eor":
            return ("def", "TOGGLE (eor imediato)") if has else ("pass", None)
    mw = _decode_movwide(w)
    if mw:
        name, imm16, hw, rd, sf = mw
        rds = ("xzr" if sf else "wzr") if rd == 31 else f"{'x' if sf else 'w'}{rd}"
        if rds != rt:
            return "no", None
        lo, hi = hw * 16, hw * 16 + 16
        if name == "movk" and not (lo <= bit < hi):
            return "pass", None                         # movk fora da lane
        if name == "movk":
            val = (imm16 >> (bit - lo)) & 1
        elif bit < 16:
            val = (imm16 >> bit) & 1
        else:                                           # fora da lane: resto zerado
            val = 0                                     # (movn inverte abaixo)
        if name == "movn":
            val ^= 1
        return "def", f"OVERWRITE bit={val} ({name})"
    # outro writer de Rd (bits 4:0 == número do rt)
    try:
        rt_num = int(rt[1:])
    except ValueError:
        return "no", None
    if (w & 0x1F) == rt_num and rt[0] in "wx" and _writes_reg(w):
        return "def", "def não-imediato (aritm/etc)"
    return "no", None


_WIDTH = {"w": 4, "x": 8, "s": 4, "d": 8, "q": 16}


def cmd_bit(imm: int, bit: int, rng: tuple[int, int] | None = None) -> None:
    """Stores de #imm com def classificado do bit pedido. -r filtra por range de VA."""
    _load()
    d = _DATA
    assert d is not None
    stats: dict[str, int] = {}
    n = 0
    for va, mi in _scan_mem(imm, load=False):
        if rng and not (rng[0] <= va <= rng[1]):
            continue
        if mi["rt2"]:                       # pares: bit ambíguo entre rt/rt2
            continue
        mn = mi["mnem"]
        width = (1 if mn.endswith("b") else 2 if mn.endswith("h")
                 else _WIDTH.get(mi["rt"][0], 4))
        if bit >= width * 8:
            continue                        # bit fora do campo gravado
        n += 1
        rt = mi["rt"]
        if rt in ("wzr", "xzr"):
            verdict, dva = "CLEAR (store de zero)", None
        else:
            verdict, dva = None, None
            off_i = va - BASE + HDR
            for back in range(1, 17):
                w = struct.unpack_from("<I", d, off_i - back * 4)[0]
                kind, v = _def_verdict(w, rt, bit)
                if kind == "def":
                    verdict, dva = v, va - back * 4
                    break
                if kind == "pass":
                    continue                # orr/and/eor sem afetar o bit: segue atrás
            if verdict is None:
                verdict = "def não achado (≤16 instr)"
        stats[verdict] = stats.get(verdict, 0) + 1
        where = f"  def@{dva:#x}" if dva else ""
        wb = mi.get("wb")
        if wb == "post":
            mem = f"[x{mi['rn']}],#{mi['off']:#x}"
        else:
            mem = f"[x{mi['rn']},#{mi['off']:#x}]" + ("!" if wb == "pre" else "")
        print(f"  {va:#x}  {mi['mnem']} {rt},{mem}"
              f"  <{name_of(va)}>{where}  → {verdict}")
    print(f"# {n} stores de #{imm:#x} cobrem bit {bit}: "
          + (", ".join(f"{v} ×{c}" for v, c in sorted(stats.items(), key=lambda kv: -kv[1]))
             or "nenhum"))


# ---------------------------------------------------------------- relocations

_RELOC_TABLE = None      # slot_mem_off -> addend (R_AARCH64_RELATIVE limpos)
_RELOC_KEYS = None       # slots ordenados


def _relocs():
    """Tabela de relocations do NSO: triplets 0x18 (r_offset, 0x403, addend).

    Clusters contíguos (stride 0x18, ≥2 records) — mata falso-positivo
    aleatório em rodata. r_offset/addend são offsets relativos ao BASE.
    """
    global _RELOC_TABLE, _RELOC_KEYS
    if _RELOC_TABLE is not None:
        return _RELOC_TABLE, _RELOC_KEYS
    _load()
    d = _DATA
    assert d is not None
    da_f, da_m, da_s = struct.unpack_from("<III", d, 0x30)
    slo, shi = da_m, da_m + da_s
    n8 = len(d) // 8
    recs = []                          # (índice qword do info, slot, addend)
    pat = struct.pack("<Q", 0x403)
    pos = 0
    while True:
        i = d.find(pat, pos)
        if i < 0:
            break
        pos = i + 1
        if i % 8:
            continue                   # desalinhado: não é triplet válido
        qi = i // 8
        if 0 < qi < n8 - 1:
            slot = struct.unpack_from("<Q", d, (qi - 1) * 8)[0]
            add = struct.unpack_from("<Q", d, (qi + 1) * 8)[0]
            if slo <= slot < shi and add < shi:
                recs.append((qi, slot, add))
    table = {}
    j = 0
    while j < len(recs):
        k = j
        while k + 1 < len(recs) and recs[k + 1][0] - recs[k][0] == 3:  # 3 qwords = 0x18 B
            k += 1
        if k > j:                      # cluster ≥2: tabela real
            for _, s, a in recs[j:k + 1]:
                table[s] = a
        j = k + 1
    _RELOC_TABLE = table
    _RELOC_KEYS = sorted(table)
    return _RELOC_TABLE, _RELOC_KEYS


def _reloc_label(addend: int) -> str:
    tgt = BASE + addend
    f = fn_of(tgt)
    if f and tgt == f[0]:
        return f[1]
    if f:
        return f"{f[1]}+{tgt - f[0]:#x}"
    assert _DATA is not None
    tm, tf, ts = struct.unpack_from("<III", _DATA, 0x10)
    return f"({'.rodata/.data' if addend >= tm + ts else '?'} @ {tgt:#x})"


# ---------------------------------------------------------------- vtables

_VT_CACHE: dict[tuple[int, int], list[tuple[int, int]]] = {}


_INV_SLOTS: dict[int, int] | None = None


def _inventory_slots(va: int) -> int | None:
    """Nº de slots da vtable em va segundo o inventário mecânico (cluster).

    Fonte autoritativa da FRONTEIRA de cada vtable (vtables-inventory.json,
    clusterização por relocations). Auto-detect (_vtable_slots max_slots=0) vaza
    por vtables densas do bloco físico (gap≤2 nunca fecha); o cluster exato é o
    teto correto. None = AP não está no inventário (vtable pequena/sem cluster).
    """
    global _INV_SLOTS
    if _INV_SLOTS is None:
        p = _root() / "data" / "vtables-inventory.json"
        _INV_SLOTS = {}
        if p.exists():
            for v in json.loads(p.read_text(encoding="utf-8")).get("vtables", []):
                _INV_SLOTS[int(v["ap"], 16)] = v["slots"]
    return _INV_SLOTS.get(va)


def _vtable_slots(va: int, max_slots: int = 0) -> list[tuple[int, int]]:
    """Slots (slot_va, target_va) de uma vtable em va — via relocations.

    Vtables MK8DX são arrays de qwords relocados: cada slot aponta pra função.
    Tolerante a gaps ≤2 slots (pares dtor Itanium / espaço reservado).
    Para em: gap ≥3, alvo fora de .text (typeinfo/dado), ou max_slots.
    Regiões compactas (sem RTTI) não têm fronteira nítida — use max_slots.
    """
    if (va, max_slots) in _VT_CACHE:
        return _VT_CACHE[(va, max_slots)]
    table, keys = _relocs()
    _load()
    assert _DATA is not None
    tm, tf, ts = struct.unpack_from("<III", _DATA, 0x10)
    text_end = BASE + tm + ts
    out: list[tuple[int, int]] = []
    m = va - BASE                     # chaves da tabela são mem offsets
    gap = 0
    while max_slots == 0 or len(out) < max_slots:
        if m in table:
            tgt = BASE + table[m]
            if not (BASE <= tgt < text_end):
                break                 # typeinfo/dado: fim da tabela
            out.append((BASE + m, tgt))
            gap = 0
        else:
            gap += 1
            if gap > 2:
                break
        m += 8
    _VT_CACHE[(va, max_slots)] = out
    return out


_VT_REGISTRY: dict[str, dict] | None = None


def _load_vt_registry() -> None:
    global _VT_REGISTRY
    if _VT_REGISTRY is not None:
        return
    _VT_REGISTRY = {}
    p = _root() / "data" / "vtables.json"
    if p.exists():
        d = json.loads(p.read_text(encoding="utf-8"))
        d.pop("_comment", None)
        _VT_REGISTRY = d


def _vt_name_for_vtable(va: int) -> str | None:
    """Nome curto do registry de vtables se va for registrado; senão None."""
    _load_vt_registry()
    assert _VT_REGISTRY is not None
    for nm, ent in _VT_REGISTRY.items():
        if ent.get("va") == f"{va:x}":
            return nm
    return None


_CTORS: dict[str, dict] | None = None


def _load_ctors() -> None:
    global _CTORS
    if _CTORS is not None:
        return
    p = _root() / "data" / "ctors.json"
    _CTORS = {}
    if p.exists():
        d = json.loads(p.read_text(encoding="utf-8"))
        d.pop("_comment", None)
        _CTORS = d


def _ctor_name_for_va(va: int) -> str | None:
    """Nome curto do registry se o ctor em va tiver nome; senão None."""
    _load_ctors()
    for nm, ent in (_CTORS or {}).items():
        if ent.get("va") == f"{va:x}":
            return nm
    return None


def cmd_ctor(va: int, json_out: bool = False, list_all: bool = False) -> None:
    """Cadeia estática do ctor: holders -> vtables instaladas por campo.

    Padrão MK8DX (descoberto no ctor KartUnit): o ctor não materializa a
    vtable com adrp+add — carrega um HOLDER em .data (adrp+ldr PTR_DAT),
    cujo reloc resolve a base do bloco de vtables; add N + str [xN,#imm]
    instala a sub-vtable no campo do objeto.
    """
    _load_vt_registry()
    assert _VT_REGISTRY is not None
    if list_all:
        _load_ctors()
        assert _CTORS is not None
        print(f"# {len(_CTORS)} ctors registrados (data/ctors.json)")
        for nm, ent in sorted(_CTORS.items(), key=lambda kv: int(kv[1]["va"], 16)):
            print(f"  {nm:<28} 0x{int(ent['va'],16):x}  {ent['class'][:64]}")
        return
    if va == 0:
        print("uso: rex ctor <va|nome> [-j]")
        return
    # 1) asm do ctor
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from shard_resolve import ShardIndex
    asm = ShardIndex().load_asm(va)
    if asm is None:
        print(f"não achei corpo asm de {va:#x}")
        return
    tbl, _ = _relocs()
    vt_by_va = {int(e["va"], 16): nm for nm, e in _VT_REGISTRY.items()}
    state: dict[str, int] = {}        # reg -> VA base (pós adrp/ldr/add)
    holder_info: dict[str, tuple[int, int]] = {}  # reg -> (holder_va, reloc_alvo)
    installs: list[tuple[int, int, str]] = []     # (field_off, vtable_va, holder)
    calls: list[tuple[int, str]] = []             # (alvo, nome)
    new_sizes: list[tuple[int, str]] = []         # (tamanho, alvo bl)
    this_regs: set[str] = {"0", "19", "20"}       # x0/x19/x20 = this (convenção clang)
    last_mov_x0: int | None = None
    line_re = _get_asm_line_re()
    for line in asm.splitlines():
        if line.startswith("//"):
            state.clear()
            holder_info.clear()
            continue
        m = line_re.match(line)
        if not m:
            continue
        _, mnem, ops = m.groups()
        if mnem in ("mov", "movz") and ops.startswith("x0,"):
            try:
                last_mov_x0 = int(ops.split(",", 1)[1].lstrip("#"), 0)
            except ValueError:
                last_mov_x0 = None
            continue
        if mnem == "bl" and last_mov_x0 is not None:
            t = ops.split()[0]
            if t.startswith("0x"):
                new_sizes.append((last_mov_x0, t))
            last_mov_x0 = None
            continue
        last_mov_x0 = None
        _ctor_step(mnem, ops, state, holder_info, installs, calls, new_sizes,
                   tbl, vt_by_va, this_regs)
    # relatório (dedup preservando ordem)
    print(f"# ctor {name_of(va)} @ {va:#x}")
    reg_nm = _ctor_name_for_va(va)
    if reg_nm:
        ent = (_CTORS or {})[reg_nm]
        print(f"# {reg_nm}: {ent.get('class', '?')} — fonte: {ent.get('doc', '?')}")
    for sz, t in new_sizes:
        print(f"  new({sz:#x}) -> {t}")
    seen: set[tuple[int, int]] = set()
    uniq = [x for x in installs if not (x[:2] in seen or seen.add(x[:2]))]
    vt_installs = [x for x in uniq if x[1] >= 0x7101000000]
    data_installs = [x for x in uniq if x[1] < 0x7101000000]
    if vt_installs:
        print(f"  {len(vt_installs)} instalações de vtable (holder -> reloc):")
        for off, vt_va, holder in vt_installs:
            nm = vt_by_va.get(vt_va) or ""
            b = f" {nm}" if nm else ""
            print(f"    [{off:#x}] = 0x{vt_va:x}{b}   (holder 0x{holder:x})")
    if data_installs:
        print(f"  {len(data_installs)} tabelas .rodata instaladas:")
        for off, vt_va, holder in data_installs:
            print(f"    [{off:#x}] = 0x{vt_va:x}   (holder 0x{holder:x})")
    if calls:
        named = [f"{t:#x} {nm}" for t, nm in calls if nm and nm != f"FUN_{t:x}"]
        if named:
            print(f"  calls nomeados: {', '.join(named[:8])}")
    # dtor: NÃO detectável mecanicamente neste binário — os 16 VAs de
    # operator.delete têm ZERO callers no corpus inteiro (grep colado,
    # shard-*-asm); desalocação vai pelo allocator da engine (sead-style),
    # ainda não identificado. Convenção Itanium (slots 0/1) NÃO vale aqui:
    # KartUnit e BoostController compartilham slots 0/1 (herdados da base
    # comum) e slot 1 é um accessor lazy-init (__cxa_guard), não D0.
    if not installs and not new_sizes and not calls:
        print("  (nenhuma instalação via holder detectada — adrp+add direto?)")


def _get_asm_line_re():
    global _ASM_LINE_RE
    if _ASM_LINE_RE is None:
        _ASM_LINE.extend(["placeholder"])
        _ASM_LINE_RE = re.compile(r"^([0-9a-f]{10,12})\s+(\S+)\s*(.*)$")
    return _ASM_LINE_RE


_ASM_LINE_RE = None
_ASM_LINE: list = []

def _ctor_step(mnem: str, ops: str, state, holder_info, installs, calls, new_sizes, tbl, vt_by_va, this_regs) -> None:
    """Um passo do tracker de ctor sobre uma linha de asm.

    state: reg->VA; holder_info: reg->(holder_va, reloc_alvo); this_regs: regs
    que recebem o ponteiro do objeto (x0-x3 na entrada + callee-saveds que
    recebem cópia dele). Instalação = str de valor-holder em [this,#imm].
    """
    import re as _re
    parts = [p.strip() for p in ops.split(",")]

    def rk(t: str) -> str | None:
        m = _re.match(r"^[xw](\d+)$", t)
        return m.group(1) if m else None

    dst0 = rk(parts[0]) if parts else None

    if mnem == "adrp":
        m = _re.match(r"([xw]\d+)\s*,\s*(0x[0-9a-f]+)", ops)
        if m and rk(m.group(1)) is not None:
            state[rk(m.group(1))] = int(m.group(2), 16)
        return

    if mnem == "ldr":
        # ldr x8,[x8,#imm] — se a base é .data e o reloc resolve, vira holder
        mb = _re.search(r"\[([^\]]*)\]", ops)
        if not mb:
            return
        cparts = [p.strip() for p in mb.group(1).split(",")]
        base = rk(cparts[0]) if cparts else None
        if dst0 is None or base is None or base not in state:
            return
        if len(cparts) == 1:
            imm = 0
        elif len(cparts) == 2 and cparts[1].startswith("#"):
            imm = int(cparts[1].lstrip("#"), 0)
        else:
            return
        addr = state[base] + imm
        addend = tbl.get(addr - BASE)
        if addend is not None:
            state[dst0] = BASE + addend
            holder_info[dst0] = (addr, BASE + addend)
        else:
            state.pop(dst0, None)
            holder_info.pop(dst0, None)
        return

    if mnem == "add":
        m = _re.match(r"([xw]\d+)\s*,\s*([xw]\d+)\s*,\s*#(0x[0-9a-f]+|\d+)", ops)
        if m:
            d, b = rk(m.group(1)), rk(m.group(2))
            if d is not None and b is not None:
                if b in state:
                    state[d] = state[b] + int(m.group(3), 0)
                    if b in holder_info:
                        holder_info[d] = holder_info[b]
                else:
                    state.pop(d, None)
                    holder_info.pop(d, None)
        return

    if mnem == "str":
        # instalação: str xVal,[xThis,#imm] com xVal vindo de holder
        br = _re.search(r"\[([^\]]*)\]", ops)
        if not br:
            return
        cparts = [p.strip() for p in br.group(1).split(",")]
        obj = rk(cparts[0]) if cparts else None
        if obj is None or obj not in this_regs:
            return
        src = dst0
        if src is None or src not in holder_info:
            return
        imm = 0
        if len(cparts) > 1 and cparts[1].startswith("#"):
            imm = int(cparts[1].lstrip("#"), 0)
        vt_va = state.get(src)
        if vt_va is not None:
            installs.append((imm, vt_va, holder_info[src][0]))
        return

    if mnem == "bl":
        t = parts[0]
        if t.startswith("0x"):
            calls.append((int(t, 0), name_of(int(t, 0))))
        return

    # invalidação genérica: qualquer outro mnem que escreve dst0 mata o estado dele
    WRITES = {
        "mov", "movz", "movn", "movk", "orr", "and", "ands", "eor", "sub", "subs",
        "add", "adds", "lsl", "asr", "lsr", "mul", "madd", "csel", "csinc",
        "sxtw", "uxtw", "sxtb", "sxth", "ldr", "ldrsw", "ldur", "ldrb", "ldrh",
        "ldrsb", "ldrsh", "ldp", "fmov", "ldr d", "ldr q",
    }
    if mnem in WRITES and dst0 is not None:
        state.pop(dst0, None)
        holder_info.pop(dst0, None)


def cmd_vtable(va: int, json_out: bool = False, max_slots: int = 0, list_all: bool = False) -> None:
    """Dump de vtable: slots, funções e nomes curtos."""
    _load_vt_registry()
    assert _VT_REGISTRY is not None
    if list_all:
        for nm, ent in sorted(_VT_REGISTRY.items()):
            print(f"  {ent['va']}  {nm}  ({ent.get('class', '?')}) — {ent.get('doc', '?')}")
        return
    # nome do registry de vtables carrega o tamanho canônico
    reg_nm = _vt_name_for_vtable(va)
    if reg_nm and max_slots == 0:
        ent = _VT_REGISTRY[reg_nm]
        if int(ent.get("slots", 0)):
            max_slots = int(ent["slots"])
    slots = _vtable_slots(va, max_slots)
    if not slots:
        print(f"nenhuma relocation em {va:#x} — não é vtable (ou início errado)")
        sys.exit(1)
    print(f"# vtable @ {va:#x} — {len(slots)} slots")
    if reg_nm:
        ent = _VT_REGISTRY[reg_nm]
        print(f"# {reg_nm}: {ent.get('class', '?')} — fonte: {ent.get('doc', '?')}")
    if json_out:
        import json as _json
        payload = []
        for s, t in slots:
            payload.append(
                {"slot": f"{s:#x}", "offset": s - va, "target": f"{t:#x}",
                 "name": (_NAMES_R or {}).get(f"{t:x}", "")}
            )
        print(_json.dumps(payload, indent=1))
        return
    for s, v in slots:
        nm = (_NAMES_R or {}).get(f"{v:x}", "")
        nm_s = f"  {nm}" if nm else ""
        print(f"  [{s - va:#04x}] {v:#x}  {name_of(v)}{nm_s}")


# ---------------------------------------------------------------- BLR / dispatch virtual

_BLR_CACHE: list[tuple[int, str, int | None]] | None = None


def _blr_scan() -> list[tuple[int, str, int | None]]:
    """Todos os dispatch virtuais (BLR) em .text: (site_va, reg, slot_off|None).

    Resolve o slot-offset do padrão ldr Xn,[Xm](vptr) → ldr Xn,[Xn,#off](slot) →
    blr Xn. Escaneia por máscara de opcode (0xD63F0000), disasm capstone da
    janela anterior. slot_off = None = blr de ponteiro (não vtable dispatch) ou
    sem ldr self-referential na janela. ~1s, cache em memória.
    """
    global _BLR_CACHE
    if _BLR_CACHE is not None:
        return _BLR_CACHE
    _load()
    d = _DATA
    assert d is not None
    tfo, tmo, ts = struct.unpack_from("<III", d, 0x10)  # NSO: (file, mem, size)
    end = min(tfo + ts, len(d)) & ~3
    import re as _re
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        use_cs = True
    except ImportError:
        md, use_cs = None, False
    out: list[tuple[int, str, int | None]] = []
    for i in range(end // 4):
        w = struct.unpack_from("<I", d, i * 4)[0]
        if (w & 0xFFFFFC1F) != 0xD63F0000:   # BLR Xn
            continue
        site = BASE + i * 4 - HDR
        reg = f"x{w & 0x1F}"
        slot_off: int | None = None
        if use_cs:
            win_start = site - 8 * 4
            win = list(md.disasm(d[(win_start - BASE + HDR):(site - BASE + HDR)], win_start))
            for p in reversed(win):
                if p.mnemonic != "ldr":
                    if p.mnemonic in ("blr", "ret", "b", "br", "bl", "cbz", "tbz", "b.hi"):
                        break
                    continue
                m = _re.match(r"x(\d+),\s*\[x(\d+)(?:,\s*#(0x[0-9a-f]+|\d+))?\]", p.op_str)
                if m and m.group(1) == m.group(2) and m.group(3):
                    slot_off = int(m.group(3), 0)
                    break
        out.append((site, reg, slot_off))
    _BLR_CACHE = out
    return out


def cmd_vtable_callers(va: int, max_slots: int = 0) -> None:
    """BL + BLR callers por slot de uma vtable: quem chama cada método.

    Para cada slot: (a) BL callers diretos (rex callers do alvo), (b) BLR sites
    cujo slot-offset == offset do slot (dispatch virtual indireto). BLR é
    candidato (qualquer vtable com o mesmo offset despacha igual); BL é exato.
    """
    _load_vt_registry()
    assert _VT_REGISTRY is not None
    reg_nm = _vt_name_for_vtable(va)
    if reg_nm and max_slots == 0:
        ent = _VT_REGISTRY[reg_nm]
        if int(ent.get("slots", 0)):
            max_slots = int(ent["slots"])
        else:
            inv = _inventory_slots(va)
            if inv:
                max_slots = inv   # fronteira exata do cluster
    slots = _vtable_slots(va, max_slots)
    if not slots:
        print(f"nenhuma relocation em {va:#x} — não é vtable (ou início errado)")
        sys.exit(1)
    blr = _blr_scan()
    _load_names()
    print(f"# vtable @ {va:#x} — {len(slots)} slots  ({reg_nm or 'não registrada'})")
    # índice BLR por offset para lookup rápido
    by_off: dict[int, list[tuple[int, str]]] = {}
    for site, reg, off in blr:
        if off is not None:
            by_off.setdefault(off, []).append((site, reg))
    # índice BL por alvo (uma única varredura de .text, não por slot)
    d = _DATA
    assert d is not None
    tfo, tmo, ts = struct.unpack_from("<III", d, 0x10)
    end = min(tfo + ts, len(d)) & ~3
    bl_by_tgt: dict[int, list[int]] = {}
    for i in range(end // 4):
        w = struct.unpack_from("<I", d, i * 4)[0]
        if (w & 0xFC000000) != 0x94000000:
            continue
        src = BASE + i * 4 - HDR
        imm = w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        tgt = src + (imm << 2)
        if _INSNS:
            f = fn_of(src)
            if not (f and src < f[0] + _INSNS.get(f[0], 0) * 4):
                continue   # gap: literal/dado, não call
        bl_by_tgt.setdefault(tgt, []).append(src)
    for s, t in slots:
        off = s - va
        bls = bl_by_tgt.get(t, [])
        brl = by_off.get(off, [])
        nm = (_NAMES_R or {}).get(f"{t:x}", "")
        nm_s = f"  {nm}" if nm else ""
        print(f"\n  [{off:#04x}] target {t:#x}  {name_of(t)}{nm_s}")
        print(f"    BL callers ({len(bls)}): " +
              (", ".join(f"{b:#x}" for b in bls) if bls else "—"))
        if brl:
            print(f"    BLR no offset {off:#x} ({len(brl)} sites, candidatos):")
            for site, reg in brl[:40]:
                print(f"      {site:#x}  blr {reg}   {name_of(site)}")
            if len(brl) > 40:
                print(f"      … +{len(brl) - 40} sites")
        else:
            print(f"    BLR no offset {off:#x}: —")


def cmd_blr(va: int, list_all: bool = False) -> None:
    """Resolve um site de dispatch virtual (BLR): slot-offset + vtables candidatas."""
    blr = _blr_scan()
    if list_all:
        print(f"# {len(blr)} BLR sites em .text; "
              f"{sum(1 for _,_,o in blr if o is not None)} com slot-offset resolvido")
        from collections import Counter
        c = Counter(o for _, _, o in blr if o is not None)
        for off, n in c.most_common(20):
            print(f"  offset {off:#x}: {n} sites")
        return
    hit = [x for x in blr if x[0] == va]
    if not hit:
        print(f"{va:#x} não é um site BLR em .text")
        sys.exit(1)
    site, reg, off = hit[0]
    _load_vt_registry()
    assert _VT_REGISTRY is not None
    print(f"# BLR @ {site:#x}  blr {reg}   {name_of(site)}")
    if off is None:
        print("# sem ldr self-referential na janela — não é vtable dispatch clássico "
              "(ou ponteiro de função)")
        return
    print(f"# slot-offset {off:#x}")
    # vtables curadas com um slot nesse offset
    cands = []
    for nm, ent in _VT_REGISTRY.items():
        vva = int(ent["va"], 16)
        m = _vtable_slots(vva, int(ent.get("slots", 0)))
        if any(s - vva == off for s, _ in m):
            cands.append((nm, vva))
    if cands:
        print(f"# {len(cands)} vtable(s) curada(s) com slot em {off:#x}:")
        for nm, vva in cands:
            ent = _VT_REGISTRY[nm]
            print(f"  {nm:<26} {vva:#x}  {ent.get('class','')[:48]}")
    else:
        print(f"# nenhuma vtable curada tem slot em {off:#x} "
              "(offset genérico compartilhado ou vtable não registrada)")


def cmd_reloc(va: int, n: int = 16, back: int = 0, reverse: bool = False) -> None:
    table, keys = _relocs()
    assert table is not None and keys is not None
    if reverse:
        needle = va - BASE
        hits = [(s, a) for s, a in table.items() if a == needle]
        if not hits:
            print(f"# nenhum slot de relocation recebe {va:#x} como addend "
                  f"({len(table)} slots indexados)")
            return
        for slot, _ in sorted(hits):
            print(f"  slot {BASE + slot:#x}  ← {fn_of(va)[1]} @ {va:#x}"
                  f"  <vizinho: {name_of(BASE + slot)}>")
        print(f"# {len(hits)} slots apontam p/ {va:#x} "
              f"(vtable membership; conferir rex adrp do slot)")
        return
    m = va - BASE
    i = bisect.bisect_left(keys, m - back * 8)
    if i >= len(keys):
        print(f"# sem relocations a partir de {va:#x}")
        return
    if m not in table:
        print(f"# AVISO: {va:#x} não é slot relocated — dumpando a partir do próximo")
    shown = 0
    while i < len(keys) and shown < n:
        slot = keys[i]
        a = table[slot]
        marker = " <<<" if slot == m else ""
        print(f"  [{shown:4d}] slot {BASE + slot:#x} = {BASE + a:#x}  {_reloc_label(a)}{marker}")
        i += 1
        shown += 1
    print(f"# {shown} relocations (R_AARCH64_RELATIVE) de {va:#x} em diante"
          f" — tabela total {len(table)} slots")


_NAMES: dict[str, str] | None = None   # nome curto -> VA (hex, sem 0x)
_NAMES_R: dict[str, str] | None = None # VA -> nome curto


def _load_names() -> None:
    """Carrega data/function-names.json (registry de nomes curtos)."""
    global _NAMES, _NAMES_R
    if _NAMES is not None:
        return
    _NAMES, _NAMES_R = {}, {}
    p = _root() / "data" / "function-names.json"
    if p.exists():
        d = json.loads(p.read_text(encoding="utf-8"))
        d.pop("_comment", None)
        for va, nm in d.items():
            _NAMES[nm] = va
            _NAMES_R[va] = nm


_GLOBALS: dict[str, dict] | None = None      # nome curto -> entrada
_GLOBALS_R: dict[str, str] | None = None     # va(hex) -> nome curto


def _load_globals() -> None:
    global _GLOBALS, _GLOBALS_R
    if _GLOBALS is not None:
        return
    _GLOBALS, _GLOBALS_R = {}, {}
    p = _root() / "data" / "globals.json"
    if p.exists():
        d = json.loads(p.read_text(encoding="utf-8"))
        d.pop("_comment", None)
        _GLOBALS = d
        for nm, ent in d.items():
            _GLOBALS_R[ent["va"]] = nm


_ENUMS: dict[str, dict] | None = None        # nome do enum -> def
_ENUM_VALS: dict[int, list[str]] | None = None  # valor -> ["enum.valor: desc", ...]


def _load_enums() -> None:
    global _ENUMS, _ENUM_VALS
    if _ENUMS is not None:
        return
    _ENUMS, _ENUM_VALS = {}, {}
    p = _root() / "data" / "enums.json"
    if p.exists():
        d = json.loads(p.read_text(encoding="utf-8"))
        d.pop("_comment", None)
        _ENUMS = d
        for ename, ent in d.items():
            for kind in ("values", "bits"):
                for val_s, desc in (ent.get(kind) or {}).items():
                    try:
                        v = int(val_s, 0)
                    except ValueError:
                        continue
                    tag = f"{ename}.{val_s}"
                    if kind == "bits":
                        tag += " (bit)"
                    _ENUM_VALS.setdefault(v, []).append(f"{tag}: {desc[:80]}")


def _parse_va(tok: str) -> int:
    """Aceita '0x7100181d04', '7100181d04', 'FUN_7100181d04', 'sub_7100181d04',
    nome curto dos registries (função 'CoinAdd', vtable 'vt_*', global 'KartHolder',
    enum 'state_byte.0x07')."""
    _load_names()
    _load_vt_registry()
    assert _NAMES is not None and _VT_REGISTRY is not None
    raw = tok.strip()
    t = raw.lower()
    if raw in _NAMES:                       # case-sensitive primeiro (CoinAdd)
        return int(_NAMES[raw], 16)
    if t in _NAMES:                         # fallback case-insensitive
        return int(_NAMES[t], 16)
    if t in _VT_REGISTRY:                   # nome de vtable (vt_*)
        return int(_VT_REGISTRY[t]["va"], 16)
    _load_ctors()
    assert _CTORS is not None
    if raw in _CTORS:                       # nome de ctor (ctor_*)
        return int(_CTORS[raw]["va"], 16)
    _load_globals()
    assert _GLOBALS is not None
    if raw in _GLOBALS:                     # nome de global (case-sensitive)
        return int(_GLOBALS[raw]["va"], 16)
    _load_enums()
    assert _ENUMS is not None and _ENUM_VALS is not None
    if "." in raw and raw.split(".", 1)[0] in _ENUMS:   # state_byte.0x07
        ename, val_s = raw.split(".", 1)
        try:
            return int(val_s, 0)
        except ValueError:
            pass
    if t.startswith("ptr_dat_") or t.startswith("dat_"):
        t = t[len("ptr_dat_"):] if t.startswith("ptr_dat_") else t[4:]
    for pre in ("fun_", "sub_", "thunk_fun_"):
        if t.startswith(pre):
            t = t[len(pre):]
            break
    t = t.lstrip("_")
    return int(t, 16)


def cmd_rodata(va: int, typ: str, n: int) -> None:
    _load()
    fo = va_to_file(va)
    if fo is None:
        print(f"VA {va:#x} fora dos segmentos do NSO")
        sys.exit(1)
    sizes = {"i8": 1, "u8": 1, "i16": 2, "u16": 2, "i32": 4, "u32": 4, "f32": 4,
             "i64": 8, "u64": 8, "f64": 8, "hex": 1}
    if typ not in sizes:
        print(f"tipo desconhecido: {typ} (use {'|'.join(sizes)})")
        sys.exit(2)
    sz = sizes[typ]
    d = _DATA
    assert d is not None
    print(f"# {va:#x} (file {fo:#x}) {typ}×{n}")
    if typ == "hex":
        print(d[fo:fo + n].hex(" "))
        return
    fmt = {"i8": "<b", "u8": "<B", "i16": "<h", "u16": "<H", "i32": "<i", "u32": "<I",
           "f32": "<f", "i64": "<q", "u64": "<Q", "f64": "<d"}[typ]
    for i in range(n):
        chunk = d[fo + i * sz: fo + (i + 1) * sz]
        if len(chunk) < sz:
            break
        v = struct.unpack(fmt, chunk)[0]
        extra = ""
        if typ == "u64" and v < 0x2000000:      # ponteiro NSO relativo (vtable/fn)
            tgt = BASE + v
            f = fn_of(tgt)
            extra = f"  → {f[1]}" if f and tgt == f[0] else (f"  → {f[1]}+{tgt - f[0]:#x}" if f else "")
        print(f"  [{i:3d}] {va + i * sz:#x}: {v}{extra}")


def cmd_str(va: int) -> None:
    _load()
    fo = va_to_file(va)
    if fo is None:
        print(f"VA {va:#x} fora dos segmentos")
        sys.exit(1)
    d = _DATA
    assert d is not None
    end = d.find(b"\x00", fo)
    s = d[fo:end]
    printable = all(32 <= b < 127 for b in s) if s else False
    print(f"{s.decode('ascii', 'replace')!r}  (len {len(s)}, printable={printable})")


def cmd_findstr(needle: str) -> None:
    """Busca reversa: todas as ocorrências da substring nos segmentos, com VA."""
    _load()
    d = _DATA
    assert d is not None
    raw = needle.encode().decode("unicode_escape").encode("latin-1")
    hits = 0
    start = 0
    while hits < 50:
        i = d.find(raw, start)
        if i < 0:
            break
        va = file_to_va(i)
        if va is None:
            start = i + 1
            continue
        nxt = d.find(b"\x00", i)
        s = d[i:nxt if nxt > 0 else i + 64]
        print(f"  {va:#x}  {s[:120].decode('ascii', 'replace')!r}")
        hits += 1
        start = i + 1
    print(f"# {hits} ocorrências de {raw!r}" + ("  (limite 50)" if hits == 50 else ""))


def file_to_va(fo: int) -> int | None:
    """File offset → VA (inverso de va_to_file)."""
    _load()
    d = _DATA
    assert d is not None
    for off in (0x10, 0x20, 0x30):
        f_off, m_off, sz = struct.unpack_from("<III", d, off)
        if f_off <= fo < f_off + sz:
            return BASE + m_off + (fo - f_off)
    return None


def _adrp_decode(w: int, pc: int) -> int | None:
    if (w & 0x9F000000) != 0x90000000:
        return None
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & 0x100000:
        imm -= 0x200000
    return (pc & ~0xFFF) + (imm << 12)


def cmd_adrp(target: int) -> None:
    _load()
    d = _DATA
    tm, tf, ts = struct.unpack_from("<III", d, 0x10)
    end = min(tf + ts, len(d)) & ~3
    hits = 0
    for i in range(end // 4 - 1):
        w = struct.unpack_from("<I", d, i * 4)[0]
        page = _adrp_decode(w, BASE + i * 4 - HDR)
        if page is None:
            continue
        w2 = struct.unpack_from("<I", d, i * 4 + 4)[0]
        # ADD imm: [x] 00100010 sh imm12 Rn Rd
        if (w2 & 0x7F800000) == 0x11000000 >> 0 or (w2 & 0xFF800000) == 0x91000000:
            imm12 = (w2 >> 10) & 0xFFF
            if page + imm12 == target:
                va = BASE + i * 4 - HDR
                print(f"  {va:#x}  adrp+add → {target:#x}  <{name_of(va)}>")
                hits += 1
        # LDR imm unsigned: 1111101001 imm12 Rn Rt (64-bit)
        if (w2 & 0xFFC00000) == 0xF9400000:
            imm12 = ((w2 >> 10) & 0xFFF) << 3
            if page + imm12 == target:
                va = BASE + i * 4 - HDR
                print(f"  {va:#x}  adrp+ldr → {target:#x}  <{name_of(va)}>")
                hits += 1
    print(f"# {hits} materializações de {target:#x}")


# ---------------------------------------------------------------- ptr / xref

def cmd_ptr(va: int) -> None:
    """Resolve um ponteiro em .data/.rodata: lê o qword no VA e identifica o alvo
    (função / vtable registrada / global / string). Cobre o workaround recorrente
    de `struct.unpack('<Q', d, m2f(va))` + decodificar BASE+val manualmente."""
    _load()
    assert _DATA is not None
    fo = va_to_file(va)
    if fo is None:
        print(f"VA {va:#x} fora dos segmentos do NSO")
        sys.exit(1)
    val = struct.unpack_from("<Q", _DATA, fo)[0]
    _load_globals()
    _load_names()
    _load_vt_registry()
    holder = (_GLOBALS_R or {}).get(f"{va:x}")
    print(f"# {holder or 'PTR_DAT_' + f'{va:x}'} @ {va:#x} = {val:#x}")
    if val >= 0x2000000:
        print(f"  (valor absoluto, não offset NSO — não é ponteiro relativo)")
        return
    tgt = BASE + val
    f = fn_of(tgt)
    if f and tgt == f[0]:
        short = (_NAMES_R or {}).get(f"{tgt:x}")
        print(f"  → {tgt:#x}  {short or f[1]}")
        return
    # vtable pode estar no próprio tgt OU +0x10 (padrão RTTI: holder aponta
    # 2 qwords antes dos slots; ctor instala `PTR_DAT + 0x10`)
    tbl, _ = _relocs()
    for cand, lbl in ((tgt, ""), (tgt + 0x10, "holder+0x10")):
        vtn = _vt_name_for_vtable(cand)
        if vtn:
            print(f"  → {cand:#x}  vtable {vtn}{('  (' + lbl + ')' if lbl else '')}")
            return
        slots = _vtable_slots(cand, 3)
        if slots:
            first = slots[0][0]
            tag = f"vtable (não registrada, {len(slots)}+ slots)"
            if lbl:
                tag += f"  (holder aponta {lbl})"
            print(f"  → {first:#x}  {tag}")
            return
    gn = (_GLOBALS_R or {}).get(f"{tgt:x}")
    if gn:
        print(f"  → {tgt:#x}  global {gn}")
        return
    sfo = va_to_file(tgt)
    if sfo is not None:
        end = _DATA.find(b"\x00", sfo)
        s = _DATA[sfo:end if end > 0 else sfo + 64]
        if s and all(32 <= b < 127 for b in s):
            print(f"  → {tgt:#x}  string {s.decode()!r}")
            return
    print(f"  → {tgt:#x}  (não identificado — conferir com rodata/dis)")


def cmd_xref(va: int, limit: int = 200) -> None:
    """Quem referencia um VA/global no corpus (decomp-full + asm-full, que têm os
    símbolos Ghidra DAT_/PTR_DAT_ e os hex crus). Mostra arquivo:linha + função
    contendo. Cobre o workaround de `grep -rn 'PTR_DAT_xxx' decomp-full/`."""
    _load_globals()
    _load_names()
    hexn = f"{va:x}"
    needles = [hexn, f"0x{hexn}"]
    gn = (_GLOBALS_R or {}).get(hexn)
    if gn:
        needles.append(gn)
    import glob as _g
    hdr = re.compile(r"^// (?:===== )?(\S+) @ [0-9a-f]+(?: =====)?$")
    hits = 0
    for corpus in ("decomp-full", "asm-full"):
        for fp in sorted(_g.glob(str(_root() / "data" / corpus / "shard-*.txt"))):
            cur = "?"
            with open(fp, errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    m = hdr.match(line.strip())
                    if m:
                        cur = m.group(1)
                        continue
                    if any(n in line for n in needles):
                        print(f"  {corpus}/{Path(fp).name}:{i} [{cur}] "
                              f"{line.strip()[:110]}")
                        hits += 1
                        if hits >= limit:
                            print(f"  ... (limite {limit})")
                            return
    if hits == 0:
        print(f"# nenhuma referência a {va:#x} no corpus")
        sys.exit(1)
    print(f"# {hits} referências a {va:#x}")


# ---------------------------------------------------------------- headers

_HEADERS: object = False   # False=não carregado, None=indisponível, HeadersDB=ok


def _load_headers() -> None:
    """HeadersDB dos headers .hpp — config REX_HEADERS (env > ~/.rexrc)."""
    global _HEADERS
    if _HEADERS is not False:
        return
    d = _cfg("REX_HEADERS", "")
    if not d or not Path(d).expanduser().exists():
        _HEADERS = None
        return
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from headers_parser import HeadersDB
        _HEADERS = HeadersDB(d)
    except Exception as e:
        print(f"# headers indisponíveis ({e})")
        _HEADERS = None


def cmd_headers(query: str) -> None:
    """`rex headers <offset>` — quem tem campo nesse offset (todas as structs);
    `rex headers <StructName>` — dump da struct (campos + offsets)."""
    _load_headers()
    if _HEADERS is None:
        sys.exit("ERRO: headers não encontrados — sete REX_HEADERS (dir include/)")
    db = _HEADERS
    if query.startswith(("0x", "+0x")) or query.lstrip("0x7100").isdigit() is False and re.fullmatch(r"[0-9a-fA-F]+", query):
        try:
            off = int(query, 16)
        except ValueError:
            off = None
        if off is not None:
            hits = db.owners_at(off)
            if not hits:
                print(f"# offset +{off:#x}: nenhum campo de header")
                sys.exit(1)
            for s, f in hits:
                print(f"  {s.name:32s} +{f.offset:#06x}  {f.type:24s} {f.name}")
            print(f"# {len(hits)} structs têm campo em +{off:#x} ({db.summary()})")
            return
    s = db.structs.get(query)
    if not s:
        near = [n for n in db.structs if query.lower() in n.lower()][:8]
        print(f"struct não achada: {query}" + (f" — parecidas: {', '.join(near)}" if near else ""))
        sys.exit(1)
    print(f"== {s.name}  ({Path(s.file).name}; {len(s.fields)} campos)")
    for f in s.fields:
        print(f"  +{f.offset:#06x}  {f.type:28s} {f.name}  {f.note[:50]}")


def cmd_fn_range(lo: int, hi: int) -> None:
    """Lista funções catalogadas com start em [lo, hi]."""
    _load()
    _load_names()
    assert _FUNCS is not None
    n = 0
    for a, nm in _FUNCS:
        if lo <= a <= hi:
            short = (_NAMES_R or {}).get(f"{a:x}")
            print(f"  {a:#x}  {short or nm}")
            n += 1
    print(f"# {n} funções em [{lo:#x}, {hi:#x}]")


# ------------------------------------------------------------- shards (geração)

def cmd_shards(target: str = "all", force: bool = False) -> None:
    """Gera o corpus (shards) via Ghidra headless — a receita inteira.

    Passos:
      1. limpa o cache OSGi (ClassNotFoundException em script modificado)
      2. compila os geradores ($REX_DUMPERS/*.java) com o classpath do Ghidra
      3. instala .java+.class em Extensions/SwitchLoader/ghidra_scripts do
         usuário — o único local onde o OSGi resolve o bundle destes scripts
         (builtin e ~/ghidra_scripts dão ClassNotFoundException; os dumps
         históricos sempre rodaram daqui)
      4. roda analyzeHeadless -noanalysis -postScript (cwd NEUTRO = /tmp) e
         FALHA o exit se houver SCRIPT ERROR no log (o exit do headless mente)
         - decomp: FullDecompDump (~6 min, RESUME via functions.tsv)
         - asm:    FullAsmDump    (~100 s)
    Saída em $REX_ROOT/data/{decomp,asm}-full/ (default = mk8dx-re).

    `target`: all | decomp | asm. `force`: ignora outputs existentes
    (decomp tem RESUME — sem force, só completa faltantes).

    Config (env > ~/.rexrc; ver rexconfig.py): REX_ROOT, REX_DUMPERS
    (default $REX_ROOT/dumpers), REX_GHIDRA_PROJ (default
    $REX_ROOT/ghidra-project), REX_GPR (default MK8DX.gpr), REX_PROGRAM
    (default uncompressed_main), GHIDRA_HOME.
    """
    import glob as _glob
    import shutil
    import subprocess

    home = Path(__file__).resolve().parent
    # dumpers: config explícita é LEI (se setada e inválida → erro, sem fallback
    # silencioso); default = $REX_ROOT/dumpers
    dumpers_env = _cfg("REX_DUMPERS", "")
    if dumpers_env:
        gens = Path(dumpers_env).expanduser()
        if not (gens / "FullDecompDump.java").exists():
            sys.exit(f"ERRO: REX_DUMPERS={gens} não tem FullDecompDump.java")
    else:
        gens = _root() / "dumpers"
        if not (gens / "FullDecompDump.java").exists():
            sys.exit("ERRO: dumpers/ não achado em $REX_ROOT — sete REX_DUMPERS "
                     "(dir com FullDecompDump.java).")

    # defaults do ambiente local (Ghidra via Homebrew)
    ghidra_cand = [
        os.environ.get("GHIDRA_HOME", ""),
        "/opt/homebrew/Cellar/ghidra/12.1.2/libexec",
        "/opt/homebrew/opt/ghidra/libexec",
    ]
    ghidra = next((Path(p) for p in ghidra_cand if p and Path(p).exists()), None)
    if ghidra is None:
        sys.exit("ERRO: Ghidra não achado — sete GHIDRA_HOME (ex.: /opt/homebrew/Cellar/ghidra/12.1.2/libexec)")
    # projeto Ghidra: default = $REX_ROOT/ghidra-project; env separado p/
    # override (ex.: REX_ROOT scratch + projeto existente do repo principal)
    gpr = _cfg("REX_GPR", "MK8DX.gpr")
    proj_env = _cfg("REX_GHIDRA_PROJ", "")
    if proj_env:
        proj = Path(proj_env).expanduser()
        if not (proj / gpr).exists():
            sys.exit(f"ERRO: REX_GHIDRA_PROJ={proj} não tem {gpr}")
    else:
        proj = _root() / "ghidra-project"
        if not (proj / gpr).exists():
            sys.exit(f"ERRO: projeto Ghidra não achado — sete REX_GHIDRA_PROJ "
                     f"(dir com {gpr}; default = $REX_ROOT/ghidra-project).")
    builtin = ghidra / "Ghidra" / "Features" / "Decompiler" / "ghidra_scripts"
    if not builtin.is_dir():
        sys.exit(f"ERRO: dir built-in não existe: {builtin}")

    def _osgiclear(cls: str) -> None:
        # cache OSGi (ClassNotFoundException em script modificado)
        base = Path.home() / "Library" / "ghidra"
        n = 0
        for ver in sorted(base.glob("ghidra_*")) if base.is_dir() else []:
            osgi = ver / "osgi"
            if osgi.is_dir():
                for item in osgi.iterdir():
                    try:
                        shutil.rmtree(item) if item.is_dir() else item.unlink()
                        n += 1
                    except OSError as e:
                        print(f"  SKIP {item.name}: {e}")
        print(f"# cache OSGi limpo ({n} itens)")

    def _run_dump(cls: str, outdir: Path, resume_ok: bool) -> None:
        src = gens / f"{cls}.java"
        if not src.exists():
            sys.exit(f"ERRO: gerador não encontrado: {src}")
        tsv = outdir / "functions.tsv"
        if resume_ok and tsv.exists() and not force:
            print(f"# {cls}: RESUME — functions.tsv existe; completando faltantes")
        print(f"== {cls} → {outdir}")
        # 1. fantasmas + cache OSGi
        _osgiclear(cls)
        # 2. compilar (classpath = todos os JARs do Ghidra)
        build = Path(tempfile.mkdtemp(prefix="rex_shards_"))
        jars = ":".join(sorted(str(p) for p in ghidra.rglob("*.jar")))
        r = subprocess.run(
            ["javac", "-d", str(build), "-proc:none", "-cp", jars, str(src)],
            capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"ERRO javac {cls}:\n{r.stdout}{r.stderr}")
        # 3. instalar em Extensions/SwitchLoader/ghidra_scripts do usuário — o
        #    ÚNICO local onde o OSGi resolve bundle p/ estes scripts neste setup
        #    (builtin e ~/ghidra_scripts → ClassNotFoundException; os dumps
        #    históricos rodaram daqui). Sobrescrever com versão fresca elimina
        #    o risco de cópia velha com path hardcoded.
        ext_dirs = sorted((Path.home() / "Library" / "ghidra").glob(
            "ghidra_*/Extensions/SwitchLoader/ghidra_scripts"))
        if not ext_dirs:
            sys.exit("ERRO: ~/Library/ghidra/ghidra_*/Extensions/SwitchLoader/"
                     "ghidra_scripts não existe — instale a ext SwitchLoader ou "
                     "crie o dir.")
        ext = ext_dirs[-1]
        shutil.copy(src, ext / src.name)
        shutil.copy(build / f"{cls}.class", ext / f"{cls}.class")
        # 4. headless com cwd NEUTRO (OSGi acha o .java do cwd em vez do par compilado)
        program = _cfg("REX_PROGRAM", "uncompressed_main")
        cmd = [str(ghidra / "support" / "analyzeHeadless"), str(proj),
               gpr.removesuffix(".gpr"),
               "-process", program, "-noanalysis",
               "-postScript", cls]
        # injeta config resolvida no env do subprocess (o Java não lê ~/.rexrc)
        sub_env = dict(os.environ)
        sub_env["REX_ROOT"] = str(_root())
        print(f"# {' '.join(cmd)}  (cwd=/tmp)")
        proc = subprocess.run(cmd, cwd="/tmp", capture_output=True, text=True,
                              env=sub_env)
        out = (proc.stdout or "") + (proc.stderr or "")
        for line in out.splitlines():
            if "ERROR" in line or "progresso" in line or "TOTAL" in line:
                print(f"  {line.strip()[:160]}")
        if proc.returncode != 0 or "SCRIPT ERROR" in out:
            sys.exit(f"ERRO: analyzeHeadless {cls} falhou "
                     f"(exit {proc.returncode}; SCRIPT ERROR no log)")
        shutil.rmtree(build, ignore_errors=True)
        # saída do dump de progresso do Ghidra fica em ROOT/data/*/progress.log

    import tempfile
    if target in ("all", "decomp"):
        _run_dump("FullDecompDump", _root() / "data" / "decomp-full", resume_ok=True)
    if target in ("all", "asm"):
        _run_dump("FullAsmDump", _root() / "data" / "asm-full", resume_ok=False)


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return
    cmd, rest = args[0], args[1:]
    try:
        if cmd == "fn":
            if rest and rest[0] == "-r":
                lo, hi = _parse_range(rest[1])
                cmd_fn_range(lo, hi)
            else:
                cmd_fn(_parse_va(rest[0]))
        elif cmd == "callers":
            cmd_callers(_parse_va(rest[0]))
        elif cmd == "ptr":
            cmd_ptr(_parse_va(rest[0]))
        elif cmd == "xref":
            cmd_xref(_parse_va(rest[0]))
        elif cmd == "dis":
            n = 24
            vas = []
            it = iter(rest)
            for x in it:
                if x == "-n":
                    n = int(next(it))
                else:
                    vas.append(_parse_va(x))
            if len(vas) == 2:
                if vas[1] < vas[0]:
                    raise ValueError("va2 < va1 no range")
                cnt = max(1, (vas[1] - vas[0]) // 4 + 1)
                cmd_dis(vas[0], cnt)
            elif len(vas) == 1:
                cmd_dis(vas[0], n)
            else:
                raise IndexError("dis requer um VA (ou dois, para range)")
        elif cmd == "body":
            a = "-a" in rest
            cmd_body(_parse_va(rest[0]), a)
        elif cmd == "ann":
            cmd_ann(_parse_va(rest[0]))
        elif cmd == "ctor":
            la = "-l" in rest
            rest2 = [x for x in rest if not x.startswith("-")]
            cmd_ctor(_parse_va(rest2[0]) if rest2 else 0, list_all=la)
        elif cmd == "vtable":
            if rest and rest[0] == "-l":
                cmd_vtable(0, list_all=True)
            else:
                j = "-j" in rest
                n = 0
                if "-n" in rest:
                    n = int(rest[rest.index("-n") + 1])
                rest2 = [x for x in rest if x not in ("-j", "-n") and x != str(n)]
                cmd_vtable(_parse_va(rest2[0]), j, n)
        elif cmd == "vtable-callers":
            if not rest:
                raise IndexError("vtable-callers requer um VA ou nome de vtable")
            cmd_vtable_callers(_parse_va(rest[0]))
        elif cmd == "blr":
            if rest and rest[0] == "-l":
                cmd_blr(0, list_all=True)
            elif rest:
                cmd_blr(_parse_va(rest[0]))
            else:
                raise IndexError("blr requer um site VA (ou -l para o resumo global)")
        elif cmd == "offset":
            load = "-l" in rest             # -l = loads; default/-w = stores (writes)
            rest = [x for x in rest if x not in ("-w", "-l")]
            msub = None
            rng = None
            vals = []
            it = iter(rest)
            for x in it:
                if x == "-m":
                    msub = next(it)
                elif x == "-r":
                    rng = _parse_range(next(it))
                else:
                    vals.append(x)
            if not vals:
                raise IndexError("offset requer um imm")
            cmd_offset(int(vals[0], 0), load, msub, rng)
        elif cmd == "bit":
            if len(rest) < 2:
                raise IndexError("bit requer <off> <bit>")
            rng = None
            br = [x for x in rest if x != "-r"]
            if len(br) != len(rest):
                rng = _parse_range(rest[rest.index("-r") + 1])
            cmd_bit(int(br[0], 0), int(br[1], 0), rng)
        elif cmd == "reloc":
            n = 16
            back = 0
            reverse = False
            v = None
            it = iter(rest)
            for x in it:
                if x == "-n":
                    n = int(next(it))
                elif x == "-b":
                    back = int(next(it))
                elif x == "-a":
                    reverse = True
                else:
                    v = _parse_va(x)
            if v is None:
                raise IndexError("reloc requer um VA")
            cmd_reloc(v, n, back, reverse)
        elif cmd == "rodata":
            typ = "i32"
            n = 16
            v = None
            it = iter(rest)
            for x in it:
                if x == "-t":
                    typ = next(it)
                elif x == "-n":
                    n = int(next(it))
                else:
                    v = _parse_va(x)
            if v is None:
                raise IndexError("rodata requer um VA")
            cmd_rodata(v, typ, n)
        elif cmd == "str":
            if rest and rest[0] == "-f":
                cmd_findstr(rest[1])
            else:
                cmd_str(_parse_va(rest[0]))
        elif cmd == "adrp":
            cmd_adrp(_parse_va(rest[0]))
        elif cmd == "headers":
            if not rest:
                raise ValueError("uso: rex headers <offset|StructName>")
            cmd_headers(rest[0])
        elif cmd == "shards":
            target = "all"
            force = False
            for a in rest:
                if a in ("all", "decomp", "asm"):
                    target = a
                elif a == "--force":
                    force = True
                else:
                    raise ValueError(f"uso: rex shards [all|decomp|asm] [--force]")
            cmd_shards(target, force)
        else:
            print(f"comando desconhecido: {cmd}")
            print(__doc__)
            sys.exit(2)
    except (ValueError, IndexError) as e:
        print(f"erro de uso: {e}\n{__doc__}")
        sys.exit(2)


if __name__ == "__main__":
    main()
