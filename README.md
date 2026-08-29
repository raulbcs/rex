# rex — faca suíça de RE (Switch/NSO)

Ferramenta standalone de análise estática: binário cru + corpus Ghidra +
headers C++. Vive fora dos projetos; **nenhum path de projeto no código** —
tudo configurável via **env > `~/.rexrc`** (ver `rexconfig.py`).

## Arquivos daqui

| arquivo | papel |
|---|---|
| `rex.py` | CLI: fn/callers/body/ann/offset/vtable/reloc/xref/... + `shards` (gera corpus) + `headers` |
| `shard_resolve.py` | resolve função→shard e carrega corpos (decomp/asm) |
| `rexconfig.py` | config: env > ~/.rexrc (REX_ROOT, REX_HEADERS, ...) |
| `headers_parser.py` | parser dos `.hpp` (structs + offsets dos comentários) |
| `dumpers/FullDecompDump.java` | dump decomp de TODAS as funções |
| `dumpers/FullAsmDump.java` | dump asm completo |

## Configuração (obrigatória: REX_ROOT)

`~/.rexrc` (ou envs — env ganha):

```
REX_ROOT=/caminho/do/alvo/03-analysis
REX_HEADERS=/caminho/dos/headers/include     # opcional (rex headers / badge ann)
```

Chaves (defaults sensatos em `rexconfig.py`): `REX_ROOT` (obrigatório),
`REX_DUMPERS` (default `$REX_ROOT/dumpers`), `REX_GHIDRA_PROJ` (default
`$REX_ROOT/ghidra-project`), `REX_GPR` (default `MK8DX.gpr`),
`REX_PROGRAM` (default `uncompressed_main`),
`REX_BIN` (default `main-binary/uncompressed_main`),
`REX_BASE` (default `0x7100000000`), `GHIDRA_HOME`.

Config explícita é **lei**: setada e inválida → erro imediato (sem fallback
silencioso). Sem `REX_ROOT` → erro claro ensinando a configurar.

## Passo a passo (projeto novo)

### 0. Ferramentas necessárias

- **uv** (Python) — tudo roda via `uv run python`
- **Ghidra 12.1.2** (Homebrew: `/opt/homebrew/Cellar/ghidra/12.1.2/libexec`; ou `GHIDRA_HOME`)
- **javac 21+** (compilar os dumpers)
- **projeto Ghidra** com o binário importado e analisado
  (NSO decomprimido; import uma vez pela GUI/headless)

### 1. Layout do alvo (`$REX_ROOT`)

```
<alvo>/                       ← REX_ROOT (qualquer dir serve)
  main-binary/uncompressed_main    binário cru (REX_BIN)
  ghidra-project/MK8DX.gpr         projeto Ghidra (REX_GHIDRA_PROJ/REX_GPR)
  dumpers/*.java                   FullDecompDump/FullAsmDump (REX_DUMPERS)
  data/decomp-full/                ← gerado pelo rex shards
  data/asm-full/                   ← gerado pelo rex shards
  data/function-names.json         opcional: nomes curtos (ann/callers)
  data/globals.json                opcional: DAT_ → nome
  data/enums.json                  opcional: valores de enum
  notes/MEMORY-MAP.md              opcional: offsets com dono (ann)
```

### 2. Gerar o corpus (os shards)

```bash
uv run python ~/projects/rex/rex.py shards          # decomp (~6min) + asm (~100s)
uv run python ~/projects/rex/rex.py shards asm      # só um dos dois
uv run python ~/projects/rex/rex.py shards --force  # regen total (ignora resume)
```

O que ele faz: limpa cache OSGi → compila os dumpers com o classpath do
Ghidra → instala o par `.java`+`.class` em
`~/Library/ghidra/ghidra_*/Extensions/SwitchLoader/ghidra_scripts/`
(**único local onde o OSGi resolve bundle** — builtin e `~/ghidra_scripts`
dão `ClassNotFoundException`) → `analyzeHeadless -noanalysis -postScript`
com cwd neutro → **falha se houver SCRIPT ERROR** (o exit do headless mente).
O subprocess recebe `REX_ROOT` resolvido no env (o Java não lê `~/.rexrc`).

Saída: `data/{decomp,asm}-full/shard-NNN.txt` (500 funcs/shard) +
`functions.tsv` (numeração idêntica entre os dois corpus — requisito do
`shard_resolve`).

### 3. Integrar os headers (opcional)

```bash
# REX_HEADERS no ~/.rexrc ou env
rex headers 0x1e4        # todas as structs com campo nesse offset
rex headers KartVehicle  # dump da struct
rex ann <va>             # agora mostra badge hdr:Struct.field
```

Parser: `class/struct X { tipo campo; //0xNN ... }` — offset explícito no
comentário. Enums/métodos/statics ignorados.

### 4. Análise (leitura)

```bash
rex fn 0x7100176474              # qual função contém o VA
rex body 0x7100174778 [-a]       # corpo decomp (ou asm)
rex ann 0x7100174778             # decomp anotado (MEMORY-MAP + registries + headers)
rex callers DriftCalc            # BL callers (com bounds-check)
rex offset 0x1e4 -w              # quem escreve nesse offset de struct
rex vtable 0x71011b4ec0          # dump de vtable via relocations
rex reloc -a 0x710013ce18        # em quais vtables a função é método
rex xref RaceInfo                # quem referencia (corpus inteiro)
```

Registries opcionais (`data/*.json`) enriquecem `ann`/`callers`; sem eles o
rex funciona do mesmo jeito (só sem nomes).

## mk8dx-re (repo principal)

O repo tem um **shim** em `03-analysis/scripts/rex.py` que seta
`REX_ROOT` = o próprio repo e carrega o módulo daqui — `import rex` (regen
pipeline) e a CLI por path continuam funcionando sem config nenhuma.

## Gotchas (aprendidos na prática)

- **OSGi/Extensions**: scripts Java novos só rodam instalados em
  `Extensions/SwitchLoader/ghidra_scripts/` do usuário; cópia velha com path
  hardcoded aí desvia o dump pro lugar errado — o rex sempre sobrescreve fresco.
- **exit do analyzeHeadless é 0 mesmo com SCRIPT ERROR** — o rex captura o
  log e falha de verdade.
- **cwd do headless deve ser neutro** (`/tmp`) — OSGi acha o `.java` do cwd
  em vez do par compilado → `ClassNotFoundException`.
- `rex callers` = 0 não significa órfã: pode ser tail-call `b` (refazer com
  scan BL bruto no corpus asm).
