# rop🌲

rop3 is a tool developed in [Python](https://www.python.org/downloads/) and it relies on the [Capstone](https://www.capstone-engine.org/) disassembly framework to search for gadgets, operations, and ROP chains using a backtracking algorithm in a tree-like structure:

![Backtracking algorithm to find a ROP chain](https://drive.google.com/uc?export=view&id=166Vbc9vkXEsMN81cdpjD4yOCuVw5jvVw) 

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Features

- **Multi-format, multi-arch**: analyzes ELF, PE and Mach-O binaries across **x86, x86-64, AArch64 (ARM64) and RISC-V (RV64, including the compressed RVC extension)**. Architecture is detected from the binary; for fat/universal Mach-O binaries, `--arch` selects the slice to analyze.
- **Gadget search**: ROP, JOP and RETF gadgets, with controls for search depth (`--depth`, architecture-specific by default), `ret <imm>`/`retf <imm>` terminators (`--ret-imm`, off by default), undeterministic gadgets (`--allow-undeterministic-gadgets`) and complex memory operands (`--allow-complex-memory-ops`).
- **Framed gadget search** (`--frame`/`--no-frame`): on AArch64 and RISC-V, where the return address lives in a register, framed search (on by default) keeps only gadgets that restore it from the stack — the ones actually reachable in a ROP chain. It has no effect on x86, where `ret` already consumes the stack.
- **Abstract-gadget search** (`--ropblock`): treats a gadget as *any run whose tail writes the program counter with a stack-derived value*, not just `ret`. It finds register returns such as `pop rax ; … ; jmp rax` (x86) and `ldr x9,[sp] ; … ; br x9` (AArch64), accepting them only when the branch register is loaded from the stack and not clobbered before the branch (x86 `ret` is the degenerate case). Applies to all architectures and runs single-threaded.
- **Operations and ROP chains**: search for high-level operations with `--op` and **positional, n-ary operands** (`--operands op1 op2 op3`), and build ROP chains from a ROPLang file (`--ropchain`, `--exhaustive`), including multi-step composite operations. `--keep-contradictory` disables the filtering of gadgets whose destination is overwritten before the terminator; `--reg-aliases` lets sub-registers (`al`, `ax`, `eax`) stand in for their full register.
- **Relocation**: rebase any binary (ELF/PE/Mach-O) with `--base`, one address per binary.
- **Bad-char filtering**: avoid bytes in the gadget address (`--badchar`) and/or in the gadget opcode bytes (`--badchar-bytes`). By default, duplicate gadgets prefer canary-free addresses (`0x00`, `0x0a`, `0x0d`, `0xff`); disable with `--keep-canary-address`.
- **Symbol annotation**: with `--symbols`, each gadget is tagged with the nearest symbol (`name+offset`) when the binary is not stripped.
- **Output formats**: human-readable text (default), machine-readable `--output json`/`--output csv` for scripting, or `--tuple` for a compact `<op, operands, written regs, read regs>` line per gadget. Colors are emitted only on a TTY. With `--verbose`, rop3 also prints a per-binary summary (format, architecture, bit width, instruction alignment and executable sections).
- **Interactive mode**: `--interactive` scans the binary once and drops into a REPL to explore gadgets, operations and chains without re-scanning.
- **Performance**: parallel scanning across processes (`--jobs N`) and an optional on-disk gadget cache (`--cache`) for repeated runs over the same file.
- **Library API**: use rop3 programmatically through the `Rop3` class (see [Use as a library](#use-as-a-library)).

## Supported architectures and formats

| Architecture | ELF | PE | Mach-O | Notes |
| --- | :---: | :---: | :---: | --- |
| x86 (i386)   | ✓ | ✓ | ✓ | |
| x86-64       | ✓ | ✓ | ✓ | |
| AArch64      | ✓ | ✓ | ✓ | 4-byte instruction alignment; framed search on by default |
| RISC-V (RV64)| ✓ |   |   | 4-byte alignment, or 2-byte with the compressed (RVC) extension; framed search on by default |

Format is detected by magic bytes and the architecture from the binary's own headers. RISC-V is 64-bit only (RV32 is rejected). The high-level operations are defined per architecture, so some operations are unavailable on some targets — for example, the carry-flag operations (`eqc`, `ltc`, `gcf-eqc`, `gcf-ltc`) are not available on RISC-V, which has no condition/carry flags.

## Installation

We recommend to install rop3's dependencies with [pip](https://pypi.org/project/pip/) in a virtual environment to not to mess up with your current configuration:

```Shell
$ sudo apt update
$ sudo apt install python3-pip python3-venv
```

Create and activate your virtual environment:

```Shell
$ python3 -m venv .
$ source bin/activate
(venv) $ git clone https://github.com/reverseame/rop3.git
(venv) $ cd rop3
```

Now, you can install dependencies in [requirements.txt](requirements.txt):

```Shell
(venv) rop3 $ python3 -m pip install -r requirements.txt
```

## Usage

```Shell
$ python rop3.py --binary /bin/ls                       # dump gadgets
$ python rop3.py --binary /bin/ls --op mov --operands rdi rax
$ python rop3.py --binary libaarch64.so --op mov --operands x0 x1
$ python rop3.py --binary libc.so.6 --ropchain chain.txt
$ python rop3.py --binary /bin/ls --interactive         # REPL, scans once
```

```
usage: rop3.py [-h] [-v] [--depth <bytes>] [--all] [--rop | --no-rop]
               [--retf | --no-retf] [--ret-imm | --no-ret-imm]
               [--jop | --no-jop] [--frame | --no-frame] [--ropblock]
               [--reg-aliases]
               [--allow-undeterministic-gadgets] [--allow-complex-memory-ops]
               [--keep-contradictory] [--verbose]
               [--binary <file> [<file> ...]] [--badchar <hex> [<hex> ...]]
               [--badchar-bytes <hex> [<hex> ...]] [--keep-canary-address]
               [--base <hex> [<hex> ...]] [--arch <name>] [--symbols]
               [--output {text,json,csv}] [--tuple] [--op <op>]
               [--operands <reg> [<reg> ...]] [--ropchain <file>]
               [--exhaustive | --no-exhaustive] [--interactive] [--jobs <n>]
               [--cache] [--cache-dir <dir>]

This tool allows you to search for gadgets, operations, and ROP chains using a
backtracking algorithm in a tree-like structure

options:
  -h, --help            show this help message and exit
  -v, --version         display rop3.py's version and exit
  --depth <bytes>       maximum gadget length in bytes (default: architecture-specific)
  --all                 show the same gadget in different addresses
  --rop, --no-rop       search for ROP gadgets
  --retf, --no-retf     search for RETF gadgets
  --ret-imm, --no-ret-imm
                        include gadgets ending in a `ret <imm>` / `retf <imm>` (disabled by default)
  --jop, --no-jop       search for JOP gadgets
  --frame, --no-frame   framed gadget search (default on): on AArch64/RISC-V keep only gadgets that restore the return address from the stack; no effect on x86
  --ropblock            abstract-gadget search: find gadgets whose tail branches through a register loaded from the stack and not clobbered (e.g. `pop rax ; ... ; jmp rax`, `ldr x9,[sp] ; ... ; br x9`), x86 `ret` being the degenerate case; runs single-threaded
  --reg-aliases         allow sub-register aliases (al, ax, eax, ...) to substitute their full register when matching operations; they are then treated as the same register for chain assignment and side effects
  --allow-undeterministic-gadgets
                        allow gadgets with conditional branches (e.g. jne) as intermediate instructions
  --allow-complex-memory-ops
                        allow gadgets whose first instruction uses complex memory addressing (e.g. [r1*r2], [r1+r2*s+disp])
  --keep-contradictory  keep 'contradictory' operation gadgets whose destination register is overwritten before the ret (e.g. `add rax, rbx ; mov rax, rcx ; ret`); by default these are filtered out of --op results
  --verbose             show progress information (gadget counts, combinations)
  --binary <file> [<file> ...]
                        specify a list of binary path files to analyze
  --badchar <hex> [<hex> ...]
                        specify a list of chars to avoid in gadget address
  --badchar-bytes <hex> [<hex> ...]
                        specify a list of chars to avoid in gadget opcode bytes
  --keep-canary-address
                        do not prefer canary-free addresses (0x00, 0x0a, 0x0d, 0xff) when discarding duplicate gadgets
  --base <hex> [<hex> ...]
                        specify a base address to relocate binary files (it may take a while). When you specify more than one base address, you need to provide one address for each binary
  --arch <name>         select the architecture slice of a fat Mach-O binary (e.g. x86_64, i386)
  --symbols             annotate gadgets with the nearest symbol (when the binary is not stripped)
  --output {text,json,csv}
                        output format (default: text)
  --tuple               print each gadget as the tuple <op_name, op1[, op2], written registers, read registers> (overrides --output text)
  --op <op>             search for operation
  --operands <reg> [<reg> ...]
                        operation operands, positionally (op1 op2 op3 ...); e.g. --op mov --operands rdi rax
  --ropchain <file>     plain text file with a ROP chain
  --exhaustive, --no-exhaustive
                        exhaustive search for ROP chains
  --interactive         scan the binary once and drop into an interactive prompt
  --jobs <n>            number of worker processes for the gadget scan (default: 1)
  --cache               cache discovered gadgets on disk and reuse them on repeated runs over the same file and options
  --cache-dir <dir>     directory for the gadget cache (default: $XDG_CACHE_HOME/rop3)
```

### Parallel scan

`--jobs N` distributes the gadget scan over `N` worker processes. Each executable section is split into chunks scanned independently, then the results are merged and deduplicated, so the output is identical to a serial run. The speedup is sublinear (the merge, deduplication and sort run in the parent, and there is per-process start-up cost), so it is worth it mainly for large binaries and/or a high `--depth`; on small inputs the process overhead dominates and `--jobs 1` (the default) is faster. Framed architectures (AArch64/RISC-V) scan serially regardless of `--jobs`.

### Gadget cache

With `--cache`, the gadgets discovered for a binary are stored on disk and reused on later runs over the same file and options, skipping the scan. The cache key binds the file content hash and every option that affects the result, so a changed binary or option misses cleanly. This is especially handy for large binaries and for the interactive mode.

```Shell
$ python rop3.py --binary libc.so.6 --cache        # first run scans and caches
$ python rop3.py --binary libc.so.6 --cache --op mov --operands rdi rax   # reuses the cache
```

### ROP chain files

A `--ropchain` file is a plain-text list of steps, one per line; `;` starts a comment. Each step is either a high-level ROPLang operation with positional operands, or an **explicit (raw) gadget** matched exactly as written:

```
; high-level operations (resolved against the ROPLang catalog)
mov(rdi, rax)
lc(rsi)

; explicit, architecture-specific gadgets:  raw([mnemonics], [operands], [dst], [src])
raw([pop, ret], [rdi], [rdi], [])              ; pop rdi ; ret
raw([mov, ret], [[rdi], rax], [rdi], [rax])    ; mov [rdi], rax ; ret   (store)
raw([syscall], [], [], [rax, rdi])             ; syscall
```

A raw gadget lists its instruction mnemonics, their operands, and the concrete registers it writes (`dst`) and reads (`src`) — the last two feed the assembler's side-effect tracking, so a raw gadget composes with the rest of the chain like any operation. It is matched verbatim (a memory operand is written `[reg]`), so raw gadgets are architecture specific and are not translated across architectures. By default every operand belongs to the first instruction; to spread operands over several instructions, wrap each instruction's operands in parentheses:

```
raw([pop, pop, ret], [(rdi), (rsi)], [rdi, rsi], [])   ; pop rdi ; pop rsi ; ret
```

### Interactive mode

With `--interactive`, rop3 scans the binary once and drops into a prompt so you can explore its gadgets without re-scanning on every query:

```Shell
$ python rop3.py --binary /bin/ls --interactive
Loaded 71 gadgets from /bin/ls
rop3> count
71
rop3> search pop rbp
[ls @ 0x100000777]: pop rbp ; ret (x29)
...
rop3> op mov rdi rax
rop3> chain chain.txt
rop3> quit
```

Commands: `gadgets`/`search [substring]`, `count`, `op <name> [operands...]`, `chain <file>`, `help`, `quit`.

### Use as a library

rop3 can also be used programmatically through the `Rop3` class. Gadgets are scanned once and cached on the instance:

```python
from rop3 import Rop3

r = Rop3("libc.so.6", base="0x7f0000000000", symbols=True)
for gadget in r.gadgets():
    print(gadget)

r.find_op("mov", operands=["rdi", "rax"])   # list of matching gadgets
r.ropchain("chain.txt")                      # iterator over ROP chains

for info in r.describe():                    # per-binary summary (arch, bits, sections, ...)
    print(info)
```

In the work that we presented in [15th IEEE Workshop on Offensive Technologies (WOOT21)](https://www.ieee-security.org/TC/SP2021/SPW2021/WOOT21/), we used rop3 to evaluate the executional power of Return Oriented Programming in a [subset of most common Windows DLLs](https://drive.google.com/file/d/1gOxUolzrw-xlaW6K-fhzZ7Z-sqxiaZeZ/view?usp=sharing>). Check the [paper](https://drive.google.com/file/d/1Pe7s7bLhJ_20MC-duQ7YiLP-Rx5VCjFK/view?usp=sharing) for further details.

```Shell
$ python rop3.py --binary ../tfg_inf/experiments/dlls/win10x86/SHELL32.dll --op mov --operands eax ecx
[SHELL32.dll @ 0x698a474c]: mov eax, ecx ; ret (x97)
[SHELL32.dll @ 0x698dc8c8]: mov eax, ecx ; pop ebx ; leave ; ret (x5) (modifies rbx, rbp)
[SHELL32.dll @ 0x6991a2b1]: mov eax, ecx ; pop ebx ; ret (x4) (modifies rbx)
[SHELL32.dll @ 0x6992d289]: mov eax, ecx ; pop esi ; ret (x11) (modifies rsi)
[SHELL32.dll @ 0x6995e30b]: mov eax, ecx ; pop edi ; ret (x2) (modifies rdi)
[SHELL32.dll @ 0x699670c1]: mov eax, ecx ; pop esi ; pop ebp ; ret (x1) (modifies rsi, rbp)
[SHELL32.dll @ 0x69b8a61b]: mov eax, ecx ; leave ; ret (x1) (modifies rbp)
[SHELL32.dll @ 0x69c3c483]: mov eax, ecx ; pop esi ; leave ; ret (x1) (modifies rsi, rbp)
# ...
```

## License

Licensed under the [GNU GPLv3](LICENSE) license.
