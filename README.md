# rop🌲

rop3 is a tool developed in [Python](https://www.python.org/downloads/) and it relies on the [Capstone](https://www.capstone-engine.org/) disassembly framework to search for gadgets, operations, and ROP chains using a backtracking algorithm in a tree-like structure:

![Backtracking algorithm to find a ROP chain](https://drive.google.com/uc?export=view&id=166Vbc9vkXEsMN81cdpjD4yOCuVw5jvVw) 

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

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

```
usage: rop3.py [-h] [-v] [--depth <bytes>] [--all] [--rop | --no-rop] [--retf | --no-retf] [--jop | --no-jop] [--allow-undeterministic-gadgets] [--allow-complex-memory-ops] [--verbose]
               [--binary <file> [<file> ...]] [--badchar <hex> [<hex> ...]] [--badchar-bytes <hex> [<hex> ...]] [--keep-canary-address] [--base <hex> [<hex> ...]] [--arch <name>] [--symbols]
               [--output {text,json,csv}] [--op <op>] [--dst <reg>] [--src <reg>] [--ropchain <file>] [--exhaustive | --no-exhaustive] [--interactive] [--jobs <n>] [--cache] [--cache-dir <dir>]

This tool allows you to search for gadgets, operations, and ROP chains using a backtracking algorithm in a tree-like structure

options:
  -h, --help            show this help message and exit
  -v, --version         display rop3.py's version and exit
  --depth <bytes>       depth for search engine (default to 5 bytes)
  --all                 show the same gadget in different addresses
  --rop, --no-rop       search for ROP gadgets
  --retf, --no-retf     search for RETF gadgets
  --jop, --no-jop       search for JOP gadgets
  --allow-undeterministic-gadgets
                        allow gadgets with conditional branches (e.g. jne) as intermediate instructions
  --allow-complex-memory-ops
                        allow gadgets whose first instruction uses complex memory addressing (e.g. [r1*r2], [r1+r2*s+disp])
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
  --op <op>             search for operation
  --dst <reg>           specify a destination register for the operation
  --src <reg>           specify a source register for the operation
  --ropchain <file>     plain text file with a ROP chain
  --exhaustive, --no-exhaustive
                        exhaustive search for ROP chains
  --interactive         scan the binary once and drop into an interactive prompt
  --jobs <n>            number of worker processes for the gadget scan (default: 1)
  --cache               cache discovered gadgets on disk and reuse them on repeated runs over the same file and options
  --cache-dir <dir>     directory for the gadget cache (default: $XDG_CACHE_HOME/rop3)
```

### Parallel scan

`--jobs N` distributes the gadget scan over `N` worker processes. Each executable section is split into chunks scanned independently, then the results are merged and deduplicated, so the output is identical to a serial run. The speedup is sublinear (the merge, deduplication and sort run in the parent, and there is per-process start-up cost), so it is worth it mainly for large binaries and/or a high `--depth`; on small inputs the process overhead dominates and `--jobs 1` (the default) is faster.

### Gadget cache

With `--cache`, the gadgets discovered for a binary are stored on disk and reused on later runs over the same file and options, skipping the scan. The cache key binds the file content hash and every option that affects the result, so a changed binary or option misses cleanly. This is especially handy for large binaries and for the interactive mode.

```Shell
$ python rop3.py --binary libc.so.6 --cache        # first run scans and caches
$ python rop3.py --binary libc.so.6 --cache --op mov --dst rdi --src rax   # reuses the cache
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

Commands: `gadgets`/`search [substring]`, `count`, `op <name> [dst] [src]`, `chain <file>`, `help`, `quit`.

### Use as a library

rop3 can also be used programmatically through the `Rop3` class. Gadgets are scanned once and cached on the instance:

```python
from rop3 import Rop3

r = Rop3("libc.so.6", base="0x7f0000000000", symbols=True)
for gadget in r.gadgets():
    print(gadget)

r.find_op("mov", dst="rdi", src="rax")   # list of matching gadgets
r.ropchain("chain.txt")                  # iterator over ROP chains
```

In the work that we presented in [15th IEEE Workshop on Offensive Technologies (WOOT21)](https://www.ieee-security.org/TC/SP2021/SPW2021/WOOT21/), we used rop3 to evaluate the executional power of Return Oriented Programming in a [subset of most common Windows DLLs](https://drive.google.com/file/d/1gOxUolzrw-xlaW6K-fhzZ7Z-sqxiaZeZ/view?usp=sharing>). Check the [paper](https://drive.google.com/file/d/1Pe7s7bLhJ_20MC-duQ7YiLP-Rx5VCjFK/view?usp=sharing) for further details.

```Shell
$ python rop3.py --binary ../tfg_inf/experiments/dlls/win10x86/SHELL32.dll --op mov --dst eax --src ecx
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
