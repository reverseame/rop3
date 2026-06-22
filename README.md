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
               [--binary <file> [<file> ...]] [--badchar <hex> [<hex> ...]] [--base <hex> [<hex> ...]] [--op <op>] [--dst <reg>] [--src <reg>] [--ropchain <file>]
               [--exhaustive | --no-exhaustive]

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
  --base <hex> [<hex> ...]
                        specify a base address to relocate binary files (it may take a while). When you specify more than one base address, you need to provide one address for each binary
  --op <op>             search for operation
  --dst <reg>           specify a destination register for the operation
  --src <reg>           specify a source register for the operation
  --ropchain <file>     plain text file with a ROP chain
  --exhaustive, --no-exhaustive
                        exhaustive search for ROP chains
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
