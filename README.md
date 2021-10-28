# rop🌲

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

rop3 is a tool developed in [Python](https://www.python.org/downloads/) and it relies on the [Capstone](https://www.capstone-engine.org/) disassembly framework to search for gadgets, operations, and ROP chains using a backtracking algorithm in a tree-like structure:

![Backtracking algorithm to find a ROP chain](https://drive.google.com/uc?export=view&id=166Vbc9vkXEsMN81cdpjD4yOCuVw5jvVw) 

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
usage: rop3.py [-h] [-v] [--depth <bytes>] [--all] [--nojop] [--noretf] [--nosides] [--silent]
               [--binary <file> [<file> ...]] [--badchar <hex> [<hex> ...]] [--base <hex> [<hex> ...]]
               [--op <op>] [--dst <reg>] [--src <reg>] [--ropchain <file>]

This tool allows you to search for gadgets, operations, and ROP chains using a backtracking algorithm
in a tree-like structure

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         display rop3.py's version and exit
  --depth <bytes>       depth for search engine (default to 5 bytes)
  --all                 show the same gadget in different addresses
  --nojop               do not search for JOP gadgets
  --noretf              do not search for gadgets terminated in a far return (retf)
  --nosides             eliminate gadgets with side-effects
  --silent              eliminate side-effects warnings
  --binary <file> [<file> ...]
                        specify a list of binary path files to analyze
  --badchar <hex> [<hex> ...]
                        specify a list of chars to avoid in gadget address
  --base <hex> [<hex> ...]
                        specify a base address to relocate binary files (it may take a while). When you
                        specify more than one base address, you need to provide one address for each
                        binary
  --op <op>             search for operation. Available: add, and, eqc, gcf, jmp, lc, ld, lsd, ltc,
                        mov, neg, not, or, spa, sps, st, sub, xor
  --dst <reg>           specify a destination register for the operation
  --src <reg>           specify a source register for the operation
  --ropchain <file>     plain text file with a ROP chain
```

In the work that we presented in [15th IEEE Workshop on Offensive Technologies (WOOT21)](https://www.ieee-security.org/TC/SP2021/SPW2021/WOOT21/), we used rop3 to evaluate the executional power of Return Oriented Programming in a [subset of most common Windows DLLs](https://drive.google.com/file/d/1gOxUolzrw-xlaW6K-fhzZ7Z-sqxiaZeZ/view?usp=sharing>). Check the [paper](https://drive.google.com/file/d/1Pe7s7bLhJ_20MC-duQ7YiLP-Rx5VCjFK/view?usp=sharing) for further details.

```Shell
$ python3 rop3.py --nojop --noretf --binary ~/dlls/win10x86/SHELL32.dll --op mov --dst eax --src ecx            
[SHELL32.dll @ 0x69b8a61b]: mov eax, ecx ; leave ; ret (modifies esp)
[SHELL32.dll @ 0x698dc8c8]: mov eax, ecx ; pop ebx ; leave ; ret (x5) (modifies esp)
[SHELL32.dll @ 0x6991a2b1]: mov eax, ecx ; pop ebx ; ret (x4) (modifies esp)
[SHELL32.dll @ 0x6995e30b]: mov eax, ecx ; pop edi ; ret (x2) (modifies esp)
[SHELL32.dll @ 0x69c3c483]: mov eax, ecx ; pop esi ; leave ; ret (modifies esp)
[SHELL32.dll @ 0x699670c1]: mov eax, ecx ; pop esi ; pop ebp ; ret (modifies esp)
[SHELL32.dll @ 0x6992d289]: mov eax, ecx ; pop esi ; ret (x11) (modifies esp)
[SHELL32.dll @ 0x698a474c]: mov eax, ecx ; ret (x97)
[SHELL32.dll @ 0x6991ea9b]: xchg eax, ecx ; add al, 0 ; leave ; ret (modifies esp)
[SHELL32.dll @ 0x698b4804]: xchg eax, ecx ; add dword ptr fs:[eax], eax ; ret
[SHELL32.dll @ 0x69b0eae2]: xchg eax, ecx ; in eax, 0xff ; leave ; ret (modifies dst=eax, esp)
[SHELL32.dll @ 0x69c8eb40]: xchg eax, ecx ; int 0xff ; leave ; ret (modifies esp)
[SHELL32.dll @ 0x69b2eade]: xchg eax, ecx ; jecxz 0x69b2eae0 ; leave ; ret (modifies esp)
[SHELL32.dll @ 0x698965e0]: xchg eax, ecx ; mov al, 0x1c ; outsb dx, byte ptr [esi] ; ret
[SHELL32.dll @ 0x698dea7e]: xchg eax, ecx ; or byte ptr [eax], al ; leave ; ret (modifies esp)
[SHELL32.dll @ 0x698feaa6]: xchg eax, ecx ; push es ; add cl, cl ; ret
[SHELL32.dll @ 0x6984d4c9]: xchg eax, ecx ; ret (x3)
[SHELL32.dll @ 0x69cd4cee]: xchg eax, ecx ; sahf ; ret
[SHELL32.dll @ 0x69c3eb09]: xchg eax, ecx ; sar bh, cl ; leave ; ret (modifies esp)
[SHELL32.dll @ 0x6995541d]: xchg eax, ecx ; test byte ptr [ecx - 0x75], ch ; ret
```

## Licence

Licensed under the [GNU GPLv3](LICENCE) licence.
