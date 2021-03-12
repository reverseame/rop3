# rop🌲

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
usage: rop3.py [-h] [-v] [--depth <bytes>] [--all] [--nojop] [--noretf]
               [--binary <file> [<file> ...]] [--base <ImageBase>]
               [--badchar <hex> [<hex> ...]] [--ins <mnemonic>] [--op <op>]
               [--dst <reg/imm>] [--src <reg/imm>] [--ropchain <file>]

This tool allows you to search for gadgets, operations, and ROP chains using a
backtracking algorithm in a tree-like structure

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         display rop3.py's version and exit
  --depth <bytes>       depth for search engine (default to 5 bytes)
  --all                 disables the removal of duplicate gadgets
  --nojop               disables JOP gadgets
  --noretf              disables gadgets terminated in a far return (retf)
  --binary <file> [<file> ...]
                        specify a list of binary path files to analyze
  --base <ImageBase>    specify a ImageBase address to relocate binary files (it may
                        take a while)
  --badchar <hex> [<hex> ...]
                        specify a list of chars to avoid in gadget address
  --ins <mnemonic>      search for instruction mnemonic
  --op <op>             search for operation. Available: add, and, eqc, gfc, jmp,
                        lc, ld, lsd, ltc, mov, neg, not, or, spa, sps, st, sub, xor
  --dst <reg/imm>       specify a destination reg/imm to instruction/operation
  --src <reg/imm>       specify a source reg/imm to instruction/operation
  --ropchain <file>     plain text file with rop chains
```

In the work that we will present in [15th IEEE Workshop on Offensive Technologies (WOOT21)](https://www.ieee-security.org/TC/SP2021/SPW2021/WOOT21/), we used rop3 to evaluate the executional power of Return Oriented Programming in a [subset of most common Windows DLLs](https://drive.google.com/file/d/1gOxUolzrw-xlaW6K-fhzZ7Z-sqxiaZeZ/view?usp=sharing>). Check the [paper](https://drive.google.com/file/d/1sPOmjqTmUfgm0iSSYJCvUAHfC10TNBAn/view) for further details.

```
$ python3 rop3.py --nojop --noretf --binary ~/dlls/win10x64/kernel32.dll --op mov --dst eax
[kernel32.dll @ 0x180007874]: mov eax, ebx ; ret
[kernel32.dll @ 0x180023dc2]: mov eax, ecx ; pop rbp ; ret
[kernel32.dll @ 0x180002258]: mov eax, ecx ; ret
[kernel32.dll @ 0x180003988]: mov eax, edx ; ret
[kernel32.dll @ 0x180003987]: mov eax, r10d ; ret
[kernel32.dll @ 0x180007873]: mov eax, r11d ; ret
[kernel32.dll @ 0x180006064]: mov eax, r8d ; ret
[kernel32.dll @ 0x180002257]: mov eax, r9d ; ret
[kernel32.dll @ 0x18000234d]: xchg eax, ebp ; ret
[kernel32.dll @ 0x18002ed9d]: xchg eax, ebp ; ret 0x1589
[kernel32.dll @ 0x180067d26]: xchg eax, ebp ; ret 0x1deb
[kernel32.dll @ 0x180014af2]: xchg eax, ebp ; ret 0xc283
[kernel32.dll @ 0x1800275ec]: xchg eax, ebp ; ret 0xe1e8
[kernel32.dll @ 0x18004bddf]: xchg eax, ebp ; ret 3
[kernel32.dll @ 0x180027849]: xchg eax, ebx ; ret
[kernel32.dll @ 0x180049aa9]: xchg eax, edx ; ret
[kernel32.dll @ 0x18005d83a]: xchg eax, edx ; ret 1
[kernel32.dll @ 0x18000222d]: xchg eax, esi ; ret
[kernel32.dll @ 0x18001dcf7]: xchg eax, esi ; ret 0x1389
[kernel32.dll @ 0x18000223a]: xchg eax, esi ; ret 0xfa83
[kernel32.dll @ 0x18001f642]: xchg eax, esp ; ret
[kernel32.dll @ 0x180011564]: xchg eax, esp ; ret 0xf741
```

## Licence

Licensed under the [GNU GPLv3](LICENCE) licence.
