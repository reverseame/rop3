'''
This file is part of rop3 (https://github.com/reverseame/rop3).

rop3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

rop3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with rop3. If not, see <https://www.gnu.org/licenses/>.
'''

import os
import struct
import __main__
import capstone

MAJOR = 2
MINOR = 0
PATCH = 0
VERSION = f'{MAJOR}.{MINOR}.{PATCH}'

TOOL_NAME = os.path.basename(os.path.realpath(__main__.__file__))

HEADER = '\
                          .d8888b.  \n\
                         d88P  Y88b \n\
                              .d88P \n\
888d888 .d88b.  88888b.      8888"  \n\
888P"  d88""88b 888 "88b      "Y8b. \n\
888    888  888 888  888 888    888 \n\
888    Y88..88P 888 d88P Y88b  d88P \n\
888     "Y88P"  88888P"   "Y8888P"  \n\
                888                 \n\
                888                 \n\
                888\n\
\n\
                A tool of RME-DisCo Research Group from University of Zaragoza\n\
                                    <https://reversea.me/>\
'

WARNING_COLOR = '\033[93m'
END_COLOR = '\033[0m'

def show_version():
    print(HEADER)
    print()
    print('Version: {0} v{1}'.format(TOOL_NAME, VERSION))

def print_gadget(gadget):
    print(gadget)

def print_ropchain(ropchain, idx=None):
    if idx is not None:
        print('#' * 40 + f' Ropchain {idx} ' + '#' * 40)
    for gad in ropchain:
        print(gad)
    if idx is not None:
        print()

def warning_text(text):
    return f'{WARNING_COLOR}{text}{END_COLOR}'

def pretty_addr(addr, mode=capstone.CS_MODE_64):
    if mode == capstone.CS_MODE_32:
        padding = 8
    elif mode == capstone.CS_MODE_64:
        padding = 16
    else:
        raise ValueError(f'unsupported mode: {mode}')

    return f'{int(addr):#0{padding}x}'

def pack_addr(addr, mode=capstone.CS_MODE_64):
    if mode == capstone.CS_MODE_32:
        formater = '<I'
    elif mode == capstone.CS_MODE_64:
        formater = '<Q'
    else:
        raise ValueError(f'unsupported mode: {mode}')

    return struct.pack(formater, addr)

def read_file(filename, flags='r'):
    with open(filename, flags) as f:
        return f.read()
