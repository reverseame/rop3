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

MAJOR = 1
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

def print_ropchains(ropchains, silent=False, nosides=False):
    if nosides:
        ropchains = filter_nosides(ropchains)

    for i, ropchain in enumerate(ropchains, start=1):
        print('=' * 80)
        print(f'Ropchain {i}')
        print('=' * 80)
        for op in ropchain:
            print(op['op']['data'], end='')
            reg_string = ''
            if op['op']['dst'] and (op['op']['dst'] != op['op'][op['op']['dst']]): reg_string += f'{op["op"]["dst"]}={op["op"][op["op"]["dst"]]}'
            if op['op']['src'] and (op['op']['src'] != op['op'][op['op']['src']]): reg_string += f', {op["op"]["src"]}={op["op"][op["op"]["src"]]}'
            if reg_string:
                print(f': {reg_string}')
            else:
                print()
            for gadget in op['gadgets']:
                string = format_gadget(gadget, silent)
                if string: print(f'\t{string}')

def print_gadget(gadget, silent=False, nosides=False):
    string = format_gadget(gadget, silent, nosides)
    if string: print(string)

def format_gadget(gadget, silent=False, nosides=False):
    if ('sides' in gadget) and (gadget['sides'] and nosides):
        return ''

    string = f'[{os.path.basename(gadget["filename"])} @ {pretty_addr(gadget["vaddr"], gadget["mode"])}]: {gadget["gadget"]}'

    if 'count' in gadget and gadget['count'] > 1:
        string += f' (x{gadget["count"]})'

    if not silent:
        if 'sides' in gadget:
            string += pretty_side_effects(gadget)

    return string

def pretty_side_effects(gadget):
    if not gadget['sides']:
        return ''

    string = ''
    list_sides = []

    for regs in gadget['sides']['regs']:
        for reg in regs:
            if reg in ['esp', 'rsp']:
                list_sides.append(reg)
            if reg == gadget['dst']:
                list_sides.append(f'dst={reg}')
            if reg == gadget['src']:
                list_sides.append(f'src={reg}')

    if list_sides:
        string = warning_text(f' (modifies {", ".join(sorted(set(list_sides)))})')

    return string

def filter_nosides(ropchains):
    ret = []

    for ropchain in ropchains:
        new_ropchain = []
        for op in ropchain:
            new_op = {}
            new_gads = [gad for gad in op['gadgets'] if not pretty_side_effects(gad)]
            if new_gads:
                new_op['op'] = op['op']
                new_op['gadgets'] = new_gads
                new_ropchain.append(new_op)
            else:
                break
        else:
            ret.append(new_ropchain)

    return ret

def warning_text(text):
    return f'{WARNING_COLOR}{text}{END_COLOR}'

def pretty_addr(addr, mode=capstone.CS_MODE_64):
    if mode == capstone.CS_MODE_32:
        padding = 8
    elif mode == capstone.CS_MODE_64:
        padding = 16

    return f'{int(addr):#0{padding}x}'

def pack_addr(addr, mode=capstone.CS_MODE_64):
    if mode == capstone.CS_MODE_32:
        formater = '<I'
    elif mode == capstone.CS_MODE_64:
        formater = '<Q'

    return struct.pack(formater, addr)

def read_file(filename, flags='r'):
    with open(filename, flags) as f:
        return f.read()
