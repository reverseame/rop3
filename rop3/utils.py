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
import sys
import json
import csv
import struct
import __main__
import capstone

MAJOR = 2
MINOR = 0
PATCH = 0
VERSION = f'{MAJOR}.{MINOR}.{PATCH}'

# __main__ may lack __file__ when imported as a library or in a spawned
# multiprocessing worker; fall back to a sensible default in that case.
TOOL_NAME = os.path.basename(os.path.realpath(getattr(__main__, '__file__', 'rop3.py')))

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

# Columns used for the CSV output (list fields are space-joined)
_CSV_COLUMNS = ['file', 'vaddr', 'gadget', 'bytes', 'count',
                'symbol', 'op', 'dst', 'src', 'modifies']

def _csv_record(gadget):
    record = gadget.to_dict()
    record['modifies'] = ' '.join(record['modifies'])
    return record

def output_gadgets(gadgets, fmt='text'):
    ''' Emit a flat list of gadgets in the requested format. '''
    if fmt == 'json':
        print(json.dumps([g.to_dict() for g in gadgets], indent=2))
    elif fmt == 'csv':
        writer = csv.DictWriter(sys.stdout, fieldnames=_CSV_COLUMNS,
                                extrasaction='ignore')
        writer.writeheader()
        for gadget in gadgets:
            writer.writerow(_csv_record(gadget))
    else:
        for gadget in gadgets:
            print(gadget)

def output_ropchains(chains, fmt='text', exhaustive=False):
    ''' Emit ROP chains (each a list of gadgets) in the requested format.
        For plain text without --exhaustive only the first chain is consumed,
        preserving the laziness of the search generator. '''
    if fmt == 'text' and not exhaustive:
        first = next(iter(chains), None)
        if first is not None:
            print_ropchain(first)
        return

    chains = list(chains)
    if fmt == 'json':
        print(json.dumps([[g.to_dict() for g in chain] for chain in chains], indent=2))
    elif fmt == 'csv':
        writer = csv.DictWriter(sys.stdout, fieldnames=['chain'] + _CSV_COLUMNS,
                                extrasaction='ignore')
        writer.writeheader()
        for idx, chain in enumerate(chains, 1):
            for gadget in chain:
                record = _csv_record(gadget)
                record['chain'] = idx
                writer.writerow(record)
    else:
        for idx, chain in enumerate(chains, 1):
            print_ropchain(chain, idx)

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
