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
import argparse

import rop3.debug as debug
import rop3.utils as utils
import rop3.parser as parser
import rop3.gadfinder as gadfinder

class ArgumentParser:
    def __init__(self):
        self.parser = parser.Parser()
        description = 'This tool allows you to search for gadgets, operations, and ROP chains using a backtracking algorithm in a tree-like structure'
        self.argparser = argparse.ArgumentParser(description=description)
        self.argparser.add_argument('-v', '--version',  action='store_true', help=f'display {utils.TOOL_NAME}\'s version and exit')
        self.argparser.add_argument('--depth', type=int, metavar='<bytes>', default=gadfinder.DEPTH, help=f'depth for search engine (default to {gadfinder.DEPTH} bytes)')
        self.argparser.add_argument('--all', action='store_true', help='show the same gadget in different addresses')
        self.argparser.add_argument('--nojop', action='store_true', help='do not search for JOP gadgets')
        self.argparser.add_argument('--noretf', action='store_true', help='do not search for gadgets terminated in a far return (retf)')
        self.argparser.add_argument('--nosides', action='store_true', help='eliminate gadgets with side-effects')
        self.argparser.add_argument('--silent', action='store_true', help='eliminate side-effects warnings')
        # self.argparser.add_argument('--verbose', action='store_true', help='full description of side-effects warnings')
        self.argparser.add_argument('--binary', type=str, metavar='<file>', nargs='+', help='specify a list of binary path files to analyze')
        self.argparser.add_argument('--badchar', type=str, metavar='<hex>', nargs='+', help='specify a list of chars to avoid in gadget address')
        self.argparser.add_argument('--base', type=str, metavar='<hex>', nargs='+', help='specify a base address to relocate binary files (it may take a while). When you specify more than one base address, you need to provide one address for each binary')
        # self.argparser.add_argument('--ins', type=str, metavar='<mnemonic>', help='search for an instruction mnemonic')
        self.argparser.add_argument('--op', type=str, metavar='<op>', help=f'search for operation. Available: {", ".join(sorted([op.name for op in self.parser.get_ops()]))}')
        self.argparser.add_argument('--dst', type=str, metavar='<reg>', help='specify a destination register for the operation')
        self.argparser.add_argument('--src', type=str, metavar='<reg>', help='specify a source register for the operation')
        self.argparser.add_argument('--ropchain', type=str, metavar='<file>', help='plain text file with a ROP chain')

    def parse_args(self, arguments):
        args = self.argparser.parse_args(arguments)

        self._check_args(args)

        args = self._convert_flags(args)
        args = self._convert_base(args)

        return args

    def _convert_flags(self, args):
        '''
        Transform user provided options to bit flags
        '''
        namespace = vars(args)
        flags = 0

        if args.all:
            flags |= gadfinder.KEEP_DUPLICATES
        if args.nojop:
            flags |= gadfinder.NO_JOP
        if args.noretf:
            flags |= gadfinder.NO_RETF

        namespace['flags'] = flags

        return args

    def _convert_base(self, args):
        ''' Replicate one base for all binaries '''
        if not args.version:
            base_addresses = args.base
            if not base_addresses:      # None
                base_addresses = [args.base] * len(args.binary)
            elif len(args.base) == 1:   # Just one base
                base_addresses = args.base * len(args.binary)

            args.base = base_addresses

        return args

    def _check_args(self, args):
        if not (args.version or args.binary):
            debug.error('You need to provide a binary (--binary or --help)')

        if args.base:
            if len(args.binary) != len(args.base):
                if len(args.base) != 1:
                    debug.error(f'Number of binaries ({len(args.binary)}) does not match number of addresses ({len(args.base)}) (--help)')

            for baddr in args.base:
                self._check_int_value(baddr)

        if args.badchar:
            for badchar in args.badchar:
                value = self._check_int_value(badchar)
                if value < 0x00 or value > 0xff:
                    debug.error(f'{badchar}: bad char must be one byte (range 0x00-0xff)')

        if args.op:
            try:
                self.parser.get_op(args.op)
            except parser.ParserException:
                debug.error(f'{args.op}: Operation not found (--help)')

        if args.ropchain:
            ropchain_filename = os.path.abspath(args.ropchain)
            if not os.path.isfile(ropchain_filename):
                debug.error(f'{ropchain_filename}: File not found (--help)')

    def _check_int_value(self, value):
        try:
            ''' With base 0, it tries to infer the integer type based in prefix '''
            return int(value, 0)
        except ValueError:
            debug.error(f'{value}: value not recognized')
