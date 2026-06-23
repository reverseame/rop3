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
        self.argparser.add_argument('--all', default=False, action='store_true', help='show the same gadget in different addresses')
        self.argparser.add_argument('--rop', action=argparse.BooleanOptionalAction, help="search for ROP gadgets", default=True)
        self.argparser.add_argument('--retf', action=argparse.BooleanOptionalAction, help="search for RETF gadgets", default=False)
        self.argparser.add_argument('--jop', action=argparse.BooleanOptionalAction, help="search for JOP gadgets", default=False)
        self.argparser.add_argument('--allow-undeterministic-gadgets', action='store_true', default=False, help='allow gadgets with conditional branches (e.g. jne) as intermediate instructions')
        self.argparser.add_argument('--allow-complex-memory-ops', action='store_true', default=False, help='allow gadgets whose first instruction uses complex memory addressing (e.g. [r1*r2], [r1+r2*s+disp])')
        self.argparser.add_argument('--verbose', action='store_true', default=False, help='show progress information (gadget counts, combinations)')
        self.argparser.add_argument('--binary', type=str, metavar='<file>', nargs='+', help='specify a list of binary path files to analyze')
        self.argparser.add_argument('--badchar', type=str, metavar='<hex>', nargs='+', help='specify a list of chars to avoid in gadget address')
        self.argparser.add_argument('--badchar-bytes', type=str, metavar='<hex>', nargs='+', help='specify a list of chars to avoid in gadget opcode bytes')
        self.argparser.add_argument('--keep-canary-address', action='store_true', default=False, help='do not prefer canary-free addresses (0x00, 0x0a, 0x0d, 0xff) when discarding duplicate gadgets')
        self.argparser.add_argument('--base', type=str, metavar='<hex>', nargs='+', help='specify a base address to relocate binary files (it may take a while). When you specify more than one base address, you need to provide one address for each binary')
        self.argparser.add_argument('--arch', type=str, metavar='<name>', default=None, help='select the architecture slice of a fat Mach-O binary (e.g. x86_64, i386)')
        self.argparser.add_argument('--symbols', action='store_true', default=False, help='annotate gadgets with the nearest symbol (when the binary is not stripped)')
        self.argparser.add_argument('--output', choices=['text', 'json', 'csv'], default='text', help='output format (default: text)')
        self.argparser.add_argument('--op', type=str, metavar='<op>', help='search for operation')
        self.argparser.add_argument('--dst', type=str, metavar='<reg>', help='specify a destination register for the operation')
        self.argparser.add_argument('--src', type=str, metavar='<reg>', help='specify a source register for the operation')
        self.argparser.add_argument('--ropchain', type=str, metavar='<file>', help='plain text file with a ROP chain')
        self.argparser.add_argument('--exhaustive', action=argparse.BooleanOptionalAction, help="exhaustive search for ROP chains", default=False)
        self.argparser.add_argument('--interactive', action='store_true', default=False, help='scan the binary once and drop into an interactive prompt')
        self.argparser.add_argument('--jobs', type=int, metavar='<n>', default=1, help='number of worker processes for the gadget scan (default: 1)')
        self.argparser.add_argument('--cache', action='store_true', default=False, help='cache discovered gadgets on disk and reuse them on repeated runs over the same file and options')
        self.argparser.add_argument('--cache-dir', type=str, metavar='<dir>', default=None, help='directory for the gadget cache (default: $XDG_CACHE_HOME/rop3)')

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
        if args.jop:
            flags |= gadfinder.JOP
        if args.rop:
            flags |= gadfinder.ROP
        if args.retf:
            flags |= gadfinder.RETF
        if args.allow_undeterministic_gadgets:
            flags |= gadfinder.ALLOW_UNDETERMINISTIC
        if args.allow_complex_memory_ops:
            flags |= gadfinder.ALLOW_COMPLEX_MEM
        if not args.keep_canary_address:
            flags |= gadfinder.AVOID_CANARY

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

        for option in (args.badchar, args.badchar_bytes):
            if not option:
                continue
            for badchar in option:
                value = self._check_int_value(badchar)
                if value < 0x00 or value > 0xff:
                    debug.error(f'{badchar}: bad char must be one byte (range 0x00-0xff)')

        if args.jobs is not None and args.jobs < 1:
            debug.error(f'--jobs must be >= 1 (got {args.jobs})')

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
