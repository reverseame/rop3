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

import argparse

import rop3.debug as debug
import rop3.utils as utils
import rop3.gadfinder as gadfinder
import rop3.template as template

def parse_args(arguments):
    description = 'This tool allows you to search gadgets, operations formed by gadgets and generate automatic ROP chains in Portable Executable (PE)'
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument('-v', '--version', action='store_true', help='display {0}\'s version and exit'.format(utils.TOOL_NAME))
    parser.add_argument('--depth', type=int, metavar='<bytes>', default=gadfinder.DEPTH, help='depth for search engine (default to {0} bytes)'.format(gadfinder.DEPTH))
    parser.add_argument('--all', action='store_true', help='disables the removal of duplicate gadgets')
    parser.add_argument('--nojop', action='store_true', help='disables JOP gadgets')
    parser.add_argument('--noretf', action='store_true', help='disables gadgets terminated in a far return (retf)')
    parser.add_argument('--binary', type=str, metavar='<file>', nargs='+', help='specify a list of binary path files to analyze')
    parser.add_argument('--base', type=str, metavar='<ImageBase>', default='', help='specify a ImageBase address to relocate binary files (it may take a while)')
    ops = ', '.join(sorted(utils.get_ops().keys()))
    parser.add_argument('--op', type=str, metavar='<op>', help='search for operation. Available: {{{0}}}'.format(ops))
    parser.add_argument('--dst', type=str, metavar='<reg/imm>', default='', help='specify a destination reg/imm to operation')
    parser.add_argument('--src', type=str, metavar='<reg/imm>', default='', help='specify a source reg/imm to operation')
    # TODO
    # parser.add_argument('--fit', action='store_true', help='search smallest operation gadgets based in number of bytes')
    parser.add_argument('--ropchain', type=str, metavar='<file>', help='plain text file with rop chains')

    args = parser.parse_args(arguments)
    args = _convert_flags(args)

    check_args(args)

    return args

def check_args(args):
    if not (args.version or args.binary):
        debug.error('You need to provide a binary (--binary or --help)')

    if args.op:
        try:
            template.TemplateOp(args.op)
        except template.OperationError as exc:
            debug.error(str(exc))

    if (args.dst or args.src) and not args.op:
        debug.error('You need to provide an operation to specify a register (--op or --help)')

    if args.base:
        try:
            base = int(args.base, 0)
            namespace = vars(args)
            namespace['base'] = base
        except ValueError:
            debug.error('\'{0}\': Unable to infer number value, try to use prefix (v.g. \'0xCACAFEA\')'.format(args.base))

def _convert_flags(args):
    namespace = vars(args)
    flags = 0

    if args.all:
        flags |= gadfinder.SKIP_DUPLICATES
    if args.nojop:
        flags |= gadfinder.NO_JOP
    if args.noretf:
        flags |= gadfinder.NO_RETF

    namespace['flags'] = flags

    return args
