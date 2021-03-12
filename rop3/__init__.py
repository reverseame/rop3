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

import rop3.args as args
import rop3.debug as debug
import rop3.utils as utils
import rop3.gadfinder as finder
import rop3.ropchain as ropchain

def main():
    argis = args.parse_args(sys.argv[1:])

    if argis.version:
        utils.show_version()
        sys.exit(0)
    elif argis.binary:
        gadfinder = finder.Finder(depth=argis.depth, flags=argis.flags)

        if argis.ropchain:
            rop = ropchain.RopChain(gadfinder, argis.ropchain)
            result = rop.search(argis.binary)

            if result:
                for i, chain in enumerate(result):
                    print('=' * 80)
                    print('Ropchain {0:n}'.format(i+1))
                    print('=' * 80)
                    for item in chain:
                        print(utils.format_op_ropchain(item['op']))
                        for gad in item['gads']:
                            print('\t{0}'.format(utils.format_op_gadget(gad)))
                        print('')
            else:
                debug.warning('Unable to find ropchain, consider to either change operations or add more libraries')
        elif argis.op:
            for gadgets in gadfinder.find_op_iter(argis.binary, op=argis.op, dst=argis.dst, src=argis.src, base=argis.base):
                for gad in gadgets:
                    print(utils.format_op_gadget(gad))
        else:
            for gadgets in gadfinder.find_iter(argis.binary, base=argis.base):
                for gad in gadgets:
                    print(utils.format_gadget(gad))
