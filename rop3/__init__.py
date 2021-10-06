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

import sys

import rop3.args
import rop3.utils as utils
import rop3.ropchain
import rop3.gadfinder as gadfinder

def main():
    args = rop3.args.ArgumentParser().parse_args(sys.argv[1:])

    if args.version:
        utils.show_version()
        sys.exit(0)
    elif args.binary:
        finder = gadfinder.GadFinder(args.depth, args.flags)

        if args.ropchain:
            ropchain = rop3.ropchain.RopChain(finder)
            result = ropchain.search(args.binary, args.ropchain, base=args.base, badchars=args.badchar)
            utils.print_ropchains(result, args.silent, args.nosides)
        elif args.op:
            for filename, base in zip(args.binary, args.base):
                for gadget in finder.find_op(filename, args.op, args.dst, args.src, base=base, badchars=args.badchar):
                    utils.print_gadget(gadget, args.silent, args.nosides)
        else:
            for filename, base in zip(args.binary, args.base):
                for gadget in finder.find(filename, base=base, badchars=args.badchar):
                    utils.print_gadget(gadget)
