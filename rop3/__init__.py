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
import rop3.debug as debug
import rop3.parser as parser
import rop3.binary as binary
import rop3.ropchain
import rop3.gadfinder as gadfinder

from rop3.api import Rop3

def main():
    args = rop3.args.ArgumentParser().parse_args(sys.argv[1:])

    if args.verbose:
        debug.set_verbose()

    if args.version:
        utils.show_version()
        sys.exit(0)
    elif args.binary:
        rop = Rop3.from_args(args)

        try:
            if args.interactive:
                from rop3.interactive import Rop3Shell
                Rop3Shell(rop).cmdloop()
            elif args.ropchain:
                result = rop.ropchain(args.ropchain)
                utils.output_ropchains(result, args.output, exhaustive=args.exhaustive)
            elif args.op:
                result = rop.find_op(args.op, args.dst, args.src)
                if result and isinstance(result[0], list):
                    ''' Composite operation: a list of chains '''
                    if args.output == 'text':
                        for chain in result:
                            for gadget in chain:
                                utils.print_gadget(gadget)
                    else:
                        utils.output_ropchains(result, args.output, exhaustive=True)
                else:
                    utils.output_gadgets(result, args.output)
            else:
                utils.output_gadgets(rop.gadgets(), args.output)
        except parser.ParserException as exc:
            debug.error(str(exc))
        except rop3.ropchain.RopChainNotFound as exc:
            debug.error(f'No ROP chain found: {exc}')
        except binary.BinaryException as exc:
            debug.error(str(exc))
