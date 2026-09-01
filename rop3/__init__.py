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
            if args.verbose:
                kinds = [k for k, on in (('ROP', args.rop), ('JOP', args.jop),
                                         ('RETF', args.retf)) if on]
                debug.info(f"search: {'+'.join(kinds) or 'none'}, "
                           f"depth {args.depth if args.depth is not None else 'auto'} bytes, "
                           f"{args.jobs} job(s)")
                for info in rop.describe():
                    for line in utils.binary_info_lines(info):
                        debug.info(line)

            if args.interactive:
                from rop3.interactive import Rop3Shell
                Rop3Shell(rop).cmdloop()
            else:
                # --tuple renders gadgets as the tuple form; it overrides the
                # textual --output (json/csv keep their structured formats).
                out_fmt = 'tuple' if args.tuple else args.output

                if args.ropchain:
                    result = rop.ropchain(args.ropchain)
                    utils.output_ropchains(result, out_fmt, exhaustive=args.exhaustive)
                elif args.op:
                    result = rop.find_op(args.op, operands=args.operands)
                    if result and isinstance(result[0], list):
                        ''' Composite operation: a list of chains '''
                        utils.output_ropchains(result, out_fmt, exhaustive=True)
                    else:
                        utils.output_gadgets(result, out_fmt)
                else:
                    utils.output_gadgets(rop.gadgets(), out_fmt)
        except parser.ParserException as exc:
            debug.error(str(exc))
        except rop3.ropchain.RopChainNotFound as exc:
            debug.error(f'No ROP chain found: {exc}')
        except binary.BinaryException as exc:
            debug.error(str(exc))
