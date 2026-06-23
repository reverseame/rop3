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

import cmd
import shlex

import rop3.utils as utils
import rop3.parser as parser
import rop3.ropchain


class Rop3Shell(cmd.Cmd):
    '''
    Interactive REPL over a Rop3 instance. The binary is scanned once (its
    gadgets are cached on the Rop3 instance), so each command is cheap.
    '''
    intro = ('rop3 interactive mode. The binary is scanned once; '
             'type "help" or "?" for commands.')
    prompt = 'rop3> '

    def __init__(self, rop3):
        super().__init__()
        self.rop3 = rop3

    def preloop(self):
        count = len(self.rop3.gadgets())
        print(f'Loaded {count} gadgets from {", ".join(self.rop3.binaries)}')

    def do_gadgets(self, arg):
        'gadgets [substring]: list gadgets, optionally filtered by a substring'
        needle = arg.strip()
        shown = 0
        for gadget in self.rop3.gadgets():
            if not needle or needle in str(gadget):
                utils.print_gadget(gadget)
                shown += 1
        print(f'({shown} gadgets)')

    do_search = do_gadgets

    def do_count(self, arg):
        'count: print the number of gadgets found'
        print(len(self.rop3.gadgets()))

    def do_op(self, arg):
        'op <name> [dst] [src]: search for an operation'
        parts = shlex.split(arg)
        if not parts:
            print('usage: op <name> [dst] [src]')
            return
        op = parts[0]
        dst = parts[1] if len(parts) > 1 else None
        src = parts[2] if len(parts) > 2 else None
        try:
            result = self.rop3.find_op(op, dst, src)
        except parser.ParserException as exc:
            print(str(exc))
            return
        if result and isinstance(result[0], list):
            for chain in result:
                for gadget in chain:
                    utils.print_gadget(gadget)
        else:
            for gadget in result:
                utils.print_gadget(gadget)

    def do_chain(self, arg):
        'chain <file>: build a ROP chain from a plain-text ROP file'
        ropfile = arg.strip()
        if not ropfile:
            print('usage: chain <file>')
            return
        try:
            chains = self.rop3.ropchain(ropfile)
            first = next(iter(chains), None)
            if first is None:
                print('No ROP chain found')
            else:
                utils.print_ropchain(first)
        except rop3.ropchain.RopChainNotFound as exc:
            print(f'No ROP chain found: {exc}')

    def do_quit(self, arg):
        'quit: exit the interactive mode'
        return True

    do_exit = do_quit

    def do_EOF(self, arg):
        print()
        return True

    def emptyline(self):
        pass
