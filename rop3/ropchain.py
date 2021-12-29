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
import re
import copy
import itertools

import rop3.debug as debug
import rop3.utils as utils
import rop3.operation as operation

'''
Matches the following with OP, DST and SRC placeholders:

lc()            -> OP: lc,  DST: None, SRC: None
neg(reg1)       -> OP: neg, DST: reg1, SRC: None
mov(reg3,reg2)  -> OP: mov, DST: reg3, SRC: reg2
mov(reg3, reg2) -> OP: mov, DST: reg3, SRC: reg2
'''
REGEX_OP = re.compile(r'^(?P<OP>[a-zA-Z]+)\((?P<DST>[a-zA-Z0-9]+)?(, ?(?P<SRC>[a-zA-Z0-9]+))?\)$')

class RopChain:
    '''
    Class to construct a rop chain
    '''
    def __init__(self, gadfinder):
        self.gadfinder = gadfinder

    def search(self, binary, ropfile, base=None, badchars=None):
        gadgets = self.gadfinder.findall(binary, base=base, badchars=badchars)
        ropchain = self.parse_ropfile(ropfile)
        tree = Tree(ropchain)
        (combinations, ops_gadgets) = tree.traverse(gadgets)
        return self.construct_ropchains(ropchain, combinations, ops_gadgets)

    def parse_ropfile(self, ropfile):
        ret = []

        data = utils.read_file(ropfile).splitlines()
        for i, op in enumerate(data, start=1):
            try:
                ret.append(self.parse_op(op))
            except SyntaxError:
                debug.error(f'{ropfile}: Line {i}: {op}: Unable to parse operation')

        return ret

    def parse_op(self, op):
        ret = {}

        match = REGEX_OP.search(op)

        if match:
            ret['data'] = match.group(0)
            ret['op'] = match.group('OP')
            ret['dst'] = match.group('DST')
            ret['src'] = match.group('SRC')
        else:
            raise SyntaxError

        return ret

    def construct_ropchains(self, ropchain, combinations, ops_gadgets):
        ret = []

        for comb in combinations:
            rop = []
            for op, op_gadgets in zip(ropchain, ops_gadgets):
                item = {}

                new_op = copy.deepcopy(op)

                for key_comb in comb:
                    if type(key_comb) == str:
                        if new_op['dst'] == key_comb:
                            new_op[new_op['dst']] = comb[new_op['dst']]
                        if new_op['src'] == key_comb:
                            new_op[new_op['src']] = comb[new_op['src']]
                    elif type(key_comb) == tuple:
                        if new_op['dst'] in key_comb:
                            new_op[new_op['dst']] = comb[key_comb][key_comb.index(new_op['dst'])]
                        if new_op['src'] in key_comb:
                            new_op[new_op['src']] = comb[key_comb][key_comb.index(new_op['src'])]

                gadgets = []
                for gadget in op_gadgets:
                    if new_op['dst'] and new_op['src']:
                        if gadget['dst'] == new_op[new_op['dst']] and gadget['src'] == new_op[new_op['src']]:
                            gadgets.append(gadget)
                    elif new_op['dst']:
                        if gadget['dst'] == new_op[new_op['dst']]:
                            gadgets.append(gadget)
                    elif new_op['src']:
                        if gadget['src'] == new_op[new_op['src']]:
                            gadgets.append(gadget)
                    else:
                        gadgets.append(gadget)

                item['op'] = new_op
                item['gadgets'] = gadgets

                rop.append(item)
            ret.append(rop)

        return ret

class Tree:
    def __init__(self, ropchain):
        self.ropchain = ropchain
        self.op_ropchain = self.parse_ropchain()

    def parse_ropchain(self):
        ret = []

        for item in self.ropchain:
            ''' Generic mask MUST start with "reg", either it is treated it as a register '''
            dst = None if item['dst'] and item['dst'].startswith('reg') else item['dst']
            src = None if item['src'] and item['src'].startswith('reg') else item['src']
            ret.append(operation.Operation(item['op'], dst, src))

        return ret

    def traverse(self, gadgets):
        (state, ops_gadgets) = self.get_initial_state(gadgets)
        return (self._traverse(state), ops_gadgets)

    def get_initial_state(self, gadgets):
        state = {}
        ops_gadgets = []

        for item, op in zip(self.ropchain, self.op_ropchain):
            op_gadgets = op.filter_gadgets(gadgets)
            if not op_gadgets:
                raise RopChainNotFound(f'{item["data"]}: Unable to find gadgets for operation')

            ops_gadgets.append(op_gadgets)
            combinations = self.get_combinations(op_gadgets)
            key = (item['dst'], item['src']) if item['src'] else item['dst']
            if key in state:
                ''' Keep combinations already present ''' 
                merged_comb = [comb for comb in combinations if comb in state[key]]
                state[key] = merged_comb
            else:
                state[key] = combinations

        return (state, ops_gadgets)

    def get_combinations(self, gadgets):
        return sorted(list(set([(gadget['dst'], gadget['src']) for gadget in gadgets if gadget['src'] is not None])) if gadgets[0]['src'] else list(set([gadget['dst'] for gadget in gadgets])))

    def _traverse(self, state):
        ret = []

        keys, values = zip(*state.items())
        combs = [dict(zip(keys, v)) for v in itertools.product(*values)]

        for comb in combs:
            valid = True
            reg_comb = {}
            for comb_key in comb:
                # Ensure different keys are not set to same registers
                if len(reg_comb.values()) != len(set(reg_comb.values())):
                    valid = False
                    break
                if type(comb_key) == str:
                    if comb_key in reg_comb:
                        if reg_comb[comb_key] != comb[comb_key]:
                            valid = False
                            break
                    else:
                        reg_comb[comb_key] = comb[comb_key]
                elif type(comb_key) == tuple:
                    if reg_comb:
                        for key in comb_key:
                            if key in reg_comb:
                                if reg_comb[key] != comb[comb_key][comb_key.index(key)]:
                                    valid = False
                                    break
                            else:
                                reg_comb[key] = comb[comb_key][comb_key.index(key)]
                    else:
                        for key in comb_key:
                            reg_comb[key] = comb[comb_key][comb_key.index(key)]

            if valid: ret.append(comb)

        return ret

class RopChainNotFound(Exception):
    pass
