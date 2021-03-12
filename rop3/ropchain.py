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
import re
import copy
import itertools

import rop3.binary as binary
import rop3.debug as debug
import rop3.operation as operation

from rop3.template import OperationError

OP = 1
REG_DST = 3
REG_SRC = 6
REGEX_OP = re.compile(r'^([a-zA-Z]+(_?[0-9]+)?)\(([a-zA-Z]+(_?[0-9]+)?)?(, ?([a-zA-Z]+(_?[0-9]+)?)?)?\)$')

class RopChain:
    def __init__(self, gadfinder, path):
        try:
            self.file_path = os.path.realpath(path)
            data = self._read_file()
            ops = self.parse_tree_data(data)
            self.tree = Tree(gadfinder, ops)
        except ParseError as exc:
            debug.error('\'{0}\': {1}'.format(self.file_path, str(exc)))
        except IOError:
            debug.error('\'{0}\': Unable to read file'.format(self.file_path))

    def _read_file(self):
        with open(self.file_path, 'r') as f:
            return f.read().splitlines()

    def parse_tree_data(self, data):
        ret = []

        for i, line in enumerate(data):
            if line:
                try:
                    ret += [self.__parse_line(line)]
                except ParseError as exc:
                    raise ParseError('{0} {1}'.format(str(exc), i+1))

        return ret

    def __parse_line(self, line):
        ret  = {}

        match = REGEX_OP.search(line)

        if not match:
            raise ParseError('\'{0}\': Unable to parse line'.format(line))

        ret['op'] = match.group(OP) if match.group(OP) else ''
        ret['dst'] = match.group(REG_DST) if match.group(REG_DST) else ''
        ret['src'] = match.group(REG_SRC) if match.group(REG_SRC) else ''
        ret['data'] = line

        return ret

    def search(self, binaries):
        try:
            return self.tree.traverse(binaries)
        except OperationError as exc:
            debug.error(str(exc))

class Tree:
    def __init__(self, gadfinder, ops):
        self.gadfinder = gadfinder
        self.ops = ops

    def traverse(self, binaries):
        ret = []

        state, gadgets = self._get_candidates(binaries)
        chains = self._construct_chains(state)

        for chain in chains:
            temp = self._construct_ropchain(chain, gadgets)
            ret += [temp]

        return ret

    def _construct_ropchain(self, chain, gadgets):
        ret = []

        for op, gads in zip(self.ops, gadgets):
            temp = []
            for gad in gads:
                if gad['op'] == op['op']:
                    if op['dst'] and op['src']:
                        if type(gad['dst']) == list:
                            equal_dst = chain[op['dst']] in gad['dst']
                        else:
                            equal_dst = chain[op['dst']] == gad['dst']

                        if type(gad['src']) == list:
                            equal_src = chain[op['src']] in gad['src']
                        else:
                            equal_src = chain[op['src']] == gad['src']

                        if equal_dst and equal_src:
                            temp += [gad]
                    elif op['dst']:
                        if type(gad['dst']) == list:
                            if chain[op['dst']] in gad['dst']:
                                temp += [gad]
                        elif chain[op['dst']] == gad['dst']:
                            temp += [gad]
                    elif op['src']:
                        if type(gad['src']) == list:
                            if chain[op['src']] in gad['src']:
                                temp += [gad]
                        elif (chain[op['src']] == gad['src']):
                            temp += [gad]
                    else:
                        temp += [gad]
            temp_op = copy.deepcopy(op)
            temp_op[op['dst']] = chain[op['dst']] if op['dst'] else ''
            temp_op[op['src']] = chain[op['src']] if op['src'] else ''
            ret += [{'op': temp_op, 'gads': temp}]

        return ret

    def _construct_chains(self, state):
        ret = []

        for key in state:
            if not state[key]:
                return ret

        combinations = self._get_combinations(state)

        for comb in combinations:
            if self._is_valid_comb(state, comb):
                if comb not in ret:
                    ret += [comb]

        return ret

    def _get_combinations(self, state):
        ret = []

        masks = self._get_possible_values(state)
        combinations = list(itertools.product(*[masks[key] for key in masks]))

        keys = list(masks.keys())

        for comb in combinations:
            sequence = {}
            for item, key in zip(comb, keys):
                sequence[key] = item
            ret += [sequence]

        return ret

    def _is_valid_comb(self, state, comb):
        if len(set([comb[key] for key in comb])) != len(comb):
            return False

        for op in self.ops:
            k = self.__get_comb(op)
            if all(item for item in k):
                reg1, reg2 = k
                to_find = (comb[reg1], comb[reg2])
                if to_find not in state[k]:
                    return False
            else:
                for key in comb:
                    if key in k:
                        index = key.index(key)
                        all_regs = [item[index] for item in state[k]]
                        if comb[key] not in all_regs:
                            return False

        return True

    def _get_possible_values(self, state):
        ret = {}

        for key in state:
            for i, reg in enumerate(key):
                if reg:
                    values = []
                    for value in state[key]:
                        values += [value[i]]

                    if reg in ret:
                        temp = ret[reg]
                        ret[reg] = list(set(temp + values))
                    else:
                        ret[reg] = list(set(values))
        return ret

    def _get_candidates(self, binaries):
        gads = []
        state = {}
        gadgets = self.gadfinder.find_all(binaries)
        regs = binary.Binary(binaries[0]).get_regs()

        for i, op in enumerate(self.ops):
            dst = op['dst'] if op['dst'] in regs else ''
            src = op['src'] if op['src'] in regs else ''
            temp = operation.Operation(op['op'], dst=dst, src=src)
            gads += [temp.get_gadgets(gadgets)]
            state = self.__update_state(state, op, gads[i])

        return state, gads

    def __update_state(self, state, op, op_gads):
        comb = self.__get_comb(op)

        if not state:
            state[comb] = self.__get_regs(op_gads)
        else:
            new_state = copy.deepcopy(state)

            if comb in state:
                filtered_regs = []
                regs = state[comb]
                new_regs = self.__get_regs(op_gads)

                for n_reg in new_regs:
                    if n_reg in regs:
                        filtered_regs += [n_reg]
            else:
                new_regs = self.__get_regs(op_gads)
                filtered_regs = self.__get_regs(op_gads)
                for index1, reg_comb in enumerate(comb):
                    if reg_comb:
                        for reg in state:
                            if reg_comb in reg:
                                index2 = reg.index(reg_comb)
                                for n_reg in new_regs:
                                    elem = n_reg[index1]
                                    if not self.__is_elem_present(elem, state[reg], index2):
                                        try:
                                            filtered_regs.remove(n_reg)
                                        except ValueError:
                                            pass

            new_state[comb] = filtered_regs

            for reg_comb in comb:
                for reg in state:
                    for index1, r_ in enumerate(reg):
                        if r_ and r_ in reg_comb:
                            index2 = comb.index(r_)
                            for p_reg in state[reg]:
                                elem = p_reg[index1]
                                if not self.__is_elem_present(elem, filtered_regs, index2):
                                    try:
                                        new_state[reg].remove(p_reg)
                                    except ValueError:
                                        pass

            state = new_state

        return state

    def __is_elem_present(self, elem, list_, index):
        for item in list_:
            if elem == item[index]:
                return True

        return False

    def __get_regs(self, gadgets):
        ret = []

        for gad in gadgets:
            if (type(gad['dst']) == str) and (type(gad['src']) == str):
                comb = (gad['dst'], gad['src'])
                # We're working with mask, filter explicit values (int)
                if comb not in ret and not any([x for x in comb if type(x) == int]):
                    ret += [comb]
            elif (type(gad['dst']) == list) and (type(gad['src']) == str):
                for item in gad['dst']:
                    comb = (item, gad['src'])
                    # We're working with mask, filter explicit values (int)
                    if comb not in ret and not any([x for x in comb if type(x) == int]):
                        ret += [comb]
            elif (type(gad['dst']) == list) and (type(gad['src']) == list):
                for item1 in gad['dst']:
                    for item2 in gad['src']:
                        comb = (item1, item2)
                        # We're working with mask, filter explicit values (int)
                        if comb not in ret and not any([x for x in comb if type(x) == int]):
                            ret += [comb]
            elif (type(gad['dst']) == str) and (type(gad['src']) == list):
                for item in gad['src']:
                    comb = (gad['dst'], item)
                    # We're working with mask, filter explicit values (int)
                    if comb not in ret and not any([x for x in comb if type(x) == int]):
                        ret += [comb]
        return ret

    def __get_comb(self, op):
        return (op['dst'], op['src'])

class ParseError(Exception):
    pass
