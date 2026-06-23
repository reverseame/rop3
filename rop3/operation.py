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

import capstone
import dataclasses

from rop3.arch import arch_singleton

import rop3.parser as parser

from .gadget import Gadget

class Operation:
    def __init__(self, op, dst=None, src=None):
        self.name = op
        self.template = parser.Parser().get_op(op)
        self.dst = dst
        self.template.set_dst(dst)
        self.src = src
        self.template.set_src(src)

    def filter_gadgets(self, gadgets) -> list[Gadget]:
        ret = []

        if not gadgets:
            return ret

        arch = gadgets[0].arch
        mode = gadgets[0].mode

        for gadget in gadgets:
            (equal, set_, dst, src) = self.template.is_equal(gadget.decodes)
            if equal:
                ''' Annotate a copy so the shared input gadget is not mutated
                    (the same object may be filtered for several operations).
                    replace() also gives the copy fresh side-effect sets. '''
                matched = dataclasses.replace(
                    gadget,
                    op=self.template.name,
                    dst=self.dst if self.dst else dst,
                    src=self.src if self.src else src,
                )
                matched.calculate_side_effects()
                ret.append(matched)

        return ret

class OperationTemplate:
    def __init__(self, op):
        self.name = op
        self.sets = []

    def __iter__(self):
        for item in self.sets:
            yield item

    def add(self, set_):
        self.sets.append(set_)

    def set_dst(self, dst):
        if dst:
            for set_ in self.sets:
                set_.set_dst(dst)

    def set_src(self, src):
        if src:
            for set_ in self.sets:
                set_.set_src(src)

    def is_equal(self, decodes):
        dst = None
        src = None

        for set_ in self.sets:
            (equal, dst, src) = set_.is_equal(decodes)
            if equal:
                return (True, set_, dst, src)
        
        return (False, None, dst, src)

class Set:
    def __init__(self):
        self.items = []

    def __iter__(self):
        for item in self.items:
            yield item

    def __len__(self):
        return len(self.items)

    def __str__(self):
        return ' ; '.join([str(item) for item in self.items])

    def add(self, item):
        self.items.append(item)

    def set_dst(self, dst):
        if dst:
            for item in self.items:
                item.set_dst(dst)

    def set_src(self, src):
        if src:
            for item in self.items:
                item.set_src(src)

    def is_equal(self, decodes):
        dst = None
        src = None

        if len(decodes) < len(self.items):
            return (False, dst, src)

        for i, item in enumerate(self.items):
            if not isinstance(item, Instruction):
                return (False, dst, src)

            (equal, ins_dst, ins_src) = item.is_equal(decodes[i])
            if not equal:
                return (False, dst, src)

            if ins_dst is not None:
                if dst is None:
                    dst = ins_dst
                elif dst != ins_dst:
                    return (False, dst, src)
            if ins_src is not None:
                if src is None:
                    src = ins_src
                elif src != ins_src:
                    return (False, dst, src)

        return (True, dst, src)

class Instruction:
    def __init__(self, mnemonic):
        self.mnemonic = mnemonic
        self.operands = []

    def __iter__(self):
        for item in self.operands:
            yield item

    def __str__(self):
        operands = ', '.join([str(operand) for operand in self.operands])

        return f'{self.mnemonic} {operands}'
    
    def add(self, operand):
        self.operands.append(operand)

    def set_dst(self, dst):
        if dst:
            for operand in self.operands:
                operand.set_dst(dst)

    def set_src(self, src):
        if src:
            for operand in self.operands:
                operand.set_src(src)
        
    def is_equal(self, decode):
        dst = None
        src = None

        if self.mnemonic != decode.mnemonic:
            return (False, dst, src)

        if len(self.operands) != len(decode.operands):
            return (False, dst, src)

        for myoperand, operand in zip(self.operands, decode.operands):
            (equal, reg) = myoperand.is_equal(decode, operand)
            if not equal:
                return (False, dst, src)
            
            dst = reg if not dst and myoperand.is_dst() else dst
            src = reg if not src and myoperand.is_src() else src

        return (True, dst, src)

class Operand:
    def __init__(self, operand, value=None):
        self.value = value
        self.type = self._parse_type(operand)

    def __str__(self) -> str:
        if self.is_reg():
            return self.reg
        elif self.is_mem():
            return f"[{self.reg}]"
        else:
            return str(self.imm)

    def _parse_type(self, reg):
        self.generic = False
        reg_name = str(reg)
        if reg_name.startswith('[') and reg_name.endswith(']'):
            self.reg = reg[1:-1]
            if self.reg in ('dst', 'src') or self.reg.startswith('REG'):
                self.generic = True
            return arch_singleton.arch.op_mem

        self.reg = reg
        
        if reg in ('dst', 'src') or reg_name.startswith('REG'):
            self.generic = True
            return arch_singleton.arch.op_reg
            
        try:
            self.imm = self._parse_imm(reg)
            return arch_singleton.arch.op_imm
        except (ValueError, TypeError):
            return arch_singleton.arch.op_reg

    def _parse_imm(self, reg):
        if isinstance(reg, int):
            return reg
        return int(reg, 0)

    def is_reg(self):
        return self.type == arch_singleton.arch.op_reg

    def is_mem(self):
        return self.type == arch_singleton.arch.op_mem

    def is_imm(self):
        return self.type == arch_singleton.arch.op_imm

    def is_dst(self):
        if self.reg is not None:
            return self.reg == 'dst'
        return False

    def set_dst(self, dst):
        if self.is_dst():
            self.reg = dst
            self.generic = False
            self.type = arch_singleton.arch.op_reg

    def is_src(self):
        if self.reg is not None:
            return self.reg == 'src'
        return False

    def set_src(self, src):
        if self.is_src():
            self.generic = False
            try:
                self.imm = self._parse_imm(src)
                self.type = arch_singleton.arch.op_imm
            except (ValueError, TypeError):
                self.reg = src
                self.type = arch_singleton.arch.op_reg

    def is_equal(self, decode, operand):
        operand_reg = None

        if self.generic and self.is_src() and operand.type == arch_singleton.arch.op_imm:
            return (True, operand.value.imm)

        if self.type != operand.type:
            return (False, operand_reg)

        if self.is_reg():
            operand_reg = decode.reg_name(operand.value.reg)
        elif self.is_mem():
            operand_reg = decode.reg_name(operand.value.mem.base)
        elif self.is_imm():
            if operand.value.imm == self.imm:
                return (True, self.imm)
            else:
                return (False, self.imm)

        if not self.generic:
            if operand_reg != self.reg:
                return (False, operand_reg)

        return (True, operand_reg)

