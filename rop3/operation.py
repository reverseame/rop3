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
import capstone.x86_const as x86_const

import rop3.parser as parser

class Operation:
    def __init__(self, op, dst=None, src=None):
        self.name = op
        self.dst = dst
        self.src = src
        self.template = parser.Parser().get_op(op)
        self.template.set_dst(dst)
        self.template.set_src(src)

    def filter_gadgets(self, gadgets):
        ret = []

        if not gadgets:
            return ret

        arch = gadgets[0]['arch']
        mode = gadgets[0]['mode']
        md = capstone.Cs(arch, mode)
        md.detail = True

        for gadget in gadgets:
            decodes = list(md.disasm(gadget['bytes'], gadget['vaddr']))
            (equal, set_, dst, src) = self.template.is_equal(decodes)
            if equal:
                gadget['op'] = self.template.name
                gadget['dst'] = self.dst if self.dst else dst
                gadget['src'] = self.src if self.src else src
                gadget['sides'] = self.get_side_effects(decodes, len(set_))
                ret.append(gadget)

        return ret

    def get_side_effects(self, decodes, offset):
        ret = {}
        regs = []

        for decode in decodes[offset:-1]:
            ins_reg = []
            # Implicit writes
            ins_reg.extend([decode.reg_name(reg) for reg in decode.regs_write])
            # Explicit writes
            (_, regs_write) = decode.regs_access()
            ins_reg.extend([decode.reg_name(reg) for reg in regs_write])
            if ins_reg:
                regs.append(ins_reg)
        if regs:
            ret['offset'] = offset
            ret['regs'] = regs

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

        for i, item in enumerate(self.items):
            if type(item) == Instruction:
                (equal, ins_dst, ins_src) = item.is_equal(decodes[i])
                if not equal:
                    return (False, dst, src)
                dst = ins_dst if not dst else dst
                src = ins_src if not src else src
                
            elif type(item) == OperationTemplate:
                (equal, _, op_dst, op_src) = item.is_equal(decodes[i:])
                if not equal:
                    return (False, dst, src)
                dst = op_dst if not dst else dst
                src = op_src if not src else src
            else:
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
        if self.is_reg() or self.is_mem():
            self.reg, self.generic = self._parse_reg(operand)
        elif self.is_imm():
            self.imm = self._parse_imm(operand)

    def __str__(self):
        if self.is_reg() or self.is_mem():
            return self.reg
        elif self.is_imm():
            return str(self.imm)

    def _parse_type(self, reg):
        if reg[0] == '[' and reg[-1] == ']':
            return x86_const.X86_OP_MEM
        
        try:
            self._parse_imm(reg)
            return x86_const.X86_OP_IMM
        except (ValueError, TypeError):
            pass

        return x86_const.X86_OP_REG

    def _parse_reg(self, reg):
        generic = False

        if self.is_mem():
            reg = reg[1:-1]

        if reg in ['dst', 'src'] or reg.startswith('REG'):
            generic = True

        return reg, generic

    def _parse_imm(self, reg):
        return int(reg, 0)

    def is_reg(self):
        return self.type == x86_const.X86_OP_REG

    def is_mem(self):
        return self.type == x86_const.X86_OP_MEM

    def is_imm(self):
        return self.type == x86_const.X86_OP_IMM

    def is_dst(self):
        if self.is_reg() or self.is_mem():
            return self.reg == 'dst'

    def set_dst(self, dst):
        if self.is_dst():
            self.reg = dst
            self.generic = False

    def is_src(self):
        if self.is_reg() or self.is_mem():
            return self.reg == 'src'

    def set_src(self, src):
        if self.is_src():
            self.reg = src
            self.generic = False

    def is_equal(self, decode, operand):
        operand_reg = None

        if self.type != operand.type:
            return (False, operand_reg)

        if self.is_reg():
            operand_reg = decode.reg_name(operand.value.reg)
        elif self.is_mem():
            operand_reg = decode.reg_name(operand.value.mem.base)

        if not self.generic:
            if operand_reg != self.reg:
                return (False, operand_reg)
            
        return (True, operand_reg)
