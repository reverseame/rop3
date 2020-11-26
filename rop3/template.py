import re
import copy
import capstone.x86_const as x86_const

import rop3.utils as utils

class TemplateOp:
    def __init__(self, op, dst='', src=''):
        self.dst = dst
        self.src = src
        self.op_str = op
        self.op = self.get_op(op)

    def __iter__(self):
        for item in self.op:
            yield item

    def __str__(self):
        ret = ''

        for ins in self.op:
            ret += '{0} || '.format(str(ins))

        return ret[:-4]
    
    def __len__(self):
        return len(self.op)

    def get_op(self, op):
        try:
            ops = utils.get_ops()
            return self.parse_op(ops[op])
        except KeyError as exc:
            ops = ', '.join(sorted(ops.keys()))
            raise OperationError('\'{0}\': Operation not found among {1}'.format(op, ops)) from exc

    def parse_op(self, op):
        ret = []

        for set_ in op:
            chain = Chain()
            for ins in set_:
                chain.add(Instruction(ins, self.dst, self.src))
            ret += [chain]

        return ret

class Chain():
    def __init__(self):
        self.chain = []
        self.dst = ''
        self.src = ''

    def __iter__(self):
        for item in self.chain:
            yield item

    def __str__(self):
        ret = ''

        for item in self.chain:
            ret += '{0} ; '.format(str(item))

        return ret[:-3]

    def __len__(self):
        return len(self.chain)

    def add(self, item):
        self.chain += [item]

    def is_equal(self, decodes):
        # TODO: check when dst/src require some specific value and we'are working
        # on that register (--dst or --src)
        dst = ''
        src = ''

        for ins, decode in zip(self.chain, decodes):
            for my_operand, operand in zip(ins.operands, decode.operands):
                if my_operand.is_generic():
                    if my_operand.is_reg() or my_operand.is_mem():
                        if my_operand.is_dst() and not dst:
                            if operand.type == x86_const.X86_OP_REG:
                                dst = decode.reg_name(operand.value.reg)
                            elif operand.type == x86_const.X86_OP_IMM:
                                dst = operand.value.imm
                        elif my_operand.is_src() and not src:
                            if operand.type == x86_const.X86_OP_REG:
                                src = decode.reg_name(operand.value.reg)
                            elif operand.type == x86_const.X86_OP_IMM:
                                src = operand.value.imm

        chain = []

        for ins in self.chain:
            new_ins = copy.deepcopy(ins)
            new_ins.set_dst(dst)
            new_ins.set_src(src)
            chain += [new_ins]

        for ins, decode in zip(chain, decodes):
            for my_operand, operand in zip(ins.operands, decode.operands):
                if my_operand.is_reg() or my_operand.is_mem():
                    if type(my_operand.reg) == int and operand.reg:
                        continue
                    if my_operand.reg  != decode.reg_name(operand.value.reg):
                        return False
                elif my_operand.is_imm():
                    if my_operand.imm != operand.value.imm:
                        return False
                else:
                    return False

        for found_ins, ins in zip(chain, self.chain):
            if len(found_ins.operands) == 2:
                if (ins.operands[0].is_reg() or ins.operands[0].is_mem()) and\
                        (ins.operands[1].is_reg() or ins.operands[1].is_mem()):
                    if ins.operands[0].reg != ins.operands[1].reg:
                        if found_ins.operands[0].reg == found_ins.operands[1].reg:
                            return False

        return True, dst, src

    def get_values(self):
        ret = []

        for ins in self.chain:
            ret += ins.get_value()

        return ret

class Instruction:
    def __init__(self, ins, dst, src):
        self.mnemonic = ins['mnemonic']
        self.operands = self._parse_operands(ins, dst, src)

    def __str__(self):
        ret = '{0} '.format(self.mnemonic)

        for op in self.operands:
            ret += ' {0},'.format(str(op))

        return ret.replace('  ', ' ')[:-1]
 
    def _parse_operands(self, ins, dst, src):
        ret = []

        if 'op1' in ins:
            operand = Operand(ins['op1'])
            operand = self.__modify_operand(operand, dst, src)
            ret += [operand]

        if 'op2' in ins:
            operand = Operand(ins['op2'])
            operand = self.__modify_operand(operand, dst, src)
            ret += [operand]

        return ret

    def __modify_operand(self, operand, dst, src):
        if operand.type in [x86_const.X86_OP_REG, x86_const.X86_OP_MEM]:
            if operand.reg == 'dst' and dst:
                try:
                    operand.reg = int(dst, 0)
                except ValueError:
                    operand.reg = dst
            if operand.reg == 'src' and src:
                try:
                    operand.reg = int(src, 0)
                except ValueError:
                    operand.reg = src

        return operand

    def is_generic(self):
        return all([op.is_generic() for op in self.operands])

    def is_equal(self, decode):
        if self.mnemonic != decode.mnemonic:
            return False

        if len(self.operands) != len(decode.operands):
            return False

        for my_operand, operand in zip(self.operands, decode.operands):
            if my_operand.type != operand.type:
                '''
                User can provide a number to dst/src, so we need to check if
                disassembled operand is an IMM with that value
                '''
                if my_operand.is_reg() and type(my_operand.reg) == int:
                    if operand.type == x86_const.X86_OP_IMM:
                        if my_operand.reg == operand.value.imm:
                            continue

                '''
                Two operands could be equal if our dst/src operand is generic,
                and the disassembled operand is an IMM
                '''
                if (my_operand.is_reg() or my_operand.is_mem()) and \
                        my_operand.is_generic() and operand.type == x86_const.X86_OP_IMM:
                    continue

                return False

            if my_operand.is_reg() and operand.type == x86_const.X86_OP_REG:
                if not my_operand.is_generic():
                    if my_operand.reg != decode.reg_name(operand.value.reg):
                        return False

            if my_operand.is_mem() and operand.type == x86_const.X86_OP_MEM:
                if not my_operand.is_generic():
                    if my_operand.reg != decode.reg_name(operand.value.mem.base):
                        return False

            if my_operand.is_imm() and operand.type == x86_const.X86_OP_IMM:
                if my_operand.imm != operand.value.imm:
                    return False

        return True

    def get_value(self):
        ret = []

        for operand in self.operands:
            ret += [operand.get_value()]

        return [i for i in ret if i]

    def set_dst(self, dst):
        for op in self.operands:
            op.set_dst(dst)

    def set_src(self, src):
        for op in self.operands:
            op.set_src(src)

class Operand:
    def __init__(self, op):
        self.type = self.parse_type(op)
        if self.is_reg():
            if type(op) == str:
                self.reg = self.get_reg(op).group(0)
            elif type(op) == dict:
                self.reg = self.get_reg(op['reg']).group(0)
                if 'value' in op:
                    self.imm = op['value']
        elif self.is_imm():
            self.imm = op['value']
        elif self.is_mem():
            self.reg = self.get_mem(op).group(1)

    def __str__(self):
        ret = ''

        if self.is_reg():
            ret = self.reg
            if type(ret) == int:
                ret = '{0:#x}'.format(ret)
            try:
                ret += ' ({0})'.format(hex(self.imm))
            except AttributeError:
                pass
        elif self.is_imm():
            ret = '{0:#x}'.format(self.imm)
        elif self.is_mem():
            ret = '[{0}]'.format(self.reg)

        return ret

    def parse_type(self, op):
        if self.is_op_reg(op):
            return x86_const.X86_OP_REG
        if self.is_op_imm(op):
            return x86_const.X86_OP_IMM
        if self.is_op_mem(op):
            return x86_const.X86_OP_MEM

        raise InstructionError('Operand unrecognized: {0}'.format(op))

    def is_reg(self):
        return self.type == x86_const.X86_OP_REG

    def is_imm(self):
        return self.type == x86_const.X86_OP_IMM

    def is_mem(self):
        return self.type == x86_const.X86_OP_MEM

    def is_op_reg(self, op):
        value = None

        if type(op) == str:
            value = self.get_reg(op)
        elif type(op) == dict:
            if 'reg' in op:
                value = self.get_reg(op['reg'])

        return value != None

    def is_generic(self):
        try:
            return self.reg in ['dst', 'src']
        except AttributeError:
            pass

        return False

    def is_op_imm(self, op):
        if type(op) == dict and len(op) == 1:
            if 'value' in op:
                if type(op['value']) == int:
                    return True
                else:
                    raise InstructionError('Value number unrecognized: {0}'.format(op['value']))

        return False

    def is_op_mem(self, op):
        if type(op) == str:
            return (self.get_mem(op) != None)

        return False

    def is_dst(self):
        try:
            return self.reg == 'dst'
        except AttributeError:
            pass

        return False
    
    def is_src(self):
        try:
            return self.reg == 'src'
        except AttributeError:
            pass

        return False

    def get_reg(self, op):
        return re.match(r'^(?!\[).+(?!\[)$', op)

    def get_mem(self, op):
        return re.match(r'^\[(.+)\]$', op)

    def get_value(self):
        ret = {}

        if self.is_reg():
            try:
                ret[self.reg] = self.imm
            except AttributeError:
                pass

        return ret

    def set_dst(self, dst):
        if self.is_dst():
            self.reg = dst

    def set_src(self, src):
        if self.is_src():
            self.reg = src

class OperationError(Exception):
    pass

class InstructionError(Exception):
    pass
