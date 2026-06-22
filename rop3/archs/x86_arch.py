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
from rop3.arch import Architecture

REGS: dict[str, dict] = {
    'rax': {'bytes': 8, 'sub': [('eax', 4), ('ax', 2), ('ah', 1), ('al', 1)]},
    'rbx': {'bytes': 8, 'sub': [('ebx', 4), ('bx', 2), ('bh', 1), ('bl', 1)]},
    'rcx': {'bytes': 8, 'sub': [('ecx', 4), ('cx', 2), ('ch', 1), ('cl', 1)]},
    'rdx': {'bytes': 8, 'sub': [('edx', 4), ('dx', 2), ('dh', 1), ('dl', 1)]},
    'rsi': {'bytes': 8, 'sub': [('esi', 4), ('si', 2), ('sil', 1)]},
    'rdi': {'bytes': 8, 'sub': [('edi', 4), ('di', 2), ('dil', 1)]},
    'rsp': {'bytes': 8, 'sub': [('esp', 4), ('sp', 2), ('spl', 1)]},
    'rbp': {'bytes': 8, 'sub': [('ebp', 4), ('bp', 2), ('bpl', 1)]},
    'r8':  {'bytes': 8, 'sub': [('r8d',  4), ('r8w',  2), ('r8b',  1)]},
    'r9':  {'bytes': 8, 'sub': [('r9d',  4), ('r9w',  2), ('r9b',  1)]},
    'r10': {'bytes': 8, 'sub': [('r10d', 4), ('r10w', 2), ('r10b', 1)]},
    'r11': {'bytes': 8, 'sub': [('r11d', 4), ('r11w', 2), ('r11b', 1)]},
    'r12': {'bytes': 8, 'sub': [('r12d', 4), ('r12w', 2), ('r12b', 1)]},
    'r13': {'bytes': 8, 'sub': [('r13d', 4), ('r13w', 2), ('r13b', 1)]},
    'r14': {'bytes': 8, 'sub': [('r14d', 4), ('r14w', 2), ('r14b', 1)]},
    'r15': {'bytes': 8, 'sub': [('r15d', 4), ('r15w', 2), ('r15b', 1)]},
}

# 'eax' -> ('rax', 4),  'al' -> ('rax', 1), 'rax' -> ('rax', 8)
REG_ALIASES: dict[str, tuple[str, int]] = {
    alias: (canon, size)
    for canon, info in REGS.items()
    for alias, size in info['sub'] + [(canon, info['bytes'])]
}

MNEMONIC_PREFIXES: tuple[str, ...] = (
    'notrack', 'bnd',
)

UNCONDITIONAL_BRANCH_MNEMONICS: tuple[str, ...] = (
    'jmp', 'call',
)

CONDITIONAL_BRANCH_MNEMONICS: tuple[str, ...] = (
    'je', 'jne', 'jz', 'jnz',
    'jg', 'jge', 'jl', 'jle',
    'ja', 'jae', 'jb', 'jbe',
    'jo', 'jno', 'js', 'jns',
    'jp', 'jnp',
    'jcxz', 'jecxz', 'jrcxz',
    'loop', 'loope', 'loopne',
)

def _base_mnemonic(mnemonic: str) -> str:
    parts = mnemonic.split()
    for part in parts:
        if part not in MNEMONIC_PREFIXES:
            return part
    return mnemonic


class X86_Architecture(Architecture):
    def get_rop_terminations(self, include_extra: bool = False):
        ret = []
        ret.extend([
            {'bytes': b'\xc3', 'size': 1},                 # ret
            {'bytes': b'\xc2[\x00-\xff]{2}', 'size': 3},   # ret <imm>
        ])
        if include_extra:
            ret.extend([
                {'bytes': b'\xcb', 'size': 1},                 # retf
                {'bytes': b'\xca[\x00-\xff]{2}', 'size': 3}    # retf <imm>
            ])

        return ret

    def get_jop_terminations(self, include_extra: bool = False):
        return [
            {'bytes': b'\xff[\x20\x21\x22\x23\x26\x27]{1}', 'size': 2},        # jmp  [reg]
            {'bytes': b'\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}', 'size': 2},    # jmp  [reg]
            {'bytes': b'\xff[\x10\x11\x12\x13\x16\x17]{1}', 'size': 2},        # jmp  [reg]
            {'bytes': b'\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}', 'size': 2}     # call [reg]
        ]

    @property
    def arch(self):
        return capstone.CS_ARCH_X86

    @property
    def mode(self):
        return capstone.CS_MODE_32

    def is_valid_rop_gadget(self, decodes, include_extra: bool = False, allow_undeterministic: bool = False):
        if include_extra:
            terminations = ('ret', 'retf')
        else:
            terminations = ('ret',)

        if decodes[-1].mnemonic not in terminations:
            return False

        # Intermediate operation checks
        intermediates = decodes[1:-1]

        # Intermediate ret (there is already a shorter version of the gadget)
        if [ins for ins in intermediates if _base_mnemonic(ins.mnemonic) in terminations]:
            return False

        # Multibranch unconditional (jmp, call)
        if [ins for ins in intermediates if _base_mnemonic(ins.mnemonic) in UNCONDITIONAL_BRANCH_MNEMONICS]:
            return False
        # Multibranch conditional (je, jne)
        if not allow_undeterministic and [ins for ins in intermediates if ins.mnemonic in CONDITIONAL_BRANCH_MNEMONICS]:
            return False
        return True

    def is_valid_jop_gadget(self, decodes, include_extra: bool = False, allow_undeterministic: bool = False):
        terminations = ('jmp', 'call')
        last = decodes[-1]
        
        if _base_mnemonic(last.mnemonic) not in terminations:
            return False

        # The \xff byte pattern can appear inside an imm operand of another
        # instruction (e.g. e9 .. ff e0 ..). After disassembly, filter those out.
        if not last.operands or last.operands[0].type == x86_const.X86_OP_IMM:
            return False

        # Intermediate operation checks
        intermediates = decodes[1:-1]

        # Multibranch unconditional (jmp, call)
        if [ins for ins in intermediates if _base_mnemonic(ins.mnemonic) in UNCONDITIONAL_BRANCH_MNEMONICS]:
            return False
        # Multibranch conditional (je, jne)
        if not allow_undeterministic and [ins for ins in intermediates if ins.mnemonic in CONDITIONAL_BRANCH_MNEMONICS]:
            return False

        return True

    @property
    def op_reg(self):
        return x86_const.X86_OP_REG

    @property
    def op_mem(self):
        return x86_const.X86_OP_MEM

    @property
    def op_imm(self):
        return x86_const.X86_OP_IMM

    @property
    def sp(self) -> str:
        return 'esp'

    @property
    def bp(self) -> str:
        return 'ebp'

    def first_insn_has_complex_mem(self, decodes) -> bool:
        first = decodes[0]
        for op in first.operands:
            if op.type == x86_const.X86_OP_MEM and op.mem.index != 0:
                return True
        return False

    def normalize_reg(self, name: str) -> str:
        entry = REG_ALIASES.get(str(name))
        if entry:
            return entry[0]
        return str(name)

    def is_valid_abstract_reg(self, name: str | int) -> bool:
        """
        Only accept 4 byte registers
        """
        entry = REG_ALIASES.get(str(name))
        if entry and entry[1] == 4:
            return True
        return False

class X64_Architecture(X86_Architecture):
    @property
    def mode(self):
        return capstone.CS_MODE_64

    @property
    def sp(self) -> str:
        return 'rsp'

    @property
    def bp(self) -> str:
        return 'rbp'

    def is_valid_abstract_reg(self, name: str | int) -> bool:
        """
        Only accept 8 byte registers
        """
        entry = REG_ALIASES.get(str(name))
        if entry and entry[1] == 8:
            return True
        return False

