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

# 'rax' -> {8: 'rax', 4: 'eax'},  'r8' -> {8: 'r8', 4: 'r8d'}
REG_BY_WIDTH: dict[str, dict[int, str]] = {
    canon: {
        info['bytes']: canon,
        **{size: name for name, size in info['sub'] if size in (4, 8)},
    }
    for canon, info in REGS.items()
}

MNEMONIC_PREFIXES: tuple[str, ...] = (
    'notrack', 'bnd',
)

UNCONDITIONAL_BRANCH_MNEMONICS: tuple[str, ...] = (
    'jmp', 'call', 'ret', 'retf'
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

class X86_Architecture(Architecture):
    # --- Mnemonic classification consumed by the shared validity algorithm ---

    @property
    def rop_termination_mnemonics(self) -> tuple[str, ...]:
        return ('ret',)

    @property
    def jop_termination_mnemonics(self) -> tuple[str, ...]:
        return ('jmp', 'call')

    @property
    def unconditional_branch_mnemonics(self) -> tuple[str, ...]:
        return UNCONDITIONAL_BRANCH_MNEMONICS

    @property
    def conditional_branch_mnemonics(self) -> tuple[str, ...]:
        return CONDITIONAL_BRANCH_MNEMONICS

    @property
    def mnemonic_prefixes(self) -> tuple[str, ...]:
        return MNEMONIC_PREFIXES

    def _has_ret_imm(self, decodes, terminations: tuple[str, ...]) -> bool:
        # A `ret <imm>` / `retf <imm>` carries an immediate operand and returns
        # at that point, so a gadget containing one anywhere behaves as a
        # ret-imm gadget.
        return any(self.base_mnemonic(ins.mnemonic) in terminations and ins.operands
                   for ins in decodes)

    def is_valid_jop_last(self, insn) -> bool:
        # The \xff byte pattern can appear inside an imm operand of another
        # instruction (e.g. e9 .. ff e0 ..). After disassembly, an immediate
        # target is not a usable indirect branch.
        return bool(insn.operands) and insn.operands[0].type != x86_const.X86_OP_IMM

    def _rop_terminations(self, include_retf: bool = False, **kwargs) -> tuple[str, ...]:
        # retf is a valid ROP terminator only when far-return gadgets are asked
        # for; x86 is the only architecture with this form.
        if include_retf:
            return self.rop_termination_mnemonics + ('retf',)
        return self.rop_termination_mnemonics

    def get_rop_terminations(self, include_retf: bool = False, include_ret_imm: bool = False, **kwargs):
        ret = [{'bytes': b'\xc3', 'size': 1}]              # ret
        if include_ret_imm:
            ret.append({'bytes': b'\xc2[\x00-\xff]{2}', 'size': 3})   # ret <imm>
        if include_retf:
            ret.append({'bytes': b'\xcb', 'size': 1})     # retf
            if include_ret_imm:
                ret.append({'bytes': b'\xca[\x00-\xff]{2}', 'size': 3})   # retf <imm>

        return ret

    def get_jop_terminations(self):
        return [
            {'bytes': b'\xff[\x20\x21\x22\x23\x26\x27]{1}', 'size': 2},        # jmp  [reg]
            {'bytes': b'\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}', 'size': 2},    # jmp  [reg]
            {'bytes': b'\xff[\x10\x11\x12\x13\x16\x17]{1}', 'size': 2},        # jmp  [reg]
            {'bytes': b'\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}', 'size': 2}     # call [reg]
        ]

    @property
    def name(self) -> str:
        return 'x86'

    @property
    def arch(self):
        return capstone.CS_ARCH_X86

    @property
    def mode(self):
        return capstone.CS_MODE_32

    @property
    def address_size(self) -> int:
        return 4

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

    @property
    def flags(self) -> str:
        return 'eflags'

    def first_insn_has_complex_mem(self, decodes) -> bool:
        first = decodes[0]
        for op in first.operands:
            if op.type == x86_const.X86_OP_MEM and op.mem.index != 0:
                return True
        return False

    def is_return(self, insn) -> bool:
        ''' An x86 gadget tail returns with a near or far return (ret/retf). '''
        return self.base_mnemonic(insn.mnemonic) in ('ret', 'retf')

    def is_stack_pivot(self, insn) -> bool:
        m = self.base_mnemonic(insn.mnemonic)
        if m == 'leave':          # mov rsp, rbp ; pop rbp -- an implicit sp write
            return True
        if m == 'push':           # push rsp reads sp as source; its adjust is implicit
            return False
        return super().is_stack_pivot(insn)

    @property
    def _canonical_width(self) -> int:
        """Register width (in bytes) used to display/normalize register names"""
        return 4

    def normalize_reg(self, name: str) -> str:
        entry = REG_ALIASES.get(str(name))
        if not entry:
            return str(name)
        canon = entry[0]
        return REG_BY_WIDTH.get(canon, {}).get(self._canonical_width, canon)

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
    def name(self) -> str:
        return 'x86-64'

    @property
    def mode(self):
        return capstone.CS_MODE_64

    @property
    def address_size(self) -> int:
        return 8

    @property
    def _canonical_width(self) -> int:
        return 8

    @property
    def sp(self) -> str:
        return 'rsp'

    @property
    def bp(self) -> str:
        return 'rbp'

    @property
    def flags(self) -> str:
        return 'rflags'

    def is_valid_abstract_reg(self, name: str | int) -> bool:
        """
        Only accept 8 byte registers
        """
        entry = REG_ALIASES.get(str(name))
        if entry and entry[1] == 8:
            return True
        return False

