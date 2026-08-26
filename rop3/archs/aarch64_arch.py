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
import capstone.arm64_const as arm64_const
from rop3.arch import Architecture
from rop3.search import aligned_scan, framed_aligned_scan

# ABI register names capstone prints for the 64-bit integer file. xzr (the
# hardwired zero register) is not a usable destination and is excluded.
REGS: frozenset[str] = frozenset(
    {f'x{i}' for i in range(31)} | {'sp', 'lr', 'fp'}
)

# Direct (b/bl) and indirect (br/blr) branches. All split a gadget.
UNCONDITIONAL_BRANCH_MNEMONICS: tuple[str, ...] = (
    'b', 'bl', 'br', 'blr', 'ret'
)

# Indirect branches usable as JOP terminations (a `ret` is handled as ROP).
JOP_TERMINATION_MNEMONICS: tuple[str, ...] = (
    'br', 'blr',
)

CONDITIONAL_BRANCH_MNEMONICS: tuple[str, ...] = (
    'b.eq', 'b.ne', 'b.cs', 'b.hs', 'b.cc', 'b.lo', 'b.mi', 'b.pl',
    'b.vs', 'b.vc', 'b.hi', 'b.ls', 'b.ge', 'b.lt', 'b.gt', 'b.le',
    'b.al', 'b.nv',
    'cbz', 'cbnz', 'tbz', 'tbnz',
)

# First byte of a `RET/BR/BLR Rn`: the register number's low 3 bits sit in bits
# 7:5, so byte 0 is (Rn & 7) << 5.
_RN_LOW = b'[\x00\x20\x40\x60\x80\xa0\xc0\xe0]'


class AArch64_Architecture(Architecture):
    '''
    AArch64 (ARM64). A fixed-width (every instruction is 4 bytes), naturally
    4-byte-aligned ISA, so gadgets can only begin on instruction boundaries and
    the aligned linear-sweep search both suffices and is faster than Galileo
    (see `scan`).
    '''

    @property
    def scan_name(self) -> str:
        return 'aligned'

    @property
    def parallelizable(self) -> bool:
        # The linear sweep is single-pass and not chunkable by byte offset.
        return False

    @property
    def default_depth(self) -> int:
        # Fixed 4-byte instructions: allow ~5 of them so multi-instruction
        # gadgets are found, not just a lone `ret`.
        return 20

    def scan(self, opcodes, base_vaddr, depth, disasm, is_valid_gadget,
             terminations=None, accept_candidate=None, accept_match=None,
             framed=True):
        # Fixed-width, naturally aligned ISA: the aligned linear sweep finds the
        # same gadgets as Galileo, faster, with no unintended gadgets. When
        # framed, keep only gadgets that restore the return address (lr/x30)
        # from the stack before returning. Byte `terminations`/`accept_match`
        # (Galileo-only) are unused here.
        if framed:
            yield from framed_aligned_scan(
                opcodes, base_vaddr, depth, self.alignment, disasm,
                is_valid_gadget, self.is_frame_load, self.is_return,
                accept_candidate=accept_candidate)
        else:
            yield from aligned_scan(
                opcodes, base_vaddr, depth, self.alignment, disasm,
                is_valid_gadget, accept_candidate=accept_candidate)

    @property
    def name(self) -> str:
        return 'AArch64 (ARM64)'

    # --- Byte-level gadget terminations -------------------------------------
    # Only consulted if this architecture is ever routed through Galileo; the
    # legal scan finds terminations by disassembly. Provided for completeness.

    def get_rop_terminations(self, **kwargs):
        # RET Rn = 0xD65F0000 | (Rn << 5); defaults to x30 (0xD65F03C0).
        return [{'bytes': _RN_LOW + b'[\x00-\x03]\x5f\xd6', 'size': 4}]

    def get_jop_terminations(self):
        # BR Rn = 0xD61F0000 | (Rn << 5); BLR Rn = 0xD63F0000 | (Rn << 5).
        return [{'bytes': _RN_LOW + b'[\x00-\x03][\x1f\x3f]\xd6', 'size': 4}]

    # --- Mnemonic classification --------------------------------------------

    @property
    def rop_termination_mnemonics(self) -> tuple[str, ...]:
        return ('ret',)

    @property
    def jop_termination_mnemonics(self) -> tuple[str, ...]:
        return JOP_TERMINATION_MNEMONICS

    @property
    def unconditional_branch_mnemonics(self) -> tuple[str, ...]:
        return UNCONDITIONAL_BRANCH_MNEMONICS

    @property
    def conditional_branch_mnemonics(self) -> tuple[str, ...]:
        return CONDITIONAL_BRANCH_MNEMONICS

    # --- Capstone / ABI descriptors -----------------------------------------

    @property
    def arch(self):
        return capstone.CS_ARCH_ARM64

    @property
    def mode(self):
        return capstone.CS_MODE_ARM

    @property
    def address_size(self) -> int:
        return 8

    @property
    def alignment(self) -> int:
        return 4

    @property
    def op_reg(self):
        return arm64_const.ARM64_OP_REG

    @property
    def op_mem(self):
        return arm64_const.ARM64_OP_MEM

    @property
    def op_imm(self):
        return arm64_const.ARM64_OP_IMM

    @property
    def sp(self) -> str:
        return 'sp'

    @property
    def bp(self) -> str:
        return 'x29'

    def is_valid_abstract_reg(self, name: str | int) -> bool:
        return str(name) in REGS

    def is_return(self, insn) -> bool:
        ''' A `ret` (branches to lr/x30). Drives the framed scan's requirement
            that a ROP gadget restore lr from the stack. '''
        return self.base_mnemonic(insn.mnemonic) == 'ret'

    def is_frame_load(self, insn) -> bool:
        ''' Whether `insn` restores the return address (lr/x30) from the stack,
            e.g. `ldr x30, [sp, #off]` or `ldp x29, x30, [sp], #off`. Capstone
            exposes lr as a register operand and sp as the memory base. '''
        if self.base_mnemonic(insn.mnemonic) not in ('ldr', 'ldp'):
            return False
        ops = insn.operands
        loads_lr = any(op.type == self.op_reg and insn.reg_name(op.reg) in ('x30', 'lr')
                       for op in ops)
        from_stack = any(op.type == self.op_mem and insn.reg_name(op.mem.base) in ('sp', 'wsp')
                         for op in ops)
        return loads_lr and from_stack
