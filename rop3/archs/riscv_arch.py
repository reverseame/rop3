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
import capstone.riscv_const as riscv_const
from rop3.arch import Architecture
from rop3.search import aligned_scan, framed_aligned_scan

# ABI register names capstone prints for the integer file (x0 is the hardwired
# zero register and is not a usable destination, so it is excluded).
REGS: frozenset[str] = frozenset({
    'ra', 'sp', 'gp', 'tp',
    't0', 't1', 't2', 't3', 't4', 't5', 't6',
    's0', 'fp', 's1', 's2', 's3', 's4', 's5', 's6',
    's7', 's8', 's9', 's10', 's11',
    'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7',
})

# Unconditional transfers. `ret`/`jr`/`jalr` are indirect (register targets);
# `j`/`jal` are direct. Compressed variants share the same printed mnemonics.
UNCONDITIONAL_BRANCH_MNEMONICS: tuple[str, ...] = (
    'j', 'jal', 'jalr', 'jr',
    'c.j', 'c.jal', 'c.jalr', 'c.jr',
)

# Indirect branches usable as JOP terminations (a `ret` is handled as ROP).
JOP_TERMINATION_MNEMONICS: tuple[str, ...] = (
    'jr', 'jalr', 'c.jr', 'c.jalr',
)

CONDITIONAL_BRANCH_MNEMONICS: tuple[str, ...] = (
    'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu',
    'beqz', 'bnez', 'blez', 'bgez', 'bltz', 'bgtz',
    'c.beqz', 'c.bnez',
)

# Store instructions: their first operand is the source register (rs2), not a
# destination -- they write memory, not a register.
STORE_MNEMONICS: tuple[str, ...] = (
    'sb', 'sh', 'sw', 'sd',
    'fsb', 'fsh', 'fsw', 'fsd', 'fsq',
    'c.sw', 'c.sd', 'c.swsp', 'c.sdsp',
    'c.fsw', 'c.fsd', 'c.fswsp', 'c.fsdsp',
)

# Instructions whose first register operand is read, not written -- so they
# have no destination register in operand 0. Everything else that has a leading
# register operand writes it (rd is always the first operand on RISC-V).
NON_WRITING_MNEMONICS: frozenset[str] = frozenset(
    STORE_MNEMONICS + CONDITIONAL_BRANCH_MNEMONICS
    + ('jr', 'c.jr', 'ret', 'c.jalr')
)

# Integer loads. A RISC-V ROP gadget must reload ra (x1) from the stack before
# `ret`; the canonical restore is `ld ra, off(sp)` (or compressed `c.ldsp`).
LOAD_MNEMONICS: frozenset[str] = frozenset({
    'ld', 'lw', 'lwu', 'lh', 'lhu', 'lb', 'lbu',
    'c.ldsp', 'c.lwsp', 'c.ld', 'c.lw',
})


class RISCV_Architecture(Architecture):
    '''
    RISC-V (RV64I) architecture. `compressed` reflects the presence of the C
    (compressed) extension in the binary (ELF `e_flags & EF_RISCV_RVC`): it
    both enables capstone's 16-bit decoding and relaxes the instruction
    alignment from 4 to 2 bytes.
    '''

    def __init__(self, compressed: bool = False):
        self._compressed = bool(compressed)

    @property
    def scan_name(self) -> str:
        return 'framed aligned'

    @property
    def parallelizable(self) -> bool:
        # The linear sweep is single-pass and not chunkable by byte offset.
        return False

    @property
    def default_depth(self) -> int:
        # A framed ROP gadget needs at least `ld ra, off(sp) ; ret` (8 bytes);
        # real epilogues run longer. Give ~6 base instructions of room (more
        # when compressed) so the default finds real gadgets.
        return 24

    def scan(self, opcodes, base_vaddr, depth, disasm, is_valid_gadget,
             terminations=None, accept_candidate=None, accept_match=None,
             framed=True):
        # `ret` jumps through ra, so a useful ROP gadget must first restore ra
        # from the stack: the aligned sweep gated on that frame load (the
        # default). `--no-frame` drops the requirement (plain aligned sweep).
        # Byte `terminations`/`accept_match` (Galileo-only) are unused here.
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
    def compressed(self) -> bool:
        ''' Whether the binary advertises the C (compressed) extension. '''
        return self._compressed

    @property
    def name(self) -> str:
        return 'RISC-V RV64' + (' (compressed)' if self._compressed else '')

    # --- Byte-level gadget terminations -------------------------------------

    def get_rop_terminations(self, **kwargs):
        # `ret` is the canonical return, encoded as `jalr x0, 0(ra)` (0x00008067)
        # or, with the C extension, `c.jr ra` (0x8082).
        ret = [{'bytes': b'\x67\x80\x00\x00', 'size': 4}]      # jalr x0, 0(ra)
        if self._compressed:
            ret.append({'bytes': b'\x82\x80', 'size': 2})     # c.jr ra
        return ret

    def get_jop_terminations(self):
        # `jalr rd, imm(rs1)` has opcode 0b1100111 (0x67) in the low 7 bits, so
        # its first byte is 0x67 or 0xe7 (rd bit 0 sits at bit 7). The candidate
        # is re-validated after disassembly, so a broad match is safe.
        ret = [{'bytes': b'[\x67\xe7][\x00-\xff]{3}', 'size': 4}]
        if self._compressed:
            # c.jr/c.jalr rs1: bits[15:13]=100, bits[6:2]=0, bits[1:0]=10.
            ret.append({'bytes': b'[\x02\x82][\x80-\x9f]', 'size': 2})
        return ret

    # --- Mnemonic classification --------------------------------------------

    @property
    def rop_termination_mnemonics(self) -> tuple[str, ...]:
        return ('ret',)

    def _terminates_rop(self, insn, terminations) -> bool:
        # The canonical return is `ret` (jalr x0, 0(ra)). Capstone renders the
        # compressed form `c.jr ra` under its own mnemonic, so recognize it by
        # its target register; other `c.jr <rs>` are plain indirect jumps.
        if insn.mnemonic == 'ret':
            return True
        return insn.mnemonic == 'c.jr' and insn.op_str.strip() == 'ra'

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
        return capstone.CS_ARCH_RISCV

    @property
    def mode(self):
        mode = capstone.CS_MODE_RISCV64
        if self._compressed:
            mode |= capstone.CS_MODE_RISCVC
        return mode

    @property
    def address_size(self) -> int:
        return 8

    @property
    def alignment(self) -> int:
        # Base ISA instructions are 4-byte aligned; the C extension allows
        # 2-byte alignment.
        return 2 if self._compressed else 4

    @property
    def op_reg(self):
        return riscv_const.RISCV_OP_REG

    @property
    def op_mem(self):
        return riscv_const.RISCV_OP_MEM

    @property
    def op_imm(self):
        return riscv_const.RISCV_OP_IMM

    @property
    def sp(self) -> str:
        return 'sp'

    @property
    def bp(self) -> str:
        # RISC-V has no dedicated frame pointer; s0 (x8) is used by convention.
        return 's0'

    def is_valid_abstract_reg(self, name: str | int) -> bool:
        return str(name) in REGS

    def is_return(self, insn) -> bool:
        ''' Whether `insn` is a return (`ret` / `c.jr ra`). Drives the framed
            scan's requirement that ROP gadgets restore ra from the stack. '''
        return self._terminates_rop(insn, self.rop_termination_mnemonics)

    def is_frame_load(self, insn) -> bool:
        ''' The framed-scan frame load on RISC-V is the ra restore. '''
        return self.is_ra_load(insn)

    def is_frame_prefix(self, insn) -> bool:
        ''' The ra restore frames a RISC-V ROP gadget, so an operation may
            follow it (e.g. `ld ra, off(sp) ; add a0, a1, a2 ; ret`). '''
        return self.is_ra_load(insn)

    def is_ra_load(self, insn) -> bool:
        ''' Whether `insn` loads ra (x1) from the stack, e.g. `ld ra, off(sp)`
            or `c.ldsp ra, off`. Capstone renders the base sp either as a memory
            operand's base (`ld`) or as a bare register operand (`c.ldsp`). '''
        if self.base_mnemonic(insn.mnemonic) not in LOAD_MNEMONICS:
            return False
        ops = insn.operands
        if not ops or ops[0].type != self.op_reg or insn.reg_name(ops[0].reg) != 'ra':
            return False
        for op in ops[1:]:
            if op.type == self.op_mem and insn.reg_name(op.mem.base) == 'sp':
                return True
            if op.type == self.op_reg and insn.reg_name(op.reg) == 'sp':
                return True
        return False

    def written_registers(self, insn) -> set:
        # capstone implements neither regs_access() nor per-operand access
        # flags for RISC-V, so derive the destination from the encoding: rd is
        # always the first operand and is written by every instruction except
        # stores, branches and register-reading jumps.
        if self.base_mnemonic(insn.mnemonic) in NON_WRITING_MNEMONICS:
            return set()
        ops = insn.operands
        if ops and ops[0].type == self.op_reg:
            return {ops[0].reg}
        return set()
