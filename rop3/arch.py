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

from abc import ABC, abstractmethod
from typing import List, Any

import capstone

from rop3.search import galileo_scan, backwards_framed_search

# Default search depth in bytes when the user does not pass --depth. Tuned for
# x86, whose 1-3 byte instructions pack several into a short gadget. Fixed-width
# ISAs (RISC-V, AArch64) need a larger window to fit even a two-instruction
# gadget and override `Architecture.default_depth`.
DEFAULT_DEPTH = 5

class Architecture(ABC):
    """Abstract base class for all architectures"""

    # --- Byte-level gadget terminations (architecture specific) -------------

    @abstractmethod
    def get_rop_terminations(self, **kwargs) -> List[dict]:
        pass

    @abstractmethod
    def get_jop_terminations(self) -> List[dict]:
        pass

    # --- Mnemonic classification (data supplied by each architecture) -------

    @property
    @abstractmethod
    def rop_termination_mnemonics(self) -> tuple[str, ...]:
        ''' Mnemonics that legitimately terminate a ROP gadget (e.g. ret). '''
        pass

    @property
    @abstractmethod
    def jop_termination_mnemonics(self) -> tuple[str, ...]:
        ''' Mnemonics that legitimately terminate a JOP gadget (indirect
            branch through a register). '''
        pass

    @property
    @abstractmethod
    def unconditional_branch_mnemonics(self) -> tuple[str, ...]:
        ''' Unconditional control-flow transfers that make an intermediate
            instruction split the gadget (jmp/call, j/jal, ...). '''
        pass

    @property
    @abstractmethod
    def conditional_branch_mnemonics(self) -> tuple[str, ...]:
        ''' Conditional branches; only rejected when undeterministic gadgets
            are disallowed. '''
        pass

    @property
    def mnemonic_prefixes(self) -> tuple[str, ...]:
        ''' Instruction-level prefixes that decorate a mnemonic but do not
            change its class (e.g. x86 `bnd`, `notrack`). Default: none. '''
        return ()

    def base_mnemonic(self, mnemonic: str) -> str:
        ''' The mnemonic with any architecture prefixes stripped. '''
        for part in mnemonic.split():
            if part not in self.mnemonic_prefixes:
                return part
        return mnemonic

    def _has_ret_imm(self, decodes: Any, terminations: tuple[str, ...]) -> bool:
        ''' Whether any instruction is a return-with-immediate (which returns
            at that point, shortening the gadget). Architectures without such a
            form (RISC-V) inherit False. '''
        return False

    def _terminates_rop(self, insn: Any, terminations: tuple[str, ...]) -> bool:
        ''' Whether the final instruction returns control the way a ROP
            gadget's tail does. Default: an exact terminator-mnemonic match.
            Architectures whose return shares a mnemonic with other branches
            (RISC-V `c.jr ra`) override this to inspect the operand. '''
        return insn.mnemonic in terminations

    def is_valid_jop_last(self, insn: Any) -> bool:
        ''' Whether the final instruction is a usable indirect branch target
            (i.e. through a register/memory operand, not an immediate). '''
        return True

    def _rop_terminations(self, **kwargs) -> tuple[str, ...]:
        return self.rop_termination_mnemonics

    # --- Shared gadget-validity algorithm (template methods) ----------------

    def is_valid_rop_gadget(self, decodes: Any,
                            allow_undeterministic: bool = False,
                            allow_ret_imm: bool = False, **kwargs) -> bool:
        if not decodes:
            return False

        terminations = self._rop_terminations(**kwargs)

        if not self._terminates_rop(decodes[-1], terminations):
            return False

        # A return-with-immediate returns at that point, so a gadget containing
        # one anywhere behaves as a ret-imm gadget; exclude it unless allowed.
        if not allow_ret_imm and self._has_ret_imm(decodes, terminations):
            return False

        # Every instruction but the gadget's own terminator: a termination or
        # branch here ends the gadget early, so it may not appear -- including at
        # position 0 (a leading `ret` makes `ret ; mov rax, rdi ; ret` degenerate:
        # execution stops at the first ret, and the real gadget is the shorter
        # one after it). The trailing terminator is exempt; a bare `ret` (its own
        # terminator, nothing before it) stays valid.
        intermediates = decodes[:-1]

        # Leading/intermediate termination (there is already a shorter version).
        if any(self.base_mnemonic(ins.mnemonic) in terminations for ins in intermediates):
            return False
        # Multibranch unconditional (jmp/call, j/jal).
        if any(self.base_mnemonic(ins.mnemonic) in self.unconditional_branch_mnemonics
               for ins in intermediates):
            return False
        # Multibranch conditional (je/jne, beq/bne).
        if not allow_undeterministic and any(
                ins.mnemonic in self.conditional_branch_mnemonics for ins in intermediates):
            return False
        return True

    def is_valid_jop_gadget(self, decodes: Any,
                            allow_undeterministic: bool = False) -> bool:
        if not decodes:
            return False

        terminations = self.jop_termination_mnemonics
        last = decodes[-1]

        if self.base_mnemonic(last.mnemonic) not in terminations:
            return False

        if not self.is_valid_jop_last(last):
            return False

        # Every instruction but the terminator (see is_valid_rop_gadget): a
        # branch/return at position 0 or in the middle ends the gadget early.
        intermediates = decodes[:-1]

        # Multibranch unconditional (jmp/call, j/jal).
        if any(self.base_mnemonic(ins.mnemonic) in self.unconditional_branch_mnemonics
               for ins in intermediates):
            return False
        # Multibranch conditional (je/jne, beq/bne).
        if not allow_undeterministic and any(
                ins.mnemonic in self.conditional_branch_mnemonics for ins in intermediates):
            return False
        return True

    # --- Capstone / ABI descriptors -----------------------------------------

    @property
    def name(self) -> str:
        ''' Human-readable architecture name, used for verbose reporting. '''
        return type(self).__name__

    @property
    def scan_name(self) -> str:
        ''' Short descriptive label for the gadget-search strategy this
            architecture uses -- for verbose reporting only, never dispatch. '''
        return 'galileo'

    @property
    def parallelizable(self) -> bool:
        ''' Whether this architecture's scan can be split into byte-offset
            chunks and run across worker processes (see
            GadFinder._scan_parallel). Only the Galileo backward walk supports
            it; the linear-sweep strategies run single-threaded. '''
        return True

    @property
    def default_depth(self) -> int:
        ''' Search depth in bytes used when the user does not pass --depth.
            Fixed-width ISAs override this: on RISC-V a framed ROP gadget needs
            at least `ld ra, off(sp) ; ret` (8 bytes), so the x86 default of
            DEFAULT_DEPTH would find nothing. '''
        return DEFAULT_DEPTH

    def splits_gadget(self, insn) -> bool:
        """
        Whether `insn` may not appear *inside* a gadget -- an intermediate
        control-flow transfer that would end it early: an unconditional branch or
        return, or a conditional branch. The gadget's own terminator is exempt
        (the abstract-gadget search checks only the instructions before it).
        """
        return (self.base_mnemonic(insn.mnemonic) in self.unconditional_branch_mnemonics
                or insn.mnemonic in self.conditional_branch_mnemonics)

    def _ropblock_scan(self, opcodes, base_vaddr, depth, disasm,
                       accept_candidate=None):
        ''' Abstract-gadget backward search (search.backwards_framed_search)
            wired with this architecture's own ropblock predicates; yields
            ``(vaddr, raw, decodes, frame)``. '''
        yield from backwards_framed_search(
            opcodes, base_vaddr, depth, self.alignment, disasm,
            self.is_pc_reg_write, self.ropblock_branch_reg,
            self.is_stack_load, self.clobbers_reg, self.is_frame_instruction,
            splits=self.splits_gadget, accept_candidate=accept_candidate)

    def scan(self, opcodes, base_vaddr, depth, disasm, is_valid_gadget,
             terminations=None, accept_candidate=None, accept_match=None,
             framed=True, ropblock=False):
        '''
        Yield this architecture's gadgets within one executable section as
        ``(vaddr, raw, decodes, frame)`` tuples (`frame` is the per-instruction
        framing mask, non-None only for the abstract-gadget search). Each
        architecture wires the search strategy (see rop3.search) that fits its
        ISA; the finder calls this uniformly and never branches on the
        architecture.

        The default is the Galileo backward walk -- required on variable-length
        (x86) ISAs, where gadgets hide inside longer instructions -- driven by
        the byte-pattern `terminations` the finder supplies. `accept_match`
        partitions terminations across parallel chunks (see _scan_parallel) and
        is ignored by strategies that do not chunk. `framed` is honored only by
        architectures with a framed scan (AArch64, RISC-V); Galileo ignores it.
        `ropblock` selects the abstract-gadget backward search instead.
        '''
        if ropblock:
            yield from self._ropblock_scan(opcodes, base_vaddr, depth, disasm,
                                           accept_candidate=accept_candidate)
            return
        for vaddr, raw, decodes in galileo_scan(
                opcodes, base_vaddr, terminations, depth, self.alignment, disasm,
                is_valid_gadget, accept_match=accept_match,
                accept_candidate=accept_candidate):
            yield vaddr, raw, decodes, None

    @property
    @abstractmethod
    def arch(self) -> int:
        pass

    @property
    @abstractmethod
    def mode(self) -> int:
        pass

    @property
    @abstractmethod
    def address_size(self) -> int:
        ''' Pointer width in bytes (4 for 32-bit, 8 for 64-bit). Drives
            address packing/formatting independently of the capstone mode
            constant (which is not a clean 32/64 flag on every architecture). '''
        pass

    @property
    def alignment(self) -> int:
        ''' Minimum instruction alignment in bytes. Gadgets may only start (and
            terminate) at addresses that are a multiple of this value. x86 is
            byte-aligned (1); RISC-V is 4-byte aligned, or 2-byte when the
            compressed (C) extension is present. '''
        return 1

    @property
    @abstractmethod
    def op_reg(self) -> int:
        pass

    @property
    @abstractmethod
    def op_mem(self) -> int:
        pass

    @property
    @abstractmethod
    def op_imm(self) -> int:
        pass

    @property
    @abstractmethod
    def sp(self) -> str:
        pass

    @property
    @abstractmethod
    def bp(self) -> str:
        pass

    @property
    def flags(self) -> str | None:
        """
        Name of the architecture's condition/flags register, spelled as capstone
        reports it (e.g. x86-64 'rflags', x86-32 'eflags', AArch64 'nzcv'), or
        None when the architecture has no flags register (RISC-V).
        """
        return None

    def normalize_reg(self, name: str | int) -> str:
        """
        Standard instance method. Base implementation just returns the name,
        but specific architectures can override this
        """
        return str(name)

    @abstractmethod
    def is_valid_abstract_reg(self, name: str | int) -> bool:
        """
        Returns whether a register can be used as an abstract one in the
        architecture
        """
        pass

    def first_insn_has_complex_mem(self, decodes) -> bool:
        """
        Returns True if the first instruction uses a complex memory addressing
        mode (e.g. base + index*scale). Default: False
        """
        return False

    def is_frame_prefix(self, insn) -> bool:
        """
        Whether `insn` may appear in a gadget's frame prologue -- the leading
        run of instructions that an operation is allowed to follow. When
        matching an operation, this prologue is skipped, so the operation's
        first instruction must be the first instruction after it (position 0
        when the prologue is empty). Default: no prologue (the operation must be
        the gadget's first instruction). RISC-V overrides this to allow the ra
        restore that frames a real ROP gadget.
        """
        return False

    def is_return(self, insn) -> bool:
        """
        Whether `insn` returns control the way a ROP gadget's tail does (x86
        ret/retf, AArch64/RISC-V `ret`). The framed scan uses it to require a
        preceding frame load, and the symbolic analyzer to find each gadget's
        terminator. Default: no return recognition; every architecture that has
        a return overrides this.
        """
        return False

    def is_stack_pivot(self, insn) -> bool:
        """
        Whether `insn` redirects the stack pointer other than by the implicit
        adjustment of a natural stack operation. The architecture-neutral case
        is an explicit stack-pointer *destination* operand -- `mov sp, *`,
        `add/sub sp, *`, `pop rsp`, AArch64 `mov sp, x0`. Push/pop and the
        load/store writeback that frames a gadget adjust the stack pointer
        implicitly (their destination operand is another register) and are not
        pivots. Architectures with an implicit pivot instruction (x86 `leave`)
        override to add it.
        """
        ops = insn.operands
        if not ops or ops[0].type != self.op_reg:
            return False
        return (self.normalize_reg(insn.reg_name(ops[0].reg))
                == self.normalize_reg(self.sp))

    def is_frame_instruction(self, insn) -> bool:
        """
        Whether `insn` is a *position-independent* framing instruction -- a frame
        prologue prefix, a return, or a PC-writing terminator.
        Marks the prologue/epilogue of a gadget: dimmed in the gadget view, and
        (for an abstract gadget) skipped by operation matching. The data-flow
        prologue -- the stack load of the terminator's branch register -- is
        marked separately by the search, which knows that register.
        """
        return (self.is_frame_prefix(insn) or self.is_return(insn)
                or self.is_pc_reg_write(insn))

    def is_pc_reg_write(self, insn) -> bool:
        """
        Whether `insn` is a ropblock terminator: it writes the program counter
        from a register (an indirect jmp/br through a register) or, for x86,
        pops it straight off the stack (`ret`). Default: none.
        """
        return False

    def ropblock_branch_reg(self, insn):
        """
        The register a ropblock terminator branches through, or None when the
        terminator pops the program counter straight off the stack and is thus
        its own prologue (x86 `ret`). Default: None.
        """
        return None

    def is_stack_load(self, insn, reg) -> bool:
        """
        Whether `insn` is a ropblock prologue for `reg`: it loads `reg` from the
        stack (`pop reg`, `ldr reg, [sp]`, `ld reg, off(sp)`). Default: no.
        """
        return False

    def clobbers_reg(self, insn, reg) -> bool:
        """
        Whether `insn` overwrites `reg` (breaking a prologue -> terminator
        data-flow). Default: no.
        """
        return False

    def is_frame_load(self, insn) -> bool:
        """
        Whether `insn` establishes the gadget's return frame by restoring the
        return target from the stack (e.g. RISC-V `ld ra, off(sp)`). The framed
        scan emits a return gadget only once its run covers one. Default: none.
        """
        return False

    def written_registers(self, insn) -> set:
        """
        Capstone register ids written by `insn`, explicit and implicit. The
        default relies on capstone's ``regs_access()`` helper (implemented for
        x86); architectures for which capstone does not provide it override
        this. Used to compute a gadget's clobbered ("side effect") registers.
        """
        try:
            _, writes = insn.regs_access()
        except capstone.CsError:
            # regs_access() is unimplemented for this architecture; fall back
            # to the (implicit-only) detail array.
            writes = ()
        return set(insn.regs_write) | set(writes)

    def read_registers(self, insn) -> set:
        """
        Capstone register ids read by `insn`, explicit and implicit. Mirror of
        written_registers: prefers regs_access() and falls back to the
        (implicit-only) detail array where capstone does not implement it. Used
        for the read set of a gadget's tuple representation.
        """
        try:
            reads, _ = insn.regs_access()
        except capstone.CsError:
            reads = ()
        return set(insn.regs_read) | set(reads)

class ArchitectureSingleton:
    def __init__(self):
        self._arch = None
        self.allow_reg_aliases = False

    def initialize(self, arch: Architecture):
        if self._arch is not None:
            return
        self._arch = arch

    def reset(self) -> None:
        ''' Clear the current architecture (mainly for tests / library use) '''
        self._arch = None
        self.allow_reg_aliases = False

    def is_initialized(self) -> bool:
        return self._arch is not None

    def matches(self, arch: Architecture) -> bool:
        return self._arch is not None and \
            (self._arch.arch, self._arch.mode) == (arch.arch, arch.mode)

    @property
    def arch(self) -> Architecture:
        if self._arch is None:
            raise RuntimeError("Architecture context accessed before initialization.")
        return self._arch

arch_singleton = ArchitectureSingleton()
