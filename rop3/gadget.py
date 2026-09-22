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

from dataclasses import dataclass, field

from rop3.arch import arch_singleton

import os
import sys

WARNING_COLOR = '\033[93m'
FRAME_COLOR = '\033[90m'
END_COLOR = '\033[0m'

def _colorize(text: str, color: str = WARNING_COLOR) -> str:
    ''' Wrap text in `color` only when writing to a terminal and NO_COLOR is
        unset, so redirected/piped output stays clean. '''
    if sys.stdout.isatty() and not os.environ.get('NO_COLOR'):
        return f'{color}{text}{END_COLOR}'
    return text

@dataclass
class Gadget:
    filename: str = None
    arch: str = None
    mode: str = None
    vaddr: str = None
    decodes: list = None
    text_repr: str = None
    bytes: str = None
    count: int = None
    op: str = None
    dst: set = None    # concrete register names written (may overlap src)
    src: set = None    # concrete register names read (may overlap dst)
    symbol: str = None
    # Per-instruction frame mask (parallel to `decodes`): True where the
    # instruction is a prologue/epilogue framing instruction rather than the
    # operation body.
    frame: tuple = None
    side_regs: set[str] = field(init=False, default_factory=set)
    # Concrete registers bound to the operation's two operand slots.
    slot_op1: str = field(init=False, default=None)
    slot_op2: str = field(init=False, default=None)
    # Display form of the same two operand slot.
    disp_op1: str = field(init=False, default=None)
    disp_op2: str = field(init=False, default=None)

    def __post_init__(self):
        self.text_repr = ' ; '.join([f'{d.mnemonic} {d.op_str}' if d.op_str else \
                d.mnemonic for d in self.decodes])

    def calculate_side_effects(self) -> None:
        arch = arch_singleton.arch
        excluded = {arch.normalize_reg(arch.sp)}
        excluded |= {arch.normalize_reg(r) for r in (self.dst or ())}

        for decode in self.decodes:
            for reg in arch.written_registers(decode):
                normalized = arch.normalize_reg(decode.reg_name(reg))
                if normalized not in excluded:
                    self.side_regs.add(normalized)

    def _register_set(self, accessor) -> set[str]:
        ''' Normalized registers accessed by the whole gadget via `accessor`
            (arch.written_registers / arch.read_registers), excluding the stack
            pointer (every ret/pop touches it, so it is noise). '''
        arch = arch_singleton.arch
        sp = arch.normalize_reg(arch.sp)
        regs = set()
        for decode in self.decodes:
            for reg in accessor(decode):
                normalized = arch.normalize_reg(decode.reg_name(reg))
                if normalized != sp:
                    regs.add(normalized)
        return regs

    def tuple_repr(self) -> str:
        ''' The gadget as a tuple for --tuple output:
            <op_name, op1[, op2], written registers, read registers> '''
        arch = arch_singleton.arch
        written = self._register_set(arch.written_registers)
        read = self._register_set(arch.read_registers)

        parts = [self.op or '']
        for operand in (self.disp_op1, self.disp_op2):
            if operand is not None:
                parts.append(str(operand))
        parts.append('{' + ', '.join(sorted(written)) + '}')
        parts.append('{' + ', '.join(sorted(read)) + '}')
        return '\u27e8' + ', '.join(parts) + '\u27e9'

    def writes_reg(self, normalized_reg: str) -> bool:
        ''' Whether the gadget explicitly or implicitly writes normalized_reg. '''
        arch = arch_singleton.arch
        for decode in self.decodes:
            for reg in arch.written_registers(decode):
                if arch.normalize_reg(decode.reg_name(reg)) == normalized_reg:
                    return True
        return False

    def result_clobbered(self, matched_indices, dst_regs) -> bool:
        ''' Whether an instruction between the operation and the terminator
            overwrites the operation's result register, so it never reaches the
            ret (e.g. `add rax, rbx ; mov rax, rcx ; ret`). `matched_indices`
            are the matched instructions' positions, `dst_regs` the destination
            registers.

            Only registers the matched instructions actually write are guarded
            (a store leaves its result in memory, so it guards nothing). The
            terminator is excluded: its stack-pointer write is the exit
            mechanism, not a clobber, so `add rsp, 8 ; ret` is fine. Matches are
            contiguous, so only the tail after the last matched index is
            scanned. '''
        if not dst_regs:
            return False

        arch = arch_singleton.arch

        def writes(insn):
            return {arch.normalize_reg(insn.reg_name(r))
                    for r in arch.written_registers(insn)}

        produced = {reg for i in matched_indices for reg in writes(self.decodes[i])}
        # The stack pointer is never guarded. It is the control/exit register and
        # is *expected* to keep moving after the operation -- the ret's own pop,
        # and, for a stack pivot, the frame-restore writeback that follows the
        # pivot. Treating a later sp write as a clobber would reject every pivot,
        # e.g. AArch64 `mov sp, x29 ; ldp x29, x30, [sp], #16 ; ret` (the `ldp`
        # writeback re-writes sp) or x86 `mov rsp, rax ; pop rbp ; ret`.
        guarded = (set(dst_regs) & produced) - {arch.normalize_reg(arch.sp)}
        if not guarded:
            return False

        last = max(matched_indices)
        clobbered = {reg for insn in self.decodes[last + 1:-1] for reg in writes(insn)}
        return bool(guarded & clobbered)

    def subsumes(self, rhs) -> bool:
        if (self.dst or set()) != (rhs.dst or set()):
            return False
        if (self.src or set()) != (rhs.src or set()):
            return False
        if self.side_regs.issubset(rhs.side_regs):
            return True
        return False

    def __eq__(self, other) -> bool:
        return self.text_repr == other.text_repr

    def __hash__(self):
        return hash(self.text_repr)

    def __repr__(self) -> str:
        ret = f"[{os.path.basename(self.filename)} @ {hex(self.vaddr)}]: "
        ret += self.text_repr
        if self.dst:
            ret += f" (dst = {self.dst})"
        if self.src:
            ret += f" (src = {self.src})"
        if self.side_regs:
            ret += f" (side regs = {self.side_regs})"
        ret += f" (count: {self.count})"

        return ret

    def display_repr(self) -> str:
        ''' The gadget text with its prologue/epilogue framing instructions
            (the `frame` mask) dimmed, so the operation body stands out. Falls
            back to the plain text when no frame mask is known. '''
        if not self.frame:
            return self.text_repr
        parts = []
        for i, d in enumerate(self.decodes):
            text = f'{d.mnemonic} {d.op_str}' if d.op_str else d.mnemonic
            if i < len(self.frame) and self.frame[i]:
                text = _colorize(text, FRAME_COLOR)
            parts.append(text)
        return ' ; '.join(parts)

    def __str__(self) -> str:
        ret = f"[{os.path.basename(self.filename)} @ {hex(self.vaddr)}]: "
        ret += self.display_repr()
        if self.symbol:
            ret += f" <{self.symbol}>"
        if self.count and self.count > 1:
            ret += f" (x{self.count})"
        side_regs = list(self.side_regs)
        if len(side_regs) > 0:
            modifies = ', '.join(side_regs)
            ret += f" {_colorize(f'(modifies {modifies})')}"

        return ret

    def to_dict(self) -> dict:
        ''' Serializable representation for machine-readable output. '''
        return {
            'file': os.path.basename(self.filename),
            'vaddr': hex(self.vaddr),
            'gadget': self.text_repr,
            'instructions': [
                f'{d.mnemonic} {d.op_str}'.strip() for d in self.decodes
            ],
            'bytes': self.bytes.hex() if self.bytes is not None else None,
            'count': self.count,
            'symbol': self.symbol,
            'op': self.op,
            'dst': sorted(self.dst) if self.dst else None,
            'src': sorted(self.src) if self.src else None,
            'modifies': sorted(self.side_regs),
        }

def heuristic_basic_count(gadget: "Gadget") -> int:
    ''' Cost of a gadget (lower is better): a clobbered register costs 4, an
        instruction costs 2, so fewer side effects are preferred over fewer
        instructions. '''
    return 4 * len(gadget.side_regs) + 2 * len(gadget.decodes)

