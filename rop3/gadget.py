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
        ''' Formal tuple representation of the gadget:
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
        ''' Whether this gadget overwrites an operation's result before its
            terminator -- a "contradictory" gadget (e.g.
            `add rax, rbx ; mov rax, rcx ; ret`) whose result never reaches the
            ret. `matched_indices` are the positions of the operation's matched
            instructions and `dst_regs` its declared destination registers.

            `dst_regs` are intersected with the registers the matched
            instructions actually write, so a store (whose result is in memory)
            protects nothing and is never falsely rejected. A gadget is
            contradictory when an instruction between the last matched one and
            the terminator writes such a register.

            The final (terminating) instruction is excluded: it is control flow,
            and its incidental write to the stack pointer (an x86 `ret` pops) is
            the gadget's exit mechanism, not a clobber of the result -- so a
            stack-pointer operation like `add rsp, 8 ; ret` is not
            contradictory.

            `matched_indices` are contiguous (Set.is_equal matches a consecutive
            run), so only the tail after `max(matched_indices)` needs scanning;
            a clobber can never hide between two matched instructions. '''
        if not dst_regs:
            return False

        arch = arch_singleton.arch

        def writes(insn):
            return {arch.normalize_reg(insn.reg_name(r))
                    for r in arch.written_registers(insn)}

        produced = {reg for i in matched_indices for reg in writes(self.decodes[i])}
        guarded = set(dst_regs) & produced
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
    """
    Cost function — lower is better:
      side_regs  : each clobbered register costs 4   (shift-left 2)
      decodes    : each extra instruction costs 2    (shift-left 1)
    """
    return (
        (len(gadget.side_regs) << 2)   # 4 pts per clobbered register
      + (len(gadget.decodes)   << 1)   # 2 pts per instruction
    )

