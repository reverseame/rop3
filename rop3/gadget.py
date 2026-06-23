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
END_COLOR = '\033[0m'

def _colorize(text: str) -> str:
    ''' Wrap text in the warning color only when writing to a terminal and
        NO_COLOR is unset, so redirected/piped output stays clean. '''
    if sys.stdout.isatty() and not os.environ.get('NO_COLOR'):
        return f'{WARNING_COLOR}{text}{END_COLOR}'
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
    dst: str = None
    src: str = None
    side_regs: set[str] = field(init=False, default_factory=set)
    side_mem: set[str] = field(init=False, default_factory=set)

    def __post_init__(self):
        self.text_repr = ' ; '.join([f'{d.mnemonic} {d.op_str}' if d.op_str else \
                d.mnemonic for d in self.decodes])

    def has_dst(self) -> bool:
        return self.dst is not None

    def has_src(self) -> bool:
        return self.src is not None

    def calculate_side_effects(self) -> None:
        arch = arch_singleton.arch
        excluded = {arch.normalize_reg(r) for r in (self.dst, self.src, arch.sp) if r is not None}

        for decode in self.decodes:
            explicit = {decode.reg_name(r) for r in decode.regs_write}
            _, implicit_ids = decode.regs_access()
            implicit = {decode.reg_name(r) for r in implicit_ids}
            for reg in explicit | implicit:
                normalized = arch.normalize_reg(reg)
                if normalized not in excluded:
                    self.side_regs.add(normalized)

    def subsumes(self, rhs) -> bool:
        if str(self.dst) != str(rhs.dst):
            return False
        if str(self.src) != str(rhs.src):
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
        if self.side_mem:
            ret += f" (side mem = {self.side_mem})"
        ret += f" (count: {self.count})"

        return ret

    def __str__(self) -> str:
        ret = f"[{os.path.basename(self.filename)} @ {hex(self.vaddr)}]: "
        ret += self.text_repr
        if self.count and self.count > 1:
            ret += f" (x{self.count})"
        side_regs = list(self.side_regs)
        if len(side_regs) > 0:
            modifies = ', '.join(side_regs)
            ret += f" {_colorize(f'(modifies {modifies})')}"

        return ret

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

