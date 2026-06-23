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

import rop3.gadget as gadget_mod
from rop3.gadget import heuristic_basic_count

from conftest import make_gadget


def test_text_repr_and_equality():
    g1 = make_gadget(b'\x58\xc3', 0x1000)            # pop rax ; ret
    g2 = make_gadget(b'\x58\xc3', 0x2000)            # same text, different addr
    g3 = make_gadget(b'\x5b\xc3', 0x1000)            # pop rbx ; ret
    assert g1.text_repr == 'pop rax ; ret'
    assert g1 == g2                                  # equality is text-based
    assert hash(g1) == hash(g2)
    assert g1 != g3


def test_calculate_side_effects_excludes_dst_src_sp(x64):
    # inc rcx ; pop rbp ; ret
    g = make_gadget(b'\x48\xff\xc1\x5d\xc3', 0x1000)
    g.calculate_side_effects()
    assert 'rcx' in g.side_regs
    assert 'rbp' in g.side_regs


def test_calculate_side_effects_x86_uses_32bit_names(x86):
    # inc ecx ; pop ebp ; ret
    g = make_gadget(b'\x41\x5d\xc3', 0x1000, mode=capstone.CS_MODE_32)
    g.calculate_side_effects()
    assert 'ecx' in g.side_regs and 'ebp' in g.side_regs
    # no 64-bit names leak into a 32-bit context
    assert not ({'rcx', 'rbp'} & g.side_regs)


def test_subsumes(x64):
    base = make_gadget(b'\x58\xc3', 0x1000)          # pop rax ; ret
    noisy = make_gadget(b'\x58\x5b\xc3', 0x2000)     # pop rax ; pop rbx ; ret
    base.side_regs = set()
    noisy.side_regs = {'rbx'}
    assert base.subsumes(noisy)
    assert not noisy.subsumes(base)


def test_heuristic_basic_count(x64):
    g = make_gadget(b'\x58\xc3', 0x1000)
    g.side_regs = {'rbx'}
    # 1 side reg (<<2 = 4) + 2 instructions (<<1 = 4)
    assert heuristic_basic_count(g) == 8


def test_str_no_color_when_not_tty(x64, monkeypatch, capsys):
    ''' Regression for issue #14: no ANSI escapes on non-TTY output. '''
    monkeypatch.setattr('sys.stdout.isatty', lambda: False, raising=False)
    g = make_gadget(b'\x48\xff\xc1\xc3', 0x1000)     # inc rcx ; ret
    g.calculate_side_effects()
    text = str(g)
    assert 'modifies' in text
    assert '\033' not in text


def test_colorize_honors_tty_and_no_color(monkeypatch):
    monkeypatch.setattr('sys.stdout.isatty', lambda: True, raising=False)
    monkeypatch.delenv('NO_COLOR', raising=False)
    assert '\033' in gadget_mod._colorize('x')
    monkeypatch.setenv('NO_COLOR', '1')
    assert '\033' not in gadget_mod._colorize('x')
