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

import rop3.operation as operation

from conftest import make_gadget


def test_lc_matches_pop_reg(x64):
    ''' lc (load constant) matches `pop <reg> ; ret`. '''
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
        make_gadget(b'\x90\xc3', 0x1020),   # nop ; ret  (no match)
    ]
    matched = operation.Operation('lc').filter_gadgets(gadgets)
    texts = {g.text_repr for g in matched}
    assert 'pop rax ; ret' in texts
    assert 'pop rbx ; ret' in texts
    assert 'nop ; ret' not in texts


def test_lc_with_dst_filter(x64):
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
    ]
    matched = operation.Operation('lc', dst='rax').filter_gadgets(gadgets)
    assert [g.text_repr for g in matched] == ['pop rax ; ret']
    assert matched[0].dst == 'rax'


def test_filter_gadgets_empty_input(x64):
    assert operation.Operation('lc').filter_gadgets([]) == []


def test_operand_parse_imm_supports_hex_and_negative(x64):
    ''' Regression: immediates parsed with int(x, 0). '''
    op = operation.Operand('rax')
    assert op._parse_imm('0xffffffff') == 0xffffffff
    assert op._parse_imm('-1') == -1
    assert op._parse_imm(42) == 42
