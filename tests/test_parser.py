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

import pytest

import rop3.parser as parser


def test_get_ops_loads_roplang(x64):
    ops = parser.Parser().get_ops()
    names = {getattr(o, 'name', None) for o in ops}
    # a representative subset that must always be present
    for expected in ('mov', 'lc', 'jmp', 'lsd', 'not', 'xor'):
        assert expected in names


def test_get_op_unknown_raises(x64):
    with pytest.raises(parser.ParserException):
        parser.Parser().get_op('definitely_not_an_op')


def test_composite_op_is_recognised(x64):
    ''' lsd is a composite (compose:) operation. '''
    resolved = parser.Parser().get_op('lsd')
    assert isinstance(resolved, parser.CompositeOperation)
    assert resolved.steps


def _jmp_mov_op1():
    ''' jmp is a composite whose first step is `mov REG_BP, src`. '''
    jmp = parser.Parser().get_op('jmp')
    assert isinstance(jmp, parser.CompositeOperation)
    mov = next(s for s in jmp.steps if s['operation'] == 'mov')
    return mov['op1']


def test_reg_aliases_resolved_per_arch_x64(x64):
    ''' REG_BP must resolve to rbp on x64 (not stay as the alias). '''
    assert _jmp_mov_op1() == 'rbp'


def test_reg_aliases_resolved_per_arch_x86(x86):
    assert _jmp_mov_op1() == 'ebp'
