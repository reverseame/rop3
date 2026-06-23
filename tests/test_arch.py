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
import pytest

from rop3.arch import arch_singleton, ArchitectureSingleton
from rop3.archs.x86_arch import (
    X86_Architecture, X64_Architecture, REG_BY_WIDTH,
)


def test_singleton_initialize_and_matches():
    s = ArchitectureSingleton()
    assert not s.is_initialized()
    s.initialize(X64_Architecture())
    assert s.is_initialized()
    assert s.matches(X64_Architecture())
    assert not s.matches(X86_Architecture())


def test_singleton_initialize_is_sticky():
    ''' initialize() is a no-op once set (single-arch run guarantee). '''
    s = ArchitectureSingleton()
    s.initialize(X64_Architecture())
    s.initialize(X86_Architecture())
    assert s.matches(X64_Architecture())


def test_arch_accessed_before_init_raises():
    s = ArchitectureSingleton()
    with pytest.raises(RuntimeError):
        _ = s.arch


def test_arch_modes_and_pointers():
    assert X86_Architecture().mode == capstone.CS_MODE_32
    assert X64_Architecture().mode == capstone.CS_MODE_64
    assert (X86_Architecture().sp, X86_Architecture().bp) == ('esp', 'ebp')
    assert (X64_Architecture().sp, X64_Architecture().bp) == ('rsp', 'rbp')


@pytest.mark.parametrize('alias,expected', [
    ('rax', 'eax'), ('eax', 'eax'), ('ax', 'eax'), ('al', 'eax'),
    ('rbp', 'ebp'), ('r8', 'r8d'), ('r8d', 'r8d'), ('r14', 'r14d'),
])
def test_normalize_reg_x86_is_32bit(alias, expected):
    assert X86_Architecture().normalize_reg(alias) == expected


@pytest.mark.parametrize('alias,expected', [
    ('rax', 'rax'), ('eax', 'rax'), ('al', 'rax'),
    ('rbp', 'rbp'), ('r8d', 'r8'), ('r14', 'r14'),
])
def test_normalize_reg_x64_is_64bit(alias, expected):
    assert X64_Architecture().normalize_reg(alias) == expected


def test_normalize_reg_passthrough_unknown():
    ''' Abstract / unknown register names are returned unchanged. '''
    assert X64_Architecture().normalize_reg('REG1') == 'REG1'
    assert X86_Architecture().normalize_reg('dst') == 'dst'


def test_reg_by_width_table():
    assert REG_BY_WIDTH['rax'] == {8: 'rax', 4: 'eax'}
    assert REG_BY_WIDTH['r8'] == {8: 'r8', 4: 'r8d'}


def test_is_valid_abstract_reg_width():
    assert X64_Architecture().is_valid_abstract_reg('rax')
    assert not X64_Architecture().is_valid_abstract_reg('eax')
    assert X86_Architecture().is_valid_abstract_reg('eax')
    assert not X86_Architecture().is_valid_abstract_reg('rax')
