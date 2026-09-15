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


def test_rop_terminations_exclude_ret_imm_by_default():
    arch = X64_Architecture()
    assert all(t['size'] == 1 for t in arch.get_rop_terminations())   # only plain ret
    assert any(t['size'] == 3 for t in arch.get_rop_terminations(include_ret_imm=True))


def test_x86_retf_terminator_only_with_include_retf():
    ''' retf is recognized as a ROP terminator only when far-return gadgets are
        requested (the x86-only include_retf option); plain ret always is. '''
    arch = X64_Architecture()
    assert 'ret' in arch._rop_terminations()
    assert 'retf' not in arch._rop_terminations()
    assert 'retf' in arch._rop_terminations(include_retf=True)


def test_include_retf_adds_retf_termination():
    arch = X64_Architecture()
    without = arch.get_rop_terminations()
    with_retf = arch.get_rop_terminations(include_retf=True)
    assert b'\xcb' in {t['bytes'] for t in with_retf}   # retf byte present
    assert b'\xcb' not in {t['bytes'] for t in without}


def test_is_valid_rop_gadget_retf_gating():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
    arch = X64_Architecture()
    retf = list(md.disasm(b'\x58\xcb', 0))              # pop rax ; retf
    assert not arch.is_valid_rop_gadget(retf)           # retf is not a plain ret
    assert arch.is_valid_rop_gadget(retf, include_retf=True)


def test_is_valid_rop_gadget_ret_imm_gating():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
    arch = X64_Architecture()
    ret_imm = list(md.disasm(b'\x58\xc2\x08\x00', 0))   # pop rax ; ret 8
    plain = list(md.disasm(b'\x58\xc3', 0))             # pop rax ; ret
    assert not arch.is_valid_rop_gadget(ret_imm)
    assert arch.is_valid_rop_gadget(ret_imm, allow_ret_imm=True)
    assert arch.is_valid_rop_gadget(plain)


def test_ret_imm_anywhere_gated():
    ''' A `ret <imm>` returns at that point. As the gadget's terminator it is a
        ret-imm gadget, gated by allow_ret_imm (see
        test_is_valid_rop_gadget_ret_imm_gating). Anywhere else it ends the
        gadget early -- a leading `ret <imm>` makes the trailing instructions
        dead ("prologue after prologue") -- so the gadget is rejected regardless
        of ret-imm being allowed; the standalone `ret <imm>` is found on its
        own. '''
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
    arch = X64_Architecture()
    lead_ret_imm = list(md.disasm(b'\xc2\x48\x89\xc3', 0))   # ret 0x8948 ; ret
    assert not arch.is_valid_rop_gadget(lead_ret_imm)
    assert not arch.is_valid_rop_gadget(lead_ret_imm, allow_ret_imm=True)
