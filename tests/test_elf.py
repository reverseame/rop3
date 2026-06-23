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

import rop3.binaries.elf as elfmod
import rop3.binary as binary
from rop3.archs.x86_arch import X86_Architecture, X64_Architecture

from conftest import build_minimal_elf, EM_386, EM_X86_64, ET_DYN

TEXT = b'\x58\xc3'   # pop rax ; ret


def test_elf_detects_x64():
    data = build_minimal_elf(64, EM_X86_64, TEXT, 0x1000, ET_DYN)
    assert isinstance(elfmod.ELF(data, None).get_arch(), X64_Architecture)


def test_elf_detects_x86():
    data = build_minimal_elf(32, EM_386, TEXT, 0x8048000, ET_DYN)
    assert isinstance(elfmod.ELF(data, None).get_arch(), X86_Architecture)


def test_elf_exec_section_extraction():
    data = build_minimal_elf(64, EM_X86_64, TEXT, 0x1000, ET_DYN)
    secs = elfmod.ELF(data, None).get_exec_sections()
    assert len(secs) == 1
    assert secs[0]['vaddr'] == 0x1000
    assert secs[0]['opcodes'] == TEXT


def test_elf_base_relocation_pie():
    ''' Issue #13: --base must relocate ELF (ET_DYN image base is 0). '''
    data = build_minimal_elf(64, EM_X86_64, TEXT, 0x1000, ET_DYN)
    secs = elfmod.ELF(data, '0x400000').get_exec_sections()
    assert secs[0]['vaddr'] == 0x401000


def test_elf_no_base_keeps_addresses():
    data = build_minimal_elf(64, EM_X86_64, TEXT, 0x1000, ET_DYN)
    secs = elfmod.ELF(data, None).get_exec_sections()
    assert secs[0]['vaddr'] == 0x1000


def test_binary_dispatches_elf_by_magic(tmp_path):
    data = build_minimal_elf(64, EM_X86_64, TEXT, 0x1000, ET_DYN)
    path = tmp_path / 'fake.elf'
    path.write_bytes(data)
    b = binary.Binary(str(path), None)
    assert isinstance(b.get_arch(), X64_Architecture)
    assert b.get_exec_sections()[0]['opcodes'] == TEXT


def test_binary_unknown_format_raises(tmp_path):
    path = tmp_path / 'junk.bin'
    path.write_bytes(b'not a real binary header')
    with pytest.raises(binary.BinaryException):
        binary.Binary(str(path), None)
