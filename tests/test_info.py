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

import rop3.utils as utils
from rop3 import Rop3
from rop3.binary import Binary

from conftest import (build_minimal_elf, EM_386, EM_X86_64, EM_RISCV,
                      EF_RISCV_RVC, ET_DYN)

_riscv = pytest.mark.skipif(not hasattr(capstone, 'CS_ARCH_RISCV'),
                            reason='capstone build without RISC-V support')


def _write(tmp_path, data, name='b.elf'):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_describe_x86_64(tmp_path):
    path = _write(tmp_path, build_minimal_elf(64, EM_X86_64, b'\x90\xc3', 0x1000, ET_DYN))
    info = Binary(path, None).describe()
    assert info['format'] == 'ELF64'
    assert info['arch'] == 'x86-64'
    assert info['bits'] == 64
    assert info['alignment'] == 1
    assert info['endianness'] == 'little'
    assert info['sections'] == [{'name': '.text', 'vaddr': 0x1000, 'size': 2}]


def test_describe_x86_32(tmp_path):
    path = _write(tmp_path, build_minimal_elf(32, EM_386, b'\x90\xc3', 0x8048000, ET_DYN))
    info = Binary(path, None).describe()
    assert (info['format'], info['arch'], info['bits']) == ('ELF32', 'x86', 32)
    assert info['alignment'] == 1


@_riscv
def test_describe_riscv_noncompressed(tmp_path):
    path = _write(tmp_path, build_minimal_elf(64, EM_RISCV, b'\x67\x80\x00\x00',
                                              0x1000, ET_DYN))
    info = Binary(path, None).describe()
    assert info['arch'] == 'RISC-V RV64'
    assert info['alignment'] == 4


@_riscv
def test_describe_riscv_compressed_reports_alignment_2(tmp_path):
    # rv64gc reports e_flags == 0x5; the RVC bit relaxes alignment to 2.
    path = _write(tmp_path, build_minimal_elf(64, EM_RISCV, b'\x82\x80', 0x1000,
                                              ET_DYN, e_flags=0x5))
    info = Binary(path, None).describe()
    assert info['arch'] == 'RISC-V RV64 (compressed)'
    assert info['alignment'] == 2


def test_binary_info_lines_formatting():
    info = {
        'filename': '/some/where/foo.elf', 'format': 'ELF64', 'arch': 'x86-64',
        'bits': 64, 'endianness': 'little', 'alignment': 1,
        'entry': 0x1040, 'image_base': 0x0,
        'sections': [{'name': '.text', 'vaddr': 0x1000, 'size': 16}],
    }
    lines = utils.binary_info_lines(info)
    assert lines[0] == 'foo.elf: ELF64, x86-64, 64-bit, little-endian'
    assert 'entry: 0x1040' in lines[1] and 'instruction alignment: 1 byte(s)' in lines[1]
    assert lines[2] == '1 executable section(s), 16 bytes total'
    assert lines[3] == '  .text @ 0x1000 (16 bytes)'


def test_binary_info_lines_tolerates_missing_optional_fields():
    ''' A loader without get_info() (no entry/endianness) still renders. '''
    info = {
        'filename': 'x.bin', 'format': None, 'arch': 'x86', 'bits': 32,
        'alignment': 1,
        'sections': [{'name': None, 'vaddr': 0x400000, 'size': 4}],
    }
    lines = utils.binary_info_lines(info)
    assert lines[0] == 'x.bin: unknown, x86, 32-bit'
    assert lines[1] == 'instruction alignment: 1 byte(s)'
    assert lines[-1] == '  section @ 0x400000 (4 bytes)'


def test_rop3_describe_one_per_binary(tmp_path):
    p1 = _write(tmp_path, build_minimal_elf(64, EM_X86_64, b'\x90\xc3', 0x1000, ET_DYN), 'a.elf')
    p2 = _write(tmp_path, build_minimal_elf(32, EM_386, b'\x90\xc3', 0x8048000, ET_DYN), 'b.elf')
    infos = Rop3([p1, p2]).describe()
    assert [i['arch'] for i in infos] == ['x86-64', 'x86']
