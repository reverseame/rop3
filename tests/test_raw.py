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

import rop3.binaries.raw as rawmod
import rop3.binary as binary
import rop3.args as args
from rop3.archs.x86_arch import X86_Architecture, X64_Architecture
from rop3.archs.riscv_arch import RISCV_Architecture
from rop3.archs.aarch64_arch import AArch64_Architecture

TEXT = b'\x58\xc3'   # pop rax ; ret


# --- Raw loader unit tests (no Binary/file involved) ----------------------

def test_raw_detects_x64():
    assert isinstance(rawmod.Raw(TEXT, None, 'x86_64').get_arch(), X64_Architecture)


def test_raw_detects_x86():
    arch = rawmod.Raw(TEXT, None, 'x86').get_arch()
    # X64 subclasses X86, so exclude it explicitly.
    assert isinstance(arch, X86_Architecture) and not isinstance(arch, X64_Architecture)


def test_raw_detects_aarch64():
    assert isinstance(rawmod.Raw(TEXT, None, 'aarch64').get_arch(), AArch64_Architecture)


def test_raw_detects_riscv64_uncompressed():
    arch = rawmod.Raw(TEXT, None, 'riscv64').get_arch()
    assert isinstance(arch, RISCV_Architecture) and arch.alignment == 4


def test_raw_detects_riscv64_compressed():
    arch = rawmod.Raw(TEXT, None, 'riscv64c').get_arch()
    assert isinstance(arch, RISCV_Architecture) and arch.alignment == 2


def test_raw_arch_aliases():
    assert isinstance(rawmod.Raw(TEXT, None, 'amd64').get_arch(), X64_Architecture)
    assert isinstance(rawmod.Raw(TEXT, None, 'arm64').get_arch(), AArch64_Architecture)


def test_raw_arch_is_case_insensitive():
    assert isinstance(rawmod.Raw(TEXT, None, 'X86_64').get_arch(), X64_Architecture)


def test_raw_whole_file_is_one_section():
    secs = rawmod.Raw(TEXT, None, 'x86_64').get_exec_sections()
    assert len(secs) == 1
    assert secs[0]['name'] == 'raw'
    assert secs[0]['vaddr'] == 0
    assert secs[0]['opcodes'] == TEXT


def test_raw_base_is_absolute_load_vaddr():
    secs = rawmod.Raw(TEXT, '0x400000', 'x86_64').get_exec_sections()
    assert secs[0]['vaddr'] == 0x400000


def test_raw_requires_arch():
    with pytest.raises(binary.BinaryException):
        rawmod.Raw(TEXT, None, None)


def test_raw_rejects_unknown_arch():
    with pytest.raises(binary.BinaryException):
        rawmod.Raw(TEXT, None, 'sparc')


def test_raw_has_no_symbols():
    # No get_symbols on the loader -> Binary.get_symbols returns [].
    assert not hasattr(rawmod.Raw(TEXT, None, 'x86_64'), 'get_symbols')


def test_raw_get_info():
    info = rawmod.Raw(TEXT, '0x400000', 'x86_64').get_info()
    assert info['format'] == 'Raw'
    assert info['image_base'] == 0x400000


# --- Through the Binary wrapper (disk file, explicit raw=True) -------------

def test_binary_raw_dispatch(tmp_path):
    path = tmp_path / 'dump.bin'
    path.write_bytes(TEXT)
    b = binary.Binary(str(path), None, 'x86_64', raw=True)
    assert b.format == 'Raw'
    assert isinstance(b.get_arch(), X64_Architecture)
    assert b.get_symbols() == []
    secs = b.get_exec_sections()
    assert secs[0]['vaddr'] == 0 and secs[0]['opcodes'] == TEXT


def test_binary_raw_base(tmp_path):
    path = tmp_path / 'dump.bin'
    path.write_bytes(TEXT)
    b = binary.Binary(str(path), '0x400000', 'x86_64', raw=True)
    assert b.get_exec_sections()[0]['vaddr'] == 0x400000


def test_binary_raw_ignores_elf_magic(tmp_path):
    ''' raw=True forces the raw loader even when the bytes start with a real
        format's magic -- the header is treated as ordinary code. '''
    from conftest import build_minimal_elf, EM_X86_64, ET_DYN
    path = tmp_path / 'real.elf'
    path.write_bytes(build_minimal_elf(64, EM_X86_64, TEXT, 0x1000, ET_DYN))
    b = binary.Binary(str(path), None, 'x86_64', raw=True)
    assert b.format == 'Raw'
    # One section spanning the whole file, starting at the ELF magic byte.
    assert b.get_exec_sections()[0]['opcodes'][:1] == b'\x7f'


# --- End-to-end through Rop3 ----------------------------------------------

def test_rop3_raw_finds_gadgets(tmp_path):
    from rop3 import Rop3
    path = tmp_path / 'dump.bin'
    path.write_bytes(b'\x58\x5f\xc3')   # pop rax ; pop rdi ; ret
    gadgets = Rop3(str(path), raw=True, arch='x86_64').gadgets()
    reprs = {g.text_repr for g in gadgets}
    assert 'pop rax ; pop rdi ; ret' in reprs
    assert 'pop rdi ; ret' in reprs


def test_rop3_raw_base_offsets_addresses(tmp_path):
    from rop3 import Rop3
    path = tmp_path / 'dump.bin'
    path.write_bytes(b'\x58\xc3')   # pop rax ; ret
    gadgets = Rop3(str(path), raw=True, arch='x86_64', base='0x400000').gadgets()
    assert all(g.vaddr >= 0x400000 for g in gadgets)
    assert any(g.text_repr == 'pop rax ; ret' for g in gadgets)


# --- Argument parsing / validation ----------------------------------------

def test_args_raw_requires_arch():
    with pytest.raises(SystemExit):
        args.ArgumentParser().parse_args(['--binary', 'x', '--raw'])


def test_args_raw_with_arch_ok():
    ns = args.ArgumentParser().parse_args(['--binary', 'x', '--raw', '--arch', 'x86_64'])
    assert ns.raw is True
    assert ns.arch == 'x86_64'


def test_args_raw_defaults_false():
    ns = args.ArgumentParser().parse_args(['--binary', 'x'])
    assert ns.raw is False
