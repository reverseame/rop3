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

import os

import capstone
import pytest

import rop3.binaries.macho as machomod
import rop3.binary as binary
from rop3 import Rop3
from rop3.archs.x86_arch import X64_Architecture
from rop3.archs.aarch64_arch import AArch64_Architecture

from conftest import build_minimal_macho, CPU_TYPE_ARM64, CPU_TYPE_X86_64

RET_ARM = bytes.fromhex('c0035fd6')          # ret
LDP_FRAME = bytes.fromhex('fd7bc1a8')         # ldp x29, x30, [sp], #16
ADD = b'\x20\x00\x02\x8b'                      # add x0, x1, x2

_arm64 = pytest.mark.skipif(not hasattr(capstone, 'CS_ARCH_ARM64'),
                            reason='capstone build without ARM64 support')


# --- In-memory thin Mach-O (no committed binary) --------------------------

def test_inmemory_detects_x86_64():
    macho = machomod.MachO(build_minimal_macho(CPU_TYPE_X86_64, b'\xc3\xc3'), None)
    assert isinstance(macho.get_arch(), X64_Architecture)


@_arm64
def test_inmemory_detects_arm64():
    macho = machomod.MachO(build_minimal_macho(CPU_TYPE_ARM64, RET_ARM * 2), None)
    arch = macho.get_arch()
    assert isinstance(arch, AArch64_Architecture)
    assert (arch.arch, arch.address_size, arch.alignment) == (capstone.CS_ARCH_ARM64, 8, 4)


@_arm64
def test_inmemory_explicit_arch_arm64():
    data = build_minimal_macho(CPU_TYPE_ARM64, RET_ARM)
    assert isinstance(machomod.MachO(data, None, 'arm64').get_arch(), AArch64_Architecture)


@_arm64
def test_inmemory_arm64_exec_section_bytes():
    macho = machomod.MachO(build_minimal_macho(CPU_TYPE_ARM64, RET_ARM * 3), None)
    secs = macho.get_exec_sections()
    assert len(secs) == 1 and secs[0]['opcodes'] == RET_ARM * 3


def test_inmemory_unsupported_cputype_raises():
    CPU_TYPE_POWERPC = 0x12                    # recognized by macholib, unsupported here
    with pytest.raises(binary.BinaryException):
        machomod.MachO(build_minimal_macho(CPU_TYPE_POWERPC, b'\x00\x00\x00\x00'), None)


def test_inmemory_absent_explicit_arch_raises():
    # An x86_64 slice does not contain arm64.
    with pytest.raises(binary.BinaryException):
        machomod.MachO(build_minimal_macho(CPU_TYPE_X86_64, b'\xc3'), None, 'arm64')


@_arm64
def test_inmemory_arm64_end_to_end_framed_gadget(tmp_path):
    path = tmp_path / 'a.macho'
    path.write_bytes(build_minimal_macho(CPU_TYPE_ARM64, ADD + LDP_FRAME + RET_ARM))
    reprs = {g.text_repr for g in Rop3(str(path), depth=24).gadgets()}
    assert 'ldp x29, x30, [sp], #0x10 ; ret' in reprs         # framed (restores lr)
    assert 'ret' not in reprs                                  # bare ret dropped


# --- Real fat Mach-O (macOS /bin/ls: x86_64 + arm64e) ---------------------

FAT = '/bin/ls'
requires_fat = pytest.mark.skipif(
    not os.path.exists(FAT) or open(FAT, 'rb').read(4) != b'\xca\xfe\xba\xbe',
    reason='requires a fat Mach-O binary (macOS /bin/ls)')


def _data():
    with open(FAT, 'rb') as f:
        return f.read()


@requires_fat
def test_default_slice_is_x86_64():
    assert isinstance(machomod.MachO(_data(), None).get_arch(), X64_Architecture)


@requires_fat
def test_explicit_arch_x86_64():
    assert isinstance(machomod.MachO(_data(), None, 'x86_64').get_arch(), X64_Architecture)


@requires_fat
def test_explicit_arch_arm64_selects_aarch64():
    # /bin/ls ships an arm64e slice; it shares the ARM64 cputype, so --arch
    # arm64 selects it now that AArch64 is supported.
    assert isinstance(machomod.MachO(_data(), None, 'arm64').get_arch(), AArch64_Architecture)


@requires_fat
def test_unsupported_arch_raises():
    with pytest.raises(binary.BinaryException):
        machomod.MachO(_data(), None, 'ppc')       # not a supported arch name


@requires_fat
def test_absent_arch_raises():
    with pytest.raises(binary.BinaryException):
        machomod.MachO(_data(), None, 'i386')      # supported but not present in /bin/ls


@requires_fat
def test_get_symbols_returns_list():
    syms = machomod.MachO(_data(), None).get_symbols()
    assert isinstance(syms, list)
    assert all(isinstance(a, int) and isinstance(n, str) for a, n in syms)
