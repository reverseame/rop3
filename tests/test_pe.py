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

import rop3.binary as binary
from rop3 import Rop3
from rop3.binaries.pe import PE
from rop3.archs.x86_arch import X64_Architecture
from rop3.archs.aarch64_arch import AArch64_Architecture

from conftest import (build_minimal_pe, IMAGE_FILE_MACHINE_AMD64,
                      IMAGE_FILE_MACHINE_ARM64)

RET_ARM = bytes.fromhex('c0035fd6')          # ret
LDP_FRAME = bytes.fromhex('fd7bc1a8')         # ldp x29, x30, [sp], #16
ADD = b'\x20\x00\x02\x8b'                      # add x0, x1, x2

_arm64 = pytest.mark.skipif(not hasattr(capstone, 'CS_ARCH_ARM64'),
                            reason='capstone build without ARM64 support')


def test_pe_detects_amd64():
    arch = PE(build_minimal_pe(IMAGE_FILE_MACHINE_AMD64, b'\xc3\xc3'), None).get_arch()
    assert isinstance(arch, X64_Architecture)


@_arm64
def test_pe_detects_arm64():
    arch = PE(build_minimal_pe(IMAGE_FILE_MACHINE_ARM64, RET_ARM * 2), None).get_arch()
    assert isinstance(arch, AArch64_Architecture)
    assert (arch.arch, arch.address_size, arch.alignment) == (capstone.CS_ARCH_ARM64, 8, 4)


@_arm64
def test_pe_arm64_exec_section_bytes():
    pe = PE(build_minimal_pe(IMAGE_FILE_MACHINE_ARM64, RET_ARM * 3), None)
    secs = pe.get_exec_sections()
    assert len(secs) == 1 and secs[0]['opcodes'] == RET_ARM * 3


def test_pe_unsupported_machine_raises():
    IMAGE_FILE_MACHINE_ARM = 0x01c0          # 32-bit ARM (not supported)
    with pytest.raises(binary.BinaryException):
        PE(build_minimal_pe(IMAGE_FILE_MACHINE_ARM, b'\x00\x00'), None)


@_arm64
def test_pe_arm64_end_to_end_framed_gadget(tmp_path):
    path = tmp_path / 'a.exe'
    path.write_bytes(build_minimal_pe(IMAGE_FILE_MACHINE_ARM64, ADD + LDP_FRAME + RET_ARM))
    reprs = {g.text_repr for g in Rop3(str(path), depth=24).gadgets()}
    assert 'ldp x29, x30, [sp], #0x10 ; ret' in reprs        # framed (restores lr)
    assert 'ret' not in reprs                                 # bare ret dropped
