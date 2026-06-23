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

import pytest

import rop3.binaries.macho as machomod
import rop3.binary as binary
from rop3.archs.x86_arch import X64_Architecture

# /bin/ls on macOS is a fat Mach-O (x86_64 + arm64e): handy real fixture.
FAT = '/bin/ls'
pytestmark = pytest.mark.skipif(
    not os.path.exists(FAT) or open(FAT, 'rb').read(4) != b'\xca\xfe\xba\xbe',
    reason='requires a fat Mach-O binary (macOS /bin/ls)')


def _data():
    with open(FAT, 'rb') as f:
        return f.read()


def test_default_slice_is_x86_64():
    assert isinstance(machomod.MachO(_data(), None).get_arch(), X64_Architecture)


def test_explicit_arch_x86_64():
    assert isinstance(machomod.MachO(_data(), None, 'x86_64').get_arch(), X64_Architecture)


def test_unsupported_arch_raises():
    with pytest.raises(binary.BinaryException):
        machomod.MachO(_data(), None, 'arm64')


def test_absent_arch_raises():
    with pytest.raises(binary.BinaryException):
        machomod.MachO(_data(), None, 'i386')   # not present in /bin/ls


def test_get_symbols_returns_list():
    syms = machomod.MachO(_data(), None).get_symbols()
    assert isinstance(syms, list)
    assert all(isinstance(a, int) and isinstance(n, str) for a, n in syms)
