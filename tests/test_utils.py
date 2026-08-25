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


def test_pretty_addr_padding():
    # padding is the total field width including the '0x' prefix
    assert utils.pretty_addr(0x1000, 4) == '0x001000'
    assert utils.pretty_addr(0x1000, 8) == '0x00000000001000'
    assert len(utils.pretty_addr(0x1000, 4)) == 8
    assert len(utils.pretty_addr(0x1000, 8)) == 16


def test_pack_addr_endianness_and_width():
    assert utils.pack_addr(0x41424344, 4) == b'\x44\x43\x42\x41'
    assert utils.pack_addr(0x41424344, 8) == \
        b'\x44\x43\x42\x41\x00\x00\x00\x00'


@pytest.mark.parametrize('fn', [utils.pretty_addr, utils.pack_addr])
def test_addr_helpers_reject_unknown_size(fn):
    ''' Regression for issue #15: unbound local on unsupported address size. '''
    with pytest.raises(ValueError):
        fn(0x1000, size=999)
