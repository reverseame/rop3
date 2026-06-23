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

from rop3 import Rop3

from conftest import build_minimal_elf, EM_X86_64, ET_DYN


def _key(gadgets):
    return sorted((g.vaddr, g.text_repr, g.count) for g in gadgets)


@pytest.fixture
def big_elf(tmp_path):
    # A larger .text with many ret (0xc3) bytes so chunks actually split, and
    # a ret as the very last byte to exercise the closing-window boundary.
    text = (b'\x58\x5b\x59\x5a\xc3' * 4000) + b'\xc3'
    data = build_minimal_elf(64, EM_X86_64, text, 0x1000, ET_DYN)
    path = tmp_path / 'big.elf'
    path.write_bytes(data)
    return str(path)


@pytest.mark.parametrize('jobs', [2, 4])
def test_parallel_matches_serial(big_elf, jobs):
    serial = Rop3(big_elf).gadgets()
    parallel = Rop3(big_elf, jobs=jobs).gadgets()
    assert _key(serial) == _key(parallel)


def test_parallel_matches_serial_with_options(big_elf):
    ''' Same equivalence with bad-char and depth options. '''
    kwargs = dict(depth=8, badchar_bytes=['0x59'])
    serial = Rop3(big_elf, **kwargs).gadgets()
    parallel = Rop3(big_elf, jobs=4, **kwargs).gadgets()
    assert _key(serial) == _key(parallel)


def test_parallel_with_cache(big_elf, tmp_path):
    ''' Parallel scan results are cacheable and reload identically. '''
    cache_dir = str(tmp_path / 'cache')
    cold = Rop3(big_elf, jobs=4, cache=True, cache_dir=cache_dir).gadgets()
    warm = Rop3(big_elf, cache=True, cache_dir=cache_dir).gadgets()
    assert _key(cold) == _key(warm)
