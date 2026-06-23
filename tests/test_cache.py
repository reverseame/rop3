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

from rop3.cache import GadgetCache
from rop3 import Rop3

from conftest import build_minimal_elf, EM_X86_64, ET_DYN

TEXT = b'\x58\xc3\x5b\xc3\x90\xc3'   # pop rax;ret  pop rbx;ret  nop;ret


def test_key_changes_with_content(tmp_path):
    c = GadgetCache(str(tmp_path))
    h1 = c.file_hash(b'aaaa')
    h2 = c.file_hash(b'bbbb')
    assert c.key(h1, {'depth': 5}) != c.key(h2, {'depth': 5})
    assert c.key(h1, {'depth': 5}) == c.key(h1, {'depth': 5})


def test_key_changes_with_params(tmp_path):
    c = GadgetCache(str(tmp_path))
    h = c.file_hash(b'aaaa')
    assert c.key(h, {'depth': 5}) != c.key(h, {'depth': 6})


def test_store_and_load_roundtrip(tmp_path):
    c = GadgetCache(str(tmp_path))
    key = c.key('hash', {'depth': 5})
    assert c.load(key) is None
    records = [[0x1000, '58c3'], [0x1010, '5bc3']]
    c.store(key, records)
    assert c.load(key) == records


def _elf(tmp_path):
    data = build_minimal_elf(64, EM_X86_64, TEXT, 0x1000, ET_DYN)
    path = tmp_path / 'sample.elf'
    path.write_bytes(data)
    return str(path)


def test_cache_produces_same_gadgets(tmp_path):
    ''' A warm cache yields the same gadgets as a cold scan. '''
    elf = _elf(tmp_path)
    cache_dir = str(tmp_path / 'cache')

    cold = Rop3(elf, cache=True, cache_dir=cache_dir)
    first = sorted((g.vaddr, g.text_repr) for g in cold.gadgets())

    warm = Rop3(elf, cache=True, cache_dir=cache_dir)   # fresh instance, warm cache
    second = sorted((g.vaddr, g.text_repr) for g in warm.gadgets())

    assert first == second
    assert first == sorted((g.vaddr, g.text_repr)
                           for g in Rop3(elf).gadgets())   # == uncached


def test_cache_file_written(tmp_path):
    elf = _elf(tmp_path)
    cache_dir = tmp_path / 'cache'
    Rop3(elf, cache=True, cache_dir=str(cache_dir)).gadgets()
    assert list(cache_dir.glob('*.json'))
