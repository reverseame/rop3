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

import rop3.gadfinder as gadfinder
from rop3.archs.x86_arch import X86_Architecture


def test_avoid_bytes_defaults_to_canary():
    f = gadfinder.GadFinder()
    assert f._avoid_bytes(None) == set(gadfinder.CANARY_BYTES)
    assert f._avoid_bytes(['0x00', '0x0a', '0x0d', '0xff']) == {0x00, 0x0a, 0x0d, 0xff}


def test_avoid_bytes_uses_user_badchars():
    f = gadfinder.GadFinder()
    assert f._avoid_bytes(['0x41', '0x42']) == {0x41, 0x42}


def test_addr_canary_score(x86):
    from conftest import make_gadget
    f = gadfinder.GadFinder()
    avoid = set(gadfinder.CANARY_BYTES)
    clean = make_gadget(b'\xc3', 0x12345620, mode=capstone.CS_MODE_32)
    dirty = make_gadget(b'\xc3', 0x1234560a, mode=capstone.CS_MODE_32)  # low byte 0x0a
    assert f._addr_canary_score(clean, avoid) == 0
    assert f._addr_canary_score(dirty, avoid) == 1


class _FakeBinary:
    def __init__(self, vaddr, opcodes, filename='fake'):
        self.filename = filename
        self._vaddr = vaddr
        self._opcodes = opcodes

    def get_exec_sections(self):
        return [{'vaddr': self._vaddr, 'opcodes': self._opcodes}]

    def get_arch(self):
        return X86_Architecture()


def _run_find(flags, buf, base_vaddr):
    f = gadfinder.GadFinder(flags=flags)
    f._open_binary = lambda fn, b: _FakeBinary(base_vaddr, bytes(buf))
    return f.find(['fake'])


def test_dedup_prefers_canary_free_address(x86):
    ''' Issue #5: among duplicates keep the address with fewest canary bytes. '''
    base = 0x12345600
    buf = bytearray(0x40)
    buf[0x0a] = 0xc3   # ret at ...0a (canary)
    buf[0x20] = 0xc3   # ret at ...20 (clean)

    flags = gadfinder.ROP | gadfinder.AVOID_CANARY
    rets = [g for g in _run_find(flags, buf, base) if g.text_repr == 'ret']
    assert len(rets) == 1
    assert rets[0].vaddr == 0x12345620
    assert rets[0].count == 2


def test_dedup_keep_canary_keeps_first_seen(x86):
    base = 0x12345600
    buf = bytearray(0x40)
    buf[0x0a] = 0xc3
    buf[0x20] = 0xc3

    rets = [g for g in _run_find(gadfinder.ROP, buf, base) if g.text_repr == 'ret']
    assert len(rets) == 1
    assert rets[0].vaddr == 0x1234560a   # first seen, no canary preference
    assert rets[0].count == 2


def test_results_sorted_by_address(x86):
    base = 0x10000
    buf = bytearray(0x40)
    for off in (0x30, 0x05, 0x18):
        buf[off] = 0xc3
    gadgets = _run_find(gadfinder.ROP, buf, base)
    vaddrs = [g.vaddr for g in gadgets]
    assert vaddrs == sorted(vaddrs)
