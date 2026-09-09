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
    def __init__(self, vaddr, opcodes, filename='fake', symbols=None):
        self.filename = filename
        self._vaddr = vaddr
        self._opcodes = opcodes
        self._symbols = symbols or []

    def get_exec_sections(self):
        return [{'vaddr': self._vaddr, 'opcodes': self._opcodes}]

    def get_arch(self):
        return X86_Architecture()

    def get_symbols(self):
        return self._symbols


def _run_find(flags, buf, base_vaddr, symbols_table=None, **kwargs):
    f = gadfinder.GadFinder(flags=flags)
    f._open_binary = lambda fn, b, arch=None: _FakeBinary(base_vaddr, bytes(buf), symbols=symbols_table)
    return f.find(['fake'], **kwargs)


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


def test_badchar_bytes_filters_on_opcode_bytes(x86):
    ''' Issue #21: reject gadgets whose opcode bytes contain a forbidden byte. '''
    base = 0x10000
    buf = bytearray(0x40)
    buf[0x10] = 0xc3                 # ret  -> bytes c3
    buf[0x20:0x22] = b'\x5d\xc3'     # pop ebp ; ret -> bytes 5d c3
    gadgets = _run_find(gadfinder.ROP, buf, base, badchar_bytes=['0x5d'])
    reprs = {g.text_repr for g in gadgets}
    assert 'ret' in reprs
    assert 'pop ebp ; ret' not in reprs
    assert all(0x5d not in g.bytes for g in gadgets)


def test_symbol_annotation(x86):
    ''' Issue #22: gadgets get the nearest symbol at or below their address. '''
    base = 0x10000
    buf = bytearray(0x40)
    buf[0x10:0x12] = b'\x90\xc3'   # nop ; ret  -> gadget at 0x10010
    buf[0x30:0x32] = b'\x58\xc3'   # pop eax ; ret -> gadget at 0x10030
    symbols = [(0x10000, 'start'), (0x10020, 'middle')]
    gadgets = _run_find(gadfinder.ROP, buf, base, symbols=True, symbols_table=symbols)
    by_text = {g.text_repr: g.symbol for g in gadgets}
    assert by_text['nop ; ret'] == 'start+0x10'        # nearest <= 0x10010
    assert by_text['pop eax ; ret'] == 'middle+0x10'   # nearest <= 0x10030


def test_symbol_annotation_exact_address(x86):
    base = 0x10000
    buf = bytearray(0x40)
    buf[0x0] = 0xc3    # ret exactly at symbol address 0x10000
    gadgets = _run_find(gadfinder.ROP, buf, base, symbols=True,
                        symbols_table=[(0x10000, 'start')])
    assert gadgets[0].symbol == 'start'   # no +offset when offset is 0


def test_ret_imm_gadgets_gated_by_flag(x86):
    base = 0x12345600
    buf = bytearray(0x40)
    buf[0x10:0x14] = b'\x58\xc2\x08\x00'   # pop eax ; ret 8
    default = [g.text_repr for g in _run_find(gadfinder.ROP, buf, base)]
    assert not any('ret 8' in t for t in default)
    with_imm = [g.text_repr for g in _run_find(gadfinder.ROP | gadfinder.ALLOW_RET_IMM, buf, base)]
    assert 'pop eax ; ret 8' in with_imm


def test_ropblock_flag_finds_register_return_with_frame(x86):
    ''' --ropblock (the ROPBLOCK flag) drives backwards_framed_search: it finds
        `pop eax ; jmp eax` (a register return the plain ROP scan misses) and
        attaches the per-instruction frame mask (prologue + terminator). '''
    base = 0x400000
    buf = b'\x58\xff\xe0'                                   # pop eax ; jmp eax
    gadgets = _run_find(gadfinder.ROP | gadfinder.ROPBLOCK, buf, base)
    reg = [g for g in gadgets if g.text_repr == 'pop eax ; jmp eax']
    assert reg, [g.text_repr for g in gadgets]
    assert reg[0].frame == (True, True)                    # prologue, terminator

    # the plain ROP scan does not treat a `jmp reg` tail as a gadget
    plain = _run_find(gadfinder.ROP, buf, base)
    assert not any(g.text_repr == 'pop eax ; jmp eax' for g in plain)


def test_ropblock_disables_parallel(x86):
    ''' The abstract-gadget backward search is not chunkable, so it runs
        single-threaded even with --jobs > 1 (produces the same gadgets). '''
    base = 0x400000
    buf = b'\x58\xff\xe0\x5b\xc3'          # pop eax ; jmp eax ; pop ebx ; ret
    serial = {g.text_repr for g in _run_find(gadfinder.ROP | gadfinder.ROPBLOCK, buf, base)}
    f = gadfinder.GadFinder(flags=gadfinder.ROP | gadfinder.ROPBLOCK, jobs=4)
    f._open_binary = lambda fn, b, arch=None: _FakeBinary(base, bytes(buf))
    parallel = {g.text_repr for g in f.find(['fake'])}
    assert serial == parallel
    assert 'pop eax ; jmp eax' in serial


def test_classical_scan_populates_frame_mask(x86):
    ''' Ordinary (classical-scan) gadgets carry a frame mask marking the
        terminator, which operation matching consults like any other gadget's.
        An explicit stack-pointer adjustment is a meaningful side effect, not
        display framing, so it stays undimmed. '''
    base = 0x400000
    buf = b'\x58\xc3'                                  # pop eax ; ret
    g = next(x for x in _run_find(gadfinder.ROP, buf, base)
             if x.text_repr == 'pop eax ; ret')
    assert g.frame == (False, True)                    # pop = body, ret = frame

    buf2 = b'\x83\xc4\x08\xc3'                          # add esp, 8 ; ret
    g2 = next(x for x in _run_find(gadfinder.ROP, buf2, base)
              if x.text_repr == 'add esp, 8 ; ret')
    assert g2.frame == (False, True)                    # add esp = side effect, ret = frame
