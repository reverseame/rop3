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

from rop3.search import galileo_scan, aligned_scan, framed_aligned_scan, _linear_disasm
from rop3.archs.x86_arch import X86_Architecture, X64_Architecture

_riscv = pytest.mark.skipif(not hasattr(capstone, 'CS_ARCH_RISCV'),
                            reason='capstone build without RISC-V support')


def _x86_md():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return md


def _texts(gen):
    out = {}
    for vaddr, _raw, decodes in gen:
        text = ' ; '.join(f'{d.mnemonic} {d.op_str}'.strip() for d in decodes)
        out.setdefault(vaddr, set()).add(text)
    return out


# --- scan strategy is architecture-dependent ------------------------------

def test_scan_name_and_parallelism_are_architecture_dependent():
    from rop3.archs.riscv_arch import RISCV_Architecture
    from rop3.archs.aarch64_arch import AArch64_Architecture
    # scan_name is a descriptive label; parallelizable gates chunked scanning.
    assert X86_Architecture().scan_name == 'galileo'
    assert X64_Architecture().scan_name == 'galileo'
    assert RISCV_Architecture(compressed=True).scan_name == 'framed aligned'
    assert AArch64_Architecture().scan_name == 'aligned'
    # Only the Galileo backward walk is chunkable across worker processes.
    assert X64_Architecture().parallelizable
    assert not RISCV_Architecture(compressed=True).parallelizable
    assert not AArch64_Architecture().parallelizable


# --- Galileo (backward from every offset) ---------------------------------

def _galileo(opcodes, base, depth=5, alignment=1):
    arch = X64_Architecture()
    return _texts(galileo_scan(opcodes, base, arch.get_rop_terminations(), depth,
                               alignment, _x86_md().disasm, arch.is_valid_rop_gadget))


def test_galileo_walks_backward_from_every_ret():
    res = _galileo(b'\x58\xc3\x5b\xc3', 0x1000)   # pop rax;ret / pop rbx;ret
    assert 'pop rax ; ret' in res[0x1000]
    assert 'ret' in res[0x1001]
    assert 'pop rbx ; ret' in res[0x1002]
    assert 'ret' in res[0x1003]


def test_galileo_respects_depth_bound():
    assert _galileo(b'\x58\xc3', 0x1000, depth=1) == {0x1001: {'ret'}}


def test_galileo_rejects_intermediate_ret():
    res = _galileo(b'\x58\xc3\x5b\xc3', 0x1000)
    assert 'pop rax ; ret ; pop rbx ; ret' not in res.get(0x1000, set())


def test_galileo_alignment_filters_odd_starts():
    code = b'\xc3\x90\xc3\x90'   # ret ; nop ; ret ; nop
    assert any(v % 2 for v in _galileo(code, 0x1000, alignment=1))
    assert all(v % 2 == 0 for v in _galileo(code, 0x1000, alignment=2))


def test_galileo_accept_match_partitions_terminations():
    arch = X64_Architecture()
    kept = _texts(galileo_scan(b'\x58\xc3\x5b\xc3', 0x1000, arch.get_rop_terminations(),
                               5, 1, _x86_md().disasm, arch.is_valid_rop_gadget,
                               accept_match=lambda ref: ref == 2))
    assert set(kept) == {0x1000, 0x1001}


# --- Aligned (intended-instruction linear sweep) --------------------------

# mov eax, 0xc3 ; ret -- the immediate carries a 0xc3 (ret) byte.
UNINTENDED = b'\xb8\xc3\x00\x00\x00\xc3'


def _aligned(opcodes, base, depth=8):
    arch = X64_Architecture()
    return _texts(aligned_scan(opcodes, base, depth, 1, _x86_md().disasm,
                               arch.is_valid_rop_gadget))


def test_aligned_extracts_only_intended_instructions():
    res = _aligned(UNINTENDED, 0x1000, depth=8)
    assert res[0x1000] == {'mov eax, 0xc3 ; ret'}
    assert res[0x1005] == {'ret'}
    assert set(res) == {0x1000, 0x1005}          # nothing inside the mov imm


def test_aligned_respects_byte_depth():
    assert _aligned(UNINTENDED, 0x1000, depth=5) == {0x1005: {'ret'}}


def test_aligned_resyncs_past_undecodable_tail():
    # ret then a lone 0xb8 (truncated mov) which cannot decode.
    assert _aligned(b'\xc3\xb8', 0x1000, depth=4) == {0x1000: {'ret'}}


def test_linear_disasm_is_program_order():
    insns = _linear_disasm(UNINTENDED, 0x1000, 1, _x86_md().disasm)
    assert [i.mnemonic for i in insns] == ['mov', 'ret']
    assert [i.address for i in insns] == [0x1000, 0x1005]


@_riscv
def test_aligned_equals_galileo_on_fixed_width():
    from rop3.archs.riscv_arch import RISCV_Architecture
    arch = RISCV_Architecture()                  # non-compressed: 4-byte aligned
    md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64)
    md.detail = True
    code = b'\x33\x85\xc5\x00' + b'\x93\x06\x07\x00' + b'\x67\x80\x00\x00'  # add;mv;ret

    def keys(gen):
        return {(v, r.hex()) for v, r, _ in gen}

    galileo = keys(galileo_scan(code, 0x1000, arch.get_rop_terminations(), 16, 4,
                                md.disasm, arch.is_valid_rop_gadget))
    aligned = keys(aligned_scan(code, 0x1000, 16, 4, md.disasm, arch.is_valid_rop_gadget))
    assert aligned == galileo
    assert len(aligned) == 3


# --- RISC-V (only ra-restoring ROP gadgets) -------------------------------

# ld ra,8(sp)=83 30 81 00 ; add a0,a1,a2=33 85 c5 00 ; addi sp,sp,16=13 01 01 01
# ld ra,8(a0)=83 30 85 00 ; ret=67 80 00 00 ; c.ldsp ra,8(sp)=a2 60
LD_RA_SP = b'\x83\x30\x81\x00'
LD_RA_A0 = b'\x83\x30\x85\x00'
ADD = b'\x33\x85\xc5\x00'
ADDI_SP = b'\x13\x01\x01\x01'
RET = b'\x67\x80\x00\x00'


def _riscv_texts(code, base=0x1000, depth=16, compressed=True):
    from rop3.archs.riscv_arch import RISCV_Architecture
    arch = RISCV_Architecture(compressed=compressed)
    mode = capstone.CS_MODE_RISCV64 | (capstone.CS_MODE_RISCVC if compressed else 0)
    md = capstone.Cs(capstone.CS_ARCH_RISCV, mode)
    md.detail = True
    return _texts(framed_aligned_scan(code, base, depth, arch.alignment, md.disasm,
                                      arch.is_valid_rop_gadget, arch.is_frame_load,
                                      arch.is_return))


@_riscv
def test_riscv_scan_keeps_ra_restoring_gadget():
    res = _riscv_texts(LD_RA_SP + RET)
    assert res == {0x1000: {'ld ra, 8(sp) ; ret'}}   # bare ret at 0x1004 dropped


@_riscv
def test_riscv_scan_drops_gadget_without_ra_load():
    assert _riscv_texts(ADD + RET) == {}              # no ra restore -> nothing


@_riscv
def test_riscv_scan_requires_stack_source_not_just_ra():
    assert _riscv_texts(LD_RA_A0 + RET) == {}         # ra loaded, but from a0


@_riscv
def test_riscv_scan_ra_load_may_precede_other_instructions():
    res = _riscv_texts(LD_RA_SP + ADDI_SP + RET)
    assert res == {0x1000: {'ld ra, 8(sp) ; addi sp, sp, 0x10 ; ret'}}


@_riscv
def test_riscv_scan_compressed_ra_load():
    res = _riscv_texts(b'\xa2\x60' + RET)             # c.ldsp ra, 8(sp) ; ret
    assert res == {0x1000: {'c.ldsp ra, 8(sp) ; ret'}}


@_riscv
def test_riscv_is_ra_load_predicate():
    from rop3.archs.riscv_arch import RISCV_Architecture
    arch = RISCV_Architecture(compressed=True)
    md = capstone.Cs(capstone.CS_ARCH_RISCV,
                     capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC)
    md.detail = True

    def is_ra_load(code):
        return arch.is_ra_load(list(md.disasm(code, 0x1000))[0])

    assert is_ra_load(LD_RA_SP)          # ld ra, 8(sp)
    assert is_ra_load(b'\xa2\x60')       # c.ldsp ra, 8(sp)
    assert not is_ra_load(LD_RA_A0)      # ld ra, 8(a0)  -- not the stack
    assert not is_ra_load(b'\x03\x35\x81\x00')  # ld a0, 8(sp)  -- not ra
    assert not is_ra_load(ADD)           # not a load
