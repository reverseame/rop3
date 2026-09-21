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

from rop3.search import (galileo_scan, aligned_scan, linear_instructions,
                         backward_instructions, backwards_framed_search,
                         literal_scan, aligned_literal_scan,
                         raw_byte_scan, assemble)
from rop3.archs.x86_arch import X86_Architecture, X64_Architecture

_riscv = pytest.mark.skipif(not hasattr(capstone, 'CS_ARCH_RISCV'),
                            reason='capstone build without RISC-V support')


def _x86_md():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return md


def _texts(gen):
    out = {}
    for vaddr, _raw, decodes, *_frame in gen:
        text = ' ; '.join(f'{d.mnemonic} {d.op_str}'.strip() for d in decodes)
        out.setdefault(vaddr, set()).add(text)
    return out


# --- scan strategy is architecture-dependent ------------------------------

def test_scan_name_and_parallelism_are_architecture_dependent():
    from rop3.archs.riscv_arch import RISCV_Architecture
    from rop3.archs.aarch64_arch import AArch64_Architecture
    # scan_name mirrors scan()'s strategy selection for the given flags;
    # parallelizable gates chunked scanning.
    assert X86_Architecture().scan_name() == 'galileo'
    assert X64_Architecture().scan_name() == 'galileo'
    assert RISCV_Architecture(compressed=True).scan_name() == 'framed aligned'
    assert AArch64_Architecture().scan_name() == 'framed aligned'
    # --no-frame drops the aligned sweeps to a plain aligned scan.
    assert AArch64_Architecture().scan_name(framed=False) == 'aligned'
    assert RISCV_Architecture().scan_name(framed=False) == 'aligned'
    # --ropblock selects the abstract-gadget search on every architecture.
    assert X64_Architecture().scan_name(ropblock=True) == 'ropblock'
    assert AArch64_Architecture().scan_name(ropblock=True) == 'ropblock'
    assert RISCV_Architecture().scan_name(ropblock=True) == 'ropblock'
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


def test_linear_instructions_is_program_order():
    insns = list(linear_instructions(UNINTENDED, 0x1000, 1, _x86_md().disasm))
    assert [i.mnemonic for i in insns] == ['mov', 'ret']
    assert [i.address for i in insns] == [0x1000, 0x1005]


@pytest.mark.parametrize('chunk_size', [1, 2, 3, 4, 5, 6, 7])
def test_linear_instructions_unaffected_by_scan_chunk_size(monkeypatch, chunk_size):
    ''' `_linear_instruction_stream` decodes in bounded `_SCAN_CHUNK_SIZE`
        pieces (see its docstring) purely to bound capstone's native
        allocation on huge sections -- it must still yield the exact same
        instruction stream as one big call, including across a forced chunk
        boundary that lands mid-buffer or right at the "unintended" ret
        byte's offset. '''
    import rop3.search as search_mod
    monkeypatch.setattr(search_mod, '_SCAN_CHUNK_SIZE', chunk_size)
    insns = list(linear_instructions(UNINTENDED, 0x1000, 1, _x86_md().disasm))
    assert [i.mnemonic for i in insns] == ['mov', 'ret']
    assert [i.address for i in insns] == [0x1000, 0x1005]


@pytest.mark.parametrize('chunk_size', [4, 8, 12])
def test_aligned_scan_unaffected_by_scan_chunk_size(monkeypatch, chunk_size):
    import rop3.search as search_mod
    monkeypatch.setattr(search_mod, '_SCAN_CHUNK_SIZE', chunk_size)
    baseline = _aligned(UNINTENDED, 0x1000, depth=8)
    monkeypatch.setattr(search_mod, '_SCAN_CHUNK_SIZE', 1 << 20)
    assert _aligned(UNINTENDED, 0x1000, depth=8) == baseline


@_riscv
@pytest.mark.parametrize('chunk_size', [1, 2, 3, 4])
def test_riscv_aligned_scan_unaffected_by_scan_chunk_size(monkeypatch, chunk_size):
    import rop3.search as search_mod
    monkeypatch.setattr(search_mod, '_SCAN_CHUNK_SIZE', chunk_size)
    chunked = _riscv_texts(LD_RA_SP + RET)
    monkeypatch.setattr(search_mod, '_SCAN_CHUNK_SIZE', 1 << 20)
    assert chunked == _riscv_texts(LD_RA_SP + RET)


def test_galileo_frame_marks_only_the_terminator():
    ''' The classical scans build the frame mask inline as they recognize each
        gadget. On x86 (no return-address-restore prologue) that is just the
        terminator the walk anchored on. '''
    arch = X64_Architecture()
    frames = {}
    for vaddr, _raw, decodes, frame in galileo_scan(
            b'\x58\xc3', 0x1000, arch.get_rop_terminations(), 5, 1,
            _x86_md().disasm, arch.is_valid_rop_gadget):
        frames[' ; '.join(f'{d.mnemonic} {d.op_str}'.strip() for d in decodes)] = frame
    assert frames['pop rax ; ret'] == (False, True)      # pop = body, ret = frame
    assert frames['ret'] == (True,)


@_riscv
def test_aligned_equals_galileo_on_fixed_width():
    from rop3.archs.riscv_arch import RISCV_Architecture
    arch = RISCV_Architecture()                  # non-compressed: 4-byte aligned
    md = capstone.Cs(capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64)
    md.detail = True
    code = b'\x33\x85\xc5\x00' + b'\x93\x06\x07\x00' + b'\x67\x80\x00\x00'  # add;mv;ret

    def keys(gen):
        return {(v, r.hex()) for v, r, *_ in gen}

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
    return _texts(aligned_scan(code, base, depth, arch.alignment, md.disasm,
                               arch.is_valid_rop_gadget,
                               restores_return_address=arch.restores_return_address,
                               is_return=arch.is_return))


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
def test_riscv_framed_sweep_frames_ra_load_and_terminator():
    ''' The framed aligned sweep builds the frame inline: the ra restore it
        walked past (`restores_return_address`) and the `ret` it anchored on are frame;
        the operation body between them is not. '''
    from rop3.archs.riscv_arch import RISCV_Architecture
    arch = RISCV_Architecture(compressed=True)
    mode = capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC
    md = capstone.Cs(capstone.CS_ARCH_RISCV, mode)
    md.detail = True
    frames = {}
    for _v, _r, decodes, frame in aligned_scan(
            LD_RA_SP + ADD + RET, 0x1000, 16, arch.alignment, md.disasm,
            arch.is_valid_rop_gadget, restores_return_address=arch.restores_return_address,
            is_return=arch.is_return):
        frames[tuple(d.mnemonic for d in decodes)] = frame
    # ld ra (prologue) / add (body) / ret (terminator)
    assert frames[('ld', 'add', 'ret')] == (True, False, True)


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


# --- Literal scan (raw() chain-step candidates) ----------------------------

# mov eax, 0x0000050f ; ret -- the 2-byte `syscall` encoding (0f 05) sits at
# offset 1, inside the mov's immediate, not on an intended instruction
# boundary a normal (sequential) disassembly pass would ever visit.
HIDDEN_SYSCALL = b'\xb8\x0f\x05\x00\x00\xc3'


def _syscall_vaddrs(opcodes, alignment=1, base=0x1000):
    matches = literal_scan(opcodes, base, alignment, _x86_md().disasm, 1)
    return [vaddr for vaddr, _raw, decodes in matches if decodes[0].mnemonic == 'syscall']


def test_literal_scan_matches_intended_instruction():
    assert _syscall_vaddrs(b'\x0f\x05\xc3') == [0x1000]


def test_literal_scan_finds_pattern_hidden_inside_another_instruction():
    ''' Unlike a sequential/intended disassembly pass, every byte offset is
        tried (on x86, alignment 1), so the `syscall` hiding inside the
        `mov`'s immediate is still found -- this is the whole point of trying
        "unintended" offsets, not just instruction boundaries. '''
    assert _syscall_vaddrs(HIDDEN_SYSCALL) == [0x1001]


def test_literal_scan_respects_alignment():
    ''' On a fixed-width ISA (alignment > 1) only aligned offsets are tried,
        so the same "unintended", unaligned match is never found -- this is
        what makes the scan reduce to "intended only" on AArch64/RISC-V. '''
    assert _syscall_vaddrs(HIDDEN_SYSCALL, alignment=4) == []


def test_literal_scan_multi_instruction_pattern():
    matches = list(literal_scan(b'\x48\x31\xc0\x0f\x05', 0x2000, 1,
                                _x86_md().disasm, 2))   # xor rax, rax ; syscall
    mnems = [[d.mnemonic for d in decodes] for _v, _r, decodes in matches]
    assert ['xor', 'syscall'] in mnems


def test_literal_scan_rejects_short_trailing_window():
    ''' Near the end of the buffer, fewer than `pattern_len` instructions can
        decode -- those offsets yield no candidate rather than a short one. '''
    matches = list(literal_scan(b'\x0f\x05', 0x1000, 1, _x86_md().disasm, 2))
    assert matches == []


# --- Aligned literal scan (raw() on fixed-width ISAs) ----------------------
#
# The single-pass counterpart to literal_scan for aligned ISAs. Exercised with
# AArch64 (alignment 4): mov x0, x1 = e0 03 01 aa, ret = c0 03 5f d6.

def _arm64_md():
    if not hasattr(capstone, 'CS_ARCH_ARM64'):
        pytest.skip('capstone build without ARM64 support')
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    return md


def _aligned_mnems(opcodes, pattern_len, base=0x1000):
    matches = aligned_literal_scan(opcodes, base, 4, _arm64_md().disasm, pattern_len)
    return [(vaddr, [d.mnemonic for d in decodes])
            for vaddr, _raw, decodes in matches]


def test_aligned_literal_scan_single_instruction_each_position():
    ''' Every aligned instruction of the intended stream is yielded once, in a
        single pass (one disasm call, not one per offset). '''
    code = b'\xe0\x03\x01\xaa\xc0\x03\x5f\xd6'   # mov x0, x1 ; ret
    assert _aligned_mnems(code, 1) == [(0x1000, ['mov']), (0x1004, ['ret'])]


def test_aligned_literal_scan_multi_instruction_window():
    ''' A multi-instruction pattern is matched as a contiguous window sliding
        along the intended stream. '''
    code = b'\xe0\x03\x01\xaa\xc0\x03\x5f\xd6'   # mov x0, x1 ; ret
    assert _aligned_mnems(code, 2) == [(0x1000, ['mov', 'ret'])]


def test_aligned_literal_scan_resyncs_and_breaks_window_across_gap():
    ''' An undecodable word (ff ff ff ff) is a resync gap: the two real
        instructions on either side are not contiguous, so a 2-instruction
        window never spans the hole -- while a 1-instruction scan still finds
        each real instruction. '''
    code = (b'\xe0\x03\x01\xaa'    # mov x0, x1   @ 0x1000
            b'\xff\xff\xff\xff'    # undecodable  @ 0x1004
            b'\xc0\x03\x5f\xd6')   # ret          @ 0x1008
    assert _aligned_mnems(code, 1) == [(0x1000, ['mov']), (0x1008, ['ret'])]
    assert _aligned_mnems(code, 2) == []          # window can't cross the gap


def test_aligned_literal_scan_rejects_short_trailing_window():
    ''' A stream shorter than `pattern_len` instructions yields no candidate. '''
    code = b'\xc0\x03\x5f\xd6'                     # just ret
    assert _aligned_mnems(code, 2) == []


# --- Assemble + byte-regex fast path (raw()) -------------------------------
#
# raw_byte_scan is fed the needle bytes directly, so it is exercised here
# independently of whether Keystone is installed / loadable.

def test_assemble_returns_none_or_expected_bytes():
    ''' assemble() yields the needle when Keystone is available, else None so
        find_raw_gadgets can fall back -- it is never fatal. '''
    from rop3.archs.x86_arch import X64_Architecture
    result = assemble('syscall', X64_Architecture())
    assert result is None or result == b'\x0f\x05'


def test_raw_byte_scan_finds_first_and_all_appearances_x86():
    ''' On x86 (alignment 1) every occurrence of the needle is yielded in
        address order; a caller taking the first stops at the lowest address. '''
    opcodes = b'\x0f\x05\x90\x0f\x05'              # syscall ; nop ; syscall
    hits = list(raw_byte_scan(opcodes, 0x1000, b'\x0f\x05', 1, _x86_md().disasm))
    assert [v for v, _r, _d in hits] == [0x1000, 0x1003]


def test_raw_byte_scan_finds_unintended_offset_x86():
    ''' The needle is located by its bytes, so a `syscall` hiding inside the
        `mov`'s immediate (offset 1, not an intended boundary) is still found. '''
    hits = list(raw_byte_scan(HIDDEN_SYSCALL, 0x1000, b'\x0f\x05', 1,
                              _x86_md().disasm))
    assert [v for v, _r, _d in hits] == [0x1001]
    assert hits[0][2][0].mnemonic == 'syscall'


def test_raw_byte_scan_respects_alignment():
    ''' On a fixed-width ISA (alignment > 1) only aligned occurrences pass. '''
    opcodes = b'\x00\x00\xef\xbe\x00\x00\xef\xbe'   # needle at off 2 (unaligned), 6
    stub = lambda raw, va: []
    hits = list(raw_byte_scan(opcodes, 0x1000, b'\xef\xbe', 4, stub))
    assert [v for v, _r, _d in hits] == []          # neither offset is 4-aligned
    opcodes = b'\x00\x00\x00\x00\xef\xbe'           # needle at off 4 (aligned)
    hits = list(raw_byte_scan(opcodes, 0x1000, b'\xef\xbe', 4, stub))
    assert [v for v, _r, _d in hits] == [0x1004]


def test_raw_byte_scan_enumerates_overlapping_so_alignment_never_hides_a_hit():
    ''' Overlapping occurrences are enumerated, so an aligned hit sitting within
        needle-length of an earlier unaligned one is not skipped (a plain
        non-overlapping search would jump past it). '''
    opcodes = b'\x00\x00' + b'\xaa' * 6             # needle 'aaaa' at off 2, 3, 4
    stub = lambda raw, va: []
    hits = [v for v, _r, _d in raw_byte_scan(opcodes, 0x1000, b'\xaa\xaa\xaa\xaa',
                                             4, stub)]
    assert hits == [0x1004]                          # the one aligned occurrence


def test_raw_byte_scan_not_found_yields_nothing():
    hits = list(raw_byte_scan(b'\x90\x90\xc3', 0x1000, b'\x0f\x05', 1,
                              _x86_md().disasm))
    assert hits == []


# --- Backward framed (ropblock) search ------------------------------------

def _backwards_framed(opcodes, base, depth=8):
    ''' Yields (vaddr, raw, decodes), dropping the frame mask so the shared
        `_texts` helper can consume it. '''
    arch = X64_Architecture()
    md = _x86_md()
    for vaddr, raw, decodes, _frame in backwards_framed_search(
            opcodes, base, depth, arch.alignment, md.disasm,
            arch.is_pc_reg_write, arch.ropblock_branch_reg,
            arch.is_stack_load, arch.clobbers_reg, arch.restores_return_address):
        yield vaddr, raw, decodes


def test_backward_instructions_steps_backward_by_alignment():
    md = _x86_md()
    code = b'\x90\x5f\xc3'                 # nop ; pop rdi ; ret
    pairs = list(backward_instructions(code, 0x1000, 1, md.disasm))
    assert [off for off, _ in pairs] == [2, 1, 0]        # high -> low, every byte
    seen = {off: insn.mnemonic for off, insn in pairs}
    assert (seen[2], seen[1], seen[0]) == ('ret', 'pop', 'nop')


@_riscv
def test_backward_instructions_alignment_skips_bytes():
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM) \
        if hasattr(capstone, 'CS_ARCH_ARM64') else None
    if md is None:
        pytest.skip('capstone build without ARM64 support')
    md.detail = True
    code = bytes.fromhex('e0031faa') + bytes.fromhex('c0035fd6')  # mov x0,xzr ; ret
    offs = [off for off, _ in backward_instructions(code, 0x1000, 4, md.disasm)]
    assert offs == [4, 0]                                # 4-byte aligned steps only


def test_backwards_framed_ret_is_self_framing():
    # x86 ret pops PC off the stack: it frames every run that ends in it.
    texts = _texts(_backwards_framed(b'\x5f\xc3', 0x1000))   # pop rdi ; ret
    assert texts[0x1000] == {'pop rdi ; ret'}
    assert texts[0x1001] == {'ret'}


def test_backwards_framed_reg_terminator_needs_prologue():
    # pop rax ; jmp rax  -- pop rax is the prologue for the jmp's branch register.
    texts = _texts(_backwards_framed(b'\x58\xff\xe0', 0x1000))
    assert texts[0x1000] == {'pop rax ; jmp rax'}
    assert 0x1001 not in texts                # bare `jmp rax` has no prologue


def test_backwards_framed_rejects_unframed_and_clobbered_reg():
    # mov rax, rbx ; jmp rax  -- rax never comes off the stack.
    assert _texts(_backwards_framed(b'\x48\x89\xd8\xff\xe0', 0x1000)) == {}
    # pop rax ; mov rax, rbx ; jmp rax  -- rax recomputed after the stack load.
    texts = _texts(_backwards_framed(b'\x58\x48\x89\xd8\xff\xe0', 0x1000))
    assert all(not t.endswith('jmp rax') for ts in texts.values() for t in ts)


def test_backwards_framed_marks_prologue_body_epilogue():
    # pop rax ; mov rdi, rsi ; jmp rax  -- prologue(pop rax) / body(mov) /
    # terminator(jmp rax): the frame mask marks the prologue and terminator.
    arch = X64_Architecture()
    md = _x86_md()
    runs = {tuple(d.mnemonic for d in decodes): frame
            for _v, _r, decodes, frame in backwards_framed_search(
                b'\x58\x48\x89\xf7\xff\xe0', 0x1000, 8, arch.alignment, md.disasm,
                arch.is_pc_reg_write, arch.ropblock_branch_reg,
                arch.is_stack_load, arch.clobbers_reg, arch.restores_return_address)}
    assert runs[('pop', 'mov', 'jmp')] == (True, False, True)


def test_backwards_framed_sp_pivot_is_not_framed():
    # pop rax ; add rsp, 8 ; jmp rax  -- control returns through rax (JOP), not
    # the stack, so `add rsp, 8` is a real stack operation, not framing. Only the
    # prologue (pop rax) and the terminator (jmp rax) are framed.
    arch = X64_Architecture()
    md = _x86_md()
    runs = {tuple(d.mnemonic for d in decodes): frame
            for _v, _r, decodes, frame in backwards_framed_search(
                b'\x58\x48\x83\xc4\x08\xff\xe0', 0x1000, 12, arch.alignment, md.disasm,
                arch.is_pc_reg_write, arch.ropblock_branch_reg,
                arch.is_stack_load, arch.clobbers_reg, arch.restores_return_address)}
    assert runs[('pop', 'add', 'jmp')] == (True, False, True)


def test_backwards_framed_leading_sp_pivot_is_body():
    # add rsp, 8 ; ret  -- ret is self-framing (its own prologue); the stack
    # pivot is the operation body, left unframed so `--op add` surfaces it.
    arch = X64_Architecture()
    md = _x86_md()
    runs = {tuple(d.mnemonic for d in decodes): frame
            for _v, _r, decodes, frame in backwards_framed_search(
                b'\x48\x83\xc4\x08\xc3', 0x1000, 12, arch.alignment, md.disasm,
                arch.is_pc_reg_write, arch.ropblock_branch_reg,
                arch.is_stack_load, arch.clobbers_reg, arch.restores_return_address)}
    assert runs[('add', 'ret')] == (False, True)
