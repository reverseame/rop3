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

import rop3.gadfinder as gadfinder
from rop3.archs.riscv_arch import RISCV_Architecture
from rop3.binaries.elf import ELF

from conftest import build_minimal_elf, EM_RISCV, EF_RISCV_RVC, ET_DYN, make_operation

# jalr x0, 0(ra)  == ret            (0x00008067, little-endian)
RET = b'\x67\x80\x00\x00'
# c.jr ra         == ret (compressed, 0x8082)
C_RET = b'\x82\x80'
# addi a0, a1, 0  == mv a0, a1      (0x00058513)
MV_A0_A1 = b'\x13\x85\x05\x00'
# ld ra, 8(sp)  -- restores the return address from the stack (0x00813083)
LD_RA_SP = b'\x83\x30\x81\x00'
# c.ldsp ra, 8(sp)  -- compressed ra restore (0x60a2)
C_LDSP_RA = b'\xa2\x60'

pytestmark = pytest.mark.skipif(not hasattr(capstone, 'CS_ARCH_RISCV'),
                                reason='capstone build without RISC-V support')


# --- ELF detection & alignment -------------------------------------------

def test_elf_detects_riscv64():
    arch = ELF(build_minimal_elf(64, EM_RISCV, RET, 0x1000, ET_DYN), None).get_arch()
    assert isinstance(arch, RISCV_Architecture)
    assert arch.arch == capstone.CS_ARCH_RISCV
    assert arch.address_size == 8
    assert arch.alignment == 4                 # no C extension advertised


def test_elf_rvc_flag_enables_compressed_and_2byte_alignment():
    arch = ELF(build_minimal_elf(64, EM_RISCV, C_RET, 0x1000, ET_DYN,
                                 e_flags=EF_RISCV_RVC), None).get_arch()
    assert arch.alignment == 2
    assert arch.mode & capstone.CS_MODE_RISCVC


def test_elf_rvc_detected_within_rv64gc_flags():
    ''' rv64gc binaries report e_flags == 0x5 (RVC | float-abi-double); only
        the RVC bit (0x1) governs instruction alignment. '''
    arch = ELF(build_minimal_elf(64, EM_RISCV, C_RET, 0x1000, ET_DYN,
                                 e_flags=0x5), None).get_arch()
    assert arch.alignment == 2


def test_elf_riscv32_not_supported():
    with pytest.raises(NotImplementedError):
        ELF(build_minimal_elf(32, EM_RISCV, RET, 0x1000, ET_DYN), None)


# --- Architecture descriptors --------------------------------------------

def test_riscv_rop_terminations():
    assert [t['bytes'] for t in RISCV_Architecture().get_rop_terminations()] == [RET]
    compressed = RISCV_Architecture(compressed=True).get_rop_terminations()
    assert {t['size'] for t in compressed} == {4, 2}


def test_riscv_abstract_registers():
    arch = RISCV_Architecture()
    assert arch.is_valid_abstract_reg('a0')
    assert arch.is_valid_abstract_reg('sp')
    assert not arch.is_valid_abstract_reg('zero')
    assert not arch.is_valid_abstract_reg('x0')


# --- Validity via real disassembly ---------------------------------------

def _disasm(code, compressed=False):
    mode = capstone.CS_MODE_RISCV64
    if compressed:
        mode |= capstone.CS_MODE_RISCVC
    md = capstone.Cs(capstone.CS_ARCH_RISCV, mode)
    md.detail = True
    return list(md.disasm(code, 0x1000))


def test_riscv_ret_is_valid_rop_gadget():
    decodes = _disasm(RET)
    assert decodes[-1].mnemonic == 'ret'
    assert RISCV_Architecture().is_valid_rop_gadget(decodes)


def test_riscv_compressed_ret_is_valid_rop_gadget():
    # Capstone renders the compressed return `c.jr ra` under its own mnemonic.
    decodes = _disasm(C_RET, compressed=True)
    assert (decodes[-1].mnemonic, decodes[-1].op_str) == ('c.jr', 'ra')
    assert RISCV_Architecture(compressed=True).is_valid_rop_gadget(decodes)


def test_riscv_compressed_indirect_jump_is_not_a_return():
    # `c.jr t0` is an indirect jump, not a stack-driven return.
    decodes = _disasm(b'\x82\x82', compressed=True)   # c.jr t0
    assert decodes[-1].mnemonic == 'c.jr'
    assert not RISCV_Architecture(compressed=True).is_valid_rop_gadget(decodes)


# --- End-to-end gadget search --------------------------------------------

def _elf_path(tmp_path, text, e_flags=0):
    data = build_minimal_elf(64, EM_RISCV, text, 0x1000, ET_DYN, e_flags=e_flags)
    path = tmp_path / 'sample.elf'
    path.write_bytes(data)
    return str(path)


def test_gadfinder_finds_ra_restoring_gadget(tmp_path):
    # ld ra, 8(sp) ; ret -- a real RISC-V ROP gadget (restores ra from stack).
    path = _elf_path(tmp_path, LD_RA_SP + RET)
    finder = gadfinder.GadFinder(depth=8, flags=gadfinder.ROP)
    reprs = {g.text_repr for g in finder.find([path])}
    assert 'ld ra, 8(sp) ; ret' in reprs
    assert 'ret' not in reprs                 # a bare ret does not restore ra


def test_gadfinder_drops_gadget_without_ra_restore(tmp_path):
    # mv a0, a1 ; ret does not reload ra, so it is not a usable ROP gadget.
    path = _elf_path(tmp_path, MV_A0_A1 + RET)
    finder = gadfinder.GadFinder(depth=8, flags=gadfinder.ROP)
    assert finder.find([path]) == []


def test_riscv_default_depth_fits_a_framed_gadget():
    # The x86 default (5 bytes) cannot fit `ld ra, off(sp) ; ret` (8 bytes), so
    # RISC-V must raise its default or the finder silently returns nothing.
    assert RISCV_Architecture().default_depth >= len(LD_RA_SP + RET)


def test_gadfinder_default_depth_finds_riscv_gadget(tmp_path):
    # Regression: with no explicit --depth, the finder must use the RISC-V
    # architecture default (not the 5-byte x86 default) and still find gadgets.
    path = _elf_path(tmp_path, LD_RA_SP + RET)
    finder = gadfinder.GadFinder(flags=gadfinder.ROP)   # depth defaults per-arch
    reprs = {g.text_repr for g in finder.find([path])}
    assert 'ld ra, 8(sp) ; ret' in reprs


def test_riscv_written_registers_from_encoding():
    # capstone raises on regs_access() for RISC-V, so writes come from the
    # encoding: rd is operand 0, absent for stores/branches/register-jumps.
    arch = RISCV_Architecture(compressed=True)

    def writes(code):
        insn = _disasm(code, compressed=True)[0]
        return {insn.reg_name(r) for r in arch.written_registers(insn)}

    assert writes(b'\x33\x85\xc5\x00') == {'a0'}      # add a0, a1, a2
    assert writes(b'\x03\xb5\x05\x00') == {'a0'}      # ld  a0, 0(a1)
    assert writes(b'\x2e\x95') == {'a0'}              # c.add a0, a1
    assert writes(b'\x23\xb0\xb5\x00') == set()       # sd (store) -> no reg write
    assert writes(b'\x82\x80') == set()               # c.jr ra
    assert writes(b'\x67\x80\x00\x00') == set()       # ret

    # The encoding-derived writes drive operand semantics through
    # Operation.filter_gadgets. Two consequences worth pinning here:
    import rop3.operation as operation
    from rop3.arch import arch_singleton
    from rop3.gadget import Gadget
    arch_singleton.reset()
    arch_singleton.initialize(RISCV_Architecture(compressed=True))
    mode = capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC
    md = capstone.Cs(capstone.CS_ARCH_RISCV, mode)
    md.detail = True

    def gadget(code):
        return Gadget(filename='t', arch=capstone.CS_ARCH_RISCV, mode=mode,
                      vaddr=0x1000, decodes=list(md.disasm(code, 0x1000)), bytes=code)

    # (1) An immediate operand (addi a0, a0, 8) must not leak into the src
    # register set or slot_op2, and an immediate query must not match a register
    # add gadget (mirrors the x86 immediate handling).
    imm = gadget(LD_RA_SP + _i(0x13, 0, 10, 10, 8) + RET)       # ld ra ; addi a0,a0,8 ; ret
    matched = make_operation('add', ['a0', '8']).filter_gadgets([imm])
    assert matched and matched[0].src == {'a0'} and matched[0].slot_op2 is None
    reg = gadget(LD_RA_SP + _r(0x33, 0, 0x00, 10, 10, 11) + RET)  # ld ra ; add a0,a0,a1 ; ret
    assert make_operation('add', ['a0', '8']).filter_gadgets([reg]) == []

    # (2) A store writes no register (its result is in memory), so reusing its
    # address register afterwards does not make the gadget contradictory.
    sd = _s(0x23, 3, 11, 10, 0)                                 # sd a0, 0(a1)
    mv = _i(0x13, 0, 11, 12, 0)                                 # mv a1, a2 (reuses a1)
    reuse = gadget(LD_RA_SP + sd + mv + RET)
    assert make_operation('st', ['a1', 'a0']).filter_gadgets([reuse])


def test_riscv_calculate_side_effects_without_regs_access():
    # Regression: gadget annotation crashed with CS_ERR_ARCH because side-effect
    # computation called capstone's regs_access(), unimplemented for RISC-V; it
    # now derives writes from the encoding instead.
    from rop3.arch import arch_singleton
    from rop3.gadget import Gadget
    arch_singleton.reset()
    arch_singleton.initialize(RISCV_Architecture())
    code = b'\x33\x85\xc5\x00' + RET          # add a0, a1, a2 ; ret
    decodes = _disasm(code)
    gadget = Gadget(filename='t', arch=capstone.CS_ARCH_RISCV,
                    mode=RISCV_Architecture().mode, vaddr=0x1000,
                    decodes=decodes, bytes=code)
    gadget.calculate_side_effects()           # must not raise
    assert 'a0' in gadget.side_regs


def test_riscv_frame_prefix_lets_operation_follow_ra_load():
    ''' On RISC-V the ra restore frames a gadget, so an operation may sit right
        after it -- but not behind other (non-frame) instructions. '''
    import rop3.operation as operation
    from rop3.arch import arch_singleton
    arch_singleton.reset()
    arch_singleton.initialize(RISCV_Architecture(compressed=True))

    pattern = operation.Set()                       # c.add op1, op2
    ins = operation.Instruction('c.add')
    ins.add(operation.Operand('op1'))
    ins.add(operation.Operand('op2'))
    pattern.add(ins)

    C_ADD = b'\x2e\x95'                             # c.add a0, a1

    # ld ra, 8(sp) ; c.add a0, a1 ; ret  -- operation after the ra-load frame
    assert pattern.is_equal(_disasm(LD_RA_SP + C_ADD + RET, compressed=True))[0]
    # c.add a0, a1 ; ld ra, 8(sp) ; ret  -- operation first (frame in epilogue)
    assert pattern.is_equal(_disasm(C_ADD + LD_RA_SP + RET, compressed=True))[0]
    # mv a0, a1 ; c.add a0, a1 ; ret  -- non-frame junk before the operation
    assert not pattern.is_equal(_disasm(MV_A0_A1 + C_ADD + RET, compressed=True))[0]


def _riscv_op_matches(op, operands, body):
    ''' Build a framed gadget `ld ra, 8(sp) ; <body> ; ret` and return whether
        the given operation matches it via the RISC-V ROPLang patterns. '''
    import rop3.operation as operation
    from rop3.arch import arch_singleton
    from rop3.gadget import Gadget
    arch_singleton.reset()
    arch_singleton.initialize(RISCV_Architecture(compressed=True))
    mode = capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC
    md = capstone.Cs(capstone.CS_ARCH_RISCV, mode)
    md.detail = True
    code = LD_RA_SP + body + RET
    gadget = Gadget(filename='t', arch=capstone.CS_ARCH_RISCV, mode=mode,
                    vaddr=0x1000, decodes=list(md.disasm(code, 0x1000)), bytes=code)
    return bool(make_operation(op, operands).filter_gadgets([gadget]))


def _r(op, f3, f7, rd, rs1, rs2):
    import struct
    return struct.pack('<I', (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op)


def _i(op, f3, rd, rs1, imm):
    import struct
    return struct.pack('<I', ((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op)


def _s(op, f3, rs1, rs2, imm):
    import struct
    return struct.pack('<I', (((imm >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15)
                       | (f3 << 12) | ((imm & 0x1f) << 7) | op)


# rd=a0(10), rs1/rs2 = a0(10)/a1(11), sp=2, zero=0
@pytest.mark.parametrize('op,operands,body', [
    ('add', ['a0', 'a1'], _r(0x33, 0, 0x00, 10, 10, 11)),   # add a0,a0,a1
    ('add', ['a0', 'a1'], b'\x2e\x95'),                     # c.add a0,a1
    ('sub', ['a0', 'a1'], _r(0x33, 0, 0x20, 10, 10, 11)),   # sub a0,a0,a1
    ('and', ['a0', 'a1'], _r(0x33, 7, 0x00, 10, 10, 11)),   # and a0,a0,a1
    ('or',  ['a0', 'a1'], _r(0x33, 6, 0x00, 10, 10, 11)),   # or  a0,a0,a1
    ('xor', ['a0', 'a1'], _r(0x33, 4, 0x00, 10, 10, 11)),   # xor a0,a0,a1
    ('inc', ['a0'],       _i(0x13, 0, 10, 10, 1)),          # addi a0,a0,1
    ('neg', ['a0'],       _r(0x33, 0, 0x20, 10, 0, 10)),    # neg a0,a0
    ('not', ['a0'],       _i(0x13, 4, 10, 10, -1)),         # not a0,a0
    ('mov', ['a0', 'a1'], _i(0x13, 0, 10, 11, 0)),          # mv a0,a1
    ('mov', ['a0', 'a1'], b'\x2e\x85'),                     # c.mv a0,a1
    ('mov', ['a0', 'a1'], _r(0x33, 0, 0x00, 10, 0, 11)),    # add a0,zero,a1
    ('lc',  ['a0'],       _i(0x03, 3, 10, 2, 16)),          # ld a0,16(sp)
    ('ld',  ['a0', 'a1'], _i(0x03, 3, 10, 11, 0)),          # ld a0,0(a1)
    ('st',  ['a1', 'a0'], _s(0x23, 3, 11, 10, 0)),          # sd a0,0(a1) -> [a1]<-a0
    # immediate forms: addi/andi/ori/xori reg, reg, #imm  ==  op(reg, #imm)
    ('add', ['a0', '8'],  _i(0x13, 0, 10, 10, 8)),          # addi a0,a0,8
    ('add', ['a0', '8'],  b'\x21\x05'),                     # c.addi a0,8
    ('and', ['a0', '12'], _i(0x13, 7, 10, 10, 12)),         # andi a0,a0,12
    ('or',  ['a0', '5'],  _i(0x13, 6, 10, 10, 5)),          # ori a0,a0,5
    ('xor', ['a0', '5'],  _i(0x13, 4, 10, 10, 5)),          # xori a0,a0,5
])
def test_riscv_roplang_patterns_match(op, operands, body):
    assert _riscv_op_matches(op, operands, body)


def test_riscv_jmp_is_a_stack_pivot(tmp_path):
    ''' jmp is a stack pivot (SP <- op1), realized by reusing mov to write sp;
        a framed `mv sp, a0` gadget realizes jmp(a0). '''
    import struct
    import rop3.parser as parser
    from rop3 import Rop3
    from rop3.arch import arch_singleton
    arch_singleton.reset()
    arch_singleton.initialize(RISCV_Architecture())

    # Resolves to a compound reusing mov(REG_SP -> sp, op1).
    jmp = parser.Parser().get_op('jmp')
    assert not jmp.realizations[0].is_single_gadget
    ref = jmp.realizations[0].links[0]
    assert ref.name == 'mov' and ref.bindings == {'op1': 'sp', 'op2': 'op1'}

    # end-to-end: ld ra, 8(sp) ; mv sp, a0 ; ret  realizes jmp(a0)
    mv_sp_a0 = struct.pack('<I', (0 << 20) | (10 << 15) | (2 << 7) | 0x13)  # mv sp, a0
    path = _elf_path(tmp_path, LD_RA_SP + mv_sp_a0 + RET)
    chains = Rop3(path, depth=40).find_op('jmp', operands=['a0'])
    texts = [g.text_repr for chain in chains for g in chain]
    assert any('mv sp, a0' in t for t in texts)


def test_riscv_roplang_skips_flag_ops():
    ''' The carry/flag operations do not translate to RISC-V (no condition or
        carry flags) and expose no realizations. jmp-rel is *not* in this set:
        it reuses lc + spa, both of which RISC-V supports, so it stays a
        realizable compound (see the cross-arch matrix). '''
    import rop3.parser as parser
    from rop3.arch import arch_singleton
    arch_singleton.reset()
    arch_singleton.initialize(RISCV_Architecture())
    for name in ('gcf-eqc', 'gcf-ltc'):
        assert parser.Parser().get_op(name).realizations == []


def test_riscv_gcf_ops_marked_not_available():
    ''' The gcf-* operations carry an explicit `available: false` marker on
        RISC-V and raise OperationNotAvailable when used. '''
    import rop3.operation as operation
    import rop3.parser as parser
    from rop3.arch import arch_singleton
    arch_singleton.reset()
    arch_singleton.initialize(RISCV_Architecture())

    assert issubclass(parser.OperationNotAvailable, parser.ParserException)
    for name in ('gcf-eqc', 'gcf-ltc'):
        defn = parser.Parser().get_op(name)
        assert defn.available is False
        assert defn.unavailable_reason            # a human-readable reason
        with pytest.raises(parser.OperationNotAvailable):
            make_operation(name)


def test_gcf_ops_still_available_on_x86(x86):
    ''' The availability marker is per-architecture: gcf-* remain realizable on
        x86 and must not raise. '''
    import rop3.operation as operation
    import rop3.parser as parser
    defn = parser.Parser().get_op('gcf-eqc')
    assert defn.available is True and defn.realizations
    make_operation('gcf-eqc')                # must not raise


def test_gadfinder_compressed_2byte_ra_restore(tmp_path):
    # With RVC, alignment relaxes to 2 bytes: a compressed ra restore + return.
    path = _elf_path(tmp_path, C_LDSP_RA + C_RET, e_flags=EF_RISCV_RVC)
    finder = gadfinder.GadFinder(depth=4, flags=gadfinder.ROP)
    gadgets = finder.find([path])
    assert {g.text_repr for g in gadgets} == {'c.ldsp ra, 8(sp) ; c.jr ra'}
    assert all(g.vaddr % 2 == 0 for g in gadgets)
