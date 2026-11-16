import capstone
import pytest

from rop3 import Rop3
from rop3.arch import arch_singleton
from rop3.archs.aarch64_arch import AArch64_Architecture
from rop3.archs.riscv_arch import RISCV_Architecture
from rop3.archs.x86_arch import X64_Architecture
from rop3.gadfinder import GadFinder
from rop3.gadget import Gadget
from rop3.ropchain import RopChain, RopChainNotFound
from rop3.search import aligned_scan, backwards_framed_search


A64_RET = bytes.fromhex('c0035fd6')
A64_FRAME = bytes.fromhex('fd7bc1a8')


def _gadget(arch, code, address=0x1000):
    md = capstone.Cs(arch.arch, arch.mode)
    md.detail = True
    decodes = list(md.disasm(code, address))
    assert sum(i.size for i in decodes) == len(code)
    frame = tuple(i == len(decodes) - 1 or arch.restores_return_address(insn)
                  for i, insn in enumerate(decodes))
    return Gadget(filename='regression', arch=arch.arch, mode=arch.mode,
                  vaddr=address, decodes=decodes, bytes=code, frame=frame)


@pytest.mark.parametrize('code', ['c3', '415841ffe0', '584889f7ffe0', '66c3'])
def test_predicate_only_ropblock_matches_pattern_search(code):
    arch = X64_Architecture()
    md = capstone.Cs(arch.arch, arch.mode)
    md.detail = True
    args = (bytes.fromhex(code), 0x1000, 16, 1, md.disasm,
            arch.is_pc_reg_write, arch.ropblock_branch_reg,
            arch.is_stack_load, arch.clobbers_reg)

    def records(**kwargs):
        return [(v, raw, frame) for v, raw, _, frame in
                backwards_framed_search(*args, **kwargs)]

    actual = records()
    expected = records(terminations=arch.get_ropblock_terminations())
    assert set(actual) == set(expected)
    assert len(actual) == len(set(actual))


def test_predicate_only_scan_honors_filters():
    arch = X64_Architecture()
    md = capstone.Cs(arch.arch, arch.mode)
    md.detail = True
    runs = list(backwards_framed_search(
        bytes.fromhex('58c390c3'), 0x1000, 4, 1, md.disasm,
        arch.is_pc_reg_write, arch.ropblock_branch_reg,
        arch.is_stack_load, arch.clobbers_reg,
        accept_match=lambda end: end == 4,
        accept_candidate=lambda addr, raw: addr == 0x1003))
    assert [(v, raw) for v, raw, _, _ in runs] == [(0x1003, b'\xc3')]


@pytest.mark.parametrize('ropblock', [False, True])
@pytest.mark.parametrize('padding', [0, 1, 2, 3])
def test_aarch64_scans_absolute_alignment(tmp_path, ropblock, padding):
    # Each buffer starts before the first legal instruction address.
    start = 0x1004 - padding
    path = tmp_path / 'arm.bin'
    path.write_bytes(b'\0' * padding + bytes.fromhex('fe0340f9') + A64_RET)
    gadgets = Rop3(str(path), raw=True, arch='aarch64', base=hex(start),
                   ropblock=ropblock).gadgets()
    assert [(g.vaddr, g.text_repr) for g in gadgets] == [
        (0x1004, 'ldr x30, [sp] ; ret')]


@pytest.mark.parametrize('ropblock', [False, True])
def test_aarch64_rejects_unaligned_instructions(tmp_path, ropblock):
    path = tmp_path / 'arm.bin'
    path.write_bytes(bytes.fromhex('fe0340f9') + A64_RET)
    assert not Rop3(str(path), raw=True, arch='aarch64', base='0x1001',
                    ropblock=ropblock).gadgets()


@pytest.mark.parametrize('body,operand', [
    ('0000018b', 'x1'),      # add x0,x0,x1
    ('000c018b', 'x1'),      # add x0,x0,x1,lsl #3
    ('0040218b', 'w1'),      # add x0,x0,w1,uxtw
    ('00044091', '1'),       # add x0,x0,#1,lsl #12
])
def test_aarch64_arithmetic_modifiers(body, operand):
    arch = AArch64_Architecture()
    arch_singleton.initialize(arch)
    gadget = _gadget(arch, bytes.fromhex(body) + A64_FRAME + A64_RET)
    # Exercise extensions even when sub-register aliases are allowed.
    arch_singleton.allow_reg_aliases = True
    matched = GadFinder().find_op_from_gadgets([gadget], 'add', ['x0', operand])
    assert bool(matched) == (body == '0000018b')


@pytest.mark.parametrize('arch,body,clobber,operands', [
    (AArch64_Architecture(), '000001eb', '420400b1', ['x0', 'x1']),
    (X64_Architecture(), '4829d8', '4885c9', ['rax', 'rbx']),
])
def test_comparison_requires_flags_to_survive(arch, body, clobber, operands):
    arch_singleton.initialize(arch)
    tail = A64_FRAME + A64_RET if isinstance(arch, AArch64_Architecture) else b'\xc3'
    clean = _gadget(arch, bytes.fromhex(body) + tail)
    dirty = _gadget(arch, bytes.fromhex(body + clobber) + tail)
    finder = GadFinder()
    assert finder.find_op_from_gadgets([clean], 'ltc', operands)
    assert not finder.find_op_from_gadgets([dirty], 'ltc', operands)
    request = [{'op': 'ltc', 'operands': operands, 'data': 'ltc'}]
    assert list(RopChain(finder).search([clean], request))
    with pytest.raises(RopChainNotFound):
        list(RopChain(finder).search([dirty], request))


def test_aarch64_non_flag_setting_sub_is_not_comparison():
    arch = AArch64_Architecture()
    arch_singleton.initialize(arch)
    gadget = _gadget(arch, bytes.fromhex('000001cb') + A64_FRAME + A64_RET)
    assert not GadFinder().find_op_from_gadgets([gadget], 'ltc', ['x0', 'x1'])


@pytest.mark.parametrize('arch,restore,clobber,ret', [
    ('aarch64', 'fe0340f9', 'fe0300aa', 'c0035fd6'),  # mov x30,x0
    ('aarch64', 'fe0340f9', 'de031eca', 'c0035fd6'),  # eor x30,x30,x30
    ('riscv64i', '83308100', '93000000', '67800000'), # mv ra,zero
])
def test_framed_return_rejects_overwritten_target(tmp_path, arch, restore, clobber, ret):
    path = tmp_path / 'code.bin'
    path.write_bytes(bytes.fromhex(restore + clobber + ret))
    assert not Rop3(str(path), raw=True, arch=arch, depth=24).gadgets()
    assert Rop3(str(path), raw=True, arch=arch, depth=24, framed=False).gadgets()


def test_framed_return_uses_explicit_aarch64_target(tmp_path):
    path = tmp_path / 'code.bin'
    path.write_bytes(bytes.fromhex('e90340f920015fd6'))  # ldr x9,[sp]; ret x9
    gadgets = Rop3(str(path), raw=True, arch='aarch64').gadgets()
    assert len(gadgets) == 1
    assert gadgets[0].frame == (True, True)


def test_low_level_framed_scan_checks_return_data_flow():
    arch = AArch64_Architecture()
    md = capstone.Cs(arch.arch, arch.mode)
    md.detail = True
    code = bytes.fromhex('fe0340f9fe0300aac0035fd6')
    assert not list(aligned_scan(
        code, 0x1000, 20, 4, md.disasm, arch.is_valid_rop_gadget,
        restores_return_address=arch.restores_return_address,
        is_return=arch.is_return))


@pytest.mark.parametrize('arch,code', [
    ('aarch64', 'fe0340f9de230091c0035fd6'),  # ldr x30; add x30,x30,#8; ret
    ('riscv64', '83308100850067800000'),     # ld ra; c.addi ra,1; ret
    ('aarch64', 'fe0340f9fe0300aafe0340f9c0035fd6'), # restore again after clobber
])
def test_framed_return_keeps_controlled_targets(tmp_path, arch, code):
    path = tmp_path / 'code.bin'
    path.write_bytes(bytes.fromhex(code))
    assert any(g.vaddr == 0 for g in Rop3(str(path), raw=True, arch=arch,
                                        depth=24).gadgets())


@pytest.mark.parametrize('code,reads,writes', [
    ('93858500', {'a1'}, {'a1'}),           # addi a1,a1,8
    ('83358100', {'sp'}, {'a1'}),           # ld a1,8(sp)
    ('2330b100', {'sp', 'a1'}, set()),       # sd a1,0(sp)
    ('e7800200', {'t0'}, {'ra'}),           # jalr t0 (implicit rd=ra)
    ('e7020300', {'t1'}, {'t0'}),           # jalr t0,t1,0
    ('ef000000', set(), {'ra'}),            # jal (implicit rd=ra)
    ('6f000000', set(), set()),             # j (rd=zero)
    ('8292', {'t0'}, {'ra'}),               # c.jalr t0
    ('2e95', {'a0', 'a1'}, {'a0'}),         # c.add a0,a1
    ('0505', {'a0'}, {'a0'}),               # c.addi a0,1
    ('2285', {'s0'}, {'a0'}),               # c.mv a0,s0
    ('8280', {'ra'}, set()),                # c.jr ra
    ('67800000', {'ra'}, set()),            # ret
    ('93000000', set(), {'ra'}),            # mv ra,zero
])
def test_riscv_register_effects(code, reads, writes):
    arch = RISCV_Architecture()
    gadget = _gadget(arch, bytes.fromhex(code))
    insn = gadget.decodes[0]
    assert {insn.reg_name(r) for r in arch.read_registers(insn)} == reads
    assert {insn.reg_name(r) for r in arch.written_registers(insn)} == writes


def test_riscv_default_finds_hidden_halfword_gadget(tmp_path):
    arch = RISCV_Architecture()
    assert arch.compressed and arch.alignment == 2
    path = tmp_path / 'rv.bin'
    # Intended stream: lui t0,0x60a20; c.jr ra. At offset 2: c.ldsp ra,8(sp).
    path.write_bytes(bytes.fromhex('b702a2608280'))
    gadgets = Rop3(str(path), raw=True, arch='riscv64').gadgets()
    assert any(g.vaddr == 2 and g.text_repr == 'c.ldsp ra, 8(sp) ; c.jr ra'
               for g in gadgets)


def test_riscv_implicit_link_write_counts_as_side_effect():
    arch = RISCV_Architecture()
    arch_singleton.initialize(arch)
    gadget = _gadget(arch, bytes.fromhex('e7800200'))
    gadget.calculate_side_effects()
    assert gadget.side_regs == {'ra'}
    assert gadget.writes_reg('ra') and not gadget.writes_reg('t0')


@pytest.mark.parametrize('arch,code,operands', [
    (X64_Architecture(), '488b4308c3', ['rax', 'rbx']),
    (AArch64_Architecture(), '200440f9fd7bc1a8c0035fd6', ['x0', 'x1']),
])
def test_memory_matching_keeps_base_only_semantics(arch, code, operands):
    arch_singleton.initialize(arch)
    gadget = _gadget(arch, bytes.fromhex(code))
    assert GadFinder().find_op_from_gadgets([gadget], 'ld', operands)
