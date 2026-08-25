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
from rop3 import Rop3
from rop3.archs.aarch64_arch import AArch64_Architecture
from rop3.binaries.elf import ELF

from conftest import build_minimal_elf, ET_DYN

EM_AARCH64 = 183

ADD = b'\x20\x00\x02\x8b'          # add x0, x1, x2
RET = b'\xc0\x03\x5f\xd6'          # ret            (0xd65f03c0)
BR_X0 = b'\x00\x00\x1f\xd6'        # br x0          (indirect jump, JOP)
# Return-address restores from the stack (frame the gadget for framed search).
LDP_FRAME = bytes.fromhex('fd7bc1a8')  # ldp x29, x30, [sp], #16
LDR_LR = bytes.fromhex('fe0740f9')     # ldr x30, [sp, #8]

pytestmark = pytest.mark.skipif(not hasattr(capstone, 'CS_ARCH_ARM64'),
                                reason='capstone build without ARM64 support')


def _elf(tmp_path, text):
    path = tmp_path / 'a.elf'
    path.write_bytes(build_minimal_elf(64, EM_AARCH64, text, 0x1000, ET_DYN))
    return str(path)


def test_elf_detects_aarch64_and_selects_aligned():
    arch = ELF(build_minimal_elf(64, EM_AARCH64, RET, 0x1000, ET_DYN), None).get_arch()
    assert isinstance(arch, AArch64_Architecture)
    assert arch.arch == capstone.CS_ARCH_ARM64
    assert (arch.address_size, arch.alignment) == (8, 4)
    assert arch.scan_name == 'aligned'
    assert not arch.parallelizable


def test_aarch64_finds_intended_rop_gadgets(tmp_path):
    path = _elf(tmp_path, ADD + ADD + RET)
    reprs = {g.text_repr for g in Rop3(path, depth=16, framed=False).gadgets()}
    assert 'ret' in reprs
    assert 'add x0, x1, x2 ; ret' in reprs
    assert 'add x0, x1, x2 ; add x0, x1, x2 ; ret' in reprs


def test_aarch64_gadgets_are_4byte_aligned(tmp_path):
    path = _elf(tmp_path, ADD + ADD + RET)
    assert all(g.vaddr % 4 == 0 for g in Rop3(path, depth=16, framed=False).gadgets())


def test_aarch64_jop(tmp_path):
    path = _elf(tmp_path, ADD + BR_X0)
    reprs = {g.text_repr for g in Rop3(path, depth=16, rop=False, jop=True).gadgets()}
    assert 'br x0' in reprs
    assert 'add x0, x1, x2 ; br x0' in reprs


def test_aarch64_calculate_side_effects_via_regs_access():
    # capstone implements regs_access() for ARM64, so gadget annotation (the
    # path that crashed on RISC-V) works through the default arch hook.
    from rop3.arch import arch_singleton
    from rop3.gadget import Gadget
    arch_singleton.reset()
    arch_singleton.initialize(AArch64_Architecture())
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    decodes = list(md.disasm(ADD + RET, 0x1000))       # add x0,x1,x2 ; ret
    gadget = Gadget(filename='t', arch=capstone.CS_ARCH_ARM64,
                    mode=capstone.CS_MODE_ARM, vaddr=0x1000,
                    decodes=decodes, bytes=ADD + RET)
    gadget.calculate_side_effects()                    # must not raise
    assert 'x0' in gadget.side_regs


def test_aarch64_written_registers_via_regs_access():
    arch = AArch64_Architecture()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    add = list(md.disasm(ADD, 0x1000))[0]
    ret = list(md.disasm(RET, 0x1000))[0]
    assert {add.reg_name(r) for r in arch.written_registers(add)} == {'x0'}
    assert arch.written_registers(ret) == set()   # ret writes no GP register


def test_aarch64_scan_is_serial_even_with_jobs(tmp_path):
    # The parallel scanner is Galileo-only; AArch64 (aligned) must stay correct
    # under --jobs by running single-threaded.
    path = _elf(tmp_path, ADD + ADD + RET)
    serial = {g.text_repr for g in Rop3(path, depth=16, jobs=1, framed=False).gadgets()}
    jobbed = {g.text_repr for g in Rop3(path, depth=16, jobs=4, framed=False).gadgets()}
    assert serial == jobbed


# --- Framed gadget search (default on for AArch64) ------------------------

def test_aarch64_is_frame_load_and_is_return_predicates():
    arch = AArch64_Architecture()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    one = lambda code: list(md.disasm(code, 0x1000))[0]
    assert arch.is_frame_load(one(LDP_FRAME))     # ldp x29, x30, [sp], #16
    assert arch.is_frame_load(one(LDR_LR))        # ldr x30, [sp, #8]
    assert not arch.is_frame_load(one(ADD))       # add does not touch the stack
    assert not arch.is_frame_load(one(RET))       # ret is not a load
    assert arch.is_return(one(RET))
    assert not arch.is_return(one(ADD))


def test_aarch64_framed_default_requires_lr_restore(tmp_path):
    # add x0,x1,x2 ; ldp x29,x30,[sp],#16 ; ret  restores lr; a lone `ret` and
    # `add ; ret` do not. Framed search (the default) keeps only the former.
    path = _elf(tmp_path, ADD + LDP_FRAME + RET + ADD + RET)
    reprs = {g.text_repr for g in Rop3(path, depth=24).gadgets()}
    assert 'ldp x29, x30, [sp], #0x10 ; ret' in reprs
    assert 'add x0, x1, x2 ; ldp x29, x30, [sp], #0x10 ; ret' in reprs
    assert 'ret' not in reprs                     # bare ret does not restore lr
    assert 'add x0, x1, x2 ; ret' not in reprs    # nor does add ; ret


def test_aarch64_no_frame_keeps_unframed_gadgets(tmp_path):
    # With framing disabled (--no-frame) the plain aligned sweep also keeps
    # gadgets that never restore lr.
    path = _elf(tmp_path, ADD + RET)
    framed = {g.text_repr for g in Rop3(path, depth=24).gadgets()}
    unframed = {g.text_repr for g in Rop3(path, depth=24, framed=False).gadgets()}
    assert 'ret' not in framed
    assert 'ret' in unframed
    assert 'add x0, x1, x2 ; ret' in unframed


def test_aarch64_framed_does_not_gate_jop(tmp_path):
    # JOP terminators (br) carry no return frame, so framed search must still
    # find them (the frame requirement applies only to `ret` gadgets).
    path = _elf(tmp_path, ADD + BR_X0)
    reprs = {g.text_repr for g in Rop3(path, depth=24, rop=False, jop=True).gadgets()}
    assert 'br x0' in reprs
    assert 'add x0, x1, x2 ; br x0' in reprs


# --- ROPLang operation patterns (AArch64) ---------------------------------

def _aarch64_op_matches(op, operands, body):
    ''' Build a framed gadget `<body> ; ldp x29, x30, [sp], #16 ; ret` (the
        operation first, the lr-restore in the epilogue) and return whether the
        given operation matches it via the AArch64 ROPLang patterns. '''
    import rop3.operation as operation
    from rop3.arch import arch_singleton
    from rop3.gadget import Gadget
    arch_singleton.reset()
    arch_singleton.initialize(AArch64_Architecture())
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    code = body + LDP_FRAME + RET
    gadget = Gadget(filename='t', arch=capstone.CS_ARCH_ARM64,
                    mode=capstone.CS_MODE_ARM, vaddr=0x1000,
                    decodes=list(md.disasm(code, 0x1000)), bytes=code)
    return bool(operation.Operation(op, operands).filter_gadgets([gadget]))


@pytest.mark.parametrize('op,operands,body', [
    ('add', ['x0', 'x1'], bytes.fromhex('0000018b')),   # add x0, x0, x1
    ('add', ['x0', '8'],  bytes.fromhex('00200091')),   # add x0, x0, #8 (imm)
    ('sub', ['x0', 'x1'], bytes.fromhex('000001cb')),   # sub x0, x0, x1
    ('and', ['x0', 'x1'], bytes.fromhex('0000018a')),   # and x0, x0, x1
    ('or',  ['x0', 'x1'], bytes.fromhex('000001aa')),   # orr x0, x0, x1
    ('xor', ['x0', 'x1'], bytes.fromhex('000001ca')),   # eor x0, x0, x1
    ('neg', ['x0'],       bytes.fromhex('e00300cb')),   # neg x0, x0
    ('not', ['x0'],       bytes.fromhex('e00320aa')),   # mvn x0, x0
    ('inc', ['x0'],       bytes.fromhex('00040091')),   # add x0, x0, #1
    ('mov', ['x0', 'x1'], bytes.fromhex('e00301aa')),   # mov x0, x1
    ('ld',  ['x0', 'x1'], bytes.fromhex('200040f9')),   # ldr x0, [x1]
    ('st',  ['x0', 'x1'], bytes.fromhex('010000f9')),   # str x1, [x0] -> [x0]<-x1
    ('lc',  ['x0'],       bytes.fromhex('e00340f9')),   # ldr x0, [sp]
    ('spa', ['x0'],       bytes.fromhex('ff63208b')),   # add sp, sp, x0
    ('sps', ['x0'],       bytes.fromhex('ff6320cb')),   # sub sp, sp, x0
    ('sc',  ['x0'], bytes.fromhex('e00300f9')),        # str x0, [sp] (direct stack store)
])
def test_aarch64_roplang_patterns_match(op, operands, body):
    assert _aarch64_op_matches(op, operands, body)


def test_aarch64_lc_and_sc_do_not_use_pop(tmp_path):
    # Regression: the AArch64 `lc`/`sc` blocks must not use x86 push/pop (which
    # do not exist on AArch64); they load/round-trip through the stack.
    import rop3.parser as parser
    from rop3.arch import arch_singleton
    arch_singleton.reset()
    arch_singleton.initialize(AArch64_Architecture())
    for name in ('lc', 'sc'):
        real = parser.Parser().get_op(name).realizations
        mnems = {ins.mnemonic
                 for r in real for s in r.links for ins in getattr(s, 'items', [])}
        assert 'pop' not in mnems and 'push' not in mnems, (name, mnems)


def test_aarch64_compound_ops_are_available():
    # Compound ops resolve to realizations on AArch64 (they reuse mov/lc/etc.).
    import rop3.parser as parser
    from rop3.arch import arch_singleton
    arch_singleton.reset()
    arch_singleton.initialize(AArch64_Architecture())
    for name in ('gsp', 'lsd', 'eqc', 'ltc', 'jmp', 'jmp-rel', 'spa', 'sps'):
        defn = parser.Parser().get_op(name)
        assert defn.available and defn.realizations, name


def test_aarch64_end_to_end_find_op_mov(tmp_path):
    # mov x0, x1 ; ldp x29, x30, [sp], #16 ; ret  realizes mov(x0, x1).
    MOV = bytes.fromhex('e00301aa')                       # mov x0, x1
    path = _elf(tmp_path, MOV + LDP_FRAME + RET)
    gadgets = Rop3(str(path), depth=24).find_op('mov', operands=['x0', 'x1'])
    assert any('mov x0, x1' in g.text_repr for g in gadgets)
