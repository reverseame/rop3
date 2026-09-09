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

import rop3.operation as operation

from conftest import make_gadget, make_operation


def test_lc_matches_pop_reg(x64):
    ''' lc (load constant) matches `pop <reg> ; ret`. '''
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
        make_gadget(b'\x90\xc3', 0x1020),   # nop ; ret  (no match)
    ]
    matched = make_operation('lc').filter_gadgets(gadgets)
    texts = {g.text_repr for g in matched}
    assert 'pop rax ; ret' in texts
    assert 'pop rbx ; ret' in texts
    assert 'nop ; ret' not in texts


def test_lc_with_dst_filter(x64):
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
    ]
    matched = make_operation('lc', ['rax']).filter_gadgets(gadgets)
    assert [g.text_repr for g in matched] == ['pop rax ; ret']
    assert matched[0].dst == {'rax'}


def test_filter_gadgets_empty_input(x64):
    assert make_operation('lc').filter_gadgets([]) == []


def test_filter_gadgets_does_not_mutate_input(x64):
    ''' filter_gadgets must annotate copies, not the shared input gadgets. '''
    g = make_gadget(b'\x58\xc3', 0x1000)             # pop rax ; ret
    assert g.op is None and g.dst is None
    matched = make_operation('lc', ['rax']).filter_gadgets([g])
    assert matched and matched[0] is not g           # a copy was returned
    assert matched[0].op == 'lc' and matched[0].dst == {'rax'}
    # original is untouched
    assert g.op is None and g.dst is None and g.side_regs == set()


def test_filter_gadgets_clobbered_destination(x64):
    '''
    Only the operation's destination matters for the "contradictory gadget"
    check:
      - a gadget that overwrites the destination before the ret is rejected by
        default and kept with reject_clobbered=False;
      - clobbering a register that is not the destination is allowed;
      - a stack-pointer op (`add rsp, 8 ; ret`) writes rsp, but the terminating
        ret's own rsp pop is control flow, not a clobber -- a valid spa, not
        contradictory.
    '''
    good = make_gadget(b'\x48\x01\xd8\xc3', 0x1000)              # add rax, rbx ; ret
    bad = make_gadget(b'\x48\x01\xd8\x48\x89\xc8\xc3', 0x1010)   # add rax, rbx ; mov rax, rcx ; ret
    op = make_operation('add', ['rax', 'rbx'])
    assert [g.text_repr for g in op.filter_gadgets([good, bad])] == ['add rax, rbx ; ret']
    kept = {g.text_repr for g in op.filter_gadgets([good, bad], reject_clobbered=False)}
    assert kept == {'add rax, rbx ; ret', 'add rax, rbx ; mov rax, rcx ; ret'}

    # clobbering a register other than the destination is fine
    other = make_gadget(b'\x48\x01\xd8\x48\x31\xc9\xc3', 0x1020)  # add rax, rbx ; xor rcx, rcx ; ret
    assert [x.text_repr for x in make_operation('add', ['rax', 'rbx']).filter_gadgets([other])] \
        == ['add rax, rbx ; xor rcx, rcx ; ret']

    # the terminator's incidental rsp write does not make a stack-pointer op
    # contradictory
    spa = make_gadget(b'\x48\x83\xc4\x08\xc3', 0x1030)           # add rsp, 8 ; ret
    assert [x.text_repr for x in make_operation('add', ['rsp', '8']).filter_gadgets([spa])] \
        == ['add rsp, 8 ; ret']


def test_operand_parse_imm_supports_hex_and_negative(x64):
    ''' Regression: immediates parsed with int(x, 0). '''
    op = operation.Operand('rax')
    assert op._parse_imm('0xffffffff') == 0xffffffff
    assert op._parse_imm('-1') == -1
    assert op._parse_imm(42) == 42


def test_ld_with_src_matches_memory_not_register(x64):
    '''
    Regression (#30, #33): `ld` (mov dst, [src]) with a concrete --src must
    match a memory load `mov <reg>, [src]`, not a register move `mov <reg>, src`.
    A previous bug overwrote the memory operand type with op_reg in set_src.
    '''
    gadgets = [
        make_gadget(b'\x48\x8b\x03\xc3', 0x1000),   # mov rax, [rbx] ; ret
        make_gadget(b'\x48\x89\xd8\xc3', 0x1010),   # mov rax, rbx ; ret (must NOT match)
    ]
    matched = make_operation('ld', [None, 'rbx']).filter_gadgets(gadgets)
    assert [g.text_repr for g in matched] == ['mov rax, qword ptr [rbx] ; ret']


def test_ld_does_not_match_immediate_load(x64):
    '''
    Regression (#33, error 3): a generic memory address must not be resolved
    into an immediate, so `mov rax, 0xcafe` is not a valid `ld` (load).
    '''
    gadgets = [
        make_gadget(b'\x48\xc7\xc0\xfe\xca\x00\x00\xc3', 0x1000),   # mov rax, 0xcafe ; ret
    ]
    assert make_operation('ld').filter_gadgets(gadgets) == []


def test_set_binding_preserves_memory_type(x64):
    '''
    Regression (#33, error 1): binding a concrete register to a `[dst]`
    placeholder must keep the operand a memory operand, not turn it into a reg.
    '''
    op = operation.Operand('[op1]')
    assert op.is_mem()
    op.set_binding('op1', 'rax')
    assert op.is_mem()
    assert op.reg == 'rax'


def test_set_binding_preserves_memory_type_src(x64):
    ''' Regression (#33, error 1): same as above for the `[src]` placeholder. '''
    op = operation.Operand('[op2]')
    assert op.is_mem()
    op.set_binding('op2', 'rbx')
    assert op.is_mem()
    assert op.reg == 'rbx'


def test_set_binding_accepts_immediate(x64):
    '''
    Regression (#33, error 2): binding an operand to an immediate produces an
    op_imm operand rather than rejecting the value.
    '''
    op = operation.Operand('op1')
    op.set_binding('op1', '0x10')
    assert op.is_imm()
    assert op.imm == 0x10


def test_xchg_src_counted_as_side_effect(x64):
    '''
    Regression (#31): in `xchg dst, src` the `src` register is clobbered, so it
    must be reported as a side effect (it was wrongly excluded before).
    '''
    gadget = make_gadget(b'\x48\x93\xc3', 0x1000)   # xchg rbx, rax ; ret
    matched = make_operation('mov', ['rbx', 'rax']).filter_gadgets([gadget])
    assert len(matched) == 1
    assert 'rax' in matched[0].side_regs


def test_mov_matches_clc_cmovae(x64):
    '''
    Regression (#32): the mov ROPLang uses the valid Capstone mnemonics
    `cmovae`/`cmovb` (not `cmovc`), so `clc ; cmovae dst, src` is a valid mov.
    '''
    gadget = make_gadget(b'\xf8\x48\x0f\x43\xc3\xc3', 0x1000)   # clc ; cmovae rax, rbx ; ret
    matched = make_operation('mov', ['rax', 'rbx']).filter_gadgets([gadget])
    assert [g.text_repr for g in matched] == ['clc ; cmovae rax, rbx ; ret']


def test_add_reports_set_valued_dst_and_src(x64):
    '''
    New model: dst/src are sets of concrete register names derived from the
    operation's role metadata. `add op1, op2` has dst:[op1], src:[op1, op2], so
    `add rdx, rax` yields dst={rdx}, src={rax, rdx} (rdx is read and written).
    '''
    gadget = make_gadget(b'\x48\x01\xc2\xc3', 0x1000)   # add rdx, rax ; ret
    matched = make_operation('add', ['rdx', 'rax']).filter_gadgets([gadget])
    assert len(matched) == 1
    assert matched[0].dst == {'rdx'}
    assert matched[0].src == {'rax', 'rdx'}


def test_same_gadget_group_requires_all_instructions(x64):
    '''
    mov's `push op2 ; pop op1` realization is a single gadget group, so it must
    match a gadget containing BOTH instructions, not a lone `push`.
    '''
    both = make_gadget(b'\x53\x58\xc3', 0x1000)    # push rbx ; pop rax ; ret
    only_push = make_gadget(b'\x53\xc3', 0x1010)   # push rbx ; ret
    matched = make_operation('mov', ['rax', 'rbx']).filter_gadgets([both, only_push])
    assert [g.text_repr for g in matched] == ['push rbx ; pop rax ; ret']


def test_register_second_operand_is_detected(x64):
    '''
    Regression: `add rsp, r8` (a register second operand) must be detected,
    including with an unconstrained destination. The register r8 must not be
    confused with the immediate 8, and vice versa.
    '''
    r8 = make_gadget(b'\x4c\x01\xc4\xc3', 0x1000)    # add rsp, r8 ; ret
    imm = make_gadget(b'\x48\x83\xc4\x08\xc3', 0x1010)   # add rsp, 8 ; ret

    assert [g.text_repr for g in make_operation('add', ['rsp', 'r8']).filter_gadgets([r8, imm])] \
        == ['add rsp, r8 ; ret']
    # unconstrained destination, concrete register source
    assert [g.text_repr for g in make_operation('add', [None, 'r8']).filter_gadgets([r8, imm])] \
        == ['add rsp, r8 ; ret']
    # the immediate query must not pick up the r8 register gadget
    assert [g.text_repr for g in make_operation('add', ['rsp', '8']).filter_gadgets([r8, imm])] \
        == ['add rsp, 8 ; ret']


def test_reg_alias_substitution_flag(x64):
    from rop3.arch import arch_singleton
    pop_ax = make_gadget(b'\x66\x58\xc3', 0x1000)   # pop ax ; ret  (alias of rax)
    # default: a sub-register does not satisfy a generic register operand
    assert make_operation('lc', [None]).filter_gadgets([pop_ax]) == []
    # with aliases enabled it matches and normalizes to the full register
    arch_singleton.allow_reg_aliases = True
    try:
        matched = make_operation('lc', [None]).filter_gadgets([pop_ax])
        assert [g.text_repr for g in matched] == ['pop ax ; ret']
        assert matched[0].slot_op1 == 'rax'
        assert matched[0].dst == {'rax'}
    finally:
        arch_singleton.allow_reg_aliases = False


# --- The two-phase matching model -----------------------------------------
#
# Every case runs off the gadget's *derived* frame mask (make_gadget leaves it
# None, so Set.iter_matches derives it via search.frame_mask_for), exercising
# the real framing computation rather than a hand-set mask. Before the frame an
# operation must be the gadget's first instruction; once inside the frame any
# body instruction matches, in any order; a framing instruction is never
# matched, but a stack pivot is body, not framing.

@pytest.mark.parametrize('desc, code, op, operands, expected', [
    # before the frame: the operation must be first -- no junk may precede it
    ('op is the first instruction',
     b'\x5b\xc3', 'lc', ['rbx'], ['pop rbx ; ret']),                 # pop rbx ; ret
    ('junk before op on x86 (no prologue)',
     b'\x48\x89\xc7\x5b\xc3', 'lc', ['rbx'], []),                    # mov rdi,rax ; pop rbx ; ret
    ('op before the prologue is first, so matched',
     b'\x48\x89\xf7\x58\xff\xe0', 'mov', ['rdi', 'rsi'],            # mov rdi,rsi ; pop rax ; jmp rax
     ['mov rdi, rsi ; pop rax ; jmp rax']),
    ('junk before a leading stack pivot',
     b'\xc9\x48\x01\xc8\xc3', 'add', ['rax', 'rcx'], []),           # leave ; add rax,rcx ; ret
    ('junk before the first of a multi-insn op',
     b'\x90\x53\x58\xc3', 'mov', ['rax', 'rbx'], []),               # nop ; push rbx ; pop rax ; ret
    # a multi-instruction body must be a consecutive run
    ('non-consecutive body is not matched',
     b'\x53\x90\x58\xc3', 'mov', ['rax', 'rbx'], []),               # push rbx ; nop ; pop rax ; ret
    ('consecutive body is matched',
     b'\x53\x58\xc3', 'mov', ['rax', 'rbx'], ['push rbx ; pop rax ; ret']),  # push rbx ; pop rax ; ret
    # inside the frame: an operation after the prologue matches
    ('op after the prologue',
     b'\x58\x48\x89\xf7\xff\xe0', 'mov', ['rdi', 'rsi'],           # pop rax ; mov rdi,rsi ; jmp rax
     ['pop rax ; mov rdi, rsi ; jmp rax']),
    # a stack pivot is body, not framing, so it still matches add
    ('sp-add in a JOP body is a real add',
     b'\x58\x48\x83\xc4\x08\xff\xe0', 'add', ['rsp', '8'],         # pop rax ; add rsp,8 ; jmp rax
     ['pop rax ; add rsp, 8 ; jmp rax']),
    ('leading sp-add (ret self-frames) is a real add',
     b'\x48\x83\xc4\x08\xc3', 'add', ['rsp', '8'], ['add rsp, 8 ; ret']),  # add rsp, 8 ; ret
])
def test_operation_matching_model(x64, desc, code, op, operands, expected):
    g = make_gadget(code, 0x1000)
    matched = [x.text_repr for x in make_operation(op, operands).filter_gadgets([g])]
    assert matched == expected
