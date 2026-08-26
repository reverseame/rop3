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

import rop3.ropchain as ropchain_mod
from rop3.ropchain import RopChain
from rop3.gadfinder import GadFinder

from conftest import make_gadget


def _op(op, dst=None, src=None):
    ''' A requested chain step. Operand slots are the positional op1/op2
        (op1 is the destination, op2 the source). '''
    return {'data': f'{op}({dst or ""},{src or ""})', 'op': op, 'op1': dst, 'op2': src}


def test_search_simple_concrete_chain(x64):
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
    ]
    results = list(RopChain(GadFinder()).search(gadgets, [_op('lc', dst='rax')]))
    assert results
    assert len(results[0]) == 1
    assert results[0][0].text_repr == 'pop rax ; ret'


def test_search_two_step_chain(x64):
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
    ]
    chain = [_op('lc', dst='rax'), _op('lc', dst='rbx')]
    results = list(RopChain(GadFinder()).search(gadgets, chain))
    assert results
    texts = [g.text_repr for g in results[0]]
    assert texts == ['pop rax ; ret', 'pop rbx ; ret']


def test_search_raises_when_no_gadget(x64):
    gadgets = [make_gadget(b'\x90\xc3', 0x1000)]   # nop ; ret (no lc)
    with pytest.raises(ropchain_mod.RopChainNotFound):
        list(RopChain(GadFinder()).search(gadgets, [_op('lc', dst='rax')]))


def test_search_generic_registers(x64):
    gadgets = [
        make_gadget(b'\x48\x89\xd8\xc3', 0x1000),   # mov rax, rbx ; ret
        make_gadget(b'\x48\x89\xd1\xc3', 0x1010),   # mov rcx, rdx ; ret
    ]
    chain = [_op('mov', dst='REG1', src='REG2')]
    results = list(RopChain(GadFinder()).search(gadgets, chain))
    assert results
    assert all(len(r) == 1 for r in results)


def test_explicit_dst_clears_clobbered_register(x64):
    '''
    Regression (#34): a register written by a later step must no longer be
    considered clobbered by an earlier step.

    Step 1 `lc(rax)` uses `pop rax ; pop rbx ; ret`, which clobbers rbx.
    Step 2 `lc(rbx)` rewrites rbx, so it must be clean again for step 3
    `mov(rdx, rbx)`, which reads rbx. Before the fix the stale clobber on rbx
    blocked step 3 and no chain was found.
    '''
    gadgets = [
        make_gadget(b'\x58\x5b\xc3', 0x1000),       # pop rax ; pop rbx ; ret
        make_gadget(b'\x5b\xc3', 0x1010),           # pop rbx ; ret
        make_gadget(b'\x48\x89\xda\xc3', 0x1020),   # mov rdx, rbx ; ret
    ]
    chain = [
        _op('lc', dst='rax'),
        _op('lc', dst='rbx'),
        _op('mov', dst='rdx', src='rbx'),
    ]
    results = list(RopChain(GadFinder()).search(gadgets, chain))
    assert results
    assert [g.text_repr for g in results[0]] == [
        'pop rax ; pop rbx ; ret',
        'pop rbx ; ret',
        'mov rdx, rbx ; ret',
    ]


def test_parse_negative_constant_source(x64, tmp_path):
    '''
    Regression (#38): a minus sign before a constant (e.g. -1) must be parsed
    as the source operand. Before the fix REGEX_OP did not allow '-' in an
    operand and the line failed with "Unable to parse operation".
    '''
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('sub(rax, -1)\n')
    parsed = RopChain(GadFinder())._parse_ropfile(str(ropfile))
    assert len(parsed) == 1
    assert parsed[0]['op'] == 'sub'
    assert parsed[0]['operands'] == ['rax', '-1']


def test_parse_hyphenated_operation_name(x64, tmp_path):
    '''
    Regression (#38): an operation whose name contains a hyphen (e.g. jmp-rel)
    must be parsed. Before the fix REGEX_OP did not allow '-' in the operation
    name and the line failed with "Unable to parse operation".
    '''
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('jmp-rel(rax)\n')
    parsed = RopChain(GadFinder())._parse_ropfile(str(ropfile))
    assert parsed
    assert parsed[0]['op'] == 'jmp-rel'
    assert parsed[0]['operands'] == ['rax']


def test_store_dst_does_not_clear_clobbered_address_register(x64):
    '''
    Regression (#36): a store `st(rbx, rax)` is `mov [rbx], rax`, where rbx is
    the address base register (read, not written). It must NOT refresh rbx's
    clobber state.

    Step 1 `lc(rcx)` uses `pop rcx ; pop rbx ; ret`, which clobbers rbx.
    Step 2 `st(rbx, rax)` reads rbx as an address; before the fix it wrongly
    cleared rbx's clobber, so step 3 `mov(rdx, rbx)` (which reads rbx) was
    allowed and an invalid chain was produced. After the fix rbx stays
    clobbered and no chain is found.
    '''
    gadgets = [
        make_gadget(b'\x59\x5b\xc3', 0x1000),       # pop rcx ; pop rbx ; ret
        make_gadget(b'\x48\x89\x03\xc3', 0x1010),   # mov [rbx], rax ; ret
        make_gadget(b'\x48\x89\xda\xc3', 0x1020),   # mov rdx, rbx ; ret
    ]
    chain = [
        _op('lc', dst='rcx'),
        _op('st', dst='rbx', src='rax'),
        _op('mov', dst='rdx', src='rbx'),
    ]
    with pytest.raises(ropchain_mod.RopChainNotFound):
        list(RopChain(GadFinder()).search(gadgets, chain))


def _opn(op, *operands):
    return {'data': f'{op}({",".join(operands)})', 'op': op, 'operands': list(operands)}


def test_compound_operation_expands_to_chain(x64):
    ''' A compound op (eqc = sub ; neg) is realized as a multi-gadget chain. '''
    gadgets = [
        make_gadget(b'\x48\x29\xd8\xc3', 0x1000),   # sub rax, rbx ; ret
        make_gadget(b'\x48\xf7\xd8\xc3', 0x1010),   # neg rax ; ret
    ]
    results = list(RopChain(GadFinder()).search(gadgets, [_op('eqc', 'rax', 'rbx')]))
    assert results
    assert [g.text_repr for g in results[0]] == ['sub rax, rbx ; ret', 'neg rax ; ret']


def test_nary_positional_operands(x64):
    ''' Steps may bind operands positionally op(op1, op2, ...). '''
    gadgets = [make_gadget(b'\x48\x89\xd8\xc3', 0x1000)]   # mov rax, rbx ; ret
    results = list(RopChain(GadFinder()).search(gadgets, [_opn('mov', 'rax', 'rbx')]))
    assert results
    assert results[0][0].text_repr == 'mov rax, rbx ; ret'


def test_parse_three_operands(x64, tmp_path):
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('add(rax, rbx, rcx)\n')
    parsed = RopChain(GadFinder())._parse_ropfile(str(ropfile))
    assert parsed[0]['operands'] == ['rax', 'rbx', 'rcx']


def test_reg_aliases_unify_across_chain_steps(x64):
    ''' With register aliases, `pop ax` (an alias of rax) and `neg rax` share the
        same generic slot REG1: they are treated as the same register. '''
    from rop3.arch import arch_singleton
    gadgets = [
        make_gadget(b'\x66\x58\xc3', 0x1000),       # pop ax ; ret
        make_gadget(b'\x48\xf7\xd8\xc3', 0x1010),   # neg rax ; ret
    ]
    chain = [_op('lc', dst='REG1'), _op('neg', dst='REG1')]
    with pytest.raises(ropchain_mod.RopChainNotFound):
        list(RopChain(GadFinder()).search(gadgets, chain))     # aliases off: pop ax unusable
    arch_singleton.allow_reg_aliases = True
    try:
        results = list(RopChain(GadFinder()).search(gadgets, chain))
        assert [g.text_repr for g in results[0]] == ['pop ax ; ret', 'neg rax ; ret']
    finally:
        arch_singleton.allow_reg_aliases = False


def test_compound_yields_one_chain_per_realization(x64):
    ''' A compound with multiple realizations expands to one distinct ropchain
        per realization (gcf-eqc has several). '''
    import rop3.parser as parser
    from rop3.operation import expand_steps
    defn = parser.Parser().get_op('gcf-eqc')
    chains = expand_steps('gcf-eqc', {'op1': 'rax', 'op2': 'rbx', 'op3': 'rcx'})
    assert len(chains) == len(defn.realizations) >= 2
    signatures = {tuple(s['op'] for s in ch) for ch in chains}
    assert len(signatures) == len(chains)     # each realization is distinct


def test_search_tries_every_realization(x64):
    ''' The search must try each realization: gadgets that satisfy only a
        non-first realization of gcf-eqc (the `rcl` variant) still yield a
        chain. '''
    gadgets = [
        make_gadget(b'\x58\xc3', 0x10),           # pop rax ; ret
        make_gadget(b'\x48\x29\xcb\xc3', 0x20),   # sub rbx, rcx ; ret
        make_gadget(b'\x48\xf7\xdb\xc3', 0x30),   # neg rbx ; ret
        make_gadget(b'\x48\xd1\xd0\xc3', 0x40),   # rcl rax, 1 ; ret  (only realization)
    ]
    step = {'op': 'gcf-eqc', 'operands': ['rax', 'rbx', 'rcx'], 'data': 'gcf-eqc(rax,rbx,rcx)'}
    results = list(RopChain(GadFinder()).search(gadgets, [step], prune_equivalent=False))
    assert results
    assert results[0][-1].text_repr == 'rcl rax, 1 ; ret'


def test_search_compound_op_gcf_eqc(x64):
    '''
    End-to-end search of a compound operation. gcf-eqc(op1, op2, op3), first
    realization, expands (nested) to:

        lc(REG1)       -> pop REG1                (REG1 is a scratch register)
        eqc(op2, op3)  -> sub(op2, op3) ; neg(op2)
        adc op1, REG1  -> adc op1, REG1

    so gcf-eqc(rax, rbx, rcx) must assemble

        pop <REG1> ; sub rbx, rcx ; neg rbx ; adc rax, <REG1>

    with REG1 unified between the pop and the adc. The `pop rsi` decoy is
    rejected because no `adc rax, rsi` exists, forcing REG1 = rdx.
    '''
    gadgets = [
        make_gadget(b'\x5a\xc3', 0x10),           # pop rdx ; ret
        make_gadget(b'\x5e\xc3', 0x18),           # pop rsi ; ret   (decoy scratch)
        make_gadget(b'\x48\x29\xcb\xc3', 0x20),   # sub rbx, rcx ; ret
        make_gadget(b'\x48\xf7\xdb\xc3', 0x30),   # neg rbx ; ret
        make_gadget(b'\x48\x11\xd0\xc3', 0x40),   # adc rax, rdx ; ret
    ]
    step = {'op': 'gcf-eqc', 'operands': ['rax', 'rbx', 'rcx'], 'data': 'gcf-eqc(rax,rbx,rcx)'}
    results = list(RopChain(GadFinder()).search(gadgets, [step]))
    assert results
    assert [g.text_repr for g in results[0]] == [
        'pop rdx ; ret',
        'sub rbx, rcx ; ret',
        'neg rbx ; ret',
        'adc rax, rdx ; ret',
    ]


def test_gcf_ltc_rejects_flag_clobbering_comparison(x64):
    '''
    The carry flag the final adc/sbb/rcl consumes is produced by the comparison
    (an inlined `sub`, which now `writes: [REG_FLAGS]`). A comparison gadget
    that overwrites the flags before its `ret` (here a trailing `test`) is
    contradictory -- its carry never reaches the consumer -- so with only such a
    `sub` available, gcf-ltc must not assemble.
    '''
    gadgets = [
        make_gadget(b'\x5a\xc3', 0x10),                       # pop rdx ; ret
        # sub rbx, rcx ; test rdx, rdx ; ret  -- `test` clobbers the flags
        make_gadget(b'\x48\x29\xcb\x48\x85\xd2\xc3', 0x20),
        make_gadget(b'\x48\x11\xd0\xc3', 0x40),               # adc rax, rdx ; ret
    ]
    step = {'op': 'gcf-ltc', 'op1': None, 'op2': None, 'data': 'gcf-ltc()'}
    with pytest.raises(ropchain_mod.RopChainNotFound):
        list(RopChain(GadFinder()).search(gadgets, [step]))


def test_search_compound_op_with_generic_operands(x64):
    '''
    Regression: searching a multi-operand compound with no operands must treat
    its operands (op1/op2/op3) as free register slots, enumerated and unified
    like REGn -- not leaked as literal names. gcf-ltc over a full gadget set
    must still assemble (this returned nothing before the fix).
    '''
    gadgets = [
        make_gadget(b'\x5a\xc3', 0x10),           # pop rdx ; ret
        make_gadget(b'\x48\x29\xcb\xc3', 0x20),   # sub rbx, rcx ; ret
        make_gadget(b'\x48\x11\xd0\xc3', 0x40),   # adc rax, rdx ; ret
    ]
    step = {'op': 'gcf-ltc', 'op1': None, 'op2': None, 'data': 'gcf-ltc()'}
    results = list(RopChain(GadFinder()).search(gadgets, [step]))
    assert results
    assert [g.text_repr for g in results[0]] == [
        'pop rdx ; ret', 'sub rbx, rcx ; ret', 'adc rax, rdx ; ret']
