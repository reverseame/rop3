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
from rop3.archs.x86_arch import X64_Architecture
from rop3.archs.aarch64_arch import AArch64_Architecture
from rop3.archs.riscv_arch import RISCV_Architecture

from conftest import make_gadget, build_minimal_elf, EM_X86_64, ET_DYN

EM_AARCH64 = 183


def _op(op, dst=None, src=None):
    ''' A requested chain step. Operand slots are the positional op1/op2
        (op1 is the destination, op2 the source). '''
    return {'data': f'{op}({dst or ""},{src or ""})', 'op': op, 'op1': dst, 'op2': src}


def _free(name):
    ''' A `free(NAME)` directive step, as RopChain._parse_free_line builds it. '''
    return {'data': f'free({name})', 'op': 'free', 'free': name}


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


# --- free(NAME) directive --------------------------------------------------

def test_free_decouples_name_reuse_new_engine(x64):
    '''
    Two structurally different steps reuse the same generic names (REG1,
    REG2): a `mov` step only has a `mov rax, rbx` gadget (so REG1=rax,
    REG2=rbx), and an `xor` step only has a `xor rcx, rdx` gadget (so
    REG1=rcx, REG2=rdx). Without `free`, REG1/REG2 are one identity for the
    whole chain: {rax} intersected with {rcx} is empty, so no chain exists
    (both engines). `free(REG1); free(REG2)` between the steps lets the
    default (order-aware) engine resolve each occurrence independently.
    '''
    gadgets = [
        make_gadget(b'\x48\x89\xd8\xc3', 0x1000),   # mov rax, rbx ; ret
        make_gadget(b'\x48\x31\xd1\xc3', 0x1010),   # xor rcx, rdx ; ret
    ]
    without_free = [
        _op('mov', dst='REG1', src='REG2'),
        _op('xor', dst='REG1', src='REG2'),
    ]
    with pytest.raises(ropchain_mod.RopChainNotFound):
        list(RopChain(GadFinder()).search(gadgets, without_free))

    with_free = [
        _op('mov', dst='REG1', src='REG2'),
        _free('REG1'),
        _free('REG2'),
        _op('xor', dst='REG1', src='REG2'),
    ]
    results = list(RopChain(GadFinder()).search(gadgets, with_free))
    assert results
    assert [g.text_repr for g in results[0]] == ['mov rax, rbx ; ret', 'xor rcx, rdx ; ret']


def test_legacy_free_rename_decouples(x64):
    ''' The same scenario as test_free_decouples_name_reuse_new_engine, but
        with legacy=True: free is only approximated by a parse-time rename of
        the second block's names, which is enough to decouple this case too. '''
    gadgets = [
        make_gadget(b'\x48\x89\xd8\xc3', 0x1000),   # mov rax, rbx ; ret
        make_gadget(b'\x48\x31\xd1\xc3', 0x1010),   # xor rcx, rdx ; ret
    ]
    chain = [
        _op('mov', dst='REG1', src='REG2'),
        _free('REG1'),
        _free('REG2'),
        _op('xor', dst='REG1', src='REG2'),
    ]
    results = list(RopChain(GadFinder()).search(gadgets, chain, legacy=True))
    assert results
    assert [g.text_repr for g in results[0]] == ['mov rax, rbx ; ret', 'xor rcx, rdx ; ret']


def test_rewrite_legacy_frees_renames_each_epoch():
    ''' Direct unit test of the rename pass: a name freed and reused twice
        gets three distinct identities (original, and one fresh name per
        free), and identical names within one epoch still share it. '''
    rc = RopChain(GadFinder())
    steps = [
        _op('mov', dst='REG1', src='REG2'),
        _free('REG1'),
        _op('mov', dst='REG1', src='REG2'),
        _free('REG1'),
        _op('mov', dst='REG1', src='REG2'),
    ]
    rewritten = rc._rewrite_legacy_frees(steps)
    assert len(rewritten) == 3
    assert all('free' not in step for step in rewritten)
    names = [step['op1'] for step in rewritten]
    assert names[0] == 'REG1'                 # first epoch: untouched
    assert len({names[0], names[1], names[2]}) == 3   # three distinct identities
    # within each rewritten step, op1/op2 still refer to each other (REG2 was
    # never freed, so it always resolves to itself)
    assert all(step['op2'] == 'REG2' for step in rewritten)


def test_free_with_no_frees_matches_no_free_legacy_and_new(x64):
    ''' Compatibility requirement: with no free() anywhere in the file, the
        default engine and --legacy-ropchain must agree with each other (and
        with today's behavior) on ordinary generic-register chains. '''
    gadgets = [
        make_gadget(b'\x48\x89\xd8\xc3', 0x1000),   # mov rax, rbx ; ret
        make_gadget(b'\x48\x89\xd1\xc3', 0x1010),   # mov rcx, rdx ; ret
    ]
    chain = [_op('mov', dst='REG1', src='REG2')]
    new_results = list(RopChain(GadFinder()).search(gadgets, chain))
    legacy_results = list(RopChain(GadFinder()).search(gadgets, chain, legacy=True))
    assert new_results
    assert ([g.text_repr for g in new_results[0]] ==
            [g.text_repr for g in legacy_results[0]])
    assert {tuple(g.text_repr for g in r) for r in new_results} == \
           {tuple(g.text_repr for g in r) for r in legacy_results}


def test_free_same_step_both_generic_pairing_still_enforced(x64):
    ''' A step with both operands generic, freed and reused: each block must
        only resolve to a real (op1, op2) gadget pair, never a cross-pair
        mismatch (e.g. rax paired with rdx, which no gadget realizes). '''
    gadgets = [
        make_gadget(b'\x48\x89\xd8\xc3', 0x1000),   # mov rax, rbx ; ret
        make_gadget(b'\x48\x89\xd1\xc3', 0x1010),   # mov rcx, rdx ; ret
    ]
    chain = [
        _op('mov', dst='REG1', src='REG2'),
        _free('REG1'),
        _free('REG2'),
        _op('mov', dst='REG1', src='REG2'),
    ]
    results = list(RopChain(GadFinder()).search(gadgets, chain))
    assert results
    valid_pairs = {'mov rax, rbx ; ret', 'mov rcx, rdx ; ret'}
    for result in results:
        assert len(result) == 2
        assert all(g.text_repr in valid_pairs for g in result)
    assert len(results) == 4   # 2 independent choices per block


@pytest.mark.parametrize('bad_free, warning_snippet', [
    ('rax', 'only a generic register-slot name'),
    ('REG9', 'was never used before this point'),
])
def test_free_invalid_target_warns_and_continues(x64, monkeypatch, bad_free, warning_snippet):
    warnings = []
    monkeypatch.setattr(ropchain_mod.debug, 'warning', lambda msg: warnings.append(msg))
    gadgets = [make_gadget(b'\x58\xc3', 0x1000)]   # pop rax ; ret
    chain = [_free(bad_free), _op('lc', dst='rax')]
    results = list(RopChain(GadFinder()).search(gadgets, chain))
    assert results
    assert any(warning_snippet in w for w in warnings)


def test_free_double_free_without_use_warns(x64, monkeypatch):
    warnings = []
    monkeypatch.setattr(ropchain_mod.debug, 'warning', lambda msg: warnings.append(msg))
    gadgets = [make_gadget(b'\x58\xc3', 0x1000)]   # pop rax ; ret
    chain = [_op('lc', dst='REG1'), _free('REG1'), _free('REG1')]
    results = list(RopChain(GadFinder()).search(gadgets, chain))
    assert results
    assert any('already freed with no intervening use' in w for w in warnings)


def test_parse_free_line(x64, tmp_path):
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('free(REG1)  ; release REG1\n')
    parsed = RopChain(GadFinder())._parse_ropfile(str(ropfile))
    assert len(parsed) == 1
    step = parsed[0]
    assert step['op'] == 'free'
    assert step['free'] == 'REG1'
    assert 'operands' not in step and 'op1' not in step and 'op2' not in step and 'defn' not in step


@pytest.mark.parametrize('line', ['free()', 'free(REG1, REG2)'])
def test_parse_free_line_malformed_raises(line):
    with pytest.raises(ropchain_mod.FreeDirectiveError):
        RopChain(GadFinder())._parse_free_line(line, [] if line == 'free()' else ['REG1', 'REG2'])


# --- TMP_REG auto-freed scratch --------------------------------------------

def test_tmp_reg_recognized_as_slot(x64):
    ''' TMP_REG is an abstract operand (matches any register), a generic slot
        the assembler binds, and resolves to None ("any register") for
        matching -- the three predicates the auto-free mechanism relies on. '''
    from rop3.operation import is_abstract_name
    from rop3.ropchain import _is_generic_slot
    from rop3.gadfinder import _is_temp_slot
    for name in ('TMP_REG', 'TMP_REG1'):
        assert is_abstract_name(name)
        assert _is_generic_slot(name)
        assert _is_temp_slot(name)
        assert GadFinder()._resolve_operand(name) is None
    # a user-named REGn slot is generic but not a TMP_REG temporary
    assert _is_generic_slot('REG1') and not _is_temp_slot('REG1')


# Gadgets realizing two lsd(op1) steps (lsd -> pop TMP_REG ; neg op1 ; and op1,
# TMP_REG) where each step's only `and` forces a *different* scratch register:
# lsd(rax) needs TMP_REG=rcx, lsd(rbx) needs TMP_REG=rdx. A single shared
# TMP_REG identity (rcx and rdx at once) is impossible, so the chain assembles
# only because each operation's TMP_REG is dropped once it ends.
_TWO_LSD_GADGETS = [
    (b'\x59\xc3', 0x1000),           # pop rcx ; ret
    (b'\x5a\xc3', 0x1010),           # pop rdx ; ret
    (b'\x48\xf7\xd8\xc3', 0x1020),   # neg rax ; ret
    (b'\x48\xf7\xdb\xc3', 0x1030),   # neg rbx ; ret
    (b'\x48\x21\xc8\xc3', 0x1040),   # and rax, rcx ; ret
    (b'\x48\x21\xd3\xc3', 0x1050),   # and rbx, rdx ; ret
]


@pytest.mark.parametrize('legacy', [False, True], ids=['default', 'legacy'])
def test_tmp_reg_auto_freed_between_operations(x64, legacy):
    ''' Two lsd steps whose scratch registers must differ assemble in both
        engines: the default engine drops TMP_REG via an auto-free event at the
        operation boundary, the legacy engine via a per-operation rename. '''
    gadgets = [make_gadget(b, addr) for b, addr in _TWO_LSD_GADGETS]
    chain = [_op('lsd', dst='rax'), _op('lsd', dst='rbx')]
    results = list(RopChain(GadFinder()).search(gadgets, chain, legacy=legacy))
    assert results
    reprs = [g.text_repr for g in results[0]]
    # first operation's scratch is rcx, the second's is rdx -- decoupled
    assert 'and rax, rcx ; ret' in reprs
    assert 'and rbx, rdx ; ret' in reprs


def test_classify_emits_autofree_event_for_tmp_reg(x64):
    ''' The default engine turns an operation's TMP_REG into a free event at
        the boundary right after its last primitive (lsd -> 3 primitives, so
        boundary 3), so _assemble_sequential releases it for the next step. '''
    gadgets = [make_gadget(b, addr) for b, addr in _TWO_LSD_GADGETS]
    realizations = GadFinder().classify_ropchain(
        gadgets, [_op('lsd', dst='rax')], legacy=False)
    assert realizations
    _, free_events = realizations[0]
    assert (3, 'TMP_REG') in free_events


def test_classify_legacy_renames_tmp_reg_uniquely(x64):
    ''' The legacy engine cannot free positionally, so it renames each
        operation instance's TMP_REG to a fresh unique generic slot and emits
        no free event -- two lsd steps get two distinct scratch identities. '''
    from rop3.gadfinder import _is_temp_slot
    gadgets = [make_gadget(b, addr) for b, addr in _TWO_LSD_GADGETS]
    realizations = GadFinder().classify_ropchain(
        gadgets, [_op('lsd', dst='rax'), _op('lsd', dst='rbx')], legacy=True)
    assert realizations
    bundle, free_events = realizations[0]
    assert free_events == []                      # nothing freed positionally
    slots = {step.get('op1') for step, _ in bundle if step.get('op1')}
    slots |= {step.get('op2') for step, _ in bundle if step.get('op2')}
    # no literal TMP_REG survives; the two operations' scratch slots are distinct
    assert not any(_is_temp_slot(s) for s in slots)
    renamed = {s for s in slots if isinstance(s, str) and s.startswith('REG99')}
    assert len(renamed) == 2


# Full expansion of every compound (compose:) operation, per architecture, as
# the complete set of primitive-step chains realize() must produce. Whenever a
# roplang/*.yaml file is modified (a realization added, removed, reordered, or
# its operands changed), update this constant to the new complete set for every
# architecture the operation touches -- see CLAUDE.md. Each nested `lc` op stays
# a single step (it is primitive; its own single-gadget variants are matched
# later), so the only multiplicity here is the compound's own alternatives. An
# empty set means the operation is unavailable on that architecture (realize
# yields nothing and defn.available is False), e.g. no carry flag on RISC-V.
#
# `arch` maps a name to (Architecture factory, operand binding); `chains` maps
# each compound op to its expected realization set under that binding.
_COMPOUND_ARCHES = {
    'x86-64': {
        'arch': lambda: X64_Architecture(),
        'operands': {'op1': 'rax', 'op2': 'rbx', 'op3': 'rcx'},
        'chains': {
            'gcf-eqc': {
                ('lc(TMP_REG)', 'sub(rbx, rcx)', 'neg(rbx)', 'adc(rax, TMP_REG)'),
                ('lc(TMP_REG)', 'sub(rbx, rcx)', 'neg(rbx)', 'sbb(rax, TMP_REG)', 'neg(rax)'),
                ('lc(rax)', 'sub(rbx, rcx)', 'neg(rbx)', 'rcl(rax)'),
            },
            'gcf-ltc': {
                ('lc(TMP_REG)', 'sub(rbx, rcx)', 'adc(rax, TMP_REG)'),
                ('lc(TMP_REG)', 'sub(rbx, rcx)', 'sbb(rax, TMP_REG)', 'neg(rax)'),
                ('lc(rax)', 'sub(rbx, rcx)', 'rcl(rax)'),
            },
            'jmp': {
                ('mov(rbp, rax)', 'leave()'),
            },
        },
    },
    'aarch64': {
        'arch': lambda: AArch64_Architecture(),
        'operands': {'op1': 'x0', 'op2': 'x1', 'op3': 'x2'},
        'chains': {
            'gcf-eqc': {
                ('lc(TMP_REG)', 'sub(x1, x2)', 'neg(x1)', 'lc(x0)', 'adc(x0, TMP_REG)'),
            },
            'gcf-ltc': {
                ('lc(TMP_REG)', 'sub(x1, x2)', 'adc(x0, TMP_REG)'),
            },
            # Single-step pivot SP <- x29, matched by the `mov sp, x29 ; ldp
            # x29, x30, [sp] ; ret` epilogue-pivot gadget. x29 (the pivot source)
            # is loaded "free" from the stack by the framed epilogue, so no
            # explicit mov into it is needed; op1 is unused. capstone spells x29
            # as `fp`; matching folds the alias.
            'jmp': {
                ('mov(sp, x29)',),
            },
        },
    },
    'riscv': {
        'arch': lambda: RISCV_Architecture(),
        'operands': {'op1': 'a0', 'op2': 'a1', 'op3': 'a2'},
        'chains': {
            'gcf-eqc': set(),   # unavailable: RISC-V has no carry/condition flags
            'gcf-ltc': set(),
            # Two pivots: the clean move (mv sp, reg) and the frame-pointer
            # `addi sp, s0, off` epilogue pivot (op1 = s0/fp, wildcard offset)
            # that no plain move can express.
            'jmp': {
                ('mov(sp, a0)',),
                ('addi(a0)',),
            },
        },
    },
}

COMPOUND_CHAIN_REALIZATIONS = [
    (arch_name, op, cfg['arch'], cfg['operands'], expected)
    for arch_name, cfg in _COMPOUND_ARCHES.items()
    for op, expected in cfg['chains'].items()
]


@pytest.mark.parametrize('arch_name, op, make_arch, operands, expected',
                         COMPOUND_CHAIN_REALIZATIONS,
                         ids=[f'{a}-{o}' for a, o, *_ in COMPOUND_CHAIN_REALIZATIONS])
def test_compound_yields_every_realization(arch_name, op, make_arch, operands, expected):
    ''' A compound operation expands to *every* possible chain realization on
        each architecture, and exactly those: the full sets are pinned in
        _COMPOUND_ARCHES so any roplang/*.yaml change surfaces here. An empty
        expected set asserts the operation is unavailable on that arch. '''
    import rop3.parser as parser
    from rop3.operation import realize
    from rop3.arch import arch_singleton
    arch_singleton.reset()
    arch_singleton.initialize(make_arch())

    defn = parser.Parser().get_op(op)
    chains = realize(defn, dict(operands))
    produced = {tuple(s['data'] for s in ch) for ch in chains}
    assert produced == expected
    assert len(chains) == len(expected)       # no duplicate realizations
    assert defn.available is bool(expected)   # empty set <=> unavailable arch


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

        lc(TMP_REG)       -> pop TMP_REG          (TMP_REG is scratch)
        eqc(op2, op3)     -> sub(op2, op3) ; neg(op2)
        adc op1, TMP_REG  -> adc op1, TMP_REG

    so gcf-eqc(rax, rbx, rcx) must assemble

        pop <TMP_REG> ; sub rbx, rcx ; neg rbx ; adc rax, <TMP_REG>

    with TMP_REG unified between the pop and the adc. The `pop rsi` decoy is
    rejected because no `adc rax, rsi` exists, forcing TMP_REG = rdx.
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


# --- Explicit (raw) gadget definitions ------------------------------------

def test_parse_raw_gadget_single_instruction(x64, tmp_path):
    ''' A raw gadget line builds a chain step carrying its own inline
        OperationDef (name, dst/src roles, one single-gadget realization). '''
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('raw([pop, ret], [rdi], [rdi], [])\n')
    parsed = RopChain(GadFinder())._parse_ropfile(str(ropfile))
    assert len(parsed) == 1
    step = parsed[0]
    assert step['op'] == 'pop rdi ; ret'
    defn = step['defn']
    assert defn.operands == 0
    assert defn.dst_roles == ['rdi'] and defn.src_roles == []
    insns = [str(i) for i in defn.realizations[0].links[0].items]
    assert insns == ['pop rdi', 'ret ']


def test_parse_raw_gadget_ignores_trailing_comment(x64, tmp_path):
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('raw([pop, ret], [rdi], [rdi], [])  ; loads rdi\n')
    parsed = RopChain(GadFinder())._parse_ropfile(str(ropfile))
    assert parsed[0]['op'] == 'pop rdi ; ret'


def test_search_raw_gadget_matches(x64):
    ''' A raw gadget is matched exactly as written. '''
    gadgets = [
        make_gadget(b'\x5f\xc3', 0x1000),   # pop rdi ; ret
        make_gadget(b'\x58\xc3', 0x1010),   # pop rax ; ret
    ]
    rc = RopChain(GadFinder())
    chain = [rc._parse_raw_line('raw([pop, ret], [rdi], [rdi], [])')]
    results = list(rc.search(gadgets, chain, symbolic=False))
    assert results
    assert results[0][0].text_repr == 'pop rdi ; ret'


def test_search_raw_gadget_with_memory_operand_annotates_dst_src(x64):
    ''' A raw store gadget matches (memory base regardless of the operand-size
        annotation) and its explicit dst/src drive the assembler's side-effect
        sets. '''
    gadgets = [make_gadget(b'\x48\x89\x07\xc3', 0x2000)]   # mov [rdi], rax ; ret
    rc = RopChain(GadFinder())
    chain = [rc._parse_raw_line('raw([mov, ret], [[rdi], rax], [rdi], [rax])')]
    results = list(rc.search(gadgets, chain, symbolic=False))
    assert results
    matched = results[0][0]
    assert matched.text_repr == 'mov qword ptr [rdi], rax ; ret'
    assert matched.dst == {'rdi'} and matched.src == {'rax'}


def test_search_raw_gadget_multi_instruction_grouped_operands(x64):
    ''' Parenthesised operand groups map operands to several instructions. '''
    gadgets = [make_gadget(b'\x5f\x5e\xc3', 0x3000)]   # pop rdi ; pop rsi ; ret
    rc = RopChain(GadFinder())
    chain = [rc._parse_raw_line('raw([pop, pop, ret], [(rdi), (rsi)], [rdi, rsi], [])')]
    results = list(rc.search(gadgets, chain, symbolic=False))
    assert results
    assert results[0][0].text_repr == 'pop rdi ; pop rsi ; ret'


def test_raw_gadget_side_effects_tracked_in_chain(x64):
    '''
    A raw gadget's declared dst registers participate in the assembler's clobber
    tracking: `pop rdi ; pop rbx ; ret` clobbers rbx, so a later `mov(rdx, rbx)`
    only assembles once rbx is reloaded in between.
    '''
    gadgets = [
        make_gadget(b'\x5f\x5b\xc3', 0x1000),       # pop rdi ; pop rbx ; ret
        make_gadget(b'\x5b\xc3', 0x1010),           # pop rbx ; ret
        make_gadget(b'\x48\x89\xda\xc3', 0x1020),   # mov rdx, rbx ; ret
    ]
    rc = RopChain(GadFinder())
    chain = [
        rc._parse_raw_line('raw([pop, pop, ret], [(rdi), (rbx)], [rdi, rbx], [])'),
        _op('lc', dst='rbx'),
        _op('mov', dst='rdx', src='rbx'),
    ]
    results = list(rc.search(gadgets, chain, symbolic=False))
    assert results
    assert [g.text_repr for g in results[0]] == [
        'pop rdi ; pop rbx ; ret',
        'pop rbx ; ret',
        'mov rdx, rbx ; ret',
    ]


def test_search_raw_gadget_no_match_raises(x64):
    gadgets = [make_gadget(b'\x90\xc3', 0x1000)]   # nop ; ret
    rc = RopChain(GadFinder())
    chain = [rc._parse_raw_line('raw([pop, ret], [rdi], [rdi], [])')]
    with pytest.raises(ropchain_mod.RopChainNotFound):
        list(rc.search(gadgets, chain, symbolic=False))


@pytest.mark.parametrize('line, reason', [
    ('raw([pop, ret], [rdi], [rdi])', 'four'),          # too few fields
    ('raw(pop, rdi, rdi, )', 'wrapped in [ ]'),          # unbracketed fields
    ('raw([], [], [], [])', 'at least one mnemonic'),    # no mnemonic
    ('raw([pop, pop], [(a), (b), (c)], [], [])', 'operand groups'),  # too many groups
])
def test_parse_raw_gadget_malformed_raises(x64, line, reason):
    with pytest.raises(ropchain_mod.RawGadgetError) as exc:
        RopChain(GadFinder())._parse_raw_line(line)
    assert reason in str(exc.value)


# --- raw gadgets with no terminator requirement ----------------------------

def test_parse_raw_gadget_bare_syscall(x64, tmp_path):
    ''' A raw gadget needs no ret/branch terminator: a bare `syscall` parses
        into a step whose inline OperationDef has no literal_gadgets resolved
        yet (those are filled in later, only when binaries are available). '''
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('raw([syscall], [], [], [rdi, rax])\n')
    parsed = RopChain(GadFinder())._parse_ropfile(str(ropfile))
    assert len(parsed) == 1
    step = parsed[0]
    assert step['op'] == 'syscall'
    defn = step['defn']
    assert defn.literal_gadgets is None
    assert defn.dst_roles == [] and defn.src_roles == ['rdi', 'rax']
    insns = [str(i) for i in defn.realizations[0].links[0].items]
    assert insns == ['syscall ']


def test_search_raw_gadget_matches_gadget_with_no_terminator(x64):
    ''' A raw gadget matches a candidate that does not end in a ret/branch --
        the matching layer itself never required a terminator (only the normal
        backward scan does): neither `syscall` nor `nop` is a valid ROP/JOP
        terminator, so GadFinder.find() could never have produced this
        candidate itself. '''
    gadgets = [make_gadget(b'\x0f\x05\x90', 0x1000)]   # syscall ; nop -- no ret
    rc = RopChain(GadFinder())
    chain = [rc._parse_raw_line('raw([syscall], [], [], [])')]
    results = list(rc.search(gadgets, chain, symbolic=False))
    assert results
    assert results[0][0].op == 'syscall'


def test_search_raw_gadget_bare_no_match_raises(x64):
    gadgets = [make_gadget(b'\x90\xc3', 0x1000)]   # nop ; ret (no syscall)
    rc = RopChain(GadFinder())
    chain = [rc._parse_raw_line('raw([syscall], [], [], [])')]
    with pytest.raises(ropchain_mod.RopChainNotFound):
        list(rc.search(gadgets, chain, symbolic=False))


def test_raw_gadget_with_no_terminator_allowed_mid_chain(x64):
    ''' A raw gadget with no terminator is no longer forced to be the last step
        (the old noret-must-be-last rule is gone): it matches wherever its
        instructions appear and a following step resolves independently. '''
    gadgets = [
        make_gadget(b'\x0f\x05\x90', 0x1000),   # syscall ; nop
        make_gadget(b'\x5f\xc3', 0x1010),       # pop rdi ; ret
    ]
    rc = RopChain(GadFinder())
    chain = [
        rc._parse_raw_line('raw([syscall], [], [], [])'),
        rc._parse_raw_line('raw([pop, ret], [rdi], [rdi], [])'),
    ]
    results = list(rc.search(gadgets, chain, symbolic=False))
    assert results
    assert [g.text_repr for g in results[0]] == ['syscall ; nop', 'pop rdi ; ret']


def test_raw_gadget_found_via_scan_not_normal_gadget_scan(tmp_path):
    '''
    End-to-end: a bare `syscall` with nothing reachable after it (no ret
    anywhere in the section) is structurally invisible to the normal backward
    gadget scan -- GadFinder.find() never emits it as a candidate at all.
    raw(...) finds it anyway via its own direct scan (GadFinder.find_raw_gadgets),
    wired in through Rop3.ropchain -> RopChain.search_from_gadgets(..., binaries=...).
    '''
    from rop3 import Rop3

    path = tmp_path / 'a.elf'
    path.write_bytes(build_minimal_elf(64, EM_X86_64, b'\x0f\x05', 0x1000, ET_DYN))

    r3 = Rop3(str(path))
    assert not any('syscall' in g.text_repr for g in r3.gadgets())

    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('raw([syscall], [], [], [])\n')
    results = list(r3.ropchain(str(ropfile)))
    assert results
    assert results[0][0].text_repr == 'syscall'
    assert results[0][0].vaddr == 0x1000


def test_find_raw_gadgets_tries_unintended_offsets_on_x86(tmp_path):
    ''' On x86 (alignment 1) the raw scan tries every byte offset, not just
        intended instruction boundaries -- so a `syscall` hiding inside another
        instruction's encoding is still found. '''
    text = b'\xb8\x0f\x05\x00\x00\xc3'   # mov eax, 0x50f ; ret (syscall @ +1)
    path = tmp_path / 'a.elf'
    path.write_bytes(build_minimal_elf(64, EM_X86_64, text, 0x1000, ET_DYN))

    finder = GadFinder()
    defn = RopChain(finder)._parse_raw_line('raw([syscall], [], [], [])')['defn']
    found = finder.find_raw_gadgets([str(path)], defn)
    assert any(g.vaddr == 0x1001 and g.text_repr == 'syscall' for g in found)


def test_find_raw_gadgets_on_aligned_arch(tmp_path):
    ''' A multi-instruction raw gadget resolves end-to-end on a fixed-width ISA
        (AArch64, alignment 4) at its aligned boundary -- via the Keystone
        byte-regex fast path when available, else the aligned Capstone scan. '''
    text = b'\xe0\x03\x01\xaa\xc0\x03\x5f\xd6'   # mov x0, x1 ; ret
    path = tmp_path / 'a.elf'
    path.write_bytes(build_minimal_elf(64, EM_AARCH64, text, 0x1000, ET_DYN))

    finder = GadFinder()
    defn = RopChain(finder)._parse_raw_line('raw([mov, ret], [(x0, x1), ()], [x0], [])')['defn']
    found = finder.find_raw_gadgets([str(path)], defn)
    assert any(g.vaddr == 0x1000 and g.text_repr == 'mov x0, x1 ; ret' for g in found)


def test_find_raw_gadgets_returns_only_first_appearance(tmp_path):
    ''' The scan returns only the first appearance of the pattern per binary --
        a raw gadget's copies are interchangeable, so one candidate is enough
        (and stopping at the first is what keeps the scan fast). '''
    text = b'\x0f\x05\x90\x0f\x05'   # syscall ; nop ; syscall (two copies)
    path = tmp_path / 'a.elf'
    path.write_bytes(build_minimal_elf(64, EM_X86_64, text, 0x1000, ET_DYN))

    finder = GadFinder()
    defn = RopChain(finder)._parse_raw_line('raw([syscall], [], [], [])')['defn']
    found = finder.find_raw_gadgets([str(path)], defn)
    assert [g.vaddr for g in found] == [0x1000]   # the lower-addressed copy only
