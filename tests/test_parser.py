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

import rop3.parser as parser


import rop3.operation as operation


def test_get_ops_loads_roplang(x64):
    ops = parser.Parser().get_ops()
    names = {getattr(o, 'name', None) for o in ops}
    # a representative subset that must always be present
    for expected in ('mov', 'lc', 'add', 'sub', 'neg', 'eqc', 'gsp'):
        assert expected in names


def test_get_op_unknown_raises(x64):
    with pytest.raises(parser.ParserException):
        parser.Parser().get_op('definitely_not_an_op')


def test_operation_metadata_parsed(x64):
    ''' Operand arity and dst/src role lists come from the YAML header. '''
    add = parser.Parser().get_op('add')
    assert isinstance(add, operation.OperationDef)
    assert add.operands == 2
    assert add.dst_roles == ['op1']
    assert add.src_roles == ['op1', 'op2']


def test_ltc_eqc_declare_flags_destination(x64):
    ''' A comparison writes the flags register, not a general register: ltc/eqc
        declare dst=[rflags], src=[op1, op2]. The arch-independent REG_FLAGS
        alias resolves to the concrete flags register (rflags on x64). '''
    for name in ('ltc', 'eqc'):
        defn = parser.Parser().get_op(name)
        assert defn.dst_roles == ['rflags'], name
        assert defn.src_roles == ['op1', 'op2'], name


def test_reg_flags_resolves_per_arch_x86(x86):
    ''' On 32-bit x86 the flags register capstone reports is eflags. '''
    assert parser.Parser().get_op('ltc').dst_roles == ['eflags']


def test_compound_op_has_operation_ref(x64):
    ''' eqc is a compound operation: a realization made of operation refs
        (replacing the old `compose:` mechanism). '''
    eqc = parser.Parser().get_op('eqc')
    assert eqc.realizations
    assert not any(real.is_single_gadget for real in eqc.realizations)
    steps = eqc.realizations[0].links
    assert all(isinstance(link, operation.OpRef) for link in steps)
    assert [link.name for link in steps] == ['sub', 'neg']


def _gsp_mov_op2():
    ''' gsp is a compound whose only step is `mov op1, REG_SP`. '''
    gsp = parser.Parser().get_op('gsp')
    ref = gsp.realizations[0].links[0]
    assert isinstance(ref, operation.OpRef)
    assert ref.name == 'mov'
    return ref.bindings['op2']


def test_reg_aliases_resolved_per_arch_x64(x64):
    ''' REG_SP must resolve to rsp on x64 (not stay as the alias). '''
    assert _gsp_mov_op2() == 'rsp'


def test_reg_aliases_resolved_per_arch_x86(x86):
    assert _gsp_mov_op2() == 'esp'


def test_removed_ops_are_gone(x64):
    ''' `adc` and `leave` are no longer standalone operations; they are used as
        raw mnemonics inside other operations instead. '''
    for name in ('adc', 'leave'):
        with pytest.raises(parser.ParserException):
            parser.Parser().get_op(name)


def test_nested_mnemonics_are_one_gadget(x64):
    ''' A nested list of mnemonics forms a single gadget (one Set with several
        instructions); mov's push/pop realization is such a group. '''
    mov = parser.Parser().get_op('mov')
    pushpop = next(
        r for r in mov.realizations
        if len(r.links) == 1 and isinstance(r.links[0], operation.Set)
        and [ins.mnemonic for ins in r.links[0].items] == ['push', 'pop']
    )
    assert len(pushpop.links[0].items) == 2   # both instructions, one gadget


def test_top_level_steps_are_separate_chain_links(x64):
    ''' Successive top-level steps are distinct gadgets in the chain: jmp is a
        `mov` operation link followed by a separate raw `leave` gadget. '''
    jmp = parser.Parser().get_op('jmp')
    links = jmp.realizations[0].links
    assert len(links) == 2
    assert isinstance(links[0], operation.OpRef) and links[0].name == 'mov'
    assert isinstance(links[1], operation.Set)
    assert [ins.mnemonic for ins in links[1].items] == ['leave']
