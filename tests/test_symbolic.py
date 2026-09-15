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

from rop3.symbolic import SymbolicAnalyzer, SymbolicResult, TRITON_AVAILABLE

from conftest import make_gadget

needs_triton = pytest.mark.skipif(
    not TRITON_AVAILABLE, reason='the Triton library is not installed')


# --- graceful behaviour without Triton / on an unsupported arch -----------

def test_empty_chain_is_unsupported():
    result = SymbolicAnalyzer().analyze_ropchain([])
    assert isinstance(result, SymbolicResult)
    assert result.supported is False
    assert result.reached is False


def test_missing_triton_is_reported_not_raised(x64):
    ''' Without Triton the analyzer must degrade gracefully (never raise), so
        ropchain search keeps working where the optional dep is absent. '''
    chain = [make_gadget(b'\xc3', 0x1000)]        # ret
    result = SymbolicAnalyzer().analyze_ropchain(chain)
    if not TRITON_AVAILABLE:
        assert result.supported is False
        assert 'Triton' in result.error
    else:
        assert result.supported is True


# --- real symbolic execution (only when Triton is installed) --------------

@needs_triton
def test_pop_rdi_ret_chain_reaches_final(x64):
    '''
    pop rdi ; ret  ->  ret (final)

    The first gadget consumes one stack slot (the popped value) and returns
    into the second. The analyzer must record two stack slots -- the popped
    value's and the return address of the first gadget -- and confirm the
    final gadget is reached once the return address is laid down.
    '''
    g1 = make_gadget(b'\x5f\xc3', 0x1000)         # pop rdi ; ret
    g2 = make_gadget(b'\xc3', 0x2000)             # ret  (final)

    result = SymbolicAnalyzer().analyze_ropchain([g1, g2])

    assert result.supported is True
    assert result.reached is True
    # Exactly one return-address slot chains g1 -> g2.
    assert len(result.stack_layout) == 1
    slot = result.stack_layout[0]
    assert slot['target'] == 0x2000
    # pop rdi consumes [sp+0], so the return address sits at [sp+8].
    assert slot['offset'] == 8


@needs_triton
def test_return_addresses_are_relative_to_base(x64):
    ''' Two chained pops: the recorded offsets must reflect the running stack
        pointer, independent of the concrete base address. '''
    g1 = make_gadget(b'\x5f\xc3', 0x1000)         # pop rdi ; ret
    g2 = make_gadget(b'\x5e\xc3', 0x2000)         # pop rsi ; ret
    g3 = make_gadget(b'\xc3', 0x3000)             # ret (final)

    result = SymbolicAnalyzer().analyze_ropchain([g1, g2, g3])

    assert result.reached is True
    offsets = [s['offset'] for s in result.stack_layout]
    targets = [s['target'] for s in result.stack_layout]
    # g1's ret slot at +8 (after pop rdi), g2's ret slot at +24
    # (after pop rdi's slot, g1 ret slot, and pop rsi's slot).
    assert offsets == [8, 24]
    assert targets == [0x2000, 0x3000]


@needs_triton
def test_memory_write_is_annotated(x64):
    ''' A store gadget's memory write must be annotated. '''
    # mov [rax], rbx ; ret
    g1 = make_gadget(b'\x48\x89\x18\xc3', 0x1000)
    g2 = make_gadget(b'\xc3', 0x2000)

    result = SymbolicAnalyzer().analyze_ropchain([g1, g2])

    writes = [m for m in result.memory_accesses if m.kind == 'write']
    assert writes, 'expected the store to be annotated'


# --- symbolic (indeterminate) initial state -------------------------------

@needs_triton
def test_data_slot_reads_are_concrete_zero_return_slots_carry_targets(x64):
    '''
    Two-pass emulation lays the chain out and re-executes. A stack slot the chain
    only pops as *data* (pop rdi's value) is unpopulated, so it reads back as a
    concrete 0; a slot that holds a *return address* reads back as the next
    gadget's address the layout pass filled in.
    '''
    g1 = make_gadget(b'\x5f\xc3', 0x1000)         # pop rdi ; ret
    g2 = make_gadget(b'\xc3', 0x2000)             # ret (final)

    result = SymbolicAnalyzer().analyze_ropchain([g1, g2])
    base = result.base

    reads = {m.address: m.value for m in result.memory_accesses
             if m.kind == 'read'}
    assert reads[base] == 0            # pop rdi's data slot: never filled
    assert reads[base + 8] == 0x2000   # g1's return slot: filled with g2


@needs_triton
def test_return_into_constant_is_unreachable(x64):
    '''
    A gadget that pushes a constant and returns transfers control to that fixed
    address: even after the layout pass fills the slot, the `push` overwrites it,
    so control never reaches the next gadget. It does not redirect the stack
    pointer, so it is unreached but not a pivot; the pushed slot reads back as
    the constant.
    '''
    g1 = make_gadget(b'\x68\x41\x41\x41\x41\xc3', 0x1000)   # push 0x41414141 ; ret
    g2 = make_gadget(b'\xc3', 0x2000)

    result = SymbolicAnalyzer().analyze_ropchain([g1, g2])

    assert result.supported is True
    assert result.reached is False
    assert result.pivots == []
    writes = [m for m in result.memory_accesses if m.kind == 'write']
    assert writes and writes[0].value == 0x41414141   # chain-defined -> concrete


@needs_triton
def test_store_of_undefined_register_is_concrete_zero(x64):
    '''
    A store of a register the chain never defined writes its concrete initial
    value, which is zero -- the annotation reports a concrete 0.
    '''
    g1 = make_gadget(b'\x48\x89\x18\xc3', 0x1000)   # mov [rax], rbx ; ret
    g2 = make_gadget(b'\xc3', 0x2000)

    result = SymbolicAnalyzer().analyze_ropchain([g1, g2])

    writes = [m for m in result.memory_accesses if m.kind == 'write']
    assert writes
    assert writes[0].value == 0


@needs_triton
def test_chain_pinned_pointer_keeps_concrete_address(x64):
    ''' When the chain fixes a pointer to a concrete value, the dereference is a
        real, concrete address (all emulated state is concrete). '''
    # mov ecx, 0x404000 ; mov [rcx], rax ; ret
    g = make_gadget(b'\xb9\x00\x40\x40\x00\x48\x89\x01\xc3', 0x1000)
    gf = make_gadget(b'\xc3', 0x2000)

    result = SymbolicAnalyzer().analyze_ropchain([g, gf])

    writes = [m for m in result.memory_accesses if m.kind == 'write']
    assert writes
    assert writes[0].address == 0x404000
    assert writes[0].on_stack is False


# --- stack pivots (jmp-like transfers off the payload) --------------------

@needs_triton
def test_leave_ret_is_flagged_as_a_pivot(x64):
    '''
    A `jmp(reg)` realized as a stack pivot (`push rax ; pop rbp ; leave ; ret`).
    `leave` (mov rsp, rbp ; pop rbp) redirects the stack pointer, so gadget #3 is
    flagged as a pivot -- a structural property, independent of the fact that,
    once the layout pass fills the slot it pops from, control still reaches the
    last gadget.
    '''
    g1 = make_gadget(b'\x58\xc3', 0x1000)             # pop rax ; ret
    g2 = make_gadget(b'\x48\x8b\x40\x10\xc3', 0x2000)  # mov rax,[rax+0x10] ; ret
    g3 = make_gadget(b'\x50\x5d\xc3', 0x3000)         # push rax ; pop rbp ; ret
    g4 = make_gadget(b'\xc9\xc3', 0x4000)             # leave ; ret   (pivot)
    g5 = make_gadget(b'\xc3', 0x5000)                 # ret (final "nop")

    result = SymbolicAnalyzer().analyze_ropchain([g1, g2, g3, g4, g5])

    assert result.supported is True
    assert [p['gadget_index'] for p in result.pivots] == [3]


@needs_triton
def test_explicit_sp_writes_are_pivots(x64):
    ''' Any gadget that writes the stack pointer other than by push/pop/ret is a
        pivot: `add rsp, imm`, `mov rsp, reg`, `pop rsp`. '''
    final = make_gadget(b'\xc3', 0x9000)              # ret
    for code, addr in [(b'\x48\x83\xc4\x08\xc3', 0x1000),   # add rsp, 8 ; ret
                       (b'\x48\x89\xc4\xc3', 0x2000),       # mov rsp, rax ; ret
                       (b'\x5c\xc3', 0x3000)]:              # pop rsp ; ret
        g = make_gadget(code, addr)
        result = SymbolicAnalyzer().analyze_ropchain([g, final])
        assert [p['gadget_index'] for p in result.pivots] == [0], code.hex()


@needs_triton
def test_jmp_reg_is_unreached_but_not_a_pivot(x64):
    '''
    A `jmp reg` tail transfers control through a register, not the stack, and
    does not write the stack pointer. With the register left at zero, control
    does not reach the next gadget, but the transition is unreached rather than a
    pivot.
    '''
    g1 = make_gadget(b'\xff\xe0', 0x1000)         # jmp rax
    g2 = make_gadget(b'\xc3', 0x2000)             # ret

    result = SymbolicAnalyzer().analyze_ropchain([g1, g2])

    assert result.reached is False
    assert result.pivots == []


@needs_triton
def test_deterministic_chain_has_no_pivots(x64):
    ''' A plain pop/ret chain is fully stack-driven, so no pivots are flagged. '''
    g1 = make_gadget(b'\x5f\xc3', 0x1000)         # pop rdi ; ret
    g2 = make_gadget(b'\x5e\xc3', 0x2000)         # pop rsi ; ret
    g3 = make_gadget(b'\xc3', 0x3000)             # ret (final)

    result = SymbolicAnalyzer().analyze_ropchain([g1, g2, g3])

    assert result.reached is True
    assert result.pivots == []

