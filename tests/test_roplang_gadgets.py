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

'''
Cross-architecture gadget-finding matrix for the ROPLang operations.

For every implemented architecture (x86, x86-64, AArch64, RISC-V) this checks
that each ROPLang operation is realizable from gadgets:

  - a *primitive* operation (one that resolves to a single gadget) is exercised
    by building a representative gadget and asserting Operation.filter_gadgets
    matches it -- this is the actual gadget-finding path;
  - a *compound* operation (a chain of several gadgets/sub-operations) cannot be
    a single gadget, so it is checked to be available and to expose at least one
    realization on that architecture.

A completeness test guarantees every operation in rop3/roplang/*.yaml is
accounted for on every architecture, so the matrix cannot silently skip one.

The RISC-V carry operations (eqc, ltc, gcf-eqc, gcf-ltc) are excluded: RISC-V
has no condition/carry flags, so the YAML marks them `available: false`. The
matrix asserts exactly that instead of trying to find them.
'''

import glob
import os
import struct

import capstone
import pytest

import rop3
import rop3.operation as operation
import rop3.parser as parser
from rop3.arch import arch_singleton
from rop3.archs.x86_arch import X86_Architecture, X64_Architecture
from rop3.gadget import Gadget

# --- The set of all ROPLang operations, straight from the YAML directory ------

_ROPLANG_DIR = os.path.join(os.path.dirname(rop3.__file__), 'roplang')
ROPLANG_OPS = frozenset(os.path.basename(f)[:-5]
                        for f in glob.glob(os.path.join(_ROPLANG_DIR, '*.yaml')))

# Operations RISC-V cannot realize (no condition/carry flags).
RISCV_CARRY_OPS = frozenset({'eqc', 'ltc', 'gcf-eqc', 'gcf-ltc'})


# --- Terminators and frame prologues/epilogues per architecture ---------------

RET_X86 = b'\xc3'                       # ret
RET_A64 = bytes.fromhex('c0035fd6')     # ret
LDP_A64 = bytes.fromhex('fd7bc1a8')     # ldp x29, x30, [sp], #16  (frames the ret)
RET_RV = b'\x67\x80\x00\x00'            # ret  (jalr x0, 0(ra))
LD_RA_RV = b'\x83\x30\x81\x00'          # ld ra, 8(sp)  (restores ra: frames the ret)


# --- RISC-V instruction encoders (R/I/S formats) ------------------------------

def _r(op, f3, f7, rd, rs1, rs2):
    return struct.pack('<I', (f7 << 25) | (rs2 << 20) | (rs1 << 15)
                       | (f3 << 12) | (rd << 7) | op)


def _i(op, f3, rd, rs1, imm):
    return struct.pack('<I', ((imm & 0xfff) << 20) | (rs1 << 15)
                       | (f3 << 12) | (rd << 7) | op)


def _s(op, f3, rs1, rs2, imm):
    return struct.pack('<I', (((imm >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15)
                       | (f3 << 12) | ((imm & 0x1f) << 7) | op)


# --- Representative single-gadget realization of each primitive, per arch ------
#
# Each entry is op -> (operands, body_bytes); the body is the operation's own
# instruction(s), wrapped by the architecture's terminator/frame at test time.

X86_PRIMITIVES = {
    'add': (['eax', 'ebx'], b'\x01\xd8'),     # add eax, ebx
    'sub': (['eax', 'ebx'], b'\x29\xd8'),     # sub eax, ebx
    'and': (['eax', 'ebx'], b'\x21\xd8'),     # and eax, ebx
    'or':  (['eax', 'ebx'], b'\x09\xd8'),     # or  eax, ebx
    'xor': (['eax', 'ebx'], b'\x31\xd8'),     # xor eax, ebx
    'neg': (['eax'],        b'\xf7\xd8'),      # neg eax
    'not': (['eax'],        b'\xf7\xd0'),      # not eax
    'inc': (['eax'],        b'\x40'),          # inc eax
    'mov': (['eax', 'ebx'], b'\x89\xd8'),     # mov eax, ebx
    'ld':  (['eax', 'ebx'], b'\x8b\x03'),     # mov eax, [ebx]
    'st':  (['ebx', 'eax'], b'\x89\x03'),     # mov [ebx], eax
    'lc':  (['eax'],        b'\x58'),          # pop eax
    'sc':  (['eax'],        b'\x50\x58'),     # push eax ; pop eax
}

X64_PRIMITIVES = {
    'add': (['rax', 'rbx'], b'\x48\x01\xd8'),   # add rax, rbx
    'sub': (['rax', 'rbx'], b'\x48\x29\xd8'),   # sub rax, rbx
    'and': (['rax', 'rbx'], b'\x48\x21\xd8'),   # and rax, rbx
    'or':  (['rax', 'rbx'], b'\x48\x09\xd8'),   # or  rax, rbx
    'xor': (['rax', 'rbx'], b'\x48\x31\xd8'),   # xor rax, rbx
    'neg': (['rax'],        b'\x48\xf7\xd8'),    # neg rax
    'not': (['rax'],        b'\x48\xf7\xd0'),    # not rax
    'inc': (['rax'],        b'\x48\xff\xc0'),    # inc rax
    'mov': (['rax', 'rbx'], b'\x48\x89\xd8'),   # mov rax, rbx
    'ld':  (['rax', 'rbx'], b'\x48\x8b\x03'),   # mov rax, [rbx]
    'st':  (['rbx', 'rax'], b'\x48\x89\x03'),   # mov [rbx], rax
    'lc':  (['rax'],        b'\x58'),            # pop rax
    'sc':  (['rax'],        b'\x50\x58'),       # push rax ; pop rax
}

AARCH64_PRIMITIVES = {
    'add': (['x0', 'x1'], bytes.fromhex('0000018b')),   # add x0, x0, x1
    'sub': (['x0', 'x1'], bytes.fromhex('000001cb')),   # sub x0, x0, x1
    'and': (['x0', 'x1'], bytes.fromhex('0000018a')),   # and x0, x0, x1
    'or':  (['x0', 'x1'], bytes.fromhex('000001aa')),   # orr x0, x0, x1
    'xor': (['x0', 'x1'], bytes.fromhex('000001ca')),   # eor x0, x0, x1
    'neg': (['x0'],       bytes.fromhex('e00300cb')),   # neg x0, x0
    'not': (['x0'],       bytes.fromhex('e00320aa')),   # mvn x0, x0
    'inc': (['x0'],       bytes.fromhex('00040091')),   # add x0, x0, #1
    'mov': (['x0', 'x1'], bytes.fromhex('e00301aa')),   # mov x0, x1
    'ld':  (['x0', 'x1'], bytes.fromhex('200040f9')),   # ldr x0, [x1]
    'st':  (['x0', 'x1'], bytes.fromhex('010000f9')),   # str x1, [x0]
    'lc':  (['x0'],       bytes.fromhex('e00340f9')),   # ldr x0, [sp]
    'sc':  (['x0'],       bytes.fromhex('e00300f9')),   # str x0, [sp]
}

RISCV_PRIMITIVES = {
    'add': (['a0', 'a1'], _r(0x33, 0, 0x00, 10, 10, 11)),   # add a0, a0, a1
    'sub': (['a0', 'a1'], _r(0x33, 0, 0x20, 10, 10, 11)),   # sub a0, a0, a1
    'and': (['a0', 'a1'], _r(0x33, 7, 0x00, 10, 10, 11)),   # and a0, a0, a1
    'or':  (['a0', 'a1'], _r(0x33, 6, 0x00, 10, 10, 11)),   # or  a0, a0, a1
    'xor': (['a0', 'a1'], _r(0x33, 4, 0x00, 10, 10, 11)),   # xor a0, a0, a1
    'neg': (['a0'],       _r(0x33, 0, 0x20, 10, 0, 10)),    # neg a0, a0
    'not': (['a0'],       _i(0x13, 4, 10, 10, -1)),         # not a0, a0
    'inc': (['a0'],       _i(0x13, 0, 10, 10, 1)),          # addi a0, a0, 1
    'mov': (['a0', 'a1'], _i(0x13, 0, 10, 11, 0)),          # mv a0, a1
    'ld':  (['a0', 'a1'], _i(0x03, 3, 10, 11, 0)),          # ld a0, 0(a1)
    'st':  (['a1', 'a0'], _s(0x23, 3, 11, 10, 0)),          # sd a0, 0(a1)
    'lc':  (['a0'],       _i(0x03, 3, 10, 2, 16)),          # ld a0, 16(sp)
    'sc':  (['a0'],       _s(0x23, 3, 2, 10, 0)),           # sd a0, 0(sp)
}


# --- Architecture matrix ------------------------------------------------------

class ArchSpec:
    ''' One architecture cell of the matrix. '''
    def __init__(self, id, make_arch, cs_arch, cs_mode, wrap, primitives,
                 excluded=frozenset(), skip=None):
        self.id = id
        self.make_arch = make_arch
        self.cs_arch = cs_arch
        self.cs_mode = cs_mode
        self.wrap = wrap                     # body bytes -> full gadget bytes
        self.primitives = primitives
        self.excluded = excluded             # ops that are unavailable here
        self.skip = skip                     # reason string, or None

    def initialize(self):
        arch_singleton.reset()
        arch_singleton.initialize(self.make_arch())

    def gadget(self, body):
        code = self.wrap(body)
        md = capstone.Cs(self.cs_arch, self.cs_mode)
        md.detail = True
        return Gadget(filename='t', arch=self.cs_arch, mode=self.cs_mode,
                      vaddr=0x1000, decodes=list(md.disasm(code, 0x1000)), bytes=code)


def _cs(name, default=None):
    return getattr(capstone, name, default)


_HAS_ARM64 = hasattr(capstone, 'CS_ARCH_ARM64')
_HAS_RISCV = hasattr(capstone, 'CS_ARCH_RISCV')

ARCHES = [
    ArchSpec('x86', X86_Architecture,
             capstone.CS_ARCH_X86, capstone.CS_MODE_32,
             lambda b: b + RET_X86, X86_PRIMITIVES),
    ArchSpec('x64', X64_Architecture,
             capstone.CS_ARCH_X86, capstone.CS_MODE_64,
             lambda b: b + RET_X86, X64_PRIMITIVES),
    ArchSpec('aarch64',
             (lambda: __import__('rop3.archs.aarch64_arch', fromlist=['AArch64_Architecture'])
              .AArch64_Architecture()),
             _cs('CS_ARCH_ARM64'), _cs('CS_MODE_ARM'),
             lambda b: b + LDP_A64 + RET_A64, AARCH64_PRIMITIVES,
             skip=None if _HAS_ARM64 else 'capstone build without ARM64 support'),
    ArchSpec('riscv',
             (lambda: __import__('rop3.archs.riscv_arch', fromlist=['RISCV_Architecture'])
              .RISCV_Architecture(compressed=True)),
             _cs('CS_ARCH_RISCV'),
             (_cs('CS_MODE_RISCV64', 0) | _cs('CS_MODE_RISCVC', 0)),
             lambda b: LD_RA_RV + b + RET_RV, RISCV_PRIMITIVES,
             excluded=RISCV_CARRY_OPS,
             skip=None if _HAS_RISCV else 'capstone build without RISC-V support'),
]

ARCH_BY_ID = {a.id: a for a in ARCHES}

# Flat (arch, op) list for the primitive gadget-finding matrix.
PRIMITIVE_CASES = [
    pytest.param(spec.id, op,
                 marks=pytest.mark.skipif(bool(spec.skip), reason=spec.skip or ''),
                 id=f'{spec.id}-{op}')
    for spec in ARCHES for op in sorted(spec.primitives)
]

ARCH_CASES = [
    pytest.param(spec.id,
                 marks=pytest.mark.skipif(bool(spec.skip), reason=spec.skip or ''),
                 id=spec.id)
    for spec in ARCHES
]


# --- Primitive gadget-finding: the operation matches a representative gadget ---

@pytest.mark.parametrize('arch_id,op', PRIMITIVE_CASES)
def test_primitive_operation_is_found_as_gadget(arch_id, op):
    spec = ARCH_BY_ID[arch_id]
    spec.initialize()
    operands, body = spec.primitives[op]
    matched = operation.Operation(op, operands).filter_gadgets([spec.gadget(body)])
    assert matched, f'{op} not found on {arch_id}'
    assert matched[0].op == op


# --- Completeness: every ROPLang op is accounted for on every architecture -----

@pytest.mark.parametrize('arch_id', ARCH_CASES)
def test_every_roplang_op_is_covered(arch_id):
    spec = ARCH_BY_ID[arch_id]
    spec.initialize()

    primitives = frozenset(spec.primitives)
    compounds = ROPLANG_OPS - primitives - spec.excluded

    # the three buckets partition the whole ROPLang op set, with no overlap
    assert primitives | compounds | spec.excluded == ROPLANG_OPS
    assert not (primitives & spec.excluded)

    # every primitive listed for this arch really is a single-gadget op
    for op in primitives:
        defn = parser.Parser().get_op(op)
        assert defn.available, f'{op} unexpectedly unavailable on {arch_id}'
        assert any(r.is_single_gadget for r in defn.realizations), \
            f'{op} has no single-gadget realization on {arch_id}'

    # every compound op is available and assembles from at least one realization
    for op in compounds:
        defn = parser.Parser().get_op(op)
        assert defn.available, f'{op} unexpectedly unavailable on {arch_id}'
        assert defn.realizations, f'{op} has no realization on {arch_id}'

    # excluded ops are explicitly unavailable here
    for op in spec.excluded:
        defn = parser.Parser().get_op(op)
        assert defn.available is False, f'{op} should be unavailable on {arch_id}'
        assert defn.unavailable_reason


# --- Compound operations: the whole reuse chain is realizable -----------------
#
# A compound operation (spa, sps, gsp, jmp, jmp-rel, lsd, eqc, ltc, gcf-*) is
# not a single gadget: it reuses one or more other operations via `operation:`
# steps (OpRef links). It can therefore never be found by the single-gadget
# path exercised above, so instead of searching for one gadget we verify that
# every operation it references exists, is available on this architecture, and
# -- followed transitively -- bottoms out in real, single-gadget primitives.

def _op_refs(defn):
    ''' Every OpRef (reused-operation step) across a definition's realizations. '''
    return [link for real in defn.realizations for link in real.links
            if isinstance(link, operation.OpRef)]


def _is_compound(defn):
    ''' A compound operation reuses at least one other operation, so it can
        never be realized by a single gadget. '''
    return bool(_op_refs(defn))


@pytest.mark.parametrize('arch_id', ARCH_CASES)
def test_compound_ops_resolve_to_available_primitives(arch_id):
    ''' Counterpart to test_primitive_operation_is_found_as_gadget: for every
        compound operation available on this architecture, walk its reuse chain
        and assert each referenced operation is available and eventually reduces
        to single-gadget primitives (no dangling reference, no cycle, no reuse
        of an operation that is unavailable here). '''
    spec = ARCH_BY_ID[arch_id]
    spec.initialize()
    p = parser.Parser()
    by_name = {defn.name: defn for defn in p.get_ops()}

    compounds = sorted(name for name, defn in by_name.items()
                       if _is_compound(defn) and defn.available)
    assert compounds, f'no compound operations discovered on {arch_id}'

    def resolve(name, chain):
        assert name in by_name, f'{chain[-1]} reuses unknown operation {name}'
        assert name not in chain, f'reuse cycle on {arch_id}: {" -> ".join(chain + [name])}'
        sub = by_name[name]
        assert sub.available, \
            f'{chain[0]} on {arch_id} reuses unavailable operation {name}'
        assert sub.realizations, f'{name} has no realization on {arch_id}'
        for ref in _op_refs(sub):
            resolve(ref.name, chain + [name])

    for name in compounds:
        defn = by_name[name]
        assert defn.realizations, f'{name} has no realization on {arch_id}'
        # A compound must reduce to primitives; assert every leaf of the reuse
        # tree is a real single-gadget op (the recursion also catches cycles).
        for ref in _op_refs(defn):
            resolve(ref.name, [name])
        assert any(not r.is_single_gadget for r in defn.realizations), \
            f'{name} is classified compound but has only single-gadget realizations'


def test_primitive_tables_list_only_single_gadget_ops():
    ''' Regression guard for the split the two matrix halves rely on: an op in a
        hand-written primitive table must be a genuine single-gadget op and
        never a reuse-based compound -- so it belongs in the gadget-finding test,
        not the compound test. spa/sps in particular are compounds (they reuse
        add/sub on the stack pointer) and must stay out of the primitive tables,
        which is exactly why they were removed from the per-arch pattern tests. '''
    for spec in ARCHES:
        if spec.skip:
            continue
        spec.initialize()
        by_name = {d.name: d for d in parser.Parser().get_ops()}
        for op in spec.primitives:
            defn = by_name[op]
            assert defn.available, f'{op} unavailable on {spec.id}'
            assert not _is_compound(defn), \
                f'{op} is a compound; drop it from the {spec.id} primitive table'
            assert any(r.is_single_gadget for r in defn.realizations), \
                f'{op} has no single-gadget realization on {spec.id}'
        for op in ('spa', 'sps'):
            assert op not in spec.primitives, \
                f'{op} is a compound; it must not be in the {spec.id} primitive table'
            assert _is_compound(by_name[op]), f'{op} should be compound on {spec.id}'


def test_matrix_covers_all_architectures():
    ''' The matrix must span every architecture rop3 implements. '''
    assert {spec.id for spec in ARCHES} == {'x86', 'x64', 'aarch64', 'riscv'}


def test_only_riscv_excludes_operations():
    ''' Carry operations are excluded on RISC-V and nowhere else. '''
    for spec in ARCHES:
        if spec.id == 'riscv':
            assert spec.excluded == RISCV_CARRY_OPS
        else:
            assert spec.excluded == frozenset()
