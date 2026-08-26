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

import re
import copy
import dataclasses
from itertools import product

from rop3.arch import arch_singleton

import rop3.parser as parser

from .gadget import Gadget

# Abstract operand placeholders: operation operands op1, op2, op3, ... and the
# scratch helper registers REG1, REG10, ...
_ABSTRACT_RE = re.compile(r'^(op\d+|REG\d+)$')


def is_abstract_name(name) -> bool:
    return isinstance(name, str) and bool(_ABSTRACT_RE.match(name))


def is_immediate(value) -> bool:
    ''' Whether a value is a numeric immediate (e.g. 8, '8', '0x10', '#0', -1)
        rather than a register name. '''
    if isinstance(value, int):
        return True
    try:
        int(str(value).lstrip('#'), 0)
        return True
    except (ValueError, TypeError):
        return False


class Operation:
    '''
    Matcher for a single-gadget realization of an operation. The operation's
    operands are given explicitly and positionally as `operands` = [op1, op2,
    op3, ...] (an operation has 1, 2 or 3 of them); a value of None leaves that
    operand unconstrained (matches any register).
    '''
    def __init__(self, op, operands=None):
        self.defn = op if isinstance(op, OperationDef) else parser.Parser().get_op(op)
        if not self.defn.available:
            reason = self.defn.unavailable_reason or 'not available for this architecture'
            raise parser.OperationNotAvailable(f'{self.defn.name}: {reason}')
        self.name = self.defn.name
        self.bindings: dict = {}
        for i, value in enumerate(operands or ()):
            if value is not None:
                self.bindings[f'op{i + 1}'] = value

    def filter_gadgets(self, gadgets, reject_clobbered=True) -> list[Gadget]:
        ''' Gadgets whose instructions realize this operation. The operation's
            first instruction must be the gadget's first instruction after the
            architecture's frame prologue (Set.is_equal); its remaining
            instructions may be separated by other instructions.

            With `reject_clobbered` (the default), a gadget is discarded when
            its destination register is overwritten before the terminator (a
            "contradictory" gadget that does not actually realize the
            operation). The check runs inside the match, so clobbered gadgets
            are rejected before the (more expensive) annotation. '''
        ret = []
        if not gadgets:
            return ret

        protect = self._destination_registers if reject_clobbered else None
        for real in self.defn.realizations:
            if not real.is_single_gadget:
                continue
            set_ = real.links[0].bound(self.bindings)
            for gadget in gadgets:
                (equal, binds) = set_.is_equal(gadget.decodes, protect=protect)
                if not equal:
                    continue
                ret.append(self._annotate(gadget, binds))

        return ret

    def _as_register(self, name, binds):
        ''' The concrete register bound to an operand name, following one level
            of placeholder indirection (opN -> free REGn -> concrete). None if
            the operand is an immediate or is unbound. '''
        arch = arch_singleton.arch
        val = self.bindings.get(name, name)
        if isinstance(val, str) and is_abstract_name(val):
            val = binds.get(val, val)
        if not isinstance(val, str) or is_abstract_name(val) or is_immediate(val):
            return None
        return arch.normalize_reg(val)

    def _as_operand(self, name, binds):
        ''' Display value bound to an operand name: a concrete register (like
            _as_register) or, when the operand bound to a numeric literal, that
            immediate formatted as a string. None if the operand is an unbound
            placeholder or is unused. '''
        val = self.bindings.get(name, name)
        if isinstance(val, str) and is_abstract_name(val):
            val = binds.get(val, val)
        if isinstance(val, str) and is_abstract_name(val):
            return None                         # still an unbound placeholder
        if is_immediate(val):
            return self._format_imm(val)
        if isinstance(val, str):
            return arch_singleton.arch.normalize_reg(val)
        return None

    @staticmethod
    def _format_imm(val) -> str:
        ''' Render an immediate the way the disassembly does: small magnitudes
            in decimal (e.g. -1), larger ones in hex (e.g. 0x1000). '''
        n = int(str(val).lstrip('#'), 0) if not isinstance(val, int) else val
        return str(n) if -256 < n < 256 else hex(n)

    def _destination_registers(self, binds):
        ''' The concrete destination register(s) this operation writes, under
            the given match bindings. Passed to Set.is_equal so the match can
            reject gadgets that overwrite the result before returning. '''
        return {r for r in (self._as_register(n, binds) for n in self.defn.dst_roles) if r}

    def _annotate(self, gadget, binds) -> Gadget:
        ''' Annotate a copy so the shared input gadget is not mutated. '''
        def as_register(name):
            return self._as_register(name, binds)

        matched = dataclasses.replace(gadget, op=self.name)
        # dst/src register sets come from the operation's role metadata (which
        # operands it writes / reads); the two solver slots are just op1 and op2.
        matched.dst = {r for r in map(as_register, self.defn.dst_roles) if r}
        matched.src = {r for r in map(as_register, self.defn.src_roles) if r}
        matched.slot_op1 = as_register('op1')
        matched.slot_op2 = as_register('op2')
        matched.disp_op1 = self._as_operand('op1', binds)
        matched.disp_op2 = self._as_operand('op2', binds)
        matched.calculate_side_effects()
        return matched


# --- Operation expansion --------------------------------------------------
#
# Operations are *defined* with N named operands (opN), but a ROP chain is
# *constructed* only from 2-operand primitives. `expand_steps` resolves an
# operation into a flat list of 2-operand primitive steps:
#
#   - a "primitive" operation (all realizations are single gadgets) becomes one
#     step referencing that operation; its alternative single-gadget
#     realizations are resolved later by Operation.filter_gadgets;
#   - a "compound" operation is flattened by walking its realization's links,
#     recursing into operation references and emitting inline raw-gadget links
#     (e.g. the `leave`/`adc` mnemonics) as synthetic single-gadget primitives.
#
# It lives here (not in ropchain.py) because it works entirely on the operation
# definition structures above; the assembler reaches it via GadFinder.

def _is_primitive(defn) -> bool:
    return bool(defn.realizations) and all(r.is_single_gadget for r in defn.realizations)


def _operand_names(set_) -> list:
    ''' Abstract operand names appearing in a gadget-pattern, in order. '''
    names = []
    for ins in set_.items:
        for op in ins.operands:
            if op.abstract and op.reg not in names:
                names.append(op.reg)
    return names


def _inline_operation_def(set_):
    '''
    Wrap an inline raw-gadget link (a Set of mnemonics used directly inside a
    compound, e.g. `leave` or `adc op1, REG1`) as a synthetic single-gadget
    operation with positional operands op1, op2, ...: operand 0 is the
    destination, all operands count as sources (accumulator-safe). Its operands
    are renamed to op1/op2/... so it matches like any other 2-operand primitive.

    A Set may also declare extra implicit registers via `extra_writes` /
    `extra_reads` (concrete names such as 'rflags').

    Returns (defn, original_names), the original operand names in position order.
    '''
    names = _operand_names(set_)
    rename = {orig: f'op{i + 1}' for i, orig in enumerate(names)}
    positional = list(rename.values())
    renamed = set_.renamed(rename)
    mnemonic = renamed.items[0].mnemonic if renamed.items else 'inline'
    dst_roles = positional[:1] + list(getattr(set_, 'extra_writes', None) or [])
    src_roles = positional + list(getattr(set_, 'extra_reads', None) or [])
    defn = OperationDef(mnemonic, operands=len(positional),
                        dst_roles=dst_roles, src_roles=src_roles)
    real = Realization()
    real.add(renamed)
    defn.add(real)
    return defn, names


def _primary_operands(defn, binding):
    ''' The two operand-slot values of a primitive under `binding`: the primary
        destination operand (op1) and the primary non-accumulator source operand
        (op2). Unbound operands are None (matches any register). '''
    op1 = binding.get(defn.dst_roles[0]) if defn.dst_roles else None
    op2_name = next((r for r in defn.src_roles if r not in defn.dst_roles), None)
    op2 = binding.get(op2_name) if op2_name is not None else None
    return op1, op2


def _format(op, op1, op2) -> str:
    inside = '' if op1 is None else str(op1)
    if op2 is not None:
        inside += f', {op2}'
    return f'{op}({inside})'


def expand_steps(op: str, binding: dict) -> list[list[dict]]:
    '''
    Expand an operation into its alternative realizations, each a flat list of
    2-operand primitive steps. A compound operation yields one chain per
    realization, and one per combination of its operation references' own
    alternatives (cartesian product): every possibility is a distinct ROP chain.
    A primitive yields a single chain of one step (its single-gadget
    realizations are resolved later by Operation.filter_gadgets).

    Raises parser.ParserException if `op` (or a referenced sub-operation) is
    undefined; GadFinder.expand_operation translates that to RopChainNotFound.
    '''
    try:
        defn = parser.Parser().get_op(op)
    except parser.ParserException as exc:
        raise parser.ParserException(f'{op}: undefined operation referenced') from exc

    if _is_primitive(defn):
        op1, op2 = _primary_operands(defn, binding)
        return [[{'data': _format(op, op1, op2), 'op': op, 'defn': defn,
                  'op1': op1, 'op2': op2}]]

    chains: list[list[dict]] = []
    for real in defn.realizations:
        # Each link contributes a list of alternative sub-chains; the cartesian
        # product over the links yields this realization's chains.
        link_alternatives = []
        for link in real.links:
            if isinstance(link, OpRef):
                sub_binding = {slot: binding.get(expr, expr)
                               for slot, expr in link.bindings.items()}
                link_alternatives.append(expand_steps(link.name, sub_binding))
            else:   # inline Set
                syn, names = _inline_operation_def(link)
                # Step operand values are the resolved original operands, in the
                # same positional order as the synthetic op's op1/op2.
                values = [binding.get(name, name) for name in names]
                op1 = values[0] if len(values) > 0 else None
                op2 = values[1] if len(values) > 1 else None
                link_alternatives.append([[{'data': _format(syn.name, op1, op2),
                                            'op': syn.name, 'defn': syn,
                                            'op1': op1, 'op2': op2}]])
        if any(not alt for alt in link_alternatives):
            continue   # some link cannot be realized on this architecture
        for combo in product(*link_alternatives):
            chains.append([step for part in combo for step in part])

    return chains


class OperationDef:
    '''
    Parsed definition of a ROPLang operation for the current architecture: its
    operand arity, which operands it writes (dst_roles) / reads (src_roles) for
    side-effect accounting, and the list of alternative realizations (each a
    chain of gadget-patterns and operation references).
    '''
    def __init__(self, name, operands=0, dst_roles=None, src_roles=None,
                 available=True, unavailable_reason=None):
        self.name = name
        self.operands = operands
        self.dst_roles = list(dst_roles or [])
        self.src_roles = list(src_roles or [])
        self.realizations: list[Realization] = []
        # Whether this operation is realizable on the current architecture.
        # A YAML `<arch>: {available: false}` marks it unavailable (see parser).
        self.available = available
        self.unavailable_reason = unavailable_reason

    def add(self, realization):
        self.realizations.append(realization)


class Realization:
    ''' One alternative realization: an ordered chain of links, each either a
        Set (a gadget-pattern of consecutive instructions) or an OpRef. '''
    def __init__(self):
        self.links: list = []

    def add(self, link):
        self.links.append(link)

    @property
    def is_single_gadget(self) -> bool:
        return len(self.links) == 1 and isinstance(self.links[0], Set)


class OpRef:
    ''' A step that reuses another operation, binding its operands. '''
    def __init__(self, name, bindings):
        self.name = name
        self.bindings = dict(bindings)   # sub-op operand -> outer operand/value


class Set:
    ''' A gadget-pattern: consecutive instructions matched within one gadget. '''
    def __init__(self):
        self.items = []
        self.extra_writes: list = []
        self.extra_reads: list = []

    def __str__(self):
        return ' ; '.join(str(item) for item in self.items)

    def add(self, item):
        self.items.append(item)

    def bound(self, bindings: dict) -> "Set":
        ''' A copy with the given operand names bound to concrete values. Each
            operand is bound once by its own name, so binding an operand to a
            value that happens to be another operand's name cannot cascade
            (e.g. {op1: op2, op2: op3} yields `op2, op3`, not `op3, op3`). '''
        clone = copy.deepcopy(self)
        for item in clone.items:
            for operand in item.operands:
                name = operand.reg
                if operand.abstract and name in bindings:
                    operand.set_binding(name, bindings[name])
        return clone

    def renamed(self, mapping: dict) -> "Set":
        ''' A copy with abstract operand names remapped (e.g. REG1 -> op2). '''
        clone = copy.deepcopy(self)
        for item in clone.items:
            for operand in item.operands:
                if operand.abstract and operand.reg in mapping:
                    operand.reg = mapping[operand.reg]
        return clone

    def is_equal(self, decodes, protect=None):
        '''
        Match this pattern against a gadget's decoded instructions.

        The gadget is viewed as [frame prologue] [operation body] [epilogue].
        The architecture's frame prologue (Architecture.is_frame_prefix) -- a
        leading run of framing instructions, e.g. the RISC-V `ld ra, off(sp)`
        restore; empty on x86/AArch64 -- is skipped, and the operation's FIRST
        instruction must sit right after it (position 0 when the prologue is
        empty). This anchors detection to real gadgets instead of matching an
        operation buried behind arbitrary leading instructions.

        The remaining pattern instructions then match as an ordered subsequence:
        they must appear in order but may be separated by other instructions
        (e.g. `push rbx ; nop ; pop rax` still realizes `push ; pop`). Trailing
        instructions after the last matched one form the epilogue.

        `protect`, if given, is a callable (bindings) -> set of the operation's
        destination registers. A match is rejected when any epilogue instruction
        overwrites a destination the operation actually produces -- a
        "contradictory" gadget (e.g. `add rax, rbx ; mov rax, rcx ; ret`) whose
        result never reaches the terminator. Doing this here fails fast, before
        the gadget is annotated.

        Returns (matched, bindings) with the first consistent binding found.
        '''
        if not self.items:
            return (True, {})

        arch = arch_singleton.arch
        start = 0
        while start < len(decodes) and arch.is_frame_prefix(decodes[start]):
            start += 1

        if len(decodes) - start < len(self.items):
            return (False, {})

        # The operation's first instruction is anchored at `start`; the rest
        # follow as an ordered subsequence.
        (equal, binds) = self.items[0].is_equal(decodes[start])
        if not equal:
            return (False, {})
        bindings: dict = {}
        if not self._merge(bindings, binds):
            return (False, {})

        (ok, bindings, indices) = self._match_subsequence(1, decodes, start + 1,
                                                          bindings, [start])
        if not ok:
            return (False, {})
        if protect is not None and self._result_clobbered(decodes, indices, protect(bindings)):
            return (False, {})
        return (True, bindings)

    def _match_subsequence(self, item_idx, decodes, start, bindings, indices):
        ''' Place self.items[item_idx:] onto increasing positions of `decodes`
            (>= start), backtracking on binding conflicts. `indices` collects
            the matched instruction positions. '''
        if item_idx == len(self.items):
            return (True, bindings, indices)
        item = self.items[item_idx]
        remaining = len(self.items) - item_idx
        # Leave room for the remaining items at strictly increasing positions.
        for i in range(start, len(decodes) - remaining + 1):
            (equal, binds) = item.is_equal(decodes[i])
            if not equal:
                continue
            merged = dict(bindings)
            if not self._merge(merged, binds):
                continue
            (ok, result, idxs) = self._match_subsequence(item_idx + 1, decodes,
                                                         i + 1, merged, indices + [i])
            if ok:
                return (ok, result, idxs)
        return (False, {}, [])

    def _result_clobbered(self, decodes, indices, dst_regs):
        ''' Whether the operation's destination is overwritten before the
            terminator. `dst_regs` are the operation's declared destinations;
            they are intersected with the registers the matched instructions
            actually write (so a store, whose result is in memory, protects
            nothing and is never falsely rejected). A gadget is contradictory if
            an instruction between the last matched one and the terminator
            writes such a register.

            The final (terminating) instruction is excluded: it is control flow,
            and its incidental write to the stack pointer (an x86 `ret` pops) is
            the gadget's exit mechanism, not a clobber of the result -- so a
            stack-pointer operation like `add rsp, 8 ; ret` is not contradictory. '''
        if not dst_regs:
            return False

        arch = arch_singleton.arch

        def writes(insn):
            return {arch.normalize_reg(insn.reg_name(r))
                    for r in arch.written_registers(insn)}

        produced = {reg for i in indices for reg in writes(decodes[i])}
        guarded = dst_regs & produced
        if not guarded:
            return False

        last = max(indices)
        clobbered = {reg for insn in decodes[last + 1:-1] for reg in writes(insn)}
        return bool(guarded & clobbered)

    @staticmethod
    def _merge(bindings: dict, binds: dict) -> bool:
        ''' Fold `binds` into `bindings` in place; False on a conflicting
            reassignment of an abstract operand. '''
        for name, val in binds.items():
            if name in bindings and bindings[name] != val:
                return False
            bindings[name] = val
        return True


class Instruction:
    def __init__(self, mnemonic):
        self.mnemonic = mnemonic
        self.operands = []

    def __str__(self):
        operands = ', '.join(str(operand) for operand in self.operands)
        return f'{self.mnemonic} {operands}'

    def add(self, operand):
        self.operands.append(operand)

    def set_binding(self, name, value):
        for operand in self.operands:
            operand.set_binding(name, value)

    def is_equal(self, decode):
        if self.mnemonic != decode.mnemonic:
            return (False, {})
        if len(self.operands) != len(decode.operands):
            return (False, {})

        bindings: dict = {}
        for myoperand, operand in zip(self.operands, decode.operands):
            (equal, bind) = myoperand.is_equal(decode, operand)
            if not equal:
                return (False, {})
            if bind is not None:
                name, val = bind
                if name in bindings and bindings[name] != val:
                    return (False, {})
                bindings[name] = val

        return (True, bindings)


class Operand:
    '''
    A pattern operand. It is one of:
      - a register (abstract placeholder like op1/REG1, or a concrete reg name),
      - a memory reference [base] (abstract or concrete base), or
      - an immediate (numeric, optionally written #NN as in ARM/RISC-V asm).
    '''
    def __init__(self, operand):
        self.mem = False
        self.abstract = False
        self.reg = None
        self.imm = None
        self._parse(operand)

    def __str__(self) -> str:
        if self.is_mem():
            return f'[{self.reg}]'
        if self.is_imm():
            return str(self.imm)
        return str(self.reg)

    def _parse(self, operand):
        s = str(operand)
        if s.startswith('[') and s.endswith(']'):
            self.mem = True
            s = s[1:-1]

        if not self.mem:
            imm = self._try_imm(s)
            if imm is not None:
                self.imm = imm
                return

        self.reg = s
        self.abstract = is_abstract_name(s)

    def _try_imm(self, value):
        try:
            return self._parse_imm(value)
        except (ValueError, TypeError):
            return None

    def _parse_imm(self, value):
        if isinstance(value, int):
            return value
        value = str(value)
        if value.startswith('#'):
            value = value[1:]
        return int(value, 0)

    def is_reg(self) -> bool:
        return not self.mem and self.imm is None

    def is_mem(self) -> bool:
        return self.mem

    def is_imm(self) -> bool:
        return not self.mem and self.imm is not None

    def set_binding(self, name, value):
        ''' Bind this operand if it is the abstract placeholder `name`.
            Binding to another placeholder (a free chain variable such as REG1)
            keeps the operand abstract so the ROP-chain solver can resolve it. '''
        if not self.abstract or self.reg != name:
            return
        imm = None if self.mem else self._try_imm(value)
        if imm is not None:
            self.imm = imm
            self.reg = None
            self.abstract = False
        else:
            self.reg = str(value)
            self.abstract = is_abstract_name(value)

    def is_equal(self, decode, operand):
        arch = arch_singleton.arch

        # A generic register operand may match an immediate (reg -> imm subst),
        # but never a memory operand (a load address is not an immediate).
        if self.abstract and self.is_reg() and operand.type == arch.op_imm:
            return (True, (self.reg, operand.value.imm))

        if self.is_mem():
            if operand.type != arch.op_mem:
                return (False, None)
            base = decode.reg_name(operand.value.mem.base)
            if self.abstract:
                if not self._alias_ok(arch, base):
                    return (False, None)
                return (True, (self.reg, base))
            return (base == self.reg, None)

        if self.is_imm():
            if operand.type != arch.op_imm:
                return (False, None)
            return (operand.value.imm == self.imm, None)

        # register operand
        if operand.type != arch.op_reg:
            return (False, None)
        reg = decode.reg_name(operand.value.reg)
        if self.abstract:
            if not self._alias_ok(arch, reg):
                return (False, None)
            return (True, (self.reg, reg))
        # Concrete registers must match exactly: writing a sub-register (ah/eax)
        # is not the same as writing the full register (rax).
        return (reg == self.reg, None)

    @staticmethod
    def _alias_ok(arch, reg) -> bool:
        ''' Whether a concrete register may fill an abstract operand. By default
            only full (canonical-width) registers qualify; with register aliases
            enabled, sub-registers (al, ax, eax) qualify too and are normalized
            to their full register for assignment and side effects. '''
        return arch_singleton.allow_reg_aliases or arch.is_valid_abstract_reg(reg)
