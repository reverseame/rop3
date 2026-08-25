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
from collections import Counter
from itertools import product, count
from typing import Iterator

import rop3.debug as debug
import rop3.utils as utils
import rop3.operation as operation
import rop3.parser as parser

from rop3.arch import arch_singleton

from .gadget import Gadget, heuristic_basic_count

'''
Matches an operation line with an arbitrary number of comma-separated operands:

    neg(reg1)              -> OP: neg, ARGS: 'reg1'
    mov(reg3, reg2)        -> OP: mov, ARGS: 'reg3, reg2'
    gcf-ltc(r1, r2, r3)    -> OP: gcf, ARGS: 'r1, r2, r3'
    sub(rax, -1)           -> OP: sub, ARGS: 'rax, -1'
'''
REGEX_OP = re.compile(
    r'^(?P<OP>[a-zA-Z0-9-]+)'
    r'\((?P<ARGS>[^)]*)\)'
    r'(?:\s*;.*)?$'
)
COMMENT = re.compile(r'^(?:\s*;.*)?$')

# Base for the fresh generic register slots that stand in for an operation's
# unbound operands. Kept far above any REGn a ROPLang definition uses so the two
# never collide.
_FRESH_SLOT_BASE = 9000000


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
    Returns (defn, original_names), the original operand names in position order.
    '''
    names = _operand_names(set_)
    rename = {orig: f'op{i + 1}' for i, orig in enumerate(names)}
    positional = list(rename.values())
    renamed = set_.renamed(rename)
    mnemonic = renamed.items[0].mnemonic if renamed.items else 'inline'
    defn = operation.OperationDef(mnemonic, operands=len(positional),
                                  dst_roles=positional[:1], src_roles=positional)
    real = operation.Realization()
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
    '''
    try:
        defn = parser.Parser().get_op(op)
    except parser.ParserException:
        raise RopChainNotFound(f'{op}: undefined operation referenced')

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
            if isinstance(link, operation.OpRef):
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


class RopChain:
    '''
    Class to construct a rop chain
    '''
    def __init__(self, gadfinder):
        self.gadfinder = gadfinder

    def search_from_files(self, binaries: list[str], ropfile, base=None, badchars=None,
                          badchar_bytes=None, arch=None, symbols=False) -> Iterator[list[Gadget]]:
        gadgets = self.gadfinder.find(binaries, base=base, badchars=badchars,
                                      badchar_bytes=badchar_bytes, arch=arch, symbols=symbols)
        return self.search_from_gadgets(gadgets, ropfile)

    def search_from_gadgets(self, gadgets, ropfile) -> Iterator[list[Gadget]]:
        ropchain = self._parse_ropfile(ropfile)
        return self.search(gadgets, ropchain)

    def search(self, gadgets, ropchain, prune_equivalent=True) -> Iterator[list[Gadget]]:
        '''
        `ropchain` is a list of requested steps ({op, op1/op2 or operands}). Each
        step expands into its alternative primitive chains (one per compound
        realization); the cartesian product across steps enumerates the candidate
        ROP chains, each resolved by Tree and assembled by DFS.
        '''
        fresh = count()   # source of fresh generic slots for unbound operands
        per_step_alternatives = []
        for step in ropchain:
            defn = parser.Parser().get_op(step['op'])
            binding = self._step_binding(step, defn, fresh)
            alternatives = expand_steps(step['op'], binding)
            if not alternatives:
                raise RopChainNotFound(
                    f'{step.get("data", step["op"])}: no realization for operation')
            per_step_alternatives.append(alternatives)
        return self._search_alternatives(gadgets, per_step_alternatives, prune_equivalent)

    def _search_alternatives(self, gadgets, per_step_alternatives,
                             prune_equivalent) -> Iterator[list[Gadget]]:
        found = False
        for combo in product(*per_step_alternatives):
            primitives = [step for chain in combo for step in chain]
            try:
                for solution in self._get_pruned_ropchain_iterator(
                        gadgets, primitives, prune_equivalent):
                    found = True
                    yield solution
            except RopChainNotFound:
                continue
        if not found:
            raise RopChainNotFound('no suitable ropchain combination found')

    def _step_binding(self, step: dict, defn, fresh) -> dict:
        '''
        Resolve every operand of the operation to a value. Operands the user
        gave (positionally: an `operands` list or the op1/op2 keys) become
        concrete registers; any unbound operand becomes a fresh generic register
        slot. So the expanded steps -- and thus ropchain construction -- only
        ever contain concrete registers and generic (REGn) slots, never the
        operation's opN names, regardless of how many operands it has.
        '''
        operands = step.get('operands')
        if operands is None:
            operands = [step.get('op1'), step.get('op2')]
        binding = {}
        for i in range(defn.operands):
            value = operands[i] if i < len(operands) else None
            if value is None:
                value = f'REG{_FRESH_SLOT_BASE + next(fresh)}'
            binding[f'op{i + 1}'] = value
        return binding

    def _get_pruned_ropchain_iterator(self, gadgets, ropchain, prune_equivalent) -> Iterator[list[Gadget]]:
        tree = Tree(ropchain)
        (combinations, ops_gadgets) = tree.traverse(gadgets)
        per_comb = self._build_per_comb_gadgets(ropchain, combinations, ops_gadgets, prune_equivalent)
        return self._construct_ropchain(ropchain, per_comb, combinations)

    def _build_per_comb_gadgets(
        self,
        ropchain: list[dict],
        combinations: list[dict],
        ops_gadgets: list[list[Gadget]],
        prune_equivalent: bool,
    ) -> list[list[list[Gadget]]]:
        '''
        For each register combination, produce a per-step gadget list already
        filtered to the combination's concrete slot registers, sorted by
        heuristic_basic_count, and (optionally) pruned of subsumed gadgets. The
        filter+prune result is memoized per (step, req_dst, req_src).
        '''
        sorted_gadgets = [sorted(gl, key=heuristic_basic_count) for gl in ops_gadgets]
        cache: dict = {}

        def build_step(i, req_op1, req_op2):
            key = (i,
                   None if req_op1 is None else str(req_op1),
                   None if req_op2 is None else str(req_op2))
            if key not in cache:
                filtered = [gad for gad in sorted_gadgets[i]
                            if (req_op1 is None or str(gad.slot_op1) == str(req_op1))
                            and (req_op2 is None or str(gad.slot_op2) == str(req_op2))]
                cache[key] = self._prune(filtered) if prune_equivalent else filtered
            return cache[key]

        result = []
        for comb in combinations:
            per_step = []
            for i in range(len(sorted_gadgets)):
                op = ropchain[i]
                req_op1 = comb.get(op.get('op1'))
                req_op2 = comb.get(op.get('op2'))
                per_step.append(build_step(i, req_op1, req_op2))
            result.append(per_step)

        return result

    def _prune(self, gadget_list: list[Gadget]) -> list[Gadget]:
        '''
        Remove gadgets subsumed by an earlier gadget in the list. Assumes all
        gadgets share the same (slot_op1, slot_op2) and are sorted ascending by
        heuristic_basic_count.
        '''
        ret: list[Gadget] = []
        for gad in gadget_list:
            if not any(kept.subsumes(gad) for kept in ret):
                ret.append(gad)
        return ret

    def _construct_ropchain(
        self,
        ops_ropchain: list[dict],
        per_comb_gadgets: list[list[list[Gadget]]],
        combinations: list[dict],
    ) -> Iterator[list[Gadget]]:
        '''
        DFS over per-combination gadget lists. Side effects are tracked with the
        gadgets' dst/src register *sets*: a register a step reads must not be
        clobbered, a register a step writes gets a fresh value (clearing an
        earlier clobber), and a store's address register (read, not written)
        keeps its clobber (issue #36).
        '''
        found_any = False

        for comb, comb_gadgets in zip(combinations, per_comb_gadgets):

            def backtrack(index: int, chain: list[Gadget],
                          clobbered: Counter) -> Iterator[list[Gadget]]:
                if index == len(ops_ropchain):
                    yield chain.copy()
                    return

                for gad in comb_gadgets[index]:
                    if any(clobbered.get(reg, 0) > 0 for reg in gad.src):
                        continue

                    for reg in gad.side_regs:
                        clobbered[reg] += 1
                    refreshed = {}
                    for reg in gad.dst:
                        if gad.writes_reg(reg):
                            refreshed[reg] = clobbered.get(reg, 0)
                            clobbered[reg] = 0

                    chain.append(gad)
                    yield from backtrack(index + 1, chain, clobbered)
                    chain.pop()

                    for reg, old in refreshed.items():
                        clobbered[reg] = old
                    for reg in gad.side_regs:
                        clobbered[reg] -= 1

            for valid_chain in backtrack(0, [], Counter()):
                found_any = True
                yield valid_chain

        if not found_any:
            raise RopChainNotFound('no suitable ropchain combination found in DFS')

    def _parse_ropfile(self, ropfile: str) -> list[dict]:
        ret = []

        data = utils.read_file(ropfile).splitlines()
        for i, line in enumerate(data, start=1):
            match = REGEX_OP.search(line)
            if match:
                op_name = match.group('OP')
                args = match.group('ARGS').strip()
                operands = [a.strip() for a in args.split(',')] if args else []
                operands = [a for a in operands if a]
                ret.append({
                    'data': match.group(0),
                    'op': op_name,
                    'operands': operands,
                    'op1': operands[0] if len(operands) > 0 else None,
                    'op2': operands[1] if len(operands) > 1 else None,
                })
            elif COMMENT.search(line):
                pass
            else:
                debug.error(f'{ropfile}: Line {i}: {line}: Unable to parse operation')

        return ret


class Tree:
    '''
    Resolves the concrete register assignments for the generic register slots
    (regN) shared across the (already expanded, 2-operand) chain steps.
    '''
    def __init__(self, ropchain):
        self.ropchain = ropchain
        self.op_ropchain = self._parse_ropchain()

    def traverse(self, gadgets: list[Gadget]):
        (state, ops_gadgets, op_pairs) = self._get_initial_state(gadgets)
        combinations = self._traverse(state, op_pairs)
        debug.info(f'Exploring {len(combinations)} register combinations')
        return (combinations, ops_gadgets)

    def _parse_ropchain(self) -> list[operation.Operation]:
        ret = []
        arch = arch_singleton.arch
        arch_aliases = {'REG_SP': arch.sp, 'REG_BP': arch.bp}

        def resolve(val):
            if val is None:
                return None
            if val in arch_aliases:
                return arch_aliases[val]
            if isinstance(val, str) and val.lower().startswith('reg'):   # REGn -> a free slot
                return None
            return val

        for item in self.ropchain:
            ret.append(operation.Operation(
                item['defn'], [resolve(item['op1']), resolve(item['op2'])]))
        return ret

    def _get_initial_state(self, gadgets: list[Gadget]):
        state: dict[str, list[str]] = {}
        ops_gadgets: list[list[Gadget]] = []
        op_pairs: list = []

        arch = arch_singleton.arch

        def is_generic(key):
            return key is not None and isinstance(key, str) and key.lower().startswith('reg')

        for item, op in zip(self.ropchain, self.op_ropchain):
            op_gadgets = op.filter_gadgets(gadgets)
            if not op_gadgets:
                raise RopChainNotFound(f'{item["data"]}: Unable to find gadgets for operation')
            debug.info(f'{item["data"]}: {len(op_gadgets)} matching gadgets')

            ops_gadgets.append(op_gadgets)

            op1_key, op2_key = item.get('op1'), item.get('op2')

            if is_generic(op1_key) and is_generic(op2_key):
                pairs = frozenset(
                    (g.slot_op1, g.slot_op2)
                    for g in op_gadgets
                    if g.slot_op1 and g.slot_op2
                    and arch.is_valid_abstract_reg(g.slot_op1)
                    and arch.is_valid_abstract_reg(g.slot_op2)
                )
                op_pairs.append((op1_key, op2_key, pairs))
                op1_vals = sorted({p[0] for p in pairs})
                op2_vals = sorted({p[1] for p in pairs})
            else:
                op_pairs.append(None)
                op1_vals = sorted({
                    g.slot_op1 for g in op_gadgets
                    if g.slot_op1 and arch.is_valid_abstract_reg(g.slot_op1)
                }) if is_generic(op1_key) else []

                op2_vals = sorted({
                    g.slot_op2 for g in op_gadgets
                    if g.slot_op2 and arch.is_valid_abstract_reg(g.slot_op2)
                }, key=str) if is_generic(op2_key) else []

            for key, vals in ((op1_key, op1_vals), (op2_key, op2_vals)):
                if key is None or not is_generic(key):
                    continue
                if key in state:
                    state[key] = [v for v in vals if v in state[key]]
                else:
                    state[key] = vals

        return (state, ops_gadgets, op_pairs)

    def _traverse(self, state: dict[str, list[str]], op_pairs: list) -> list[dict[str, str]]:
        '''
        Enumerate the register assignments for the abstract slots. Distinct
        slots MAY share a register: an operation can legitimately alias its
        operands (e.g. `sub op1, op2 ; adc op1, REGn` with op1 == op2). Validity
        is enforced by _check_pairs (only real gadget pairs) and, later, by the
        DFS side-effect tracking -- not by forcing every slot to differ.
        '''
        items = list(state.items())
        results: list[dict[str, str]] = []

        def backtrack(index: int, current: dict[str, str]) -> None:
            if index == len(items):
                if self._check_pairs(current, op_pairs):
                    results.append(current.copy())
                return

            key, possible_values = items[index]

            for val in possible_values:
                current[key] = val
                backtrack(index + 1, current)
                del current[key]

        backtrack(0, {})
        return results

    def _check_pairs(self, combo: dict[str, str], op_pairs: list) -> bool:
        for entry in op_pairs:
            if entry is None:
                continue
            op1_key, op2_key, pairs = entry
            op1_val = combo.get(op1_key)
            op2_val = combo.get(op2_key)
            if op1_val is not None and op2_val is not None:
                if (op1_val, op2_val) not in pairs:
                    return False
        return True


class RopChainNotFound(Exception):
    pass
