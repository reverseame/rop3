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
from typing import Iterator

import rop3.debug as debug
import rop3.utils as utils
import rop3.operation as operation

import rop3.parser as parser

from rop3.arch import arch_singleton

from .gadget import Gadget, heuristic_basic_count

'''
Matches the following with OP, DST and SRC placeholders:

lc()            -> OP: lc,  DST: None, SRC: None
neg(reg1)       -> OP: neg, DST: reg1, SRC: None
sc(,reg1)       -> OP: sc,  DST: None, SRC: reg1
mov(reg3,reg2)  -> OP: mov, DST: reg3, SRC: reg2
mov(reg3, reg2) -> OP: mov, DST: reg3, SRC: reg2
'''
REGEX_OP = re.compile(
    r'^(?P<OP>[a-zA-Z]+)' + \
    r'\((?P<DST>[a-zA-Z0-9]+)?(, ?(?P<SRC>[a-zA-Z0-9]+))?\)' + \
    r'(?:\s*;.*)?$'
)
COMMENT = re.compile(r'^(?:\s*;.*)?$')

class RopChain:
    '''
    Class to construct a rop chain
    '''
    def __init__(self, gadfinder):
        self.gadfinder = gadfinder

    def search_from_files(self, binaries: list[str], ropfile, base=None, badchars=None) -> Iterator[list[Gadget]]:
        gadgets = self.gadfinder.find(binaries, base=base, badchars=badchars)
        return self.search_from_gadgets(gadgets, ropfile)

    def search_from_gadgets(self, gadgets, ropfile) -> Iterator[list[Gadget]]:
        ropchain = self._parse_ropfile(ropfile)
        return self.search(gadgets, ropchain)

    def search(self, gadgets, ropchain, prune_equivalent=True) -> Iterator[list[Gadget]]:
        return self._get_pruned_ropchain_iterator(gadgets, ropchain, prune_equivalent)

    def _get_pruned_ropchain_iterator(self, gadgets, ropchain, prune_equivalent) -> Iterator[list[Gadget]]:
        tree = Tree(ropchain)
        (combinations, ops_gadgets) = tree.traverse(gadgets)
        per_comb = self._build_per_comb_gadgets(ropchain, combinations, ops_gadgets, prune_equivalent)
        ops_gadgets = None
        return self._construct_ropchain(ropchain, per_comb, combinations)

    def expand_steps(self, steps: list[dict], dst, src) -> list[dict]:
        """
        Expands ROPLang complex OPs into ROPChains
        """
        dst_key = dst if dst is not None else 'reg_dst'
        src_key = src if src is not None else 'reg_src'

        expanded = []
        for step in steps:
            step_op1 = step.get('op1')
            step_op2 = step.get('op2')
    
            def resolve(placeholder, _dst=dst_key, _src=src_key):
                if placeholder == 'dst': return _dst
                if placeholder == 'src': return _src
                return placeholder
    
            sub_op  = step['operation']
            sub_dst = resolve(step_op1) if step_op1 else None
            sub_src = resolve(step_op2) if step_op2 else None
    
            resolved = parser.Parser().get_op(sub_op)
            if isinstance(resolved, parser.CompositeOperation):
                expanded.extend(self.expand_steps(resolved.steps, sub_dst, sub_src))
            else:
                expanded.append({
                    'data': f'{sub_op}({sub_dst or ""},{sub_src or ""})',
                    'op':   sub_op,
                    'dst':  sub_dst,
                    'src':  sub_src,
                })
    
        return expanded

    def _parse_ropfile(self, ropfile: str) -> list[dict[str, str]]:
        ret = []
    
        data = utils.read_file(ropfile).splitlines()
        for i, line in enumerate(data, start=1):
            match = REGEX_OP.search(line)
            if match:
                op_name = match.group('OP')
                dst     = match.group('DST')
                src     = match.group('SRC')
                resolved = parser.Parser().get_op(op_name)
    
                if isinstance(resolved, parser.CompositeOperation):
                    ret.extend(self.expand_steps(resolved.steps, dst, src))
                else:
                    ret.append({
                        'data': match.group(0),
                        'op':   op_name,
                        'dst':  dst,
                        'src':  src,
                    })
    
            elif COMMENT.search(line):
                pass
            else:
                debug.error(f'{ropfile}: Line {i}: {line}: Unable to parse operation')
    
        return ret

    def _build_per_comb_gadgets(
        self,
        ropchain: list[dict],
        combinations: list[dict],
        ops_gadgets: list[list[Gadget]],
        prune_equivalent: bool,
    ) -> list[list[list[Gadget]]]:
        """
        For each combination, produce a per-step gadget list that is already:
          - filtered to gadgets matching the combination's req_dst / req_src
          - sorted by heuristic_basic_count (fewest side effects first)
          - pruned of subsumed gadgets (when prune_equivalent), exploiting sort order
        Returns an array indexed [comb_idx][step_idx].

        Each operation's gadget list is sorted once up front, and the
        filter+prune result is memoised per (step, req_dst, req_src): different
        combinations frequently request the same concrete registers for a given
        step, so this avoids recomputing the same filtered list repeatedly.
        """
        sorted_gadgets = [sorted(gl, key=heuristic_basic_count) for gl in ops_gadgets]
        cache: dict = {}

        def build_step(i, req_dst, req_src):
            key = (i,
                   None if req_dst is None else str(req_dst),
                   None if req_src is None else str(req_src))
            if key not in cache:
                filtered = [ gad for gad in sorted_gadgets[i] \
                        if (req_dst is None or str(gad.dst) == str(req_dst)) \
                        and (req_src is None or str(gad.src) == str(req_src)) ]
                cache[key] = self._prune(filtered) if prune_equivalent else filtered
            return cache[key]

        result = []
        for comb in combinations:
            per_step = []
            for i in range(len(sorted_gadgets)):
                op = ropchain[i]
                req_dst = comb.get(op.get('dst'))
                req_src = comb.get(op.get('src'))
                per_step.append(build_step(i, req_dst, req_src))
            result.append(per_step)

        return result

    def _prune(self, gadget_list: list[Gadget]) -> list[Gadget]:
        """
        Remove gadgets subsumed by an earlier gadget in the list. Assumes all
        gadgets share the same (dst, src) pair and are sorted ascending by
        heuristic_basic_count
        """
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
        """
        DFS over per-combination gadget lists.
        Each per_comb_gadgets[i] is already filtered and optionally pruned
        """
        found_any = False
        arch = arch_singleton.arch

        for comb, comb_gadgets in zip(combinations, per_comb_gadgets):
            # Precompute the effective src register per step for the side-effect guard.
            effective_srcs: list = []
            for op in ops_ropchain:
                src_key = op.get('src')
                req_src = comb.get(src_key)
                if req_src is not None:
                    effective_srcs.append(arch.normalize_reg(req_src))
                elif src_key and not (isinstance(src_key, str) and src_key.lower().startswith('reg')):
                    effective_srcs.append(arch.normalize_reg(src_key))
                else:
                    effective_srcs.append(None)

            def backtrack(
                index: int,
                ropchain: list[Gadget],
                side_effected: Counter[str],
            ) -> Iterator[list[Gadget]]:
                if index == len(ops_ropchain):
                    yield ropchain.copy()
                    return

                effective_src = effective_srcs[index]
                if effective_src and side_effected.get(effective_src, 0) > 0:
                    return

                for gad in comb_gadgets[index]:
                    for side_reg in gad.side_regs:
                        side_effected[side_reg] += 1
                    ropchain.append(gad)
                    yield from backtrack(index + 1, ropchain, side_effected)
                    ropchain.pop()
                    for side_reg in gad.side_regs:
                        side_effected[side_reg] -= 1

            for valid_chain in backtrack(0, [], Counter()):
                found_any = True
                yield valid_chain

        if not found_any:
            raise RopChainNotFound('no suitable ropchain combination found in DFS')


class Tree:

    def __init__(self, ropchain):
        self.ropchain = ropchain
        self.op_ropchain = self._parse_ropchain()

    def traverse(self, gadgets: list[Gadget]):
        """
        Gadgets are the actual rop gadgets present in the binary.
        Returns (combinations, ops_gadgets) where each combination is a flat
        dict mapping every abstract-register name to a normalised concrete reg.
        """
        (state, ops_gadgets, op_pairs) = self._get_initial_state(gadgets)
        combinations = self._traverse(state, op_pairs)
        debug.info(f'Exploring {len(combinations)} register combinations')
        return (combinations, ops_gadgets)

    def _parse_ropchain(self) -> list[operation.Operation]:
        ret = []
        arch = arch_singleton.arch
    
        arch_aliases = {
            'REG_SP': arch.sp,
            'REG_BP': arch.bp,
        }

        def resolve(val):
            if val is None:
                return None
            if val in arch_aliases:
                return arch_aliases[val]
            if isinstance(val, str) and val.lower().startswith('reg'):
                return None
            return val
    
        for item in self.ropchain:
            dst = item['dst']
            src = item['src']
   
            ret.append(operation.Operation(item['op'], resolve(dst), resolve(src)))
    
        return ret

    def _get_initial_state(self, gadgets: list[Gadget]):
        """
        Build the constraint state.

        state maps each abstract-reg name (str) to the list of possible
        concrete registers seen across all gadgets for that slot.
        """
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

            dst_key, src_key = item.get('dst'), item.get('src')

            if is_generic(dst_key) and is_generic(src_key):
                pairs = frozenset(
                    (g.dst, g.src)
                    for g in op_gadgets
                    if g.has_dst() and g.has_src()
                    and arch.is_valid_abstract_reg(g.dst)
                    and arch.is_valid_abstract_reg(g.src)
                )
                op_pairs.append((dst_key, src_key, pairs))
                dst_vals = sorted({p[0] for p in pairs})
                src_vals = sorted({p[1] for p in pairs})
            else:
                op_pairs.append(None)
                dst_vals = sorted({
                    g.dst for g in op_gadgets
                    if g.has_dst() and arch.is_valid_abstract_reg(g.dst)
                }) if is_generic(dst_key) else []

                src_vals = sorted({
                    g.src for g in op_gadgets
                    if g.has_src() and arch.is_valid_abstract_reg(g.src)
                }, key=str) if is_generic(src_key) else []

            for key, vals in ((dst_key, dst_vals), (src_key, src_vals)):
                if key is None or not is_generic(key):
                    continue
                if key in state:
                    state[key] = [v for v in vals if v in state[key]]
                else:
                    state[key] = vals

        return (state, ops_gadgets, op_pairs)

    def _traverse(self, state: dict[str, list[str]], op_pairs: list) -> list[dict[str, str]]:
        """
        Returns a list of dicts: { abstract_name -> concrete_reg }.
        """
        items = list(state.items())
        results: list[dict[str, str]] = []

        def backtrack(index: int, current: dict[str, str], used: set[str]) -> None:
            if index == len(items):
                if self._check_pairs(current, op_pairs):
                    results.append(current.copy())
                return

            key, possible_values = items[index]

            for val in possible_values:
                if val in used:
                    continue
                current[key] = val
                used.add(val)
                backtrack(index + 1, current, used)
                del current[key]
                used.remove(val)

        backtrack(0, {}, set())
        return results

    def _check_pairs(self, combo: dict[str, str], op_pairs: list) -> bool:
        for entry in op_pairs:
            if entry is None:
                continue
            dst_key, src_key, pairs = entry
            dst_val = combo.get(dst_key)
            src_val = combo.get(src_key)
            if dst_val is not None and src_val is not None:
                if (dst_val, src_val) not in pairs:
                    return False
        return True


class RopChainNotFound(Exception):
    pass
