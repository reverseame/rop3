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
from itertools import count
from typing import Iterator

import rop3.debug as debug
import rop3.utils as utils

from .gadget import Gadget, heuristic_basic_count
from .operation import OperationDef

from .symbolic import SymbolicAnalyzer

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

'''
Matches an explicit inline gadget: a verbatim instruction sequence, matched as
written with no ret/branch terminator requirement (include a terminator among
the mnemonics if you want one):
    raw([mnemonic, ...], [operands], [dst regs], [src regs])
'''
REGEX_RAW = re.compile(r'^\s*raw\s*\(')

# Base for the fresh internal names --legacy-ropchain's free(NAME) rename pass
# hands out to a post-free reuse of a name. Distinct from
# gadfinder._FRESH_SLOT_BASE (9000000) so the two fresh-name spaces never
# collide within one run.
_LEGACY_FREE_SLOT_BASE = 9500000


def _is_generic_slot(key) -> bool:
    ''' Whether `key` is a generic register-slot name (regN/REGn, or a TMP_REG
        scratch temporary) rather than a concrete register or None. '''
    if key is None or not isinstance(key, str):
        return False
    return key.lower().startswith('reg') or key.upper().startswith('TMP_REG')


class RopChain:
    '''
    Class to construct a rop chain
    '''
    def __init__(self, gadfinder):
        self.gadfinder = gadfinder
        self._analyzer = SymbolicAnalyzer()
        self.last_symbolic_result = None

    def search_from_files(self, binaries: list[str], ropfile, base=None, badchars=None,
                          badchar_bytes=None, arch=None, symbols=False,
                          symbolic=False, legacy=False, raw=False) -> Iterator[list[Gadget]]:
        gadgets = self.gadfinder.find(binaries, base=base, badchars=badchars,
                                      badchar_bytes=badchar_bytes, arch=arch, symbols=symbols,
                                      raw=raw)
        return self.search_from_gadgets(gadgets, ropfile, symbolic=symbolic, legacy=legacy,
                                        binaries=binaries, base=base, badchars=badchars,
                                        badchar_bytes=badchar_bytes, arch=arch, raw=raw)

    def search_from_gadgets(self, gadgets, ropfile, symbolic=False, legacy=False,
                            binaries=None, base=None, badchars=None,
                            badchar_bytes=None, arch=None, raw=False) -> Iterator[list[Gadget]]:
        ropchain = self._parse_ropfile(ropfile)
        return self.search(gadgets, ropchain, symbolic=symbolic, legacy=legacy,
                           binaries=binaries, base=base, badchars=badchars,
                           badchar_bytes=badchar_bytes, arch=arch, raw=raw)

    def search(self, gadgets, ropchain, prune_equivalent=True,
               symbolic=False, legacy=False, binaries=None, base=None,
               badchars=None, badchar_bytes=None, arch=None, raw=False) -> Iterator[list[Gadget]]:
        '''
        `ropchain` is the parsed request: a list of steps ({op, operands}), or
        a `free(NAME)` directive step ({op: 'free', free: NAME}) releasing a
        generic register-slot name. The gadfinder classifies it into
        realizations -- one per compound-operation alternative -- each a list
        of (primitive_step, gadgets) pairs plus the free directives' positions
        among them; every realization is resolved and assembled by `_assemble`.

        `legacy` selects the pre-`free` global register-slot resolution: a
        generic name (e.g. REG1) is one identity for the whole chain (`Tree`),
        and `free` is only approximated by a parse-time rename
        (`_rewrite_legacy_frees`). The default (order-aware `_assemble_sequential`)
        lets `free(NAME)` truly release NAME partway through the chain.

        When `symbolic` is set (and Triton is available), each assembled chain
        is symbolically executed as a final validation step before it is
        yielded. Disabled by default -- it's an opt-in extra validation pass,
        not required to assemble a chain.

        `binaries`/`base`/`badchars`/`badchar_bytes`/`arch` are only consulted
        when `ropchain` contains a `raw(...)` step: they drive
        GadFinder.find_raw_gadgets, the direct scan that step's candidates come
        from (see `_resolve_raw_gadgets`). Without `binaries`, a `raw(...)` step
        degrades to matching only against `gadgets` as given -- which is what
        lets a caller with no file access (e.g. a hand-built `gadgets` list in a
        unit test) still exercise it.
        '''
        self._check_free_usage(ropchain)
        if legacy:
            ropchain = self._rewrite_legacy_frees(ropchain)
        self._resolve_raw_gadgets(ropchain, binaries, base, badchars, badchar_bytes, arch, raw)
        realizations = self.gadfinder.classify_ropchain(gadgets, ropchain, legacy=legacy)
        found = False
        for bundle, free_events in realizations:
            try:
                for solution in self._assemble(bundle, prune_equivalent, free_events, legacy):
                    found = True
                    self._symbolic_check(solution, symbolic)
                    yield solution
            except RopChainNotFound:
                continue
        if not found:
            raise RopChainNotFound('no suitable ropchain combination found')

    def _symbolic_check(self, solution: list[Gadget], symbolic: bool) -> None:
        '''
        Final step: symbolically execute the assembled chain, record the stack
        layout / memory accesses it needs, and confirm control reaches the last
        gadget.
        '''
        self.last_symbolic_result = None
        if not symbolic:
            return

        result = self._analyzer.analyze_ropchain(solution)
        self.last_symbolic_result = result
        if not result.supported:
            debug.info(f'symbolic analysis skipped: {result.error}')
            return
        if result.error:
            debug.warning(result.error)
            return
        for line in result.report_lines():
            debug.info(line)
        if result.memory_writes:
            debug.warning(
                f'concolic emulation observed {len(result.memory_writes)} memory '
                'write(s): the chain has memory side effects (see the report for '
                'addresses and values)')
        if result.pivots:
            debug.warning(
                f'concolic emulation detected {len(result.pivots)} stack '
                'pivot(s): control does not reach the next gadget through the '
                'filled return slot (redirected stack pointer or a chain-fixed '
                'return address)')
        if not result.reached:
            debug.warning('concolic emulation did not reach the final gadget: '
                          'the chain may not transfer control as expected')

    def _assemble(self, bundle, prune_equivalent, free_events=(), legacy=False) -> Iterator[list[Gadget]]:
        ''' Resolve one realization's register slots and assemble it. `bundle`
            is a list of (primitive_step, classified_gadgets) pairs. `legacy`
            picks the whole-chain Tree-based pipeline (unmodified); otherwise
            the order-aware DFS, using `free_events` (from classify_ropchain)
            to know where among these primitives a free(NAME) directive sits. '''
        if legacy:
            steps = [step for step, _ in bundle]
            ops_gadgets = [gadgets for _, gadgets in bundle]
            tree = Tree(steps, ops_gadgets, self.gadfinder)
            combinations = tree.traverse()
            per_comb = self._build_per_comb_gadgets(steps, combinations, ops_gadgets, prune_equivalent)
            return self._construct_ropchain(steps, per_comb, combinations)
        return self._assemble_sequential(bundle, prune_equivalent, free_events)

    def _assemble_sequential(
        self,
        bundle: list,
        prune_equivalent: bool,
        free_events: list,
    ) -> Iterator[list[Gadget]]:
        '''
        Order-aware assembler (the default engine): register-slot resolution
        and gadget-clobber tracking share one backtracking DFS, walking the
        chain steps in file order. A `live` map (generic name -> concrete
        register) is threaded alongside the clobbered-register Counter:
        picking a gadget for a step tentatively binds any newly-resolved
        generic slot, and a free(NAME) boundary releases NAME from `live` for
        every step from here on, restoring it symmetrically on backtrack -- so
        a later reuse of the same literal name is resolved independently
        instead of being forced to match its earlier identity (compare Tree,
        the --legacy-ropchain equivalent, which has no notion of position and
        so cannot express this).
        '''
        steps = [step for step, _ in bundle]
        sorted_gadgets = [sorted(gadgets, key=heuristic_basic_count) for _, gadgets in bundle]
        n = len(steps)

        frees_at: dict[int, list[str]] = {}
        for boundary, name in free_events:
            frees_at.setdefault(boundary, []).append(name)

        cache: dict = {}

        def candidates(index, req_op1, req_op2):
            key = (index, None if req_op1 is None else str(req_op1),
                          None if req_op2 is None else str(req_op2))
            if key not in cache:
                filtered = [g for g in sorted_gadgets[index]
                            if (req_op1 is None or str(g.slot_op1) == str(req_op1))
                            and (req_op2 is None or str(g.slot_op2) == str(req_op2))]
                cache[key] = self._prune(filtered) if prune_equivalent else filtered
            return cache[key]

        def requirement(key, live):
            ''' None means "unconstrained": key is concrete (already resolved
                upstream by match_operation/_resolve_operand) or a generic slot
                not currently bound (first use, or freed and not reused yet). '''
            if not _is_generic_slot(key):
                return None
            return live.get(key)

        found_any = False

        def backtrack(index: int, live: dict, clobbered: Counter,
                      chain: list) -> Iterator[list[Gadget]]:
            nonlocal found_any
            freed_here = frees_at.get(index, [])
            saved = {name: live.pop(name) for name in freed_here if name in live}
            try:
                if index == n:
                    found_any = True
                    yield chain.copy()
                    return

                step = steps[index]
                op1_key, op2_key = step.get('op1'), step.get('op2')
                req_op1 = requirement(op1_key, live)
                req_op2 = requirement(op2_key, live)

                for gad in candidates(index, req_op1, req_op2):
                    if any(clobbered.get(reg, 0) > 0 for reg in gad.src):
                        continue

                    newly_bound = {}
                    for k, v in ((op1_key, gad.slot_op1), (op2_key, gad.slot_op2)):
                        if _is_generic_slot(k) and k not in live:
                            live[k] = v
                            newly_bound[k] = v

                    for reg in gad.side_regs:
                        clobbered[reg] += 1
                    refreshed = {}
                    for reg in gad.dst:
                        if gad.writes_reg(reg):
                            refreshed[reg] = clobbered.get(reg, 0)
                            clobbered[reg] = 0

                    chain.append(gad)
                    yield from backtrack(index + 1, live, clobbered, chain)
                    chain.pop()

                    for reg, old in refreshed.items():
                        clobbered[reg] = old
                    for reg in gad.side_regs:
                        clobbered[reg] -= 1
                    for k in newly_bound:
                        del live[k]
            finally:
                for name, val in saved.items():
                    live[name] = val

        yield from backtrack(0, {}, Counter(), [])
        if not found_any:
            raise RopChainNotFound('no suitable ropchain combination found in DFS')

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
            if REGEX_RAW.match(line):
                try:
                    ret.append(self._parse_raw_line(line))
                except RawGadgetError as exc:
                    debug.error(f'{ropfile}: Line {i}: {line}: {exc}')
                continue

            match = REGEX_OP.search(line)
            if match:
                op_name = match.group('OP')
                args = match.group('ARGS').strip()
                raw = [a.strip() for a in args.split(',')] if args else []
                if op_name == 'free':
                    try:
                        ret.append(self._parse_free_line(match.group(0), raw))
                    except FreeDirectiveError as exc:
                        debug.error(f'{ropfile}: Line {i}: {line}: {exc}')
                    continue
                operands = self._strip_legacy_commas(op_name, raw)
                ret.append({
                    'data': match.group(0),
                    'op': op_name,
                    'operands': operands,
                })
            elif COMMENT.search(line):
                pass
            else:
                debug.error(f'{ropfile}: Line {i}: {line}: Unable to parse operation')

        return ret

    @staticmethod
    def _strip_legacy_commas(op_name: str, raw: list[str]) -> list[str]:
        '''
        LEGACY: older ROPLang files used a comma's position to mark an operand's
        role -- a comma *after* the first operand separated dst from src
        (`op(dst, src)`), and a lone source could be written with a comma
        *before* it (`op(, src)`) to push it into the src slot. Operands are now
        purely positional (op1, op2, ...) and a lone operand is always op1, so
        the empty slot such a comma produces is dropped. A comma before the
        first operand is explicitly ignored -- it never shifts the operand into
        op2 -- and warns. Kept only for backward compatibility.
        '''
        if raw and raw[0] == '':
            debug.warning(f'{op_name}: a comma before the first operand is a legacy '
                          f'dst/src marker; it is ignored (operands are positional: '
                          f'op1, op2, ...)')
        elif '' in raw:
            debug.warning(f'{op_name}: an empty operand from a legacy dst/src comma '
                          f'is ignored (operands are positional: op1, op2, ...)')
        return [a for a in raw if a]

    @staticmethod
    def _parse_free_line(data: str, raw_args: list[str]) -> dict:
        '''
        Parse a `free(NAME)` compile-time directive: from here to the end of
        the file (default engine) or to the next occurrence
        (--legacy-ropchain), NAME's identity as a generic register slot is
        released. Produces no gadget and is never resolved via
        parser.Parser().get_op -- classify_ropchain special-cases a `free`
        step before _step_defn is ever called.
        '''
        if len(raw_args) != 1 or not raw_args[0]:
            raise FreeDirectiveError(
                'free(...) takes exactly one register-slot name, e.g. free(REG1)')
        return {'data': data, 'op': 'free', 'free': raw_args[0]}

    @staticmethod
    def _step_generic_operands(step: dict) -> list:
        ''' The raw operand tokens of a (non-free) step, whichever form it was
            parsed in -- positional `operands`, or the legacy op1/op2 keys. '''
        operands = step.get('operands')
        if operands is not None:
            return operands
        return [step.get('op1'), step.get('op2')]

    @staticmethod
    def _check_free_usage(steps: list[dict]) -> None:
        ''' Diagnostics only, for both engines: freeing a non-generic name, a
            name never used before this point, or a name already freed with
            no intervening use are all harmless no-ops in both assemblers, so
            this warns rather than errors (matching _strip_legacy_commas). '''
        ever_seen: set = set()
        pending_free: set = set()
        for step in steps:
            freed = step.get('free')
            if freed is not None:
                if not _is_generic_slot(freed):
                    debug.warning(f'free({freed}): only a generic register-slot name '
                                  f'(regN) can be freed; ignoring')
                elif freed not in ever_seen:
                    debug.warning(f'free({freed}): {freed} was never used before this '
                                  f'point in the file; ignoring')
                elif freed in pending_free:
                    debug.warning(f'free({freed}): {freed} was already freed with no '
                                  f'intervening use since; ignoring the repeated free')
                else:
                    pending_free.add(freed)
                continue
            for v in RopChain._step_generic_operands(step):
                if _is_generic_slot(v):
                    ever_seen.add(v)
                    pending_free.discard(v)

    def _resolve_raw_gadgets(self, steps: list[dict], binaries, base,
                             badchars, badchar_bytes, arch, raw=False) -> None:
        ''' For every `raw(...)` step (the only producer of an inline `defn`),
            fill in defn.literal_gadgets via GadFinder.find_raw_gadgets when
            `binaries` is available -- the direct scan that finds the verbatim
            instruction sequence in the target regardless of whether it ends on
            a control-flow terminator. A step whose literal_gadgets is already
            resolved (e.g. `search` was called more than once with the same
            parsed steps) is not rescanned. '''
        if not binaries:
            return
        for step in steps:
            defn = step.get('defn')
            if defn is None:
                continue
            if defn.literal_gadgets is None:
                defn.literal_gadgets = self.gadfinder.find_raw_gadgets(
                    binaries, defn, base=base, badchars=badchars,
                    badchar_bytes=badchar_bytes, arch=arch, raw=raw)

    def _rewrite_legacy_frees(self, steps: list[dict]) -> list[dict]:
        '''
        --legacy-ropchain approximation of `free`: rewrite the step list so
        that, from a free(NAME) line onward, NAME is a brand-new internal
        identity, decoupling it from its earlier occurrences in Tree's
        whole-file global intersection. Occurrences between two frees of the
        same NAME (or before the first / after the last) still share one
        identity, exactly like today's semantics without `free`. `free` steps
        are dropped here -- classify_ropchain/Tree never see them.
        '''
        epoch: dict = {}
        fresh_for_epoch: dict = {}
        counter = count()

        def resolve(value):
            if not _is_generic_slot(value):
                return value
            e = epoch.get(value, 0)
            if e == 0:
                return value
            key = (value, e)
            if key not in fresh_for_epoch:
                fresh_for_epoch[key] = f'REG{_LEGACY_FREE_SLOT_BASE + next(counter)}'
            return fresh_for_epoch[key]

        def rewrite(step):
            new_step = dict(step)
            if step.get('operands') is not None:
                new_step['operands'] = [resolve(v) if isinstance(v, str) else v
                                        for v in step['operands']]
            for k in ('op1', 'op2'):
                if isinstance(step.get(k), str):
                    new_step[k] = resolve(step[k])
            return new_step

        out = []
        for step in steps:
            freed = step.get('free')
            if freed is not None:
                if _is_generic_slot(freed):
                    epoch[freed] = epoch.get(freed, 0) + 1
                continue
            out.append(rewrite(step))
        return out

    def _parse_explicit_gadget_fields(self, line: str) -> tuple:
        '''
        Field parsing for `raw(...)`:

            raw([mnemonic, ...], [operands], [dst], [src])

        The four bracketed fields are the instruction mnemonics, their operands,
        and the concrete registers written (dst) / read (src) for the
        assembler's side-effect tracking.

        Operands map to instructions positionally: with no parenthesised groups
        every operand belongs to the *first* instruction (the common case:
        `pop rdi ; ret`, `mov [rdi], rax ; ret`); to give operands to several
        instructions, wrap each instruction's operands in `(...)`
        (`raw([pop, pop, ret], [(rdi), (rsi)], [rdi, rsi], [])`).

        Returns (instructions, name, dst, src).
        '''
        body = self._raw_body(line)
        fields = self._split_top_level(body)
        if len(fields) != 4:
            raise RawGadgetError('a raw gadget needs exactly four bracketed '
                                 'fields: [mnemonics], [operands], [dst], [src]')

        mnemonics = self._raw_list(fields[0], 'mnemonics')
        if not mnemonics:
            raise RawGadgetError('a raw gadget needs at least one mnemonic')
        per_instr_ops = self._raw_operands(fields[1], len(mnemonics))
        dst = self._raw_list(fields[2], 'dst')
        src = self._raw_list(fields[3], 'src')

        instructions = [{'mnemonic': m, 'operands': ops}
                        for m, ops in zip(mnemonics, per_instr_ops)]
        name = ' ; '.join(
            f"{ins['mnemonic']} {', '.join(ins['operands'])}".strip()
            for ins in instructions)

        return instructions, name, dst, src

    def _parse_raw_line(self, line: str) -> dict:
        '''
        Parse an explicit-gadget line into a chain step carrying its own inline
        OperationDef:

            raw([mnemonic, ...], [operands], [dst], [src])

        The step is otherwise identical to a ROPLang step, so the
        classifier/assembler consume it unchanged; the only difference is that
        its definition is built here instead of resolved from the operation
        catalog. The gadget is matched exactly as written, hence architecture
        specific (no multi-architecture realizations).

        A raw gadget carries no ret/branch terminator requirement: its
        candidates come from GadFinder.find_raw_gadgets, a direct scan
        independent of the normal backward gadget-finder machinery (see
        RopChain.search / _resolve_raw_gadgets), so a bare non-returning tail
        such as `syscall`/`svc 0`/`ecall` is expressible. If you want a
        terminator, include it among the mnemonics (`pop rdi ; ret`).
        '''
        instructions, name, dst, src = self._parse_explicit_gadget_fields(line)

        defn = OperationDef(name, operands=0, dst_roles=dst, src_roles=src)
        defn.add_realization([{'gadget': instructions}])

        return {'data': line.strip(), 'op': name, 'operands': [], 'defn': defn}

    @staticmethod
    def _raw_body(line: str) -> str:
        ''' The text between the outermost parentheses of a `raw(...)` line,
            with any trailing `;` comment removed. '''
        line = RopChain._strip_line_comment(line).strip()
        open_paren = line.find('(')
        if open_paren == -1 or not line.endswith(')'):
            raise RawGadgetError('malformed raw gadget: expected raw(...)')
        return line[open_paren + 1:-1]

    @staticmethod
    def _strip_line_comment(line: str) -> str:
        ''' Drop a trailing `;` comment, ignoring any `;` nested inside brackets
            (a raw gadget's fields never contain `;`, but stay bracket-aware). '''
        depth = 0
        for i, ch in enumerate(line):
            if ch in '[(':
                depth += 1
            elif ch in ')]':
                depth = max(0, depth - 1)
            elif ch == ';' and depth == 0:
                return line[:i]
        return line

    @staticmethod
    def _split_top_level(s: str, sep: str = ',') -> list[str]:
        ''' Split `s` on `sep` at bracket depth 0, honouring `[]` and `()`
            nesting, and strip each part. '''
        parts, depth, cur = [], 0, ''
        for ch in s:
            if ch in '[(':
                depth += 1
            elif ch in ')]':
                depth -= 1
            if ch == sep and depth == 0:
                parts.append(cur.strip())
                cur = ''
            else:
                cur += ch
        parts.append(cur.strip())
        return parts

    @staticmethod
    def _unbracket(field: str, what: str) -> str:
        field = field.strip()
        if not (field.startswith('[') and field.endswith(']')):
            raise RawGadgetError(f'the {what} field must be wrapped in [ ]')
        return field[1:-1].strip()

    @staticmethod
    def _raw_list(field: str, what: str) -> list[str]:
        ''' A bracketed, comma-separated field ([a, b, c]) as a list of tokens,
            dropping empties (so `[]` is an empty list). '''
        inner = RopChain._unbracket(field, what)
        return [tok for tok in RopChain._split_top_level(inner) if tok]

    @staticmethod
    def _raw_operands(field: str, n_instr: int) -> list[list[str]]:
        '''
        Resolve the operands field into a per-instruction operand list (one entry
        per mnemonic). With no `(...)` groups all operands belong to the first
        instruction; with groups, each top-level element is one instruction's
        operands -- a `(...)` group its full operand list, a bare token a single
        operand -- assigned to instructions in order.
        '''
        inner = RopChain._unbracket(field, 'operands')
        elements = [e for e in RopChain._split_top_level(inner) if e]
        per_instr: list[list[str]] = [[] for _ in range(n_instr)]
        if not elements:
            return per_instr

        grouped = any(e.startswith('(') and e.endswith(')') for e in elements)
        if not grouped:
            per_instr[0] = elements
            return per_instr

        if len(elements) > n_instr:
            raise RawGadgetError(
                f'{len(elements)} operand groups for {n_instr} instruction(s)')
        for i, element in enumerate(elements):
            if element.startswith('(') and element.endswith(')'):
                ops = [o for o in RopChain._split_top_level(element[1:-1]) if o]
            else:
                ops = [element]
            per_instr[i] = ops
        return per_instr


class Tree:
    '''
    Resolves the concrete register assignments for the generic register slots
    (regN) shared across the (already expanded, 2-operand) chain steps. Works
    from the per-step classified gadgets the gadfinder produced; `gadfinder` is
    consulted only for the arch's abstract-register predicate.
    '''
    def __init__(self, steps, ops_gadgets, gadfinder):
        self.ropchain = steps
        self.ops_gadgets = ops_gadgets
        self.gadfinder = gadfinder

    def traverse(self):
        (state, op_pairs) = self._get_initial_state()
        combinations = self._traverse(state, op_pairs)
        debug.info(f'Exploring {len(combinations)} register combinations')
        return combinations

    def _get_initial_state(self):
        state: dict[str, list[str]] = {}
        op_pairs: list = []

        is_generic = _is_generic_slot

        for item, op_gadgets in zip(self.ropchain, self.ops_gadgets):
            op1_key, op2_key = item.get('op1'), item.get('op2')

            if is_generic(op1_key) and is_generic(op2_key):
                pairs = frozenset(
                    (g.slot_op1, g.slot_op2)
                    for g in op_gadgets
                    if g.slot_op1 and g.slot_op2
                    and self.gadfinder.is_abstract_reg(g.slot_op1)
                    and self.gadfinder.is_abstract_reg(g.slot_op2)
                )
                op_pairs.append((op1_key, op2_key, pairs))
                op1_vals = sorted({p[0] for p in pairs})
                op2_vals = sorted({p[1] for p in pairs})
            else:
                op_pairs.append(None)
                op1_vals = sorted({
                    g.slot_op1 for g in op_gadgets
                    if g.slot_op1 and self.gadfinder.is_abstract_reg(g.slot_op1)
                }) if is_generic(op1_key) else []

                op2_vals = sorted({
                    g.slot_op2 for g in op_gadgets
                    if g.slot_op2 and self.gadfinder.is_abstract_reg(g.slot_op2)
                }, key=str) if is_generic(op2_key) else []

            for key, vals in ((op1_key, op1_vals), (op2_key, op2_vals)):
                if key is None or not is_generic(key):
                    continue
                if key in state:
                    state[key] = [v for v in vals if v in state[key]]
                else:
                    state[key] = vals

        return (state, op_pairs)

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
                results.append(current.copy())
                return

            key, possible_values = items[index]

            for val in possible_values:
                current[key] = val
                if self._check_pairs(current, op_pairs):
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


class RawGadgetError(Exception):
    ''' A malformed explicit-gadget (`raw(...)`) line in a ROP-chain file. '''
    pass


class FreeDirectiveError(Exception):
    ''' A malformed `free(...)` directive in a ROP-chain file. '''
    pass
