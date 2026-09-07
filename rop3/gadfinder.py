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

import os
import math
import bisect
import capstone
import multiprocessing
from itertools import product, count

from rop3.cache import GadgetCache
import rop3.utils as utils
import rop3.debug as debug
import rop3.binary
from rop3.operation import OperationDef, match_gadgets, realize
from rop3.arch import arch_singleton, DEFAULT_DEPTH
from rop3.archs.x86_arch import X86_Architecture, X64_Architecture
from rop3.archs.riscv_arch import RISCV_Architecture
import rop3.parser as parser

from .gadget import Gadget

''' Default (x86) search depth in bytes; kept for backward compatibility.
    The effective default is architecture-specific (Architecture.default_depth,
    used when --depth is omitted). '''
DEPTH = DEFAULT_DEPTH

''' Flags when searching gadgets '''
DEFAULT = 0
KEEP_DUPLICATES = 1
JOP = 2
ROP = 4
RETF = 8
ALLOW_UNDETERMINISTIC = 16
ALLOW_COMPLEX_MEM = 32
AVOID_CANARY = 64
ALLOW_RET_IMM = 128
ALLOW_REG_ALIASES = 256
KEEP_CONTRADICTORY = 512
UNFRAMED = 1024

''' Terminator canary bytes to avoid in gadget addresses by default:
    0x00 (string terminator for strcpy() and alike), 0x0a and 0x0d (line
    terminators for gets() and alike) and 0xff (EOF). See issue #5. '''
CANARY_BYTES = (0x00, 0x0a, 0x0d, 0xff)

# Base for the fresh generic register slots that stand in for an operation's
# unbound operands (see GadFinder.bind_step). Kept far above any REGn a ROPLang
# definition uses so the two never collide.
_FRESH_SLOT_BASE = 9000000

class GadFinder:
    '''
    Class to search gadgets in a binary
    '''
    def __init__(self, depth=None, flags=DEFAULT, cache=False, cache_dir=None,
                 jobs=1):
        self.depth = depth
        self.flags = flags
        self._cache = GadgetCache(cache_dir) if cache else None
        self._jobs = max(1, int(jobs)) if jobs else 1

    def find(self, filenames: list[str], base=None, badchars=None,
             badchar_bytes=None, arch=None, symbols=False) -> list[Gadget]:
        ''' base is normalized to one entry per binary by the argument parser '''
        bases = base if isinstance(base, list) else [base] * len(filenames)
        avoid = self._avoid_bytes(badchars)

        if not self._keep_duplicates():
            seen: dict = {}
            for filename, file_base in zip(filenames, bases):
                binary = self._open_binary(filename, file_base, arch)
                symtab = self._symbol_table(binary) if symbols else None
                before = len(seen)
                total = 0
                for gadget in self._search_gadgets(binary, badchars, badchar_bytes, symtab):
                    total += 1
                    existing = seen.get(gadget)
                    if existing is None:
                        gadget.count = 1
                        seen[gadget] = gadget
                    else:
                        existing.count += 1
                        ''' Among duplicates, keep the address with the fewest
                            terminator canary bytes; break ties by the lower
                            address so the result is deterministic regardless
                            of scan order (serial or parallel). See issue #5. '''
                        if self._avoid_canary():
                            new_key = (self._addr_canary_score(gadget, avoid), gadget.vaddr)
                            cur_key = (self._addr_canary_score(existing, avoid), existing.vaddr)
                            if new_key < cur_key:
                                gadget.count = existing.count
                                seen[gadget] = gadget
                unique = len(seen) - before
                debug.info(f'{unique} unique gadgets ({total - unique} duplicates discarded)')
            return self._sort_gadgets(list(seen.values()))
        else:
            gadgets = []
            for filename, file_base in zip(filenames, bases):
                binary = self._open_binary(filename, file_base, arch)
                symtab = self._symbol_table(binary) if symbols else None
                gadgets.extend(self._search_gadgets(binary, badchars, badchar_bytes, symtab))
            return self._sort_gadgets(gadgets)

    def _avoid_bytes(self, badchars) -> set:
        ''' Bytes to avoid in gadget addresses when deduplicating: the
            user-supplied bad chars if any, else the default canary bytes. '''
        if badchars:
            return {int(badchar, 0) for badchar in badchars}
        return set(CANARY_BYTES)

    def _addr_canary_score(self, gadget: Gadget, avoid: set) -> int:
        ''' Number of bytes to avoid present in the gadget's packed address '''
        packed = utils.pack_addr(gadget.vaddr, arch_singleton.arch.address_size)
        return sum(byte in avoid for byte in packed)

    def _sort_gadgets(self, gadgets: list[Gadget]) -> list[Gadget]:
        return sorted(gadgets, key=lambda g: (os.path.basename(g.filename), g.vaddr))

    def _open_binary(self, filename, base, arch=None):
        binary = rop3.binary.Binary(filename, base, arch)
        binary_arch = binary.get_arch()
        if arch_singleton.is_initialized() and not arch_singleton.matches(binary_arch):
            debug.error(f'{filename}: mixing architectures (x86/x64) in a single run is not supported')
        arch_singleton.initialize(binary_arch)
        arch_singleton.allow_reg_aliases = bool(self._allow_reg_aliases())
        return binary

    def _symbol_table(self, binary):
        ''' Sorted (address, name) pairs and a parallel address list for the
            nearest-symbol bisect (see _nearest_symbol). '''
        symbols = sorted(binary.get_symbols())
        addrs = [addr for addr, _ in symbols]
        return (addrs, symbols)

    def _nearest_symbol(self, vaddr, symbol_table):
        ''' Name (with byte offset) of the closest symbol at or below vaddr. '''
        addrs, symbols = symbol_table
        idx = bisect.bisect_right(addrs, vaddr) - 1
        if idx < 0:
            return None
        sym_addr, name = symbols[idx]
        offset = vaddr - sym_addr
        return f'{name}+{hex(offset)}' if offset else name

    def find_op(self, filenames, op, operands=None, base=None,
                badchars=None, badchar_bytes=None, arch=None, symbols=False):
        gadgets = self.find(filenames, base, badchars, badchar_bytes, arch, symbols)
        return self.find_op_from_gadgets(gadgets, op, operands)

    def find_op_from_gadgets(self, gadgets, op, operands=None):
        from rop3.ropchain import RopChain, RopChainNotFound

        resolved = parser.Parser().get_op(op)

        operands = list(operands) if operands else []
        step = {'op': op, 'operands': operands,
                'data': f'{op}({", ".join(operands)})'}

        # Operations realized as multi-step chains (containing operation refs or
        # more than one gadget) expand into ROP chains; purely single-gadget
        # operations return a flat list of matching gadgets.
        has_chain = any(not real.is_single_gadget for real in resolved.realizations)
        if has_chain:
            try:
                return list(RopChain(self).search(gadgets, [step], prune_equivalent=False))
            except RopChainNotFound:
                return []

        # Operands are positional: op1, op2, op3, ...
        return self.match_operation(gadgets, resolved, operands,
                                    reject_clobbered=not self._keep_contradictory())

    # --- ROP-chain classification -----------------------------------------

    def classify_ropchain(self, gadgets, steps):
        '''
        Resolve a parsed ROP-chain request into the gadgets that realize it.

        `steps` is the parsed request: a list of {'op', 'operands', 'data'}
        dicts. Each step is bound and expanded into its alternative primitive
        chains (a compound operation has several); the cartesian product across
        steps enumerates the candidate realizations, and every 2-operand
        primitive of a realization is matched against `gadgets`.

        Returns a list of realizations, each a list of (primitive_step, gadgets)
        pairs -- the per-step classified gadgets the assembler consumes.
        Realizations in which some primitive matches no gadget are dropped.
        '''
        fresh = count()   # source of fresh generic slots for unbound operands
        per_step_alternatives = []
        for step in steps:
            defn = self._step_defn(step)
            binding = self.bind_step(step, fresh, defn=defn)
            alternatives = self.expand_operation(defn, binding)
            if not alternatives:
                from rop3.ropchain import RopChainNotFound
                raise RopChainNotFound(
                    f'{step.get("data", step["op"])}: no realization for operation')
            per_step_alternatives.append(alternatives)

        realizations = []
        for combo in product(*per_step_alternatives):
            primitives = [prim for chain in combo for prim in chain]
            bundle = self._match_primitives(gadgets, primitives)
            if bundle is not None:
                realizations.append(bundle)
        return realizations

    def _match_primitives(self, gadgets, primitives):
        ''' Match each primitive step against `gadgets`, returning a list of
            (step, gadgets) pairs. None if any primitive matches no gadget (the
            realization is infeasible and is skipped). '''
        bundle = []
        for prim in primitives:
            operands = [self._resolve_operand(prim.get('op1')),
                        self._resolve_operand(prim.get('op2'))]
            gads = self.match_operation(gadgets, prim['defn'], operands)
            if not gads:
                debug.info(f'{prim["data"]}: no matching gadgets')
                return None
            debug.info(f'{prim["data"]}: {len(gads)} matching gadgets')
            bundle.append((prim, gads))
        return bundle

    def _resolve_operand(self, val):
        ''' Map a primitive operand to a match value: REG_SP/REG_BP -> the arch
            pointer register, a generic REGn slot -> None (matches any register),
            anything else -> itself. '''
        if val is None:
            return None
        aliased = self.resolve_reg_alias(val)   # REG_SP/REG_BP -> sp/bp
        if aliased != val:
            return aliased
        if isinstance(val, str) and val.lower().startswith('reg'):
            return None
        return val

    def match_operation(self, gadgets: list[Gadget], defn: OperationDef,
                        operands, reject_clobbered: bool = True) -> list[Gadget]:
        ''' Gadgets realizing operation definition `defn` with the given
            positional operands. The single entry point for operation matching;
            the ROPLang name is resolved to `defn` here in gadfinder (via the
            parser), keeping the matcher free of name lookups. '''
        return match_gadgets(defn, operands, gadgets, reject_clobbered=reject_clobbered)

    def _step_defn(self, step):
        ''' The OperationDef backing a chain step. A step may carry its own
            `defn` (an explicit gadget defined inline in the ROP-chain file, see
            RopChain._parse_raw_line); otherwise the ROPLang name is resolved
            against the operation catalog. '''
        defn = step.get('defn')
        if defn is not None:
            return defn
        return parser.Parser().get_op(step['op'])

    def bind_step(self, step, fresh, defn=None):
        '''
        Resolve a requested chain step's operands to values, so a compound
        operation can be searched as a single operation with unbound (None)
        operands. Operands the user gave (positionally: an `operands` list or the
        op1/op2 keys) become concrete registers; any unbound operand becomes a
        fresh generic register slot drawn from `fresh` (a shared counter). So the
        expanded steps -- and thus ropchain construction -- only ever contain
        concrete registers and generic (REGn) slots, never the operation's opN
        names, regardless of how many operands it has.

        Raises parser.ParserException if the operation is undefined.
        '''
        if defn is None:
            defn = self._step_defn(step)
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

    def expand_operation(self, defn, binding: dict) -> list[list[dict]]:
        ''' Flatten a ROPLang operation definition into its alternative
            2-operand primitive step chains. `defn` is the resolved
            OperationDef (from the catalog or an explicit inline gadget); any
            operation referenced during realization but undefined surfaces as
            RopChainNotFound, the assembler's own error type. '''
        from rop3.ropchain import RopChainNotFound
        try:
            return realize(defn, binding)
        except parser.ParserException as exc:
            raise RopChainNotFound(str(exc))

    def is_abstract_reg(self, reg):
        ''' Whether `reg` may fill an abstract operand slot (a canonical-width
            register for the scanned architecture). '''
        return arch_singleton.arch.is_valid_abstract_reg(reg)

    def resolve_reg_alias(self, name):
        ''' Map the ROPLang stack/base-pointer aliases (REG_SP/REG_BP) to the
            architecture's concrete pointer registers; any other name passes
            through unchanged. '''
        arch = arch_singleton.arch
        return {'REG_SP': arch.sp, 'REG_BP': arch.bp}.get(name, name)

    def _search_gadgets(self, binary, badchars, badchar_bytes=None, symbol_table=None):
        '''
        Yield the gadgets of a binary, building them either from the on-disk
        cache (when enabled and warm) or from a fresh scan. The cache only
        stores the raw (vaddr, bytes) records; everything address/disassembly
        derived (decodes, symbol) is rebuilt here.
        '''
        # `depth is None` means "architecture default"; the arch is initialized
        # by the time any binary is scanned, so resolve it here.
        if self.depth is None:
            self.depth = arch_singleton.arch.default_depth

        key = None
        if self._cache is not None:
            key = self._cache.key(
                self._cache.file_hash(binary.raw_data),
                self._record_params(binary, badchars, badchar_bytes))
            cached = self._cache.load(key)
            if cached is not None:
                debug.info(f'{os.path.basename(binary.filename)}: '
                           f'{len(cached)} gadgets from cache')
                yield from self._reconstruct(binary, cached, symbol_table)
                return

        ''' The parallel scanner chunks by termination byte-offset, which only
            the Galileo backward walk supports; other strategies (the linear
            sweep) run single-threaded. '''
        parallelizable = arch_singleton.arch.parallelizable
        if self._jobs > 1 and parallelizable:
            records = self._scan_parallel(binary, badchars, badchar_bytes)
            if self._cache is not None:
                self._cache.store(key, records)
            yield from self._reconstruct(binary, records, symbol_table)
            return

        if self._jobs > 1 and not parallelizable:
            debug.info(f'{arch_singleton.arch.scan_name} scan runs '
                       f'single-threaded; --jobs ignored')

        records = [] if self._cache is not None else None
        arch = arch_singleton.arch.arch
        mode = arch_singleton.arch.mode
        for vaddr, raw, decodes in self._scan_sections(binary, badchars, badchar_bytes):
            if records is not None:
                records.append([vaddr, raw.hex()])
            symbol = self._nearest_symbol(vaddr, symbol_table) if symbol_table else None
            yield Gadget(filename=binary.filename, arch=arch, mode=mode,
                         vaddr=vaddr, decodes=decodes, bytes=raw, symbol=symbol)

        if records is not None:
            self._cache.store(key, records)

    def _scan_parallel(self, binary, badchars, badchar_bytes):
        '''
        Scan the executable sections across worker processes. Each section is
        split into chunks; a chunk emits only the gadgets whose termination
        falls inside its window (the slice extends `depth` bytes earlier so
        gadgets straddling a boundary are still complete), so there are no
        cross-chunk duplicates. Returns sorted [vaddr, hex] records.
        '''
        arch = arch_singleton.arch.arch
        mode = arch_singleton.arch.mode
        terminations = self._gad_terminations()

        tasks = []
        for section in binary.get_exec_sections():
            opcodes = section['opcodes']
            sec_vaddr = section['vaddr']
            n = len(opcodes)
            chunk = max(4096, math.ceil(n / (self._jobs * 4)))
            for lo in range(0, n, chunk):
                hi = min(lo + chunk, n)
                start = max(0, lo - self.depth)
                ''' Termination END offsets run in [0, n]; the final chunk owns
                    the closing n as well, so make its window inclusive. '''
                emit_hi = hi + 1 if hi == n else hi
                tasks.append((
                    arch, mode, self.depth, int(self.flags), terminations,
                    badchars, badchar_bytes,
                    opcodes[start:hi], start, sec_vaddr, lo, emit_hi,
                ))

        records = []
        with multiprocessing.Pool(self._jobs) as pool:
            for part in pool.imap_unordered(_scan_worker, tasks):
                records.extend(part)
        records.sort()   # deterministic order regardless of worker scheduling
        return records

    def _scan_sections(self, binary, badchars, badchar_bytes):
        ''' Single pass over the executable sections, delegating to the
            architecture's own gadget scan (Architecture.scan); yields the raw
            (vaddr, bytes, decodes) of every valid gadget. Each architecture
            wires the search strategy that fits its ISA, so there is no
            per-strategy branching here. '''
        arch_obj = arch_singleton.arch
        # Byte-pattern terminations drive the Galileo backward walk; the linear
        # sweeps find terminations by disassembly and ignore them.
        terminations = self._gad_terminations()

        md = capstone.Cs(arch_obj.arch, arch_obj.mode)
        md.detail = True

        def accept_candidate(vaddr, raw):
            return (self._is_valid_address(vaddr, badchars, arch_obj.address_size)
                    and self._is_valid_bytes(raw, badchar_bytes))

        for section in binary.get_exec_sections():
            opcodes, vaddr = section['opcodes'], section['vaddr']
            yield from arch_obj.scan(
                opcodes, vaddr, self.depth, md.disasm, self._is_valid_gadget,
                terminations=terminations, accept_candidate=accept_candidate,
                framed=self._framed())

    def _reconstruct(self, binary, records, symbol_table):
        ''' Rebuild Gadget objects from cached (vaddr, hex-bytes) records. '''
        arch = arch_singleton.arch.arch
        mode = arch_singleton.arch.mode
        md = capstone.Cs(arch, mode)
        md.detail = True
        for vaddr, hexbytes in records:
            raw = bytes.fromhex(hexbytes)
            decodes = list(md.disasm(raw, vaddr))
            symbol = self._nearest_symbol(vaddr, symbol_table) if symbol_table else None
            yield Gadget(filename=binary.filename, arch=arch, mode=mode,
                         vaddr=vaddr, decodes=decodes, bytes=raw, symbol=symbol)

    def _record_params(self, binary, badchars, badchar_bytes) -> dict:
        ''' Everything (besides file content) that changes the raw record set,
            so a different option misses the cache cleanly. '''
        arch = arch_singleton.arch
        return {
            'depth': self.depth,
            'flags': int(self.flags),
            'arch': [arch.arch, arch.mode],
            'badchars': sorted(badchars) if badchars else None,
            'badchar_bytes': sorted(badchar_bytes) if badchar_bytes else None,
            'sections': [[s['vaddr'], len(s['opcodes'])]
                         for s in binary.get_exec_sections()],
        }

    def _gad_terminations(self):
        ret = []

        arch = arch_singleton.arch

        ret_imm = bool(self._allow_ret_imm())
        if self._rop():
            ret.extend(arch.get_rop_terminations(include_ret_imm=ret_imm))
        if self._retf():
            ret.extend(arch.get_rop_terminations(include_retf=True, include_ret_imm=ret_imm))
        if self._jop():
            ret.extend(arch.get_jop_terminations())

        return ret

    def _rop(self):
        return self.flags & ROP

    def _jop(self):
        return self.flags & JOP

    def _retf(self):
        return self.flags & RETF

    def _allow_undeterministic(self):
        return self.flags & ALLOW_UNDETERMINISTIC

    def _allow_complex_mem(self):
        return self.flags & ALLOW_COMPLEX_MEM

    def _keep_duplicates(self):
        return self.flags & KEEP_DUPLICATES

    def _avoid_canary(self):
        return self.flags & AVOID_CANARY

    def _allow_ret_imm(self):
        return self.flags & ALLOW_RET_IMM

    def _allow_reg_aliases(self):
        return self.flags & ALLOW_REG_ALIASES

    def _keep_contradictory(self):
        return self.flags & KEEP_CONTRADICTORY

    def _framed(self):
        ''' Framed search is the default; UNFRAMED disables it. '''
        return not (self.flags & UNFRAMED)

    def _is_valid_gadget(self, decodes):
        ''' Invalid instructions and, thus, not decoded '''
        if not decodes:
            return False

        ret = False
        arch = arch_singleton.arch
        allow_undeterministic = bool(self._allow_undeterministic())
        allow_ret_imm = bool(self._allow_ret_imm())
        if self._rop():
            ret |= arch.is_valid_rop_gadget(decodes, allow_undeterministic=allow_undeterministic, allow_ret_imm=allow_ret_imm)
        if self._retf():
            ret |= arch.is_valid_rop_gadget(decodes, include_retf=True, allow_undeterministic=allow_undeterministic, allow_ret_imm=allow_ret_imm)
        if not ret and self._jop():
            ret |= arch.is_valid_jop_gadget(decodes, allow_undeterministic=allow_undeterministic)

        if ret and not self._allow_complex_mem():
            if arch.first_insn_has_complex_mem(decodes):
                return False

        return ret

    def _is_valid_address(self, vaddr, badchars, address_size):
        if not badchars:
            return True

        vaddr = utils.pack_addr(vaddr, address_size)

        return not any([bytes([int(badchar, 0)]) in vaddr for badchar in badchars])

    def _is_valid_bytes(self, gadget_bytes, badchar_bytes):
        ''' Reject gadgets whose opcode bytes contain a forbidden byte (#21). '''
        if not badchar_bytes:
            return True

        forbidden = {int(b, 0) for b in badchar_bytes}
        return not any(byte in forbidden for byte in gadget_bytes)


def _arch_for(arch_const, mode):
    ''' Rebuild the architecture object inside a worker process. '''
    if arch_const == capstone.CS_ARCH_RISCV:
        return RISCV_Architecture(compressed=bool(mode & capstone.CS_MODE_RISCVC))
    return X64_Architecture() if mode == capstone.CS_MODE_64 else X86_Architecture()


def _scan_worker(task):
    '''
    Worker (runs in its own process): scan one section chunk and return the
    raw [vaddr, hex] records for the gadgets whose termination lies in the
    chunk's window. Decodes are not returned (capstone objects are not
    picklable); the parent rebuilds them.
    '''
    (arch_const, mode, depth, flags, terminations, badchars, badchar_bytes,
     slice_bytes, slice_start, sec_vaddr, emit_lo, emit_hi) = task

    arch_obj = _arch_for(arch_const, mode)
    arch_singleton.reset()
    arch_singleton.initialize(arch_obj)
    finder = GadFinder(depth, flags)

    md = capstone.Cs(arch_const, mode)
    md.detail = True

    def accept_match(ref):
        ''' Only this chunk owns terminations ending in [emit_lo, emit_hi). '''
        return emit_lo <= slice_start + ref < emit_hi

    def accept_candidate(vaddr, raw):
        return (finder._is_valid_address(vaddr, badchars, arch_obj.address_size)
                and finder._is_valid_bytes(raw, badchar_bytes))

    # The slice starts `slice_start` bytes into the section.
    base_vaddr = sec_vaddr + slice_start
    out = []
    for vaddr, raw, _decodes in arch_obj.scan(
            slice_bytes, base_vaddr, depth, md.disasm, finder._is_valid_gadget,
            terminations=terminations, accept_candidate=accept_candidate,
            accept_match=accept_match, framed=finder._framed()):
        out.append([vaddr, raw.hex()])
    return out

