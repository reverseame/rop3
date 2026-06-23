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
import re
import math
import bisect
import capstone
import multiprocessing

from rop3.cache import GadgetCache
import rop3.utils as utils
import rop3.debug as debug
import rop3.binary
import rop3.operation as operation
from rop3.arch import arch_singleton
from rop3.archs.x86_arch import X86_Architecture, X64_Architecture
from rop3.ropchain import RopChain
import rop3.parser as parser

from .gadget import Gadget

''' Default depth engine '''
DEPTH = 5

''' Flags when searching gadgets '''
DEFAULT = 0
KEEP_DUPLICATES = 1
JOP = 2
ROP = 4
RETF = 8
ALLOW_UNDETERMINISTIC = 16
ALLOW_COMPLEX_MEM = 32
AVOID_CANARY = 64

''' Terminator canary bytes to avoid in gadget addresses by default:
    0x00 (string terminator for strcpy() and alike), 0x0a and 0x0d (line
    terminators for gets() and alike) and 0xff (EOF). See issue #5. '''
CANARY_BYTES = (0x00, 0x0a, 0x0d, 0xff)

class GadFinder:
    '''
    Class to search gadgets in a binary
    '''
    def __init__(self, depth=DEPTH, flags=DEFAULT, cache=False, cache_dir=None,
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
        packed = utils.pack_addr(gadget.vaddr, gadget.mode)
        return sum(byte in avoid for byte in packed)

    def _sort_gadgets(self, gadgets: list[Gadget]) -> list[Gadget]:
        return sorted(gadgets, key=lambda g: (os.path.basename(g.filename), g.vaddr))

    def _open_binary(self, filename, base, arch=None):
        binary = rop3.binary.Binary(filename, base, arch)
        binary_arch = binary.get_arch()
        if arch_singleton.is_initialized() and not arch_singleton.matches(binary_arch):
            debug.error(f'{filename}: mixing architectures (x86/x64) in a single run is not supported')
        arch_singleton.initialize(binary_arch)
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

    def find_op(self, filenames, op, dst=None, src=None, base=None,
                badchars=None, badchar_bytes=None, arch=None, symbols=False):
        gadgets = self.find(filenames, base, badchars, badchar_bytes, arch, symbols)
        return self.find_op_from_gadgets(gadgets, op, dst, src)

    def find_op_from_gadgets(self, gadgets, op, dst=None, src=None):
        from rop3.ropchain import RopChain, RopChainNotFound

        resolved = parser.Parser().get_op(op)

        if isinstance(resolved, parser.CompositeOperation):
            ropchain = RopChain(self).expand_steps(resolved.steps, dst, src)
            try:
                return list(RopChain(self).search(gadgets, ropchain, prune_equivalent=False))
            except RopChainNotFound:
                return []

        op_obj = operation.Operation(op, dst, src)
        return op_obj.filter_gadgets(gadgets)

    def _search_gadgets(self, binary, badchars, badchar_bytes=None, symbol_table=None):
        '''
        Yield the gadgets of a binary, building them either from the on-disk
        cache (when enabled and warm) or from a fresh scan. The cache only
        stores the raw (vaddr, bytes) records; everything address/disassembly
        derived (decodes, symbol) is rebuilt here.
        '''
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

        if self._jobs > 1:
            records = self._scan_parallel(binary, badchars, badchar_bytes)
            if self._cache is not None:
                self._cache.store(key, records)
            yield from self._reconstruct(binary, records, symbol_table)
            return

        records = [] if self._cache is not None else None
        arch = arch_singleton.arch.arch
        mode = arch_singleton.arch.mode
        for vaddr, raw, decodes in self._scan(binary, badchars, badchar_bytes):
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

    def _scan(self, binary, badchars, badchar_bytes):
        ''' Single pass over the executable sections; yields the raw
            (vaddr, bytes, decodes) of every valid gadget (one disassembly). '''
        sections = binary.get_exec_sections()
        arch = arch_singleton.arch.arch
        mode = arch_singleton.arch.mode

        gad_terminations = self._gad_terminations()

        md = capstone.Cs(arch, mode)
        md.detail = True

        for termination in gad_terminations:
            for section in sections:
                sec_opcodes = section['opcodes']
                sec_vaddr = section['vaddr']
                ''' Iterate all references to gadget termination '''
                for match in re.finditer(termination['bytes'], sec_opcodes):
                    ref = match.end()
                    ''' Search backwards from reference '''
                    for depth in range(termination['size'], self.depth + 1):
                        ''' Virtual address inside section '''
                        vaddr = sec_vaddr + ref - depth
                        if self._is_valid_address(vaddr, badchars, mode):
                            bytes_ = sec_opcodes[ref - depth:ref]
                            if not self._is_valid_bytes(bytes_, badchar_bytes):
                                continue
                            decodes = list(md.disasm(bytes_, vaddr))
                            if self._is_valid_gadget(decodes):
                                yield (vaddr, bytes_, decodes)

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

        if self._rop():
            ret.extend(arch.get_rop_terminations())
        if self._retf():
            ret.extend(arch.get_rop_terminations(include_extra=True))
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

    def _is_valid_gadget(self, decodes):
        ''' Invalid instructions and, thus, not decoded '''
        if not decodes:
            return False

        ret = False
        arch = arch_singleton.arch
        allow_undeterministic = bool(self._allow_undeterministic())
        if self._rop():
            ret |= arch.is_valid_rop_gadget(decodes, allow_undeterministic=allow_undeterministic)
        if self._retf():
            ret |= arch.is_valid_rop_gadget(decodes, include_extra=True, allow_undeterministic=allow_undeterministic)
        if not ret and self._jop():
            ret |= arch.is_valid_jop_gadget(decodes, allow_undeterministic=allow_undeterministic)

        if ret and not self._allow_complex_mem():
            if arch.first_insn_has_complex_mem(decodes):
                return False

        return ret

    def _is_valid_address(self, vaddr, badchars, arch_mode):
        if not badchars:
            return True

        vaddr = utils.pack_addr(vaddr, arch_mode)

        return not any([bytes([int(badchar, 0)]) in vaddr for badchar in badchars])

    def _is_valid_bytes(self, gadget_bytes, badchar_bytes):
        ''' Reject gadgets whose opcode bytes contain a forbidden byte (#21). '''
        if not badchar_bytes:
            return True

        forbidden = {int(b, 0) for b in badchar_bytes}
        return not any(byte in forbidden for byte in gadget_bytes)


def _arch_for(arch_const, mode):
    ''' Rebuild the architecture object inside a worker process. '''
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

    arch_singleton.reset()
    arch_singleton.initialize(_arch_for(arch_const, mode))
    finder = GadFinder(depth, flags)

    md = capstone.Cs(arch_const, mode)
    md.detail = True

    out = []
    for termination in terminations:
        for match in re.finditer(termination['bytes'], slice_bytes):
            ref_local = match.end()
            ref_off = slice_start + ref_local        # offset within the section
            ''' Only this chunk owns terminations in [emit_lo, emit_hi) '''
            if not (emit_lo <= ref_off < emit_hi):
                continue
            for d in range(termination['size'], depth + 1):
                start_local = ref_local - d
                if start_local < 0:
                    continue
                vaddr = sec_vaddr + ref_off - d
                if finder._is_valid_address(vaddr, badchars, mode):
                    raw = slice_bytes[start_local:ref_local]
                    if not finder._is_valid_bytes(raw, badchar_bytes):
                        continue
                    decodes = list(md.disasm(raw, vaddr))
                    if finder._is_valid_gadget(decodes):
                        out.append([vaddr, raw.hex()])
    return out

