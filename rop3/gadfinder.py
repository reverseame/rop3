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

import re
import capstone

import rop3.utils as utils
import rop3.debug as debug
import rop3.binary
import rop3.operation as operation
from rop3.arch import arch_singleton
from rop3.ropchain import RopChain
import rop3.parser as parser

from .gadget import Gadget

class GadFinder:
    '''
    Class to search gadgets in a binary
    '''
    def __init__(self, depth=DEPTH, flags=DEFAULT):
        self.depth = depth
        self.flags = flags

    def find(self, filenames: list[str], base=None, badchars=None) -> list[Gadget]:
        ''' base is normalised to one entry per binary by the argument parser '''
        bases = base if isinstance(base, list) else [base] * len(filenames)

        if not self._keep_duplicates():
            seen: dict = {}
            for filename, file_base in zip(filenames, bases):
                binary = self._open_binary(filename, file_base)
                before = len(seen)
                total = 0
                for gadget in self._search_gadgets(binary, badchars):
                    total += 1
                    if gadget in seen:
                        seen[gadget].count += 1
                    else:
                        gadget.count = 1
                        seen[gadget] = gadget
                unique = len(seen) - before
                debug.info(f'{unique} unique gadgets ({total - unique} duplicates discarded)')
            return list(seen.values())
        else:
            gadgets = []
            for filename, file_base in zip(filenames, bases):
                binary = self._open_binary(filename, file_base)
                gadgets.extend(self._search_gadgets(binary, badchars))
            return gadgets

    def _open_binary(self, filename, base):
        binary = rop3.binary.Binary(filename, base)
        arch = binary.get_arch()
        if arch_singleton.is_initialized() and not arch_singleton.matches(arch):
            debug.error(f'{filename}: mixing architectures (x86/x64) in a single run is not supported')
        arch_singleton.initialize(arch)
        return binary

    def find_op(self, filenames, op, dst=None, src=None, base=None, badchars=None):
        gadgets = self.find(filenames, base, badchars)
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

    def _search_gadgets(self, binary, badchars):
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
                            decodes = list(md.disasm(bytes_, vaddr))
                            if self._is_valid_gadget(decodes):
                                yield Gadget(
                                    filename=binary.filename,
                                    arch=arch,
                                    mode=mode,
                                    vaddr=vaddr,
                                    decodes=decodes,
                                    bytes=bytes_
                                )

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

