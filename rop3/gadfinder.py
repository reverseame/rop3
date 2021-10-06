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
NO_JOP = 2
NO_RETF = 4

import re
import capstone

import rop3.utils as utils
import rop3.binary
import rop3.operation as operation

class GadFinder:
    '''
    Class to search gadgets in a binary
    '''
    def __init__(self, depth=DEPTH, flags=DEFAULT):
        self.depth = depth
        self.flags = flags

    def find(self, filename, base=None, badchars=None):
        binary = rop3.binary.Binary(filename, base)
        
        gadgets = self._search_gadgets(binary, badchars)
        gadgets = self._alphasort_gadgets(gadgets)
        if not self._keep_duplicates():
            gadgets = self._summarize_gadgets(gadgets)

        return gadgets

    def findall(self, files, base=None, badchars=None):
        gadgets = []

        for filename, base in zip(files, base):
            gadgets.extend(self.find(filename, base, badchars))
        
        return gadgets

    def find_op(self, filename, op, dst=None, src=None, base=None, badchars=None):
        gadgets = self.find(filename, base, badchars)

        op = operation.Operation(op, dst, src)
        
        return op.filter_gadgets(gadgets)

    def _search_gadgets(self, binary, badchars):
        ret = []

        sections = binary.get_exec_sections()
        arch = binary.get_arch()
        mode = binary.get_arch_mode()
        gad_terminations = self._gad_terminations(arch)

        md = capstone.Cs(arch, mode)

        for termination in gad_terminations:
            for section in sections:
                sec_opcodes = section['opcodes']
                sec_vaddr = section['vaddr']
                ''' Iterate all references to gadget termination '''
                for match in re.finditer(termination['bytes'], sec_opcodes):
                    ref = match.end()
                    ''' Search backwards from reference '''
                    for depth in range(len(termination['bytes']), self.depth + 1):
                        ''' Virtual address inside section '''
                        vaddr = sec_vaddr + ref - depth
                        if self._is_valid_address(vaddr, badchars, mode):
                            bytes_ = sec_opcodes[ref - depth:ref]
                            decodes = list(md.disasm_lite(bytes_, vaddr))
                            if self._is_valid_gadget(arch, decodes):
                                gadget = ' ; '.join([f'{mnemonic} {op_str}' if op_str else mnemonic for _, _, mnemonic, op_str in decodes])
                                ret.append({'filename': binary.filename, 'arch': arch, 'mode': mode, 'vaddr': vaddr, 'gadget': gadget, 'bytes': bytes_})

        return ret

    def _gad_terminations(self, arch):
        ret = []

        if arch == capstone.CS_ARCH_X86:
            ret.extend(self._add_rop_gadgets_x86())
            ret.extend(self._add_jop_gadgets_x86())

        return ret

    def _add_rop_gadgets_x86(self):
        ret = []

        ret.extend([
            {'bytes': b'\xc3'},                     # ret
            {'bytes': b'\xc2[\x00-\xff]{2}'}        # ret <imm>
        ])
        if not self._noretf():
            ret.extend([
                {'bytes': b'\xcb'},                 # retf
                {'bytes': b'\xca[\x00-\xff]{2}'}    # retf <imm>
            ])

        return ret

    def _add_jop_gadgets_x86(self):
        ret = []

        if not self._nojop():
            ret.extend([
                {'bytes': b'\xff[\x20\x21\x22\x23\x26\x27]{1}'},        # jmp  [reg]
                {'bytes': b'\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}'},    # jmp  [reg]
                {'bytes': b'\xff[\x10\x11\x12\x13\x16\x17]{1}'},        # jmp  [reg]
                {'bytes': b'\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}'}     # call [reg]
            ])

        return ret

    def _nojop(self):
        return self.flags & NO_JOP

    def _noretf(self):
        return self.flags & NO_RETF
    
    def _keep_duplicates(self):
        return self.flags & KEEP_DUPLICATES

    def _is_valid_gadget(self, arch, decodes):
        ''' Invalid instructions and, thus, not decoded '''
        if not decodes:
            return False

        if arch == capstone.CS_ARCH_X86:
            return self._is_valid_gadget_x86(decodes)

        return False

    def _is_valid_gadget_x86(self, decodes):
        '''
        Deletes x86 gadgets without a valid termination (e.g: '\xc3' in '\x89\xc3' is
        'mov ebx, eax' and not 'ret'), multibranched gadgets with multiple terminations
        in a single gadget and retf-terminated gadgets or jop gadgets if desired

        @param decodes: disassembler decodes

        @returns True if valid gadget, False otherwise
        '''
        terminations = ['ret', 'retf', 'jmp', 'call']

        ''' Decode is the (address, size, mnemonic, op_str) tuple '''
        end_mnemonic = decodes[-1][2]
        if end_mnemonic not in terminations:
            return False
        if self._noretf() and end_mnemonic == 'retf':
            return False
        if self._nojop() and (end_mnemonic in ['jmp', 'call']):
            return False
        ''' Multibranch gadgets '''
        if [ins for ins in decodes[:-1] if ins[2] in terminations]:
            return False

        return True

    def _is_valid_address(self, vaddr, badchars, arch_mode):
        if not badchars:
            return True

        vaddr = utils.pack_addr(vaddr, arch_mode)
        
        return not any([bytes([int(badchar, 0)]) in vaddr for badchar in badchars])

    def _summarize_gadgets(self, gadgets):
        '''
        @param gadgets: MUST to be alphabetically sorted

        @returns a new list without duplicates, and counts how many times
        each gadget appears in the list
        '''
        ret = []
        already_seen = set()
        count = 0

        for gadget in gadgets:
            if gadget['gadget'] in already_seen:
                count += 1
            else:
                count = 1
                already_seen.add(gadget['gadget'])
                ret.append(gadget)

            ret[-1]['count'] = count

        return ret

    def _alphasort_gadgets(self, gadgets):
        return sorted(gadgets, key=lambda gadget: gadget['gadget'])
