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

import capstone
import io

from elftools.elf.elffile import ELFFile, ELFError

import rop3.binary as binary

SHF_EXECINSTR = 0x4


class ELF:
    ''' Parses Executable and Linkable Format (ELF) '''

    def __init__(self, data, base):
        try:
            file = io.BytesIO(data)
            self._elf = ELFFile(file)
            (self._arch, self._arch_mode) = self._parse_arch()
        except ELFError as exc:
            raise binary.BinaryException(str(exc)) from exc

    def _parse_arch(self):
        if self._elf.header.e_machine in ['EM_X86_64', 'EM_386']:
            if self._elf.elfclass == 32:
                return (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif self._elf.elfclass == 64:
                return (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        raise binary.BinaryException(
            'ELF: Unsupported architecture type')

    def get_exec_sections(self):
        ret = []

        for sec in self._elf.iter_sections():
            ''' SHF_EXECINSTR means section contains executable code '''
            if sec.header.sh_flags & SHF_EXECINSTR:
                ret.append({
                    'vaddr': sec.header.sh_addr,
                    'opcodes': sec.data()
                })
        return ret

    def get_arch(self):
        return self._arch

    def get_arch_mode(self):
        return self._arch_mode
