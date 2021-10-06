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

import pefile
import capstone

import rop3.binary as binary

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_SCN_MEM_EXECUTE = 0x20000000

class PE:
    ''' Parses Windows Portable Executable (PE) '''
    def __init__(self, data, base):
        try:
            self._pe = pefile.PE(data=data, fast_load=True)
            (self._arch, self._arch_mode) = self._parse_arch()
            if base:
                base = int(base, 0)
                self._pe.relocate_image(base)
        except pefile.PEFormatError as exc:
            raise binary.BinaryException(str(exc)) from exc

    def _parse_arch(self):
        if self._pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
            return (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif self._pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64:
            return (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            raise binary.BinaryException('PE: Unsupported architecture type in COFF header')

    def get_exec_sections(self):
        ret = []

        for sec in self._pe.sections:
            ''' Flag means section contains executable code '''
            if sec.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                ret.append({
                    'vaddr': self._pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress,
                    'opcodes': sec.get_data()
                })
        return ret

    def get_arch(self):
        return self._arch

    def get_arch_mode(self):
        return self._arch_mode
