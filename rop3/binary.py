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

import rop3.debug as debug
import rop3.binaries.elf as elf
import rop3.binaries.pe as pe
import rop3.binaries.macho as macho

class Binary:
    '''
    Interface to access binary file details
    '''
    def __init__(self, filename, base, arch=None):
        self.filename = os.path.realpath(filename)
        self.raw_data = self._read_binary()
        self._binary = self._load_binary(base, arch)

    def _read_binary(self):
        try:
            with open(self.filename, 'rb') as f:
                return f.read()
        except (IOError, FileNotFoundError):
            debug.error(f'{self.filename}: Unable to read file')

    def _load_binary(self, base, arch=None):
        # MS-DOS Stub (PE)
        if self.raw_data[:2] == b'\x4d\x5a':    # MZ
            return pe.PE(self.raw_data, base)

        # ELF Magic
        elif self.raw_data[:2] == b'\x7f\x45':
            return elf.ELF(self.raw_data, base)

        # Mach-O Magic
        elif self.raw_data[:4] in [
            b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', # 32-bit
            b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe', # 64-bit
            b'\xca\xfe\xba\xbe', # Fat header
        ]:
            return macho.MachO(self.raw_data, base, arch)

        else:
            raise BinaryException(f'{self.filename}: Format file not supported')


    def get_exec_sections(self):
        '''
        @returns a list with all executable sections
        '''
        return self._binary.get_exec_sections()

    def get_arch(self):
        '''
        @returns computer architecture, e.g: x86
        '''
        return self._binary.get_arch()

    def get_symbols(self):
        '''
        @returns a list of (address, name) tuples for the binary's symbols,
        or an empty list when the format/loader has none (e.g. stripped)
        '''
        getter = getattr(self._binary, 'get_symbols', None)
        return getter() if getter else []

class BinaryException(Exception):
    pass
