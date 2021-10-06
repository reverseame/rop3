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
import rop3.binaries.pe as pe

class Binary:
    '''
    Interface to access binary file details
    '''
    def __init__(self, filename, base):
        self.filename = os.path.realpath(filename)
        self.raw_data = self._read_binary()
        self._binary = self._load_binary(base)

    def _read_binary(self):
        try:
            with open(self.filename, 'rb') as f:
                return f.read()
        except (IOError, FileNotFoundError):
            debug.error(f'{self.filename}: Unable to read file')

    def _load_binary(self, base):
        ''' MS-DOS Stub '''
        if self.raw_data[:2] == b'\x4d\x5a':    # MZ
            return pe.PE(self.raw_data, base)
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

    def get_arch_mode(self):
        '''
        @returns computer architecture mode, e.g: 64-bits
        '''
        return self._binary.get_arch_mode()

class BinaryException(Exception):
    pass
