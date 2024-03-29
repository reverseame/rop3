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
    def __init__(self, file_name, base=''):
        self._file_name = os.path.realpath(file_name)
        self._raw_binary = self._read_data()
        self._binary = self._load_binary(base)

    def _read_data(self):
        try:
            with open(self._file_name, 'rb') as f:
                return f.read()
        except (IOError, FileNotFoundError):
            debug.error('\'{0}\': Unable to read file'.format(self._file_name))

    def _load_binary(self, base=''):
        ''' MS-DOS Stub '''
        if self._raw_binary[:2] == b'\x4d\x5a': #MZ
            return pe.PE(self._raw_binary, base)
        else:
            raise BinaryException('\'{0}\': Format file not supported'.format(self._file_name))

    def get_raw_binary(self):
        """
        @returns binary bytes
        """
        return self._raw_binary

    def get_file_name(self):
        """
        @returns binary full path
        """
        return self._file_name

    def get_entry_point(self):
        """
        @returns adress of entry point
        """
        return self._binary.get_entry_point()

    def get_exec_sections(self):
        """
        @returns a list with all executable sections
        """
        return self._binary.get_exec_sections()

    def get_arch(self):
        """
        @returns computer architecture
        """
        return self._binary.get_arch()

    def get_arch_mode(self):
        """
        @returns computer architecture mode
        """
        return self._binary.get_arch_mode()

    def get_regs(self):
        return self._binary.get_regs()

    def __str__(self):
        return str(self._binary)

class BinaryException(Exception):
    pass
