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

from macholib.MachO import MachO as _MachO
from macholib.mach_o import (
    LC_SEGMENT, LC_SEGMENT_64,
    CPU_TYPE_NAMES
)

import rop3.binary as binary

from rop3.archs.x86_arch import X86_Architecture, X64_Architecture

VM_PROT_EXECUTE = 0x04

class MachO:
    def __init__(self, data, base):
        # Dirty way to initialize the class, since it only supports reading
        # from a filename
        try:
            self._file = io.BytesIO(data)
            self._macho = _MachO.__new__(_MachO)
            self._macho.filename = 'dummy'
            self._macho.fat = None
            self._macho.headers = []
            self._macho.allow_unknown_load_commands = False
            self._macho.load(self._file)
        except Exception as exc:
            raise binary.BinaryException(str(exc)) from exc
        # Some binaries include many headers
        self._header = None
        for header in self._macho.headers:
            arch = CPU_TYPE_NAMES.get(header.header.cputype)
            self._header = header
            if arch == "x86_64":
                self._arch = X64_Architecture()
                break
            elif arch == "i386":
                self._arch = X86_Architecture()
                break
        if not self._header:
            raise binary.BinaryException(
                    'Mach-O: No supported architectures were found')

    def get_exec_sections(self):
        ret = []
        for (lc, cmd, data) in self._header.commands:
            if lc.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                if cmd.initprot & VM_PROT_EXECUTE:
                    for section in data:
                        sec_name = section.sectname.decode('utf-8').strip('\x00')
                        if sec_name == '__text':
                            offset = self._header.offset
                            self._file.seek(offset + section.offset)
                            section_data = self._file.read(section.size)
                            ret.append({
                                'vaddr': section.addr,
                                'opcodes': section_data
                            })
        return ret

    def get_arch(self):
        return self._arch

