import pefile
import capstone

from .. import binary

IMAGE_FILE_MACHINE_I386 = 0x14c
IMAGE_FILE_MACHINE_AMD64 = 0x8664

class PE:
    ''' Parses Windows Portable Executable (PE) (.exe, .dll, .sys) '''
    def __init__(self, data, base=''):
        try:
            self._pe = pefile.PE(data=data, fast_load=True)
            if base:
                self._pe.relocate_image(base)
            self._arch, self._arch_mode = self._parse_arch()
        except pefile.PEFormatError as exc:
            raise binary.BinaryException(str(exc)) from exc

    def _parse_arch(self):
        if self._pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
            return capstone.CS_ARCH_X86, capstone.CS_MODE_32
        elif self._pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64:
            return capstone.CS_ARCH_X86, capstone.CS_MODE_64
        else:
            raise binary.BinaryException('Unssuported machine CPU type in COFF File Header')

    def get_entry_point(self):
        return self._pe.OPTIONAL_HEADER.ImageBase + self._pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def get_exec_sections(self):
        ret = []

        for sec in self._pe.sections:
            ''' Flag means this section is executable '''
            if sec.Characteristics & 0x20000000 > 0:
                ret +=  [{
                            'vaddr'   : self._pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress,
                            'opcodes' : sec.get_data()
                        }]
        return ret

    def get_arch(self):
        return self._arch

    def get_arch_mode(self):
        return self._arch_mode

    def get_regs(self):
        ret = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
        ret += ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
        ret += ['ah', 'ch', 'dh', 'bh']
        ret += ['al', 'cl', 'dl', 'bl']

        if self.is_x64():
            ret = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'] + ret

        return ret

    def is_x86(self):
        return self._arch_mode == capstone.CS_MODE_32

    def is_x64(self):
        return self._arch_mode == capstone.CS_MODE_64

    def __str__(self):
        ret = 'PE'

        if self._pe.is_dll():
            ret += ' (DLL)'
        elif self._pe.is_exe():
            ret += ' (EXE)'
        elif self._pe.is_driver():
            ret += ' (SYS)'

        if self.is_x86():
            ret += ' x86'
        elif self.is_x64():
            ret += ' x86-64'

        return ret
