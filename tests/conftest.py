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

import struct

import capstone
import pytest

from rop3.arch import arch_singleton
from rop3.archs.x86_arch import X86_Architecture, X64_Architecture
from rop3.gadget import Gadget


@pytest.fixture(autouse=True)
def reset_arch():
    '''
    The architecture is a process-global singleton; reset it around every
    test so cases are independent and can pick their own architecture.
    '''
    arch_singleton._arch = None
    yield
    arch_singleton._arch = None


@pytest.fixture
def x64():
    arch_singleton._arch = None
    arch_singleton.initialize(X64_Architecture())
    return arch_singleton.arch


@pytest.fixture
def x86():
    arch_singleton._arch = None
    arch_singleton.initialize(X86_Architecture())
    return arch_singleton.arch


def make_gadget(code: bytes, vaddr: int, mode=capstone.CS_MODE_64,
                filename='test') -> Gadget:
    ''' Build a Gadget by disassembling raw bytes with capstone. '''
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = True
    decodes = list(md.disasm(code, vaddr))
    return Gadget(
        filename=filename,
        arch=capstone.CS_ARCH_X86,
        mode=mode,
        vaddr=vaddr,
        decodes=decodes,
        bytes=code,
    )


# --- Minimal in-memory ELF builder (no committed binary blobs) ------------

EM_386 = 3
EM_X86_64 = 62
ET_EXEC = 2
ET_DYN = 3
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


def build_minimal_elf(elfclass: int, machine: int, text_bytes: bytes,
                      text_addr: int, e_type: int = ET_DYN) -> bytes:
    '''
    Produce a tiny but valid ELF that pyelftools can parse: an ELF header, a
    `.text` PROGBITS section flagged executable at `text_addr`, and a
    `.shstrtab`. Enough to exercise architecture detection, executable-section
    extraction and --base relocation. ET_DYN keeps the image base at 0.
    '''
    is64 = elfclass == 64
    shstrtab = b'\x00.text\x00.shstrtab\x00'
    name_text = shstrtab.index(b'.text\x00')
    name_shstr = shstrtab.index(b'.shstrtab\x00')

    ehsize = 64 if is64 else 52
    shentsize = 64 if is64 else 40
    n_sections = 3  # NULL, .text, .shstrtab

    text_off = ehsize
    shstr_off = text_off + len(text_bytes)
    shoff = shstr_off + len(shstrtab)

    # e_ident
    ei_class = 2 if is64 else 1
    e_ident = b'\x7fELF' + bytes([ei_class, 1, 1, 0]) + b'\x00' * 8

    if is64:
        header = e_ident + struct.pack(
            '<HHIQQQIHHHHHH',
            e_type, machine, 1,            # type, machine, version
            text_addr,                     # entry
            0,                             # phoff
            shoff,                         # shoff
            0,                             # flags
            ehsize, 0, 0,                  # ehsize, phentsize, phnum
            shentsize, n_sections, 2,      # shentsize, shnum, shstrndx
        )
    else:
        header = e_ident + struct.pack(
            '<HHIIIIIHHHHHH',
            e_type, machine, 1,
            text_addr,
            0,
            shoff,
            0,
            ehsize, 0, 0,
            shentsize, n_sections, 2,
        )

    def section64(name, stype, flags, addr, offset, size):
        return struct.pack('<IIQQQQIIQQ', name, stype, flags, addr,
                           offset, size, 0, 0, 1, 0)

    def section32(name, stype, flags, addr, offset, size):
        return struct.pack('<IIIIIIIIII', name, stype, flags, addr,
                           offset, size, 0, 0, 1, 0)

    section = section64 if is64 else section32

    sections = b''.join([
        section(0, 0, 0, 0, 0, 0),                                       # NULL
        section(name_text, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
                text_addr, text_off, len(text_bytes)),                   # .text
        section(name_shstr, SHT_STRTAB, 0, 0, shstr_off, len(shstrtab)), # .shstrtab
    ])

    return header + text_bytes + shstrtab + sections
