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

import rop3.operation as operation
import rop3.parser as parser
from rop3.arch import arch_singleton
from rop3.archs.x86_arch import X86_Architecture, X64_Architecture
from rop3.gadget import Gadget


class _OpMatcher:
    ''' Test shim standing in for the former Operation class: it resolves a
        ROPLang name to its OperationDef and matches gadgets via
        operation.match_gadgets, so tests keep the compact
        `make_operation(name, operands).filter_gadgets(gadgets)` form while the
        production API is plain functions. '''
    def __init__(self, name, operands):
        self.defn = parser.Parser().get_op(name)
        if not self.defn.available:
            reason = self.defn.unavailable_reason or 'not available for this architecture'
            raise parser.OperationNotAvailable(f'{self.defn.name}: {reason}')
        self.operands = operands

    def filter_gadgets(self, gadgets, reject_clobbered=True):
        return operation.match_gadgets(self.defn, self.operands, gadgets,
                                       reject_clobbered=reject_clobbered)


def make_operation(name, operands=None):
    ''' Resolve a named ROPLang op (as gadfinder does) and return a matcher whose
        .filter_gadgets(gadgets) delegates to operation.match_gadgets. '''
    return _OpMatcher(name, operands)


@pytest.fixture(autouse=True)
def reset_arch():
    '''
    The architecture is a process-global singleton; reset it around every
    test so cases are independent and can pick their own architecture.
    '''
    arch_singleton.reset()
    yield
    arch_singleton.reset()


@pytest.fixture
def x64():
    arch_singleton.reset()
    arch_singleton.initialize(X64_Architecture())
    return arch_singleton.arch


@pytest.fixture
def x86():
    arch_singleton.reset()
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
EM_RISCV = 243
EF_RISCV_RVC = 0x1
ET_EXEC = 2
ET_DYN = 3
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
STB_GLOBAL = 1
STT_FUNC = 2


def build_minimal_elf(elfclass: int, machine: int, text_bytes: bytes,
                      text_addr: int, e_type: int = ET_DYN, symbols=None,
                      e_flags: int = 0) -> bytes:
    '''
    Produce a tiny but valid ELF that pyelftools can parse: an ELF header, a
    `.text` PROGBITS section flagged executable at `text_addr`, and a
    `.shstrtab`. With `symbols` (a list of (name, value)), it also emits a
    `.symtab`/`.strtab` pair. Enough to exercise architecture detection,
    executable-section extraction, --base relocation and symbol parsing.
    ET_DYN keeps the image base at 0.
    '''
    is64 = elfclass == 64
    symbols = symbols or []

    def section(name, stype, flags, addr, offset, size, link=0, entsize=0):
        if is64:
            return struct.pack('<IIQQQQIIQQ', name, stype, flags, addr,
                               offset, size, link, 0, 1, entsize)
        return struct.pack('<IIIIIIIIII', name, stype, flags, addr,
                           offset, size, link, 0, 1, entsize)

    def sym(name_off, value):
        info = (STB_GLOBAL << 4) | STT_FUNC
        if is64:
            return struct.pack('<IBBHQQ', name_off, info, 0, 1, value, 0)
        return struct.pack('<IIIBBH', name_off, value, 0, info, 0, 1)

    sym_size = struct.calcsize('<IBBHQQ' if is64 else '<IIIBBH')

    # Section-header string table (.shstrtab)
    names = b'\x00'
    def add_name(s):
        nonlocal names
        off = len(names)
        names += s.encode() + b'\x00'
        return off
    name_text = add_name('.text')
    name_shstr = add_name('.shstrtab')
    name_symtab = add_name('.symtab') if symbols else 0
    name_strtab = add_name('.strtab') if symbols else 0

    # Symbol string table (.strtab) and symbol entries
    strtab = b'\x00'
    sym_entries = sym(0, 0)   # mandatory null symbol at index 0
    for sname, value in symbols:
        off = len(strtab)
        strtab += sname.encode() + b'\x00'
        sym_entries += sym(off, value)

    ehsize = 64 if is64 else 52
    shentsize = 64 if is64 else 40

    # Lay out section data blocks after the header
    text_off = ehsize
    shstr_off = text_off + len(text_bytes)
    cursor = shstr_off + len(names)
    if symbols:
        symtab_off = cursor
        strtab_off = symtab_off + len(sym_entries)
        cursor = strtab_off + len(strtab)
    shoff = cursor

    n_sections = 5 if symbols else 3   # NULL, .text, .shstrtab[, .symtab, .strtab]

    ei_class = 2 if is64 else 1
    e_ident = b'\x7fELF' + bytes([ei_class, 1, 1, 0]) + b'\x00' * 8
    hdr_fmt = '<HHIQQQIHHHHHH' if is64 else '<HHIIIIIHHHHHH'
    header = e_ident + struct.pack(
        hdr_fmt,
        e_type, machine, 1,            # type, machine, version
        text_addr,                     # entry
        0,                             # phoff
        shoff,                         # shoff
        e_flags,                       # flags
        ehsize, 0, 0,                  # ehsize, phentsize, phnum
        shentsize, n_sections, 2,      # shentsize, shnum, shstrndx (.shstrtab)
    )

    section_headers = [
        section(0, 0, 0, 0, 0, 0),                                       # NULL
        section(name_text, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
                text_addr, text_off, len(text_bytes)),                   # .text
        section(name_shstr, SHT_STRTAB, 0, 0, shstr_off, len(names)),    # .shstrtab
    ]
    payload = text_bytes + names
    if symbols:
        section_headers.append(                                          # .symtab
            section(name_symtab, SHT_SYMTAB, 0, 0, symtab_off,
                    len(sym_entries), link=4, entsize=sym_size))
        section_headers.append(                                          # .strtab
            section(name_strtab, SHT_STRTAB, 0, 0, strtab_off, len(strtab)))
        payload += sym_entries + strtab

    return header + payload + b''.join(section_headers)


# --- Minimal in-memory Mach-O (thin + fat) builder ------------------------

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
MH_EXECUTE = 2
VM_PROT_READ = 0x1
VM_PROT_EXECUTE = 0x4
S_ATTR_SOME_INSTRUCTIONS = 0x400
N_SECT = 0xe
N_EXT = 0x1
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C


def build_minimal_macho(cputype: int, text_bytes: bytes,
                        text_addr: int = 0x100000000, cpusubtype: int = 0,
                        symbols=None) -> bytes:
    '''
    Produce a tiny thin (non-fat) 64-bit Mach-O that macholib parses: a
    mach_header_64 and one LC_SEGMENT_64 (__TEXT) carrying a single executable
    __text section. With `symbols` (a list of (name, value)), it also emits an
    LC_SYMTAB so symbol parsing can be exercised. Enough to exercise
    architecture detection and executable/symbol extraction without a
    committed binary.
    '''
    symbols = symbols or []
    seg_fmt = '<II16sQQQQiiII'      # segment_command_64 (72 bytes)
    sec_fmt = '<16s16sQQIIIIIIII'   # section_64 (80 bytes)
    symtab_fmt = '<IIIIII'          # symtab_command (24 bytes)
    nlist_fmt = '<IBBHQ'            # nlist_64 (16 bytes)

    seg_cmdsize = struct.calcsize(seg_fmt) + struct.calcsize(sec_fmt)
    has_syms = bool(symbols)
    ncmds = 2 if has_syms else 1
    sizeofcmds = seg_cmdsize + (struct.calcsize(symtab_fmt) if has_syms else 0)
    text_off = 32 + sizeofcmds      # after header + load commands

    # Symbol table (nlist_64 array) and its string table, laid out after __text.
    strtab = b'\x00'
    sym_entries = b''
    for name, value in symbols:
        n_strx = len(strtab)
        strtab += name.encode() + b'\x00'
        sym_entries += struct.pack(nlist_fmt, n_strx, N_SECT | N_EXT, 1, 0, value)
    symoff = text_off + len(text_bytes)
    stroff = symoff + len(sym_entries)

    header = struct.pack('<IiiIIIII', MH_MAGIC_64, cputype, cpusubtype,
                         MH_EXECUTE, ncmds, sizeofcmds, 0, 0)
    prot = VM_PROT_READ | VM_PROT_EXECUTE
    segment = struct.pack(seg_fmt, LC_SEGMENT_64, seg_cmdsize, b'__TEXT',
                          text_addr, len(text_bytes), text_off, len(text_bytes),
                          prot, prot, 1, 0)
    section = struct.pack(sec_fmt, b'__text', b'__TEXT', text_addr,
                          len(text_bytes), text_off, 2, 0, 0,
                          S_ATTR_SOME_INSTRUCTIONS, 0, 0, 0)
    blob = header + segment + section
    if has_syms:
        blob += struct.pack(symtab_fmt, LC_SYMTAB, struct.calcsize(symtab_fmt),
                            symoff, len(symbols), stroff, len(strtab))
    blob += text_bytes
    if has_syms:
        blob += sym_entries + strtab
    return blob


def build_minimal_fat_macho(slices, align: int = 0x4000) -> bytes:
    '''
    Wrap several thin Mach-O slices into a fat (universal) binary that
    macholib parses, so fat-only behaviour (default-slice pick, --arch
    selection, absent-arch errors) can be tested without a committed macOS
    binary. `slices` is a list of dicts forwarded to build_minimal_macho
    (e.g. {'cputype': CPU_TYPE_X86_64, 'text_bytes': b'\\xc3'}); their order is
    the file order the default-slice logic sees. The fat header is big-endian.
    '''
    fat_arch_fmt = '>iiIII'          # cputype, cpusubtype, offset, size, align
    header_size = 8 + struct.calcsize(fat_arch_fmt) * len(slices)
    align_log2 = align.bit_length() - 1

    def roundup(x):
        return (x + align - 1) & ~(align - 1)

    arches, payload = [], b''
    cursor = roundup(header_size)
    for spec in slices:
        thin = build_minimal_macho(**spec)
        offset = cursor
        payload += b'\x00' * (offset - (header_size + len(payload)))   # pad to offset
        payload += thin
        arches.append((spec['cputype'], spec.get('cpusubtype', 0),
                       offset, len(thin), align_log2))
        cursor = roundup(offset + len(thin))

    out = struct.pack('>II', FAT_MAGIC, len(slices))
    for cputype, cpusubtype, offset, size, al in arches:
        out += struct.pack(fat_arch_fmt, cputype, cpusubtype, offset, size, al)
    return out + payload


# --- Minimal in-memory PE (PE32+) builder ---------------------------------

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_SCN_CNT_CODE = 0x20
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000


def build_minimal_pe(machine: int, text_bytes: bytes, text_rva: int = 0x1000,
                     image_base: int = 0x140000000) -> bytes:
    '''
    Produce a tiny PE32+ (one executable .text section) that pefile parses: a
    DOS stub, the PE signature, a COFF header with `machine`, a PE32+ optional
    header with 16 (empty) data directories, and one section header. Enough for
    architecture detection and executable-section extraction.
    '''
    file_align = 0x200
    sect_align = 0x1000
    n_dirs = 16

    opt_head = struct.pack('<HBBIIIII', 0x20b, 1, 0, len(text_bytes), 0, 0,
                           text_rva, text_rva)               # magic..BaseOfCode
    opt_head += struct.pack('<Q', image_base)                # ImageBase
    opt_head += struct.pack('<II', sect_align, file_align)   # Section/FileAlignment
    opt_head += struct.pack('<HHHHHH', 6, 0, 0, 0, 6, 0)     # OS/Image/Subsystem ver
    opt_head += struct.pack('<I', 0)                         # Win32VersionValue
    size_of_image = sect_align + \
        ((len(text_bytes) + sect_align - 1) // sect_align) * sect_align
    opt_tail = struct.pack('<IIHH', 0, 0, 3, 0)              # CheckSum, Subsystem, DllChar
    opt_tail += struct.pack('<QQQQ', 0x100000, 0x1000, 0x100000, 0x1000)
    opt_tail += struct.pack('<II', 0, n_dirs)               # LoaderFlags, NumberOfRvaAndSizes
    opt_tail += b'\x00' * (8 * n_dirs)                       # data directories

    def optional_header(size_of_headers):
        return opt_head + struct.pack('<II', size_of_image, size_of_headers) + opt_tail

    opt_size = len(optional_header(0))
    coff = struct.pack('<HHIIIHH', machine, 1, 0, 0, 0, opt_size, 0x22)
    dos = b'MZ' + b'\x00' * 0x3a + struct.pack('<I', 0x40)   # e_lfanew = 0x40
    pe_sig = b'PE\x00\x00'

    section_hdr_off = 0x40 + len(pe_sig) + len(coff) + opt_size
    size_of_headers = ((section_hdr_off + 40 + file_align - 1)
                       // file_align) * file_align
    raw_ptr = size_of_headers

    section = struct.pack('<8sIIIIIIHHI', b'.text', len(text_bytes), text_rva,
                          len(text_bytes), raw_ptr, 0, 0, 0, 0,
                          IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)

    blob = dos + pe_sig + coff + optional_header(size_of_headers) + section
    blob += b'\x00' * (raw_ptr - len(blob))
    return blob + text_bytes
