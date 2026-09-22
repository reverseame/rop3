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

import rop3.binary as binary

from rop3.archs.x86_arch import X86_Architecture, X64_Architecture
from rop3.archs.riscv_arch import RISCV_Architecture
from rop3.archs.aarch64_arch import AArch64_Architecture

# Architecture name (as given to --arch) -> factory returning an Architecture.
# A raw dump carries no header, so the architecture cannot be detected and must
# come from --arch. Common aliases are accepted; RISC-V compression (which
# relaxes instruction alignment from 4 to 2 bytes) is undetectable in a
# formatless blob, so it is selected explicitly via the 'riscv64c' name.
SUPPORTED_ARCHS = {
    'x86': X86_Architecture, 'i386': X86_Architecture, 'x86_32': X86_Architecture,
    'x86_64': X64_Architecture, 'x64': X64_Architecture, 'amd64': X64_Architecture,
    'aarch64': AArch64_Architecture, 'arm64': AArch64_Architecture,
    'riscv64': lambda: RISCV_Architecture(compressed=False),
    'riscv64c': lambda: RISCV_Architecture(compressed=True),
}


class Raw:
    ''' Formatless raw code dump: the whole file is one executable section.
        Architecture comes from --arch (required), the load address from --base
        (an absolute vaddr, default 0). '''

    def __init__(self, data, base, arch=None):
        if arch is None:
            raise binary.BinaryException(
                'Raw: --arch is required for raw binaries '
                f'(choose from {", ".join(sorted(SUPPORTED_ARCHS))})')
        key = arch.lower()
        if key not in SUPPORTED_ARCHS:
            raise binary.BinaryException(
                f'Raw: unsupported --arch {arch} '
                f'(choose from {", ".join(sorted(SUPPORTED_ARCHS))})')
        self._arch = SUPPORTED_ARCHS[key]()
        self._data = data
        # Absolute load vaddr: there is no link-time image base to subtract for
        # a formatless blob, so --base is the section start directly.
        self._base = int(base, 0) if base else 0

    def get_exec_sections(self):
        return [{'name': 'raw', 'vaddr': self._base, 'opcodes': self._data}]

    def get_arch(self):
        return self._arch

    def get_info(self):
        ''' Format-level metadata for verbose reporting. '''
        return {'format': 'Raw', 'image_base': self._base}
