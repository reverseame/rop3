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

import rop3.gadfinder as gadfinder
from rop3.gadfinder import GadFinder
from rop3.ropchain import RopChain


class Rop3:
    '''
    High-level, reusable entry point to rop3.

    Example:
        from rop3 import Rop3
        r = Rop3("libc.so.6", base="0x7f0000000000")
        r.gadgets()                       # list[Gadget]
        r.find_op("mov", dst="rdi", src="rax")
        r.ropchain("chain.txt")

    The discovered gadgets are scanned once and cached on the instance, so
    repeated queries (and the interactive mode) do not re-scan the binary.
    '''

    def __init__(self, binaries, *, depth=gadfinder.DEPTH, rop=True, jop=False,
                 retf=False, all=False, allow_undeterministic=False,
                 allow_complex_mem=False, avoid_canary=True, base=None,
                 badchars=None, badchar_bytes=None, arch=None, symbols=False,
                 cache=False, cache_dir=None, jobs=1):
        self.binaries = [binaries] if isinstance(binaries, str) else list(binaries)
        self.base = base
        self.badchars = badchars
        self.badchar_bytes = badchar_bytes
        self.arch = arch
        self.symbols = symbols

        flags = 0
        if all:
            flags |= gadfinder.KEEP_DUPLICATES
        if jop:
            flags |= gadfinder.JOP
        if rop:
            flags |= gadfinder.ROP
        if retf:
            flags |= gadfinder.RETF
        if allow_undeterministic:
            flags |= gadfinder.ALLOW_UNDETERMINISTIC
        if allow_complex_mem:
            flags |= gadfinder.ALLOW_COMPLEX_MEM
        if avoid_canary:
            flags |= gadfinder.AVOID_CANARY

        self._finder = GadFinder(depth, flags, cache=cache, cache_dir=cache_dir,
                                 jobs=jobs)
        self._gadgets = None

    @classmethod
    def from_args(cls, args):
        ''' Build an instance from a parsed argparse namespace (reuses the
            already-computed flags), as the CLI does. '''
        self = cls.__new__(cls)
        self.binaries = args.binary
        self.base = args.base
        self.badchars = args.badchar
        self.badchar_bytes = args.badchar_bytes
        self.arch = args.arch
        self.symbols = args.symbols
        self._finder = GadFinder(args.depth, args.flags,
                                 cache=args.cache, cache_dir=args.cache_dir,
                                 jobs=args.jobs)
        self._gadgets = None
        return self

    @property
    def finder(self) -> GadFinder:
        return self._finder

    def gadgets(self, refresh=False):
        ''' All gadgets in the binaries (scanned once, then cached). '''
        if self._gadgets is None or refresh:
            self._gadgets = self._finder.find(
                self.binaries, base=self.base, badchars=self.badchars,
                badchar_bytes=self.badchar_bytes, arch=self.arch,
                symbols=self.symbols)
        return self._gadgets

    def find_op(self, op, dst=None, src=None):
        ''' Gadgets (or ROP chains, for composite ops) implementing `op`. '''
        return self._finder.find_op_from_gadgets(self.gadgets(), op, dst, src)

    def ropchain(self, ropfile):
        ''' Iterator over ROP chains satisfying the operations in `ropfile`. '''
        return RopChain(self._finder).search_from_gadgets(self.gadgets(), ropfile)
