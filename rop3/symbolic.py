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

from rop3.arch import arch_singleton
import rop3.debug as debug

from .gadget import Gadget

try:
    from triton import (
            TritonContext, ARCH, Instruction, MemoryAccess,
        )
    TRITON_AVAILABLE = True
except ImportError:
    TRITON_AVAILABLE = False


# A fixed, page-aligned base for the emulated stack. The real runtime stack
# address is unknown; we pin one here so the analyzer can name each cell each
# push/pop/ret touches (its offset from this base) and lay the return addresses
# out at the right slots before re-executing the chain.
_STACK_BASE = {
    4: 0x7ff00000,
    8: 0x00007ffffff00000,
}


class SymbolicMemoryAccess:
    ''' One annotated memory touch observed while emulating the chain. '''
    def __init__(self, gadget_vaddr, insn_addr, kind, address, size, value, base):
        self.gadget_vaddr = gadget_vaddr    # gadget the access belongs to
        self.insn_addr = insn_addr          # instruction that performed it
        self.kind = kind                    # 'read' | 'write'
        self.address = address              # concrete accessed address
        self.size = size                    # access width in bytes
        self.value = value                  # concrete value (loaded/stored)
        # Offset from the emulated stack base. Non-negative offsets are the
        # forward stack the chain walks (pops/rets); a store below the base or an
        # access far from it is off-stack (an ordinary memory write/read).
        self.stack_offset = address - base if base is not None else None

    @property
    def on_stack(self) -> bool:
        return self.stack_offset is not None and self.stack_offset >= 0

    def to_dict(self) -> dict:
        return {
            'gadget': hex(self.gadget_vaddr),
            'insn': hex(self.insn_addr),
            'kind': self.kind,
            'address': hex(self.address),
            'size': self.size,
            'value': hex(self.value),
            'stack_offset': (hex(self.stack_offset)
                             if self.on_stack else None),
        }

    def __str__(self) -> str:
        where = (f'[sp+{hex(self.stack_offset)}]' if self.on_stack
                 else hex(self.address))
        return (f'{self.kind:<5} {where} ({self.size}B) = {hex(self.value)} '
                f'@ {hex(self.insn_addr)}')


class SymbolicResult:
    '''
    Outcome of concolically emulating a candidate ROP chain.

      base            concrete addressing anchor for the emulated stack pointer
      stack_layout    ordered return-address slots the chain requires, each a
                      dict {offset, address, target, gadget_index} -- discovered
                      in the first pass and filled with the next gadget's address
                      for the second pass
      memory_accesses list[SymbolicMemoryAccess] observed in the second pass
      pivots          transitions whose gadget redirects the stack pointer other
                      than by the implicit push/pop/ret adjustment (`leave`,
                      `mov rsp, *`, `add/sub rsp, *`, `pop rsp`, ...); a
                      structural property, independent of reachability. Each a
                      dict {gadget_index, address, target}
      reached         whether, once the return slots are filled, control threads
                      through every gadget to the last
      supported       False when the arch/Triton is unavailable (analysis
                      skipped rather than performed)
      error           a message when analysis could not complete
    '''
    def __init__(self, base=None, stack_layout=None, memory_accesses=None,
                 pivots=None, reached=False, supported=True, error=None):
        self.base = base
        self.stack_layout = stack_layout or []
        self.memory_accesses = memory_accesses or []
        self.pivots = pivots or []
        self.reached = reached
        self.supported = supported
        self.error = error

    @property
    def memory_writes(self) -> list:
        ''' Just the store accesses -- the chain's memory side effects. '''
        return [m for m in self.memory_accesses if m.kind == 'write']

    def to_dict(self) -> dict:
        return {
            'supported': self.supported,
            'error': self.error,
            'base': None if self.base is None else hex(self.base),
            'reached': self.reached,
            'stack_layout': [
                {
                    'offset': hex(s['offset']),
                    'address': hex(s['address']),
                    'target': hex(s['target']),
                    'gadget_index': s['gadget_index'],
                }
                for s in self.stack_layout
            ],
            'pivots': [
                {
                    'gadget_index': p['gadget_index'],
                    'address': hex(p['address']),
                    'target': hex(p['target']),
                }
                for p in self.pivots
            ],
            'memory_accesses': [m.to_dict() for m in self.memory_accesses],
        }

    def report_lines(self) -> list[str]:
        ''' Human-readable multi-line summary (for --verbose reporting). '''
        if not self.supported:
            return [f'symbolic analysis skipped: {self.error}']
        lines = [f'concolic emulation (stack base {hex(self.base)}):']
        if self.stack_layout:
            lines.append('  required stack layout:')
            for s in self.stack_layout:
                where = (f'[sp+{hex(s["offset"])}]' if s['offset'] >= 0
                         else hex(s['address']))
                lines.append(f'    {where} -> {hex(s["target"])} '
                             f'(gadget #{s["gadget_index"]})')
        if self.pivots:
            lines.append('  stack pivots (control does not reach the next gadget):')
            for p in self.pivots:
                lines.append(f'    gadget #{p["gadget_index"]} @ '
                             f'{hex(p["address"])} -> {hex(p["target"])}')
        if self.memory_writes:
            lines.append('  memory writes:')
            for m in self.memory_writes:
                lines.append(f'    {m}')
        lines.append('  final gadget reached: '
                     f'{"yes" if self.reached else "NO"}')
        return lines


class SymbolicAnalyzer:
    '''
    Concolically validates a resolved ROP chain (a list of Gadgets) with Triton.

    The chain is emulated over concrete state -- the stack pointer is pinned to a
    concrete base and every other register and memory location starts at zero.
    Validation runs the chain twice:

      1. **Layout pass.** Emulate the gadgets in order and, at each gadget's
         return, record the stack slot the return address is popped from -- for
         x86 the address the `ret` pops, for AArch64 the slot the link register
         was loaded from. This yields the exact stack layout the chain needs.

      2. **Verification pass.** Fill each discovered slot with the address of the
         next gadget, then emulate the whole chain again and watch where control
         lands. The chain is `reached` when, after this fill, every gadget's
         terminator transfers control to the next gadget.

    A gadget is flagged as a **pivot** when it redirects the stack pointer other
    than by the implicit adjustment of a natural stack operation -- a `leave`, or
    an explicit write of the stack pointer (`mov rsp, *`, `add/sub rsp, *`,
    `pop rsp`, ...); see `arch.is_stack_pivot`. This is a structural property of the
    gadget, reported independently of whether the laid-out chain still reaches
    the next gadget.

    Every memory read/write of the verification pass is annotated with its
    concrete address and value; the store accesses (`memory_writes`) are the
    chain's memory side effects.
    '''

    # capstone (arch, mode) -> (triton ARCH, sp reg, pc reg, link reg or None)
    def _arch_profile(self, gadget: Gadget):
        if not TRITON_AVAILABLE:
            return None
        cs_arch, cs_mode = gadget.arch, gadget.mode
        if cs_arch == capstone.CS_ARCH_X86:
            if cs_mode == capstone.CS_MODE_64:
                return (ARCH.X86_64, 'rsp', 'rip', None)
            if cs_mode == capstone.CS_MODE_32:
                return (ARCH.X86, 'esp', 'eip', None)
        if cs_arch == capstone.CS_ARCH_ARM64:
            return (ARCH.AARCH64, 'sp', 'pc', 'x30')
        return None

    def analyze_ropchain(self, ropchain: list[Gadget]) -> SymbolicResult:
        if not TRITON_AVAILABLE:
            return SymbolicResult(supported=False,
                                  error='the Triton library is not installed')
        if not ropchain:
            return SymbolicResult(supported=False, error='empty chain')

        profile = self._arch_profile(ropchain[0])
        if profile is None:
            arch_name = arch_singleton.arch.name if arch_singleton.is_initialized() \
                else 'unknown'
            return SymbolicResult(
                supported=False,
                error=f'symbolic execution is not supported for {arch_name}')

        triton_arch, sp_name, pc_name, lr_name = profile
        ptr = arch_singleton.arch.address_size
        base = _STACK_BASE[ptr]

        try:
            layout, accesses, pivots, reached = self._run(
                ropchain, triton_arch, sp_name, pc_name, lr_name, base, ptr)
        except Exception as exc:                        # pragma: no cover
            return SymbolicResult(base=base, supported=True,
                                  error=f'symbolic execution failed: {exc}')

        return SymbolicResult(base=base, stack_layout=layout,
                              memory_accesses=accesses, pivots=pivots,
                              reached=reached)

    def _run(self, ropchain, triton_arch, sp_name, pc_name, lr_name, base, ptr):
        # Pass 1: discover where each gadget pops its return address from.
        pass1, _ = self._emulate(triton_arch, sp_name, pc_name, lr_name,
                                 ropchain, base, ptr, fills=None)

        # Lay the chain out: each discovered slot gets the next gadget's address.
        fills = {}
        for i in range(len(ropchain) - 1):
            slot = pass1[i]['slot']
            if slot is not None:
                fills[slot] = ropchain[i + 1].vaddr

        # Pass 2: re-execute with the stack filled and see where control lands.
        pass2, accesses = self._emulate(triton_arch, sp_name, pc_name, lr_name,
                                        ropchain, base, ptr, fills=fills)

        layout = []
        pivots = []
        reached = True   # a single-gadget chain trivially reaches its only gadget
        for i in range(len(ropchain) - 1):
            target = ropchain[i + 1].vaddr
            rec = pass2[i]
            reached_i = rec['pc'] == target
            reached = reached and reached_i
            if rec['slot'] is not None:
                layout.append({
                    'offset': rec['slot'] - base,
                    'address': rec['slot'],
                    'target': target,
                    'gadget_index': i + 1,
                })
            # A pivot: the gadget redirects the stack pointer other than by the
            # implicit push/pop/ret adjustment (leave, mov rsp, add rsp, ...) --
            # a structural property of the gadget, independent of whether the
            # laid-out chain still reaches the next gadget.
            if rec['sp_pivot']:
                pivots.append({'gadget_index': i, 'address': ropchain[i].vaddr,
                               'target': target})

        return layout, accesses, pivots, reached

    def _emulate(self, triton_arch, sp_name, pc_name, lr_name, ropchain, base,
                 ptr, fills):
        '''
        Emulate the whole chain once over concrete state and return, per gadget,
        a record ``{slot, pc, sp_pivot}``:

          slot      the stack address the gadget's return popped its target from
                    (AArch64: the link-register load slot); None when the gadget
                    does not end in a stack-driven return
          pc        the concrete program counter after the gadget executes
          sp_pivot  whether the gadget redirects the stack pointer other than by
                    the implicit push/pop/ret adjustment (arch.is_stack_pivot)

        `fills` (address -> value) pre-populates stack slots before execution;
        pass None to leave the stack zeroed.
        '''
        arch = arch_singleton.arch
        ctx = TritonContext(triton_arch)
        sp_reg = getattr(ctx.registers, sp_name)
        pc_reg = getattr(ctx.registers, pc_name)

        ctx.setConcreteRegisterValue(sp_reg, base)
        for gad in ropchain:
            ctx.setConcreteMemoryAreaValue(gad.vaddr, bytes(gad.bytes))
        if fills:
            for addr, value in fills.items():
                ctx.setConcreteMemoryValue(MemoryAccess(addr, ptr), value)

        records = []
        accesses = []
        lr_slot = None   # AArch64: stack slot the link register was last loaded from

        for gad in ropchain:
            slot = None
            sp_pivot = False
            for insn in gad.decodes:
                if arch.is_stack_pivot(insn):
                    sp_pivot = True

                tinst = Instruction(insn.address, bytes(insn.bytes))
                ctx.processing(tinst)
                self._collect_accesses(ctx, tinst, gad.vaddr, base, accesses)

                if lr_name is not None and arch.is_frame_load(insn):
                    lr_slot = self._lr_load_address(arch, insn, tinst, lr_name, ptr)

                if arch.is_return(insn):
                    if lr_name is not None:
                        slot = lr_slot                  # AArch64: ret branches to lr
                    else:
                        loads = [m.getAddress() for m, _ in tinst.getLoadAccess()]
                        slot = min(loads) if loads else None    # x86: ret pops [rsp]
                    lr_slot = None
                    break   # terminator ends the gadget

            records.append({
                'slot': slot,
                'pc': ctx.getConcreteRegisterValue(pc_reg),
                'sp_pivot': sp_pivot,
            })

        return records, accesses

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _lr_load_address(arch, insn, tinst, lr_name, ptr):
        ''' Stack address a frame load pulled the link register (x30) from.
            Triton reports a paired `ldp x29, x30, [sp]` as one wide access at the
            base, so derive x30's slot from its position among the load's
            destination registers: x30 is the k-th register operand (0 for `ldr
            x30, [sp,...]`, 1 for the second of an `ldp`), sitting at
            base + k*ptr. '''
        addrs = [mem.getAddress() for mem, _ in tinst.getLoadAccess()]
        if not addrs:
            return None
        load_base = min(addrs)
        # capstone prints the AArch64 link register as `lr`; accept both spellings.
        lr_aliases = {lr_name, 'lr'}
        regops = [op for op in insn.operands if op.type == arch.op_reg]
        for k, op in enumerate(regops):
            if insn.reg_name(op.reg) in lr_aliases:
                return load_base + k * ptr
        return load_base

    @staticmethod
    def _collect_accesses(ctx, tinst, gadget_vaddr, base, out):
        ''' Annotate every memory read/write the instruction performed with its
            concrete address and value (all emulated state is concrete). '''
        def make(mem, kind):
            return SymbolicMemoryAccess(
                gadget_vaddr, tinst.getAddress(), kind,
                mem.getAddress(), mem.getSize(),
                ctx.getConcreteMemoryValue(mem), base)
        for mem, _ in tinst.getLoadAccess():
            out.append(make(mem, 'read'))
        for mem, _ in tinst.getStoreAccess():
            out.append(make(mem, 'write'))
