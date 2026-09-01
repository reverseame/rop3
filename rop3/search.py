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

import re

def galileo_scan(opcodes, base_vaddr, terminations, depth, alignment, disasm,
                 is_valid_gadget, accept_match=None, accept_candidate=None):
    '''
    The Galileo algorithm.

    Introduced by Hovav Shacham in "The Geometry of Innocent Flesh on the Bone:
    Return-into-libc without Function Calls (on the x86)" (ACM CCS 2007, S 3.2,
    where he names it *Galileo*), this is the backward walk that underpins
    essentially every ROP gadget finder. Instead of disassembling forward from
    an entry point, it anchors on the bytes that *end* a gadget -- a `ret`, or
    any free-branch termination -- and disassembles backward from each such
    byte, trying every possible starting offset. On a variable-length, unaligned
    ISA a single `ret` is the tail of many distinct gadgets depending on where
    decoding begins, so the walk enumerates them all up to a bounded length.

    `alignment` collapses the "try every offset" step to the instruction
    alignment (1 on x86; 2 or 4 on RISC-V), and `terminations` carries the
    arch-specific byte patterns that end a gadget.

    Parameters
    ----------
    opcodes : bytes           -- executable bytes to scan.
    base_vaddr : int          -- virtual address of ``opcodes[0]``.
    terminations : iterable of {'bytes': <byte regex>, 'size': <int>}
                              -- gadget-terminating byte patterns and lengths.
    depth : int               -- maximum gadget length in bytes.
    alignment : int           -- instruction alignment in bytes.
    disasm : callable(raw, vaddr) -> iterable  -- e.g. capstone ``Cs.disasm``.
    is_valid_gadget : callable(decodes) -> bool -- gadget validity.
    accept_match : callable(ref) -> bool, optional -- filter on the
        termination's end offset (used to partition parallel chunks).
    accept_candidate : callable(vaddr, raw) -> bool, optional -- drop bad-char
        addresses/bytes before disassembly.

    Yields
    ------
    (vaddr, raw, decodes)
    '''
    for termination in terminations:
        term_size = termination['size']
        # Every reference to a gadget termination (a `ret`, a free branch, ...).
        for match in re.finditer(termination['bytes'], opcodes):
            ref = match.end()
            if accept_match is not None and not accept_match(ref):
                continue
            # The terminating instruction must itself be aligned.
            if alignment > 1 and (base_vaddr + match.start()) % alignment != 0:
                continue
            # Walk backward from the termination, growing the candidate one
            # length at a time up to `depth` bytes.
            for length in range(term_size, depth + 1):
                start = ref - length
                # Do not walk past the start of the buffer
                if start < 0:
                    continue
                vaddr = base_vaddr + start
                # Gadgets may only start on an aligned boundary.
                if alignment > 1 and vaddr % alignment != 0:
                    continue
                raw = opcodes[start:ref]
                if accept_candidate is not None and not accept_candidate(vaddr, raw):
                    continue
                decodes = list(disasm(raw, vaddr))
                if is_valid_gadget(decodes):
                    yield vaddr, raw, decodes


def _linear_disasm(opcodes, base_vaddr, alignment, disasm):
    '''
    Linear sweep: disassemble `opcodes` as the intended instruction stream, in
    program order. Capstone stops at the first byte it cannot decode; when that
    happens the sweep resynchronizes by skipping one aligned unit past the
    offending byte and resumes. Returns the list of decoded instructions.
    '''
    insns = []
    n = len(opcodes)
    step = max(1, alignment)
    off = 0
    while off < n:
        produced = 0
        for insn in disasm(opcodes[off:], base_vaddr + off):
            insns.append(insn)
            produced += insn.size
        # Resume right after the decoded run; if nothing decoded (bad byte at
        # `off`), skip one aligned unit to move past it.
        off += produced if produced else step
        if alignment > 1 and off % alignment:
            off += alignment - (off % alignment)
    return insns


def aligned_scan(opcodes, base_vaddr, depth, alignment, disasm,
                 is_valid_gadget, accept_candidate=None):
    '''
    Aligned (intended-instruction) gadget search.

    Where Galileo disassembles backward from *every* offset to surface
    unintended gadgets hiding inside longer instructions, this scan only yields
    gadgets made of the program's own intended instructions. It disassembles
    each section once as a linear instruction stream, then, for every
    instruction that is itself a valid termination, walks backward over the
    preceding *whole* instructions -- never splitting one -- emitting each
    contiguous run up to `depth` bytes.

    On a fixed-width, aligned ISA (AArch64) this finds the same gadgets as
    Galileo but far faster (one disassembly pass, not one per candidate); on a
    variable-length ISA it returns strictly the aligned/intended subset.

    Parameters mirror `galileo_scan`, minus the byte-pattern `terminations`
    (termination points are found by disassembly here, not by a byte regex).

    Yields
    ------
    (vaddr, raw, decodes)
    '''
    insns = _linear_disasm(opcodes, base_vaddr, alignment, disasm)

    for i, terminator in enumerate(insns):
        # A termination is any instruction that is a valid gadget on its own.
        if not is_valid_gadget([terminator]):
            continue
        term_end = terminator.address + terminator.size

        # Walk backward over the contiguous run of intended instructions.
        j = i
        while j >= 0:
            # Stop at a discontinuity (a resync gap): a gadget's bytes must be
            # a single contiguous run.
            if j < i and insns[j].address + insns[j].size != insns[j + 1].address:
                break
            if term_end - insns[j].address > depth:
                break

            vaddr = insns[j].address
            raw = opcodes[vaddr - base_vaddr:term_end - base_vaddr]
            if accept_candidate is None or accept_candidate(vaddr, raw):
                candidate = insns[j:i + 1]
                if is_valid_gadget(candidate):
                    yield vaddr, raw, candidate
            j -= 1


# --------------------------------------------------------------------------
# Framed aligned: aligned sweep restricted to gadgets that set up a return frame
# --------------------------------------------------------------------------

def framed_aligned_scan(opcodes, base_vaddr, depth, alignment, disasm,
                        is_valid_gadget, is_frame_load, is_return,
                        accept_candidate=None):
    '''
    Framed aligned gadget search.

    A frame-establishing return (e.g. RISC-V `ret`, which jumps to whatever is
    in `ra`) only yields a useful gadget if the run first reloads the return
    target from the (attacker-controlled) stack. This specialization of the
    aligned sweep keeps exactly those: it anchors on each return terminator,
    walks backward over the intended instructions up to `depth`, and emits a
    gadget only once the run contains a frame load. A single boolean carried
    across the backward walk records whether such a load has been seen -- once
    true it stays true for every longer gadget, so the check is O(1) per
    candidate rather than a re-scan.

    Non-return terminators (indirect JOP branches, when enabled) carry no such
    requirement and are emitted as usual.

    Parameters mirror `aligned_scan`, plus:

    is_frame_load : callable(insn) -> bool  -- is `insn` the frame load that
        restores the return target from the stack (RISC-V `ld ra, off(sp)`).
    is_return     : callable(insn) -> bool  -- is `insn` a return (so the gadget
        must establish its frame); false for indirect JOP terminators.

    Yields
    ------
    (vaddr, raw, decodes)
    '''
    insns = _linear_disasm(opcodes, base_vaddr, alignment, disasm)

    for i, terminator in enumerate(insns):
        if not is_valid_gadget([terminator]):
            continue
        requires_frame = is_return(terminator)
        term_end = terminator.address + terminator.size

        frame_loaded = False
        j = i
        while j >= 0:
            if j < i and insns[j].address + insns[j].size != insns[j + 1].address:
                break
            if term_end - insns[j].address > depth:
                break

            # Prepending insns[j]; once we cover the frame load the whole
            # (and every longer) run establishes its return frame.
            if is_frame_load(insns[j]):
                frame_loaded = True

            if frame_loaded or not requires_frame:
                vaddr = insns[j].address
                raw = opcodes[vaddr - base_vaddr:term_end - base_vaddr]
                if accept_candidate is None or accept_candidate(vaddr, raw):
                    candidate = insns[j:i + 1]
                    if is_valid_gadget(candidate):
                        yield vaddr, raw, candidate
            j -= 1
