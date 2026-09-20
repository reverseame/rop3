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
import math
import multiprocessing

# No single instruction is longer than this on any supported ISA, so decoding a
# window this wide is enough to recover the one instruction starting at an offset.
_MAX_INSN_BYTES = 16

def galileo_scan(opcodes, base_vaddr, terminations, depth, alignment, disasm,
                 is_valid_gadget, accept_match=None, accept_candidate=None,
                 restores_return_address=None):
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
    restores_return_address : callable(insn) -> bool, optional -- marks the
        stacked return-address restore in the inline frame mask. Default: none
        (x86 -- `ret` pops the PC off the stack, so only the terminator is framed).

    Yields
    ------
    (vaddr, raw, decodes, frame)
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
                # Decode the candidate once, building the frame mask in the same
                # pass: an instruction is framing if it restores the return
                # address off the stack; the terminator (set below) always is.
                decodes = []
                frame = []
                for insn in disasm(raw, vaddr):
                    decodes.append(insn)
                    frame.append(bool(restores_return_address)
                                 and restores_return_address(insn))
                if is_valid_gadget(decodes):
                    frame[-1] = True                # the terminator frames the run
                    yield vaddr, raw, decodes, tuple(frame)


# Bytes handed to a single `disasm()` call in `_linear_instruction_stream`.
# Capstone's `cs_disasm` decodes its *entire* input eagerly in C before the
# Python generator yields anything (it is not `cs_disasm_iter`-based), so
# passing it a whole multi-ten-MB section in one call materializes every
# decoded instruction of that section at once regardless of how the Python
# side consumes them. Chunking bounds that native allocation to this size.
_SCAN_CHUNK_SIZE = 1 << 20


def _linear_instruction_stream(opcodes, base_vaddr, alignment, disasm):
    '''
    Generator core of `linear_instructions`/`aligned_scan`: yields the
    intended instruction stream in program order, one instruction at a time,
    without ever materializing the whole section (see `_SCAN_CHUNK_SIZE`).
    For the resynchronization behavior around undecodable bytes, see
    `linear_instructions`.
    '''
    n = len(opcodes)
    step = max(1, alignment)
    off = 0
    while off < n:
        # Decode a bounded chunk plus a small overlap tail, so an instruction
        # straddling the chunk boundary still has its full bytes available.
        # Only instructions that start within the chunk's own (non-overlap)
        # core are accepted here; one starting in the overlap is left for the
        # next chunk (which starts exactly at core_end) to decode with full
        # lookahead -- so the split is invisible to the yielded stream.
        core_end = min(off + _SCAN_CHUNK_SIZE, n)
        chunk_end = min(core_end + _MAX_INSN_BYTES, n)
        core_size = core_end - off
        produced = 0
        for insn in disasm(opcodes[off:chunk_end], base_vaddr + off):
            if insn.address - (base_vaddr + off) >= core_size and core_end < n:
                break
            yield insn
            produced += insn.size
        # Resume right after the decoded run; if nothing decoded (bad byte at
        # `off`), skip one aligned unit to move past it.
        off += produced if produced else step
        if alignment > 1 and off % alignment:
            off += alignment - (off % alignment)


def linear_instructions(opcodes, base_vaddr, alignment, disasm):
    '''
    Linear sweep: disassemble `opcodes` as the intended instruction stream, in
    program order. Capstone stops at the first byte it cannot decode; when that
    happens the sweep resynchronizes by skipping one aligned unit past the
    offending byte and resumes. Returns the list of decoded instructions.
    '''
    return list(_linear_instruction_stream(opcodes, base_vaddr, alignment, disasm))


def aligned_scan(opcodes, base_vaddr, depth, alignment, disasm,
                 is_valid_gadget, restores_return_address=None, is_return=None,
                 accept_candidate=None):
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

    Framing (optional). A frame-establishing return (e.g. RISC-V `ret`, which
    jumps to whatever is in `ra`) only yields a useful gadget if the run first
    reloads the return target from the (attacker-controlled) stack. When
    `is_return` is given, a return terminator is emitted only once the backward
    walk has covered a return-address restore (`restores_return_address`); a
    single boolean carried across the walk records this, so the check is O(1)
    per candidate. Non-return terminators (indirect JOP branches) carry no such
    requirement. When `is_return` is omitted the scan degrades to the plain
    sweep, emitting every contiguous run.

    Parameters mirror `galileo_scan`, minus the byte-pattern `terminations`
    (termination points are found by disassembly here, not by a byte regex).

    restores_return_address : callable(insn) -> bool, optional -- the frame load
        that restores the return target from the stack (RISC-V `ld ra, off(sp)`,
        AArch64 `ldp .. x30, [sp]`). Gates return emission when `is_return` is
        set, and marks the inline frame mask built during the walk.
    is_return : callable(insn) -> bool, optional -- is the terminator a return
        (so the gadget must establish its frame). Omit for the plain sweep.

    Yields
    ------
    (vaddr, raw, decodes, frame)
    '''
    # A gadget never reaches back more than `depth` bytes from its terminator,
    # so only a small trailing window of the (possibly huge, e.g. a >40MB
    # .text section) instruction stream is ever reachable at once. Consuming
    # the stream lazily and trimming the window as it advances keeps peak
    # memory bounded by `depth`/`alignment`, not by section size -- avoiding
    # materializing every capstone-detail instruction in the whole section
    # (see `linear_instructions`, still eager, used directly by tests).
    window = []
    for terminator in _linear_instruction_stream(opcodes, base_vaddr, alignment, disasm):
        window.append(terminator)
        term_end = terminator.address + terminator.size
        # Trim from the front once out of `depth` reach of the current tail;
        # a later (further along) terminator's reach only moves forward, so
        # anything trimmed here is unreachable for it too.
        while window and term_end - window[0].address > depth:
            del window[0]

        # A termination is any instruction that is a valid gadget on its own.
        if not is_valid_gadget([terminator]):
            continue
        requires_frame = bool(is_return) and is_return(terminator)

        # Walk backward over the contiguous run of intended instructions,
        # growing the frame mask at its front to stay parallel to the candidate.
        frame_loaded = False
        frame = []
        n = len(window)
        idx = n - 1
        while idx >= 0:
            insn_j = window[idx]
            # Stop at a discontinuity (a resync gap): a gadget's bytes must be
            # a single contiguous run.
            if idx < n - 1 and insn_j.address + insn_j.size != window[idx + 1].address:
                break
            if term_end - insn_j.address > depth:
                break

            # Prepending insn_j: it is framing if it restores the return
            # address; once covered, the whole (and every longer) run establishes
            # its return frame.
            is_restore = bool(restores_return_address) and restores_return_address(insn_j)
            if is_restore:
                frame_loaded = True
            frame.insert(0, is_restore)

            if frame_loaded or not requires_frame:
                vaddr = insn_j.address
                raw = opcodes[vaddr - base_vaddr:term_end - base_vaddr]
                if accept_candidate is None or accept_candidate(vaddr, raw):
                    candidate = window[idx:n]
                    if is_valid_gadget(candidate):
                        mask = frame.copy()
                        mask[-1] = True             # the terminator frames the run
                        yield vaddr, raw, candidate, tuple(mask)
            idx -= 1


def literal_scan(opcodes, base_vaddr, alignment, disasm, pattern_len,
                 accept_candidate=None):
    '''
    Forward, anchor-free scan for a fixed-length instruction window: tries
    decoding `pattern_len` instructions starting at *every* `alignment`-stepped
    byte offset -- not just the offsets the binary's own intended (sequential)
    disassembly would produce, so a pattern hiding "unintended" inside another
    instruction's encoding is still found (as `galileo_scan` already does for
    gadget terminators). On a fixed-width ISA (`alignment` > 1) this reduces
    to scanning only real instruction boundaries anyway.

    Unlike every other strategy in this module there is no terminator/frame
    concept driving the walk -- every candidate window is tried independently,
    and the caller (GadFinder.find_literal_gadgets, for a chain's `noret(...)`
    step) applies the actual pattern-equality test; this stays pattern-agnostic
    like the rest of this module.

    Parameters mirror `backward_instructions`, plus `pattern_len` (the number
    of instructions a candidate window must contain) and `accept_candidate`
    (bad-char filtering, as in the other scans).

    Yields
    ------
    (vaddr, raw, decodes) for every offset where exactly `pattern_len`
    instructions decode cleanly (a single `disasm()` call over one contiguous
    slice can only ever decode a contiguous run -- it stops at the first
    undecodable byte rather than skipping it, so there is no separate
    discontinuity case to guard here, unlike the resync behaviour of the
    chunked `_linear_instruction_stream`).
    '''
    n = len(opcodes)
    step = max(1, alignment)
    window_bytes = pattern_len * _MAX_INSN_BYTES
    off = 0
    while off < n:
        vaddr = base_vaddr + off
        decodes = list(disasm(opcodes[off:off + window_bytes], vaddr))[:pattern_len]
        if len(decodes) == pattern_len:
            end = decodes[-1].address + decodes[-1].size
            raw = opcodes[off:end - base_vaddr]
            if accept_candidate is None or accept_candidate(vaddr, raw):
                yield vaddr, raw, decodes
        off += step


# --------------------------------------------------------------------------
# Backward framed (ropblock) search
# --------------------------------------------------------------------------


def backward_instructions(opcodes, base_vaddr, alignment, disasm, start=None):
    '''
    Arch-aware backward instruction iterator.

    Starting just below `start` (the end of the buffer by default) and stepping
    toward the front by the instruction `alignment` -- 1 on x86 (every byte, so
    unintended instructions hidden inside longer ones surface), 2 on compressed
    RISC-V, 4 on AArch64 / base RISC-V -- decode the single instruction that
    begins at each aligned offset and yield ``(offset, insn)``. Offsets where
    nothing decodes are skipped.

    Parameters
    ----------
    opcodes : bytes            -- executable bytes to scan.
    base_vaddr : int           -- virtual address of ``opcodes[0]``.
    alignment : int            -- instruction alignment in bytes.
    disasm : callable(raw, vaddr) -> iterable  -- e.g. capstone ``Cs.disasm``.
    start : int, optional      -- byte offset to begin below (default: len).

    Yields
    ------
    (offset, insn)
    '''
    hi = len(opcodes) if start is None else min(start, len(opcodes))
    off = hi - 1
    if off >= 0 and alignment > 1:
        off -= (base_vaddr + off) % alignment           # align the first offset
    while off >= 0:
        insn = next(iter(disasm(opcodes[off:off + _MAX_INSN_BYTES],
                                base_vaddr + off)), None)
        if insn is not None:
            yield off, insn
        off -= alignment


def backwards_framed_search(opcodes, base_vaddr, depth, alignment, disasm,
                            is_terminator, branch_reg, is_prologue, clobbers,
                            is_frame=None, splits=None, accept_candidate=None):
    '''
    Backward framed ("ropblock") gadget search.

    A ropblock gadget is framed as ``[prologue] ... [terminator]``: the
    terminator writes the program counter from a register (an indirect
    ``jmp``/``br`` through a register), and the prologue loads *that* register
    from the stack (``pop reg`` / ``ldr reg, [sp]``). x86 ``ret`` is the
    degenerate case -- it pops the program counter straight off the stack, so a
    single instruction is both prologue and epilogue (``branch_reg`` returns
    ``None`` and the frame is satisfied with no separate prologue).

    Using `backward_instructions` to find each terminator, the search walks back
    over the contiguous runs that end at that terminator (growing one length at a
    time up to `depth` bytes) and emits a run once it is *framed*: it contains,
    before the terminator, a prologue that loads the terminator's branch register
    with no intervening clobber of that register. Longer runs that still contain
    the frame keep being emitted.

    Each emitted run carries a per-instruction ``frame`` mask (a tuple[bool]
    parallel to ``decodes``): True where the instruction is a framing
    prologue/epilogue rather than the operation body. It marks the data-flow
    prologue (the stack load of the branch register) and the terminator, plus any
    position-independent framing instruction `is_frame` recognizes (a prologue
    prefix, ...). Operation matching skips these.

    Predicates (arch-derived, passed as callables):
      is_terminator(insn)     -> bool   -- a ropblock terminator (pc <- reg / ret)
      branch_reg(insn)        -> reg | None -- register the terminator branches
          through, or None when the terminator is its own prologue (x86 ret)
      is_prologue(insn, reg)  -> bool   -- does `insn` load `reg` from the stack
      clobbers(insn, reg)     -> bool   -- does `insn` overwrite `reg`
      is_frame(insn)          -> bool, optional -- a position-independent framing
          instruction (prologue prefix / terminator). A stack
          pivot (`add rsp, 8`, `leave`) is *not* framing -- it is a real stack
          operation (control flow returns through the stack or a branch register,
          never through the pivot), so `is_frame` must exclude it. Default: none.
      splits(insn)            -> bool, optional -- an instruction that may not
          appear *inside* a gadget (an intermediate branch/return); a candidate
          whose body contains one is rejected. Default: no such check.

    Yields
    ------
    (vaddr, raw, decodes, frame)
    '''
    for t_off, term in backward_instructions(opcodes, base_vaddr, alignment, disasm):
        if not is_terminator(term):
            continue
        term_end = t_off + term.size
        # Grow the candidate backward from the terminator, one length at a time.
        for length in range(term.size, depth + 1):
            q = term_end - length
            if q < 0:
                break
            if alignment > 1 and (base_vaddr + q) % alignment != 0:
                continue
            raw = opcodes[q:term_end]
            if accept_candidate is not None and not accept_candidate(base_vaddr + q, raw):
                continue
            decodes = list(disasm(raw, base_vaddr + q))
            # The run must decode cleanly and still end on the terminator.
            if not decodes:
                continue
            last = decodes[-1]
            if last.address + last.size != base_vaddr + term_end:
                continue
            if not is_terminator(last):
                continue
            # No control-flow transfer before the terminator: a branch/return
            # anywhere ahead of it ends the gadget early, including at position 0
            # (a leading `ret` makes the rest dead -- "no prologue after
            # prologue"). The trailing terminator itself is exempt; a bare `ret`
            # (nothing before it) stays valid. Matches is_valid_*_gadget.
            if splits is not None and any(splits(insn) for insn in decodes[:-1]):
                continue
            prologue = _ropblock_prologue_index(decodes, branch_reg(last),
                                                is_prologue, clobbers)
            if prologue is None:
                continue                        # not framed
            frame = _frame_mask(decodes, prologue, is_frame)
            yield base_vaddr + q, raw, decodes, frame


def _ropblock_prologue_index(decodes, reg, is_prologue, clobbers):
    '''
    Index of the prologue that frames the run (whose last instruction is the
    terminator), or None when it is not framed. The terminator's branch register
    `reg` must be loaded from the stack by a prologue that no later instruction
    clobbers: scanning backward, the nearest write of `reg` must be that stack
    load. `reg` is None for a self-framing terminator (x86 ret), whose prologue
    is the terminator itself.
    '''
    if reg is None:
        return len(decodes) - 1                 # x86 ret: its own prologue
    for i in range(len(decodes) - 2, -1, -1):
        if is_prologue(decodes[i], reg):
            return i
        if clobbers(decodes[i], reg):
            return None
    return None


def _frame_mask(decodes, prologue, is_frame):
    ''' Per-instruction framing mask: the prologue, the terminator (last), and
        any position-independent framing instruction `is_frame` recognizes.
        Stack pivots are *not* framing (see `is_frame` above), so an `add rsp, 8`
        anywhere in the run stays unmasked and matches as a real `add`. '''
    last = len(decodes) - 1
    return tuple(
        i == prologue or i == last or (is_frame(insn) if is_frame else False)
        for i, insn in enumerate(decodes))


# --------------------------------------------------------------------------
# Parallel scanning: chunk the executable sections across worker processes
# --------------------------------------------------------------------------
#
# Only the Galileo backward walk supports this (it chunks by termination byte
# offset via `accept_match`); the linear sweeps and the abstract-gadget search
# run single-threaded. The scanning lives here, isolated from the finder's
# policy: the finder hands over a picklable spec (arch consts, flags, byte
# slices) and gets back raw ``[vaddr, hex]`` records to rebuild into gadgets.


def _arch_for(arch_const, mode):
    ''' Rebuild the architecture object inside a worker process from picklable
        capstone constants. Imported lazily so this module stays free of any
        top-level rop3.archs dependency (arch.py / archs import *this* module). '''
    import capstone
    from rop3.archs.x86_arch import X86_Architecture, X64_Architecture
    from rop3.archs.riscv_arch import RISCV_Architecture
    if arch_const == capstone.CS_ARCH_RISCV:
        return RISCV_Architecture(compressed=bool(mode & capstone.CS_MODE_RISCVC))
    return X64_Architecture() if mode == capstone.CS_MODE_64 else X86_Architecture()


def _scan_chunk(task):
    '''
    Worker (runs in its own process): scan one section chunk and return the raw
    ``[vaddr, hex]`` records for the gadgets whose termination lies in the
    chunk's window. Decodes are not returned (capstone objects are not
    picklable); the parent rebuilds them.

    The flag-driven validity/bad-char predicates live on GadFinder, so a
    throwaway one is rebuilt here rather than duplicating that logic -- imported
    lazily so this module has no top-level dependency on the finder.
    '''
    import capstone
    from rop3.arch import arch_singleton
    from rop3.gadfinder import GadFinder

    (arch_const, mode, depth, flags, terminations, badchars, badchar_bytes,
     slice_bytes, slice_start, sec_vaddr, emit_lo, emit_hi) = task

    arch_obj = _arch_for(arch_const, mode)
    arch_singleton.reset()
    arch_singleton.initialize(arch_obj)
    finder = GadFinder(depth, flags)

    md = capstone.Cs(arch_const, mode)
    md.detail = True

    def accept_match(ref):
        ''' Only this chunk owns terminations ending in [emit_lo, emit_hi). '''
        return emit_lo <= slice_start + ref < emit_hi

    def accept_candidate(vaddr, raw):
        return (finder._is_valid_address(vaddr, badchars, arch_obj.address_size)
                and finder._is_valid_bytes(raw, badchar_bytes))

    # The slice starts `slice_start` bytes into the section.
    base_vaddr = sec_vaddr + slice_start
    out = []
    # Carry the scan's inline frame mask through so the parent rebuilds gadgets
    # without re-deriving it (records are [vaddr, hex, frame]).
    for vaddr, raw, _decodes, frame in arch_obj.scan(
            slice_bytes, base_vaddr, depth, md.disasm, finder._is_valid_gadget,
            terminations=terminations, accept_candidate=accept_candidate,
            accept_match=accept_match, framed=finder.framed):
        out.append([vaddr, raw.hex(),
                    [bool(f) for f in frame] if frame is not None else None])
    return out


def scan_parallel(sections, arch_const, mode, depth, flags, terminations,
                  badchars, badchar_bytes, jobs):
    '''
    Scan the executable `sections` across `jobs` worker processes and return
    sorted ``[vaddr, hex]`` records. `sections` is a list of picklable
    ``(opcodes: bytes, sec_vaddr: int)`` pairs.

    Each section is split into chunks; a chunk emits only the gadgets whose
    termination falls inside its window (the slice extends `depth` bytes earlier
    so gadgets straddling a boundary are still complete), so there are no
    cross-chunk duplicates.
    '''
    tasks = []
    for opcodes, sec_vaddr in sections:
        n = len(opcodes)
        chunk = max(4096, math.ceil(n / (jobs * 4)))
        for lo in range(0, n, chunk):
            hi = min(lo + chunk, n)
            start = max(0, lo - depth)
            ''' Termination END offsets run in [0, n]; the final chunk owns the
                closing n as well, so make its window inclusive. '''
            emit_hi = hi + 1 if hi == n else hi
            tasks.append((
                arch_const, mode, depth, int(flags), terminations,
                badchars, badchar_bytes,
                opcodes[start:hi], start, sec_vaddr, lo, emit_hi,
            ))

    records = []
    with multiprocessing.Pool(jobs) as pool:
        for part in pool.imap_unordered(_scan_chunk, tasks):
            records.extend(part)
    records.sort()   # deterministic order regardless of worker scheduling
    return records
