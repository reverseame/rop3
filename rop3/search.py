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


# --------------------------------------------------------------------------
# Emitter + policy: one gadget-search driver for every ISA/mode
# --------------------------------------------------------------------------
#
# Every gadget search in this module is a product of two independent choices:
#
#   * the EMITTER -- how candidate instruction-runs ending at a terminator are
#     enumerated. A variable-length/unaligned ISA (x86, or RISC-V where the C
#     extension admits non-canonical gadgets) must try every
#     aligned start offset and re-decode, since instructions hide inside longer
#     ones (`_emit_unaligned`). A fixed-width, naturally-aligned ISA (AArch64)
#     has a single canonical instruction
#     stream, so one linear disassembly pass with a sliding window reuses the
#     decoded objects (`_emit_aligned`).
#
#   * the POLICY -- what makes a run a gadget and how it is framed. Ordinary ROP
#     (`_RopPolicy`): the last instruction is a valid terminator and, when the
#     terminator is a return on a link-register ISA, the run first restores the
#     return address off the stack; the frame mask marks those restores and the
#     terminator. Abstract-gadget / ropblock (`_RopblockPolicy`): the terminator
#     writes the PC from a register (or x86 `ret`) and a stack-load prologue
#     feeds that register with no intervening clobber; the frame mask marks the
#     prologue, the terminator, and any position-independent framing instruction.
#
# The emitter yields `(vaddr, raw, decodes)` candidate runs; the policy turns
# each into an accepted gadget with its frame mask, or rejects it. Both emitters
# and both policies combine freely, so the four historical scan functions
# (galileo / aligned / backwards-framed / framed-linear) are now thin wrappers
# that pick one emitter and one policy -- the backward-growth loop, the
# contiguity guard, the bad-char gate and the terminator framing live in exactly
# one place each.


class _RopPolicy:
    ''' Ordinary ROP/JOP gadget policy (the Galileo / aligned sweeps).

        `is_valid_gadget(decodes)` is the finder's flag-aware validity test (it
        already checks the terminator and intermediate branches). `is_return`,
        when not None, marks a terminator that needs a return-address frame: the
        run is emitted only once some instruction restores it from the stack
        (`restores_return_address`). x86 passes `is_return=None` -- `ret` pops the
        PC straight off the stack, so it self-frames; link-register ISAs
        (AArch64/RISC-V) pass it when framed, and None when `--no-frame` drops the
        requirement. `restores_return_address` still builds the frame mask either
        way. `return_prologue(decodes)`, when supplied, locates the stack load
        feeding the actual return register and rejects subsequent clobbers. '''

    __slots__ = ('_valid', '_rra', '_is_return', '_return_prologue')

    def __init__(self, is_valid_gadget, restores_return_address=None, is_return=None,
                 return_prologue=None):
        self._valid = is_valid_gadget
        self._rra = restores_return_address
        self._is_return = is_return
        if return_prologue is None:
            # Preserve the old low-level call signature when callers pass an
            # architecture's bound return predicate directly to a scanner.
            owner = getattr(is_return, '__self__', None)
            return_prologue = getattr(owner, 'return_prologue_index', None)
        self._return_prologue = return_prologue

    def is_terminator(self, insn) -> bool:
        ''' Whether a single instruction can end a gadget (used by the aligned
            emitter to pick terminator sites): it is a valid one-instruction
            gadget. Mirrors aligned_scan's ``is_valid_gadget([terminator])``. '''
        return self._valid([insn])

    def evaluate(self, decodes):
        ''' The frame mask for an accepted gadget, or None to reject. '''
        if not self._valid(decodes):
            return None
        rra = self._rra
        prologue = None
        if self._is_return is not None and self._is_return(decodes[-1]):
            if self._return_prologue is not None:
                prologue = self._return_prologue(decodes)
                if prologue is None:
                    return None
            elif not (rra and any(rra(d) for d in decodes[:-1])):
                return None
        last = len(decodes) - 1
        return tuple(i == last or i == prologue or bool(rra and rra(d))
                     for i, d in enumerate(decodes))


class _RopblockPolicy:
    ''' Abstract-gadget (ropblock) policy. The terminator writes the PC from a
        register (or x86 `ret`); a stack-load prologue must feed that register
        with no intervening clobber. See backwards_framed_search for the predicate
        contract (is_terminator/branch_reg/is_prologue/clobbers/is_frame/splits/
        accept_decodes). '''

    __slots__ = ('_is_term', '_branch_reg', '_is_prologue', '_clobbers',
                 '_is_frame', '_splits', '_accept_decodes')

    def __init__(self, is_terminator, branch_reg, is_prologue, clobbers,
                 is_frame=None, splits=None, accept_decodes=None):
        self._is_term = is_terminator
        self._branch_reg = branch_reg
        self._is_prologue = is_prologue
        self._clobbers = clobbers
        self._is_frame = is_frame
        self._splits = splits
        self._accept_decodes = accept_decodes

    def is_terminator(self, insn) -> bool:
        return self._is_term(insn)

    def evaluate(self, decodes):
        last = decodes[-1]
        if not self._is_term(last):
            return None
        # No control-flow transfer before the terminator: a branch/return ahead
        # of it ends the gadget early (including a leading `ret`). The trailing
        # terminator is exempt; a bare `ret` stays valid. Matches is_valid_*_gadget.
        if self._splits is not None and any(self._splits(i) for i in decodes[:-1]):
            return None
        prologue = _ropblock_prologue_index(decodes, self._branch_reg(last),
                                            self._is_prologue, self._clobbers)
        if prologue is None:
            return None                             # not framed
        if self._accept_decodes is not None and not self._accept_decodes(decodes):
            return None                             # supplementary body filter
        return _frame_mask(decodes, prologue, self._is_frame)


def _emit_unaligned(opcodes, base_vaddr, depth, alignment, disasm, policy,
                    terminations, accept_candidate=None, accept_match=None):
    '''
    Unaligned emitter: enumerate candidate runs by anchoring on each terminator
    and growing the candidate backward one length at a time, re-decoding the raw
    slice. Surfaces unintended instructions hiding inside longer ones, so it is
    required on variable-length ISAs (x86 and compressed RISC-V).

    Terminator discovery: `terminations` (byte-regex patterns) is scanned with a
    single C-level overlapping `(?=(...))` match to locate terminator byte
    offsets (as galileo always did, and as the ropblock scan does to avoid a
    Capstone decode per byte); the per-length walk re-decodes and the policy
    re-checks the terminator, so a prefixed form (REX `jmp r8`) is surfaced even
    though the pattern anchors only on the trailing opcode. `accept_match(ref)`
    partitions terminator end-offsets across parallel chunks. Yields
    ``(vaddr, raw, decodes, frame)``.
    '''
    def grow(min_len, term_end):
        # Grow the candidate backward from the terminator, one length at a time.
        for length in range(min_len, depth + 1):
            q = term_end - length
            if q < 0:
                break
            vaddr = base_vaddr + q
            if alignment > 1 and vaddr % alignment != 0:
                continue
            raw = opcodes[q:term_end]
            if accept_candidate is not None and not accept_candidate(vaddr, raw):
                continue
            decodes = list(disasm(raw, vaddr))
            # The run must decode cleanly and consume the slice exactly (capstone
            # stops at the first undecodable byte, so a short/garbled decode would
            # otherwise be accepted with bytes its instructions do not account
            # for). A contiguous decode from `vaddr` ends at term_end iff it
            # consumed everything -- equivalent to galileo's sum-of-sizes check.
            if not decodes:
                continue
            last = decodes[-1]
            if last.address + last.size != base_vaddr + term_end:
                continue
            frame = policy.evaluate(decodes)
            if frame is not None:
                yield vaddr, raw, decodes, frame

    if terminations is None:
        # Predicate-only callers need no architecture-specific byte patterns.
        # Decode each absolute aligned offset, deduplicating prefixed forms
        # which can discover the same terminator end more than once.
        step = max(1, alignment)
        off = len(opcodes) - 1
        off -= (base_vaddr + off) % step
        seen_ends = set()
        while off >= 0:
            term = next(iter(disasm(opcodes[off:off + _MAX_INSN_BYTES],
                                    base_vaddr + off)), None)
            if term is not None and policy.is_terminator(term):
                ref = off + term.size
                if ref not in seen_ends:
                    seen_ends.add(ref)
                    if accept_match is None or accept_match(ref):
                        yield from grow(term.size, ref)
            off -= step
        return

    for termination in terminations:
        term_size = termination['size']
        # Zero-width lookahead so overlapping terminators are all enumerated
        # (e.g. `c2 c2 00 00` is `ret imm16` at offsets 0 and 1); plain
        # finditer skips overlaps and breaks serial/parallel chunk
        # equivalence. The patterns carry no capturing groups.
        probe = re.compile(b'(?=(' + termination['bytes'] + b'))')
        for match in probe.finditer(opcodes):
            t_off = match.start()
            ref = t_off + term_size
            if accept_match is not None and not accept_match(ref):
                continue
            # The terminating instruction must itself be aligned.
            if alignment > 1 and (base_vaddr + t_off) % alignment != 0:
                continue
            yield from grow(term_size, ref)


def _emit_aligned(opcodes, base_vaddr, depth, alignment, disasm, policy,
                  accept_candidate=None):
    '''
    Aligned emitter: one linear disassembly pass (`_linear_instruction_stream`)
    feeding a `depth`-bounded sliding window; for every instruction the policy
    calls a terminator, walk backward over the contiguous run of whole
    instructions ending at it, yielding each run (reusing the window's decoded
    objects -- no re-decode). Valid only on a fixed-width, naturally-aligned ISA,
    where every aligned offset is a canonical instruction start so this
    enumerates the same runs the unaligned emitter would. Yields
    ``(vaddr, raw, decodes, frame)``.
    '''
    window = []
    for term in _linear_instruction_stream(opcodes, base_vaddr, alignment, disasm):
        window.append(term)
        term_end = term.address + term.size
        # Trim out of `depth` reach of the current terminator; a later terminator
        # only reaches further forward, so these stay dead.
        while window and term_end - window[0].address > depth:
            del window[0]
        if not policy.is_terminator(term):
            continue
        n = len(window)
        idx = n - 1
        while idx >= 0:
            insn_j = window[idx]
            # Stop at a resync gap: a gadget's bytes are a single contiguous run.
            if idx < n - 1 and insn_j.address + insn_j.size != window[idx + 1].address:
                break
            if term_end - insn_j.address > depth:
                break
            vaddr = insn_j.address
            raw = opcodes[vaddr - base_vaddr:term_end - base_vaddr]
            if accept_candidate is None or accept_candidate(vaddr, raw):
                decodes = window[idx:n]
                frame = policy.evaluate(decodes)
                if frame is not None:
                    yield vaddr, raw, decodes, frame
            idx -= 1


def galileo_scan(opcodes, base_vaddr, terminations, depth, alignment, disasm,
                 is_valid_gadget, accept_match=None, accept_candidate=None,
                 restores_return_address=None, is_return=None,
                 return_prologue=None):
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
    is_return : callable(insn) -> bool, optional -- return terminators that
        require a stack restore (link-register architectures).
    return_prologue : callable(decodes) -> int | None, optional -- position of
        the intact stack-load prologue, or None to reject the return frame.
        Defaults to the architecture's method when is_return is a bound
        architecture predicate. Otherwise only restore presence is checked.

    Yields
    ------
    (vaddr, raw, decodes, frame)
    '''
    policy = _RopPolicy(is_valid_gadget, restores_return_address, is_return,
                        return_prologue)
    yield from _emit_unaligned(opcodes, base_vaddr, depth, alignment, disasm,
                               policy, terminations=terminations,
                               accept_candidate=accept_candidate,
                               accept_match=accept_match)


# Bytes handed to a single `disasm()` call in `_linear_instruction_stream`.
# Capstone's `cs_disasm` decodes its *entire* input eagerly in C before the
# Python generator yields anything (it is not `cs_disasm_iter`-based), so
# passing it a whole multi-ten-MB section in one call materializes every
# decoded instruction of that section at once regardless of how the Python
# side consumes them. Chunking bounds that native allocation to this size.
_SCAN_CHUNK_SIZE = 1 << 20


def _linear_instruction_stream(opcodes, base_vaddr, alignment, disasm):
    '''
    Generator core of `aligned_scan`: disassemble `opcodes` as the intended
    instruction stream, in program order, one instruction at a time, without
    ever materializing the whole section (see `_SCAN_CHUNK_SIZE`). Capstone
    stops at the first byte it cannot decode; when that happens the sweep
    resynchronizes by skipping one aligned unit past the offending byte and
    resumes.
    '''
    n = len(opcodes)
    step = max(1, alignment)
    # A raw buffer can begin before its first legal instruction address.
    off = (-base_vaddr) % step
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
        off += (-(base_vaddr + off)) % step


def aligned_scan(opcodes, base_vaddr, depth, alignment, disasm,
                 is_valid_gadget, restores_return_address=None, is_return=None,
                 accept_candidate=None, return_prologue=None):
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
    `is_return` is given, a return terminator is emitted only once the run
    contains a return-address restore (`restores_return_address`); `_RopPolicy`
    checks this per candidate by scanning the run's decodes. Non-return
    terminators (indirect JOP branches) carry no such requirement. When
    `is_return` is omitted the scan degrades to the plain sweep, emitting every
    contiguous run.

    Parameters mirror `galileo_scan`, minus the byte-pattern `terminations`
    (termination points are found by disassembly here, not by a byte regex).

    restores_return_address : callable(insn) -> bool, optional -- the frame load
        that restores the return target from the stack (RISC-V `ld ra, off(sp)`,
        AArch64 `ldp .. x30, [sp]`). Gates return emission when `is_return` is
        set, and marks the per-candidate frame mask `_RopPolicy` builds.
    is_return : callable(insn) -> bool, optional -- is the terminator a return
        (so the gadget must establish its frame). Omit for the plain sweep.
    return_prologue : callable(decodes) -> int | None, optional -- checks that
        the actual return register remains stack-derived; inferred from a bound
        architecture is_return predicate, as in galileo_scan.

    Yields
    ------
    (vaddr, raw, decodes, frame)
    '''
    # A gadget never reaches back more than `depth` bytes from its terminator,
    # so the aligned emitter keeps only a small trailing window of the (possibly
    # huge, e.g. a >40MB .text) instruction stream, bounding peak memory by
    # `depth`/`alignment` rather than section size. The return-address frame
    # requirement and inline mask formerly inlined here now live in _RopPolicy.
    policy = _RopPolicy(is_valid_gadget, restores_return_address, is_return,
                        return_prologue)
    yield from _emit_aligned(opcodes, base_vaddr, depth, alignment, disasm,
                             policy, accept_candidate=accept_candidate)


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
    and the caller (GadFinder.find_raw_gadgets, for a chain's `raw(...)`
    step) applies the actual pattern-equality test; this stays pattern-agnostic
    like the rest of this module.

    Parameters: `opcodes`/`base_vaddr`/`alignment`/`disasm` as elsewhere in
    this module, plus `pattern_len` (the number of instructions a candidate
    window must contain) and `accept_candidate` (bad-char filtering, as in the
    other scans).

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
    off = (-base_vaddr) % step
    while off < n:
        vaddr = base_vaddr + off
        decodes = list(disasm(opcodes[off:off + window_bytes], vaddr))[:pattern_len]
        if len(decodes) == pattern_len:
            end = decodes[-1].address + decodes[-1].size
            raw = opcodes[off:end - base_vaddr]
            if accept_candidate is None or accept_candidate(vaddr, raw):
                yield vaddr, raw, decodes
        off += step


def aligned_literal_scan(opcodes, base_vaddr, alignment, disasm, pattern_len,
                         accept_candidate=None):
    '''
    Fixed-length instruction-window scan over the *intended* instruction stream
    -- the single-pass counterpart to `literal_scan`, for aligned/fixed-width
    ISAs (AArch64, uncompressed RISC-V). Because every instruction on such an ISA begins on
    an aligned boundary, the intended stream already contains every position a
    gadget could start at, so there are no "unintended" mid-instruction windows
    to miss: one linear disassembly pass finds them all, replacing `literal_scan`'s
    one `disasm()` call per aligned offset.

    Slides a window of the last `pattern_len` *contiguous* instructions along
    the stream produced by `_linear_instruction_stream` (which resynchronizes
    past undecodable bytes); a resync gap breaks contiguity and resets the
    window. Like `literal_scan` it stays pattern-agnostic -- the caller
    (`GadFinder.find_raw_gadgets`) applies the actual pattern-equality test.

    Parameters mirror `literal_scan`.

    Yields
    ------
    (vaddr, raw, decodes) for every aligned offset where `pattern_len`
    contiguous instructions decode.
    '''
    window = []
    for insn in _linear_instruction_stream(opcodes, base_vaddr, alignment, disasm):
        # A gadget's bytes must be a single contiguous run; a resync gap
        # (a hole where nothing decoded) breaks it, so restart the window.
        if window and window[-1].address + window[-1].size != insn.address:
            window = []
        window.append(insn)
        if len(window) < pattern_len:
            continue
        del window[:-pattern_len]                   # keep only the last pattern_len
        start = window[0].address
        end = window[-1].address + window[-1].size
        raw = opcodes[start - base_vaddr:end - base_vaddr]
        if accept_candidate is None or accept_candidate(start, raw):
            yield start, raw, list(window)


def assemble(text, arch_obj):
    '''
    Assemble `text` (a raw gadget's instruction sequence, one instruction per
    line) to the exact bytes to search the binary for, using Keystone --
    Capstone's sister assembler. This is what makes the `raw(...)` scan fast:
    the pattern is turned into a byte needle once and located with a byte-regex
    (`raw_byte_scan`), instead of disassembling the whole binary.

    Returns the assembled bytes, or `None` when the fast path is unavailable --
    Keystone is not installed or its native library fails to load, the
    architecture has no Keystone backend (e.g. RISC-V), or the text does not
    assemble. Every `None` makes `GadFinder.find_raw_gadgets` fall back to the
    Capstone forward scan (`literal_scan` / `aligned_literal_scan`), so the fast
    path is strictly an optimization and never the only way a raw gadget is found.
    '''
    try:
        import keystone
    except Exception:                       # not installed / native lib load failure
        return None
    import capstone

    if arch_obj.arch == capstone.CS_ARCH_X86:
        ks_arch = keystone.KS_ARCH_X86
        ks_mode = (keystone.KS_MODE_64 if arch_obj.mode & capstone.CS_MODE_64
                   else keystone.KS_MODE_32)
        syntax = keystone.KS_OPT_SYNTAX_INTEL       # match Capstone's Intel operand text
    elif arch_obj.arch == capstone.CS_ARCH_ARM64:
        ks_arch = keystone.KS_ARCH_ARM64
        ks_mode = keystone.KS_MODE_LITTLE_ENDIAN
        syntax = None
    else:
        return None                                 # no Keystone backend for this arch

    try:
        ks = keystone.Ks(ks_arch, ks_mode)
        if syntax is not None:
            ks.syntax = syntax
        encoding, _count = ks.asm(text, 0)
    except Exception:
        return None
    if not encoding:
        return None
    return bytes(encoding)


def raw_byte_scan(opcodes, base_vaddr, needle, alignment, disasm,
                  accept_candidate=None):
    '''
    Byte-regex scan for a fixed `needle` (the Keystone-assembled bytes of a
    raw gadget) directly over a section's opcodes -- the fast path that skips
    per-offset disassembly entirely.

    Overlapping occurrences are enumerated (a zero-width lookahead regex) so
    that alignment filtering never hides a valid aligned hit behind an earlier
    unaligned one. On x86 (alignment 1) every offset is accepted, so a needle
    sitting "unintended" inside another instruction's encoding is still found
    (as `literal_scan` finds it by trying every offset); on a fixed-width ISA
    only aligned offsets pass. Hits are yielded lazily in address order, so a
    caller taking only the first appearance stops the scan at the first hit.

    Yields
    ------
    (vaddr, raw, decodes) -- `raw` is the needle; `decodes` is the needle
    disassembled at `vaddr` (so the caller can pattern-check and build a Gadget).
    '''
    if not needle:
        return
    probe = re.compile(b'(?=(' + re.escape(needle) + b'))')
    for match in probe.finditer(opcodes):
        off = match.start()
        vaddr = base_vaddr + off
        if alignment > 1 and vaddr % alignment != 0:
            continue
        if accept_candidate is not None and not accept_candidate(vaddr, needle):
            continue
        yield vaddr, needle, list(disasm(needle, vaddr))


# --------------------------------------------------------------------------
# Backward framed (ropblock) search
# --------------------------------------------------------------------------


def backwards_framed_search(opcodes, base_vaddr, depth, alignment, disasm,
                            is_terminator, branch_reg, is_prologue, clobbers,
                            is_frame=None, splits=None, accept_candidate=None,
                            accept_decodes=None, terminations=None,
                            accept_match=None):
    '''
    Backward framed ("ropblock") gadget search.

    A ropblock gadget is framed as ``[prologue] ... [terminator]``: the
    terminator writes the program counter from a register (an indirect
    ``jmp``/``br`` through a register), and the prologue loads *that* register
    from the stack (``pop reg`` / ``ldr reg, [sp]``). x86 ``ret`` is the
    degenerate case -- it pops the program counter straight off the stack, so a
    single instruction is both prologue and epilogue (``branch_reg`` returns
    ``None`` and the frame is satisfied with no separate prologue).

    Using a byte-regex over `terminations` to find each terminator, the search
    walks back over the contiguous runs that end at that terminator (growing one
    length at a time up to `depth` bytes) and emits a run once it is *framed*: it
    contains,
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
      accept_decodes(decodes) -> bool, optional -- a supplementary whole-gadget
          filter the caller applies (complex-memory / segment-override /
          conditional-branch rejection) that this search's terminator/frame
          logic does not itself cover; a candidate it rejects is dropped.
          Default: no such check.
      terminations : iterable of {'bytes': <byte regex>, 'size': <int>}
          -- terminators are located with a single C-level overlapping
          byte-regex (as `galileo_scan` does). The patterns need only match a
          terminator's *trailing* bytes: the per-length backward walk re-decodes
          each candidate and the `is_terminator(last)` re-check guarantees the
          decoded tail is a genuine pc-reg-write, so prefixed forms (e.g. REX
          `jmp r8`) are surfaced by the walk even though the pattern anchors only
          on the unprefixed opcode. A fixed-width ISA with a single canonical
          instruction stream (AArch64) uses the linear-pass
          `framed_linear_search` instead of this per-offset search. When omitted,
          terminators are discovered by decoding each legal offset instead.
      accept_match(ref) -> bool, optional -- filter on a terminator's end
          offset, used to partition parallel chunks (mirrors `galileo_scan`).
          Default: no such check.

    Yields
    ------
    (vaddr, raw, decodes, frame)
    '''
    policy = _RopblockPolicy(is_terminator, branch_reg, is_prologue, clobbers,
                             is_frame=is_frame, splits=splits,
                             accept_decodes=accept_decodes)
    yield from _emit_unaligned(opcodes, base_vaddr, depth, alignment, disasm,
                               policy, terminations=terminations,
                               accept_candidate=accept_candidate,
                               accept_match=accept_match)


def framed_linear_search(opcodes, base_vaddr, depth, alignment, disasm,
                         is_terminator, branch_reg, is_prologue, clobbers,
                         is_frame=None, splits=None, accept_candidate=None,
                         accept_decodes=None):
    '''
    Linear-pass abstract-gadget ("ropblock") search for a fixed-width, fully
    naturally-aligned ISA (AArch64).

    Equivalent to `backwards_framed_search` but, where that re-decodes each
    candidate from every offset, this disassembles the section once as an
    intended instruction stream (`_linear_instruction_stream`) and reuses the
    decoded instruction objects from a sliding window -- exactly as
    `aligned_scan` does for the ordinary framed sweep. On an ISA whose
    instructions are all one `alignment`-wide, naturally-aligned unit, every
    aligned offset is a canonical instruction start, so the per-offset backward
    walk and this single pass enumerate the *same* contiguous runs (there are no
    unintended instructions hiding inside longer ones). This is **not** valid on
    a variable-length ISA (x86) or one with mixed widths at sub-instruction
    alignment (RISC-V + C extension), which must keep `backwards_framed_search`.

    The framing/validation (prologue data-flow, `splits`, `accept_decodes`,
    frame mask) is identical to `backwards_framed_search`; only terminator
    discovery and candidate decoding differ. Yields ``(vaddr, raw, decodes,
    frame)``.
    '''
    policy = _RopblockPolicy(is_terminator, branch_reg, is_prologue, clobbers,
                             is_frame=is_frame, splits=splits,
                             accept_decodes=accept_decodes)
    yield from _emit_aligned(opcodes, base_vaddr, depth, alignment, disasm,
                             policy, accept_candidate=accept_candidate)


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
