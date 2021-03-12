import re
import capstone

import rop3.debug as debug
import rop3.utils as utils
import rop3.binary as binary
import rop3.operation as operation

# Default depth engine
DEPTH = 5

# Flags when searching gadgets
KEEP_DUPLICATES = 1
NO_JOP = 2
NO_RETF = 4

class Finder:
    '''
    Class to search gadgets in a binary
    '''
    def __init__(self, depth=DEPTH, flags=0):
        self.depth = depth
        self.flags = flags
        self.gad_terminations = self._set_terminations()

    def find(self, filename, base=''):
        gadgets = []

        try:
            gadgets = self._search_gadgets(filename, base)
            gadgets = self._clean_gadgets(gadgets)
            if not self._skip_duplicates():
                gadgets = utils.delete_duplicate_gadgets(gadgets)
            gadgets = self._alpha_sortgadgets(gadgets)
        except binary.BinaryException as exc:
            debug.warning(str(exc))

        return gadgets

    def find_iter(self, filename, base=''):
        for file in filename:
            yield self.find(file, base)

    def find_all(self, filename):
        ret = []

        for file in filename:
            ret += self.find(file)

        return ret

    def find_op(self, filename, op, dst='', src=''):
        op = operation.Operation(op, dst=dst, src=src)

        gadgets = self.find_all(filename)

        return op.get_gadgets(gadgets)

    def find_op_iter(self, filename, op, dst='', src='', base=''):
        op = operation.Operation(op, dst=dst, src=src)

        for gadgets in self.find_iter(filename, base):
            yield op.get_gadgets(gadgets)

    def _set_terminations(self):
        ret = []

        ret += self._add_rop_gadgets()
        ret += self._add_jop_gadgets()

        return ret

    def _add_rop_gadgets(self):
        ret = [
            {'bytes': b'\xc3'},               # ret
            {'bytes': b'\xc2[\x00-\xff]{2}'}  # ret <imm>
        ]
        if not self._noretf():
            ret += [
                {'bytes': b'\xcb'},                # retf
                {'bytes': b'\xca[\x00-\xff]{2}'}   # retf <imm>
            ]

        return ret

    def _add_jop_gadgets(self):
        ret = []

        if not self._nojop():
            ret += [
                {'bytes': b'\xff[\x20\x21\x22\x23\x26\x27]{1}'},        # jmp  [reg]
                {'bytes': b'\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}'},    # jmp  [reg]
                {'bytes': b'\xff[\x10\x11\x12\x13\x16\x17]{1}'},        # jmp  [reg]
                {'bytes': b'\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}'}     # call [reg]
            ]

        return ret

    def _nojop(self):
        return self.flags & NO_JOP

    def _noretf(self):
        return self.flags & NO_RETF

    def _skip_duplicates(self):
        return self.flags & KEEP_DUPLICATES

    def _search_gadgets(self, file, base=''):
        ret = []

        binfile = binary.Binary(file, base)

        filename = binfile.get_file_name()
        sections = binfile.get_exec_sections()
        arch = binfile.get_arch()
        mode = binfile.get_arch_mode()

        md = capstone.Cs(arch, mode)

        for termination in self.gad_terminations:
            for section in sections:
                opcodes = section['opcodes']
                vaddr = section['vaddr']
                """All references to gadget termination"""
                all_ref = [m.end() for m in re.finditer(termination['bytes'], opcodes)]
                for ref in all_ref:
                    """Search backwards from reference"""
                    for depth in range(1, self.depth + 1):
                        bytes_ = opcodes[ref - depth:ref]
                        """Virtual address inside section"""
                        addr = vaddr + ref - depth
                        decodes = md.disasm(bytes_, addr)
                        gadget = ''
                        for decode in decodes:
                            gadget += '{0} {1} ; '.format(decode.mnemonic, decode.op_str).replace('  ', ' ')
                        if len(gadget) > 0:
                            gadget = gadget[:-3]
                            ret += [{'file': filename, 'arch': arch, 'mode': mode, 'vaddr': addr, 'gadget': gadget, 'bytes': bytes_, 'values': []}]

        return ret

    def _clean_gadgets(self, gadgets):
        """
        Deletes x86 gadgets without a valid termination (e.g: '\xc3' in '\x89\xc3' is
        'mov ebx, eax' and not 'ret'), multibranched gadgets with multiple terminations
        in a single gadget and retf-terminated gadgets or jop gadgets if desired

        @param gadgets: a list of gadgets

        @returns a cleaned list of gadgets
        """
        new = []
        br = ['ret', 'retf', 'jmp', 'call']

        for gadget in gadgets:
            insts = gadget['gadget'].split(' ; ')
            """Valid gadget termination"""
            end = insts[-1].split(' ')[0]
            if end not in br:
                continue
            if self._noretf() and end == 'retf':
                continue
            if self._nojop() and (end in ['jmp', 'call']):
                continue
            if self._is_multibr(insts, br):
                continue
            new += [gadget]

        return new

    def _is_multibr(self, insts, br):
        """
        Check if there are more than one terminations in a single gadget

        @param insts: a list with gadget's instructions
        @param br: possible terminations

        @returns True if multibranched, False otherwise
        """
        count = 0

        for inst in insts:
            if inst.split()[0] in br:
                count += 1

        return count > 1

    def _alpha_sortgadgets(self, gadgets):
        return sorted(gadgets, key=lambda gadget: gadget['gadget'])
