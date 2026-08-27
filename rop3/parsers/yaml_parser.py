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

import os
import re
import yaml
import glob
import capstone

import rop3.parser as parser
from rop3.operation import OperationDef

from rop3.arch import arch_singleton

_OP_KEY_RE = re.compile(r'^op\d+$')

class YamlParser:
    def __init__(self):
        self.folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'roplang')

    def get_op(self, op):
        ops = self.get_ops()
        names = [item.name for item in ops]

        if op in names:
            i = names.index(op)
            return ops[i]
        else:
            raise parser.ParserException(f'{op}: Operation not found')

    def get_ops(self):
        ret = []

        files = self._get_op_files()

        for filename in files:
            content = self._read_yaml(filename)
            ''' Merge dicts '''
            if content:
                for op in content.keys():
                    ret.append(self._parse_op(op, content[op]))

        return ret

    def _get_op_files(self):
        return [filename for filename in glob.glob(os.path.join(self.folder, '**', '*.yaml'), recursive=True) if os.path.isfile(filename)]

    def _read_yaml(self, filename):
        with open(filename, 'r') as f:
            return yaml.safe_load(f.read())

    def _resolve_alias(self, value):
        if not isinstance(value, str):
            return value
        arch = arch_singleton.arch
        aliases = {
            'REG_SP': arch.sp,
            'REG_BP': arch.bp,
            'REG_FLAGS': arch.flags,
        }
        return aliases.get(value, value)

    def _resolve_roles(self, roles):
        ''' Resolve a dst/src role list, mapping arch-independent register
            aliases (REG_FLAGS, REG_SP, REG_BP) to concrete register names while
            leaving operand slots (op1, REG10, ...) untouched. '''
        if not roles:
            return []
        return [self._resolve_alias(r) for r in roles]

    def _arch_family(self) -> str:
        ''' YAML architecture block key for the current architecture. '''
        cs_arch = arch_singleton.arch.arch
        if cs_arch == capstone.CS_ARCH_X86:
            return 'x86'
        if cs_arch in (capstone.CS_ARCH_ARM, getattr(capstone, 'CS_ARCH_ARM64', object())):
            return 'arm'
        if cs_arch == getattr(capstone, 'CS_ARCH_RISCV', object()):
            return 'riscv'
        return 'x86'

    def _parse_op(self, op, content):
        '''
        Parse an operation definition in the multi-architecture format:

            <op>:
              operands: N
              dst: [opI, ...]
              src: [opJ, ...]
              <arch>:
                - steps: [ {mnemonic|operation, op1, op2, ...}, ... ]
        '''
        defn = OperationDef(
            op,
            operands=content.get('operands', 0),
            dst_roles=self._resolve_roles(content.get('dst')),
            src_roles=self._resolve_roles(content.get('src')),
        )

        arch_block = content.get(self._arch_family())
        if isinstance(arch_block, dict):
            # Availability marker instead of a realization list, e.g.
            #   riscv:
            #     available: false
            #     reason: RISC-V has no condition/carry flags
            if arch_block.get('available', True) is False:
                defn.mark_unavailable(arch_block.get('reason'))
        elif arch_block:
            for entry in arch_block:
                steps = entry.get('steps', []) if isinstance(entry, dict) else entry
                defn.add_realization(self._realization_links(steps))

        return defn

    def _realization_links(self, steps):
        '''
        Translate the YAML steps of one realization into the neutral link data
        that OperationDef.add_realization consumes. Each entry of `steps` is one
        chain link:

          - a nested list of `mnemonic` steps  -> a single gadget whose
            instructions must appear together;
          - a single `mnemonic` step           -> a one-instruction gadget
            (with optional implicit `writes`/`reads`);
          - an `operation` step                -> a reference into another
            operation (replacing the old `compose:` mechanism).

        Successive links are distinct gadgets in the chain. To place several
        instructions in the *same* gadget, nest them in a list.
        '''
        links = []
        for entry in steps:
            if isinstance(entry, list):
                links.append({'gadget': [self._instruction_data(s) for s in entry]})
            elif 'mnemonic' in entry:
                links.append({
                    'gadget': [self._instruction_data(entry)],
                    'writes': self._resolve_roles(entry.get('writes')),
                    'reads': self._resolve_roles(entry.get('reads')),
                })
            elif 'operation' in entry:
                bindings = {
                    k: self._resolve_alias(v)
                    for k, v in entry.items() if _OP_KEY_RE.match(k)
                }
                links.append({'opref': entry['operation'], 'bindings': bindings})

        return links

    def _instruction_data(self, step):
        ''' One instruction as neutral data: its mnemonic and its alias-resolved
            operands in positional (op1, op2, ...) order. '''
        op_keys = sorted((k for k in step if _OP_KEY_RE.match(k)),
                         key=lambda k: int(k[2:]))
        return {'mnemonic': step['mnemonic'],
                'operands': [self._resolve_alias(step[key]) for key in op_keys]}

