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
import yaml
import glob
import __main__
 
import rop3.parser as parser
import rop3.operation as operation

from rop3.arch import arch_singleton

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
        }
        return aliases.get(value, value)

    def _parse_op(self, op, content):
        # Composite operation logic
        if (
            isinstance(content, list)
            and len(content) == 1
            and isinstance(content[0], dict)
            and 'compose' in content[0]
        ):
            steps = content[0]['compose']
            # Resolve aliases in composite steps
            resolved_steps = []
            for step in steps:
                resolved_step = dict(step)
                for key in ('op1', 'op2'):
                    if key in resolved_step:
                        resolved_step[key] = self._resolve_alias(resolved_step[key])
                resolved_steps.append(resolved_step)
            return parser.CompositeOperation(op, resolved_steps)


        # Normal operation
        ret = operation.OperationTemplate(op)
        for set_ in content:
            s = operation.Set()
            for item in set_:
                if 'mnemonic' in item:
                    i = operation.Instruction(item['mnemonic'])
                    for operand in ('op1', 'op2'):
                        if operand in item:
                            current_op = item[operand]
                            if type(current_op) == dict:
                                raise NotImplementedError
                            else:
                                # Resolve aliases if necessary
                                i.add(operation.Operand(self._resolve_alias(item[operand])))
                elif 'operation' in item:
                    i = item
                s.add(i)

            ret.add(s)

        return ret

