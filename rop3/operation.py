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

import rop3.template as template
import rop3.utils as utils

class Operation:
    def __init__(self, op, dst='', src=''):
        self.template = template.TemplateOp(op, dst=dst, src=src)

    def get_gadgets(self, gadgets):
        ret = []

        if not gadgets:
            return ret

        arch = gadgets[0]['arch']
        mode = gadgets[0]['mode']
        md = capstone.Cs(arch, mode)
        md.detail = True

        for chain in self.template:
            for gadget in gadgets:
                decodes = list(md.disasm(gadget['bytes'], gadget['vaddr']))
                for ins, decode in zip(chain, decodes):
                    if not ins.is_equal(decode):
                        break
                else:
                    value = chain.get_values()
                    gadget['values'] = value
                    result = chain.is_equal(decodes)
                    if result:
                        (dst_chain, src_chain, allow_promotion) = result
                        dst = self.template.dst
                        src = self.template.src
                        if not dst:
                            dst = dst_chain
                            if allow_promotion:
                                if utils.is_x64_qword_reg(dst):
                                    dst = [dst, utils.promote_x64_qword_reg(dst)]
                        elif allow_promotion:
                            if utils.is_x64_qword_reg(dst):
                                dst = [dst, utils.promote_x64_qword_reg(dst)]

                        if not src:
                            src = src_chain
                            if allow_promotion:
                                if utils.is_x64_qword_reg(src):
                                    src = [src, utils.promote_x64_qword_reg(src)]
                        elif allow_promotion:
                            if utils.is_x64_qword_reg(src):
                                src = [src, utils.promote_x64_qword_reg(src)]
                        gadget['op'] = self.template.op_str
                        gadget['dst'] = dst
                        gadget['src'] = src
                        ret += [gadget]

        return utils.delete_duplicate_gadgets(ret)
