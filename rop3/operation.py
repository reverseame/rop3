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
                        dst = self.template.dst
                        src = self.template.src
                        if not dst:
                            dst = result[1]
                        if not src:
                            src = result[2]
                        gadget['op'] = self.template.op_str
                        gadget['dst'] = dst
                        gadget['src'] = src
                        ret += [gadget]

        return utils.delete_duplicate_gadgets(ret)
