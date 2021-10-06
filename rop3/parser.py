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

YAML = 0

import rop3.debug as debug
import rop3.parsers.yaml_parser as yaml_parser

class Parser:
    def __init__(self, type_=YAML):
        if type_ == YAML:
            self.parser = yaml_parser.YamlParser()
        else:
            raise ParserException(f'Parser not supported')

    def get_op(self, op):
        return self.parser.get_op(op)

    def get_ops(self):
        return self.parser.get_ops()

class ParserException(Exception):
    pass
