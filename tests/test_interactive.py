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

from rop3 import Rop3
from rop3.interactive import Rop3Shell

from conftest import build_minimal_elf, EM_X86_64, ET_DYN


def test_do_chain_reports_unknown_operation_without_crashing(tmp_path, capsys):
    '''
    Regression: do_chain caught only RopChainNotFound, so a ParserException from
    a misspelled/unknown operation name escaped and aborted the REPL. It must be
    reported like do_op instead.
    '''
    path = tmp_path / 'a.elf'
    path.write_bytes(build_minimal_elf(64, EM_X86_64, b'\x58\xc3', 0x1000, ET_DYN))
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('definitely-not-an-op(rax)\n')

    shell = Rop3Shell(Rop3(str(path)))
    shell.do_chain(str(ropfile))                    # must not raise
    out = capsys.readouterr().out
    assert 'definitely-not-an-op' in out and 'not found' in out.lower()
