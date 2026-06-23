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

import pytest

from rop3 import Rop3
from rop3.interactive import Rop3Shell

from conftest import build_minimal_elf, EM_X86_64, ET_DYN

# pop rax ; ret   pop rbx ; ret   nop ; ret
TEXT = b'\x58\xc3\x5b\xc3\x90\xc3'


@pytest.fixture
def elf_path(tmp_path):
    data = build_minimal_elf(64, EM_X86_64, TEXT, 0x1000, ET_DYN)
    path = tmp_path / 'sample.elf'
    path.write_bytes(data)
    return str(path)


def test_rop3_gadgets(elf_path):
    r = Rop3(elf_path)
    gadgets = r.gadgets()
    assert gadgets
    assert any(g.text_repr == 'ret' for g in gadgets)


def test_rop3_caches_gadgets(elf_path):
    r = Rop3(elf_path)
    assert r.gadgets() is r.gadgets()           # cached
    assert r.gadgets(refresh=True) is not None  # refresh recomputes


def test_rop3_accepts_single_path_or_list(elf_path):
    assert Rop3(elf_path).binaries == [elf_path]
    assert Rop3([elf_path]).binaries == [elf_path]


def test_rop3_find_op(elf_path):
    r = Rop3(elf_path)
    matched = r.find_op('lc', dst='rax')
    assert [g.text_repr for g in matched] == ['pop rax ; ret']


def test_shell_count_and_search(elf_path, capsys):
    shell = Rop3Shell(Rop3(elf_path))
    shell.onecmd('count')
    out = capsys.readouterr().out
    assert out.strip().isdigit() and int(out.strip()) > 0

    shell.onecmd('search pop rax')
    out = capsys.readouterr().out
    assert 'pop rax ; ret' in out
    assert 'pop rbx' not in out


def test_shell_op(elf_path, capsys):
    shell = Rop3Shell(Rop3(elf_path))
    shell.onecmd('op lc rax')
    out = capsys.readouterr().out
    assert 'pop rax ; ret' in out


def test_shell_quit_returns_true(elf_path):
    shell = Rop3Shell(Rop3(elf_path))
    assert shell.onecmd('quit') is True
    assert shell.onecmd('exit') is True
