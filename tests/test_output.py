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

import csv
import io
import json

import rop3.utils as utils

from conftest import make_gadget


def test_output_gadgets_json(x64, capsys):
    gadgets = [make_gadget(b'\x58\xc3', 0x1000), make_gadget(b'\x5b\xc3', 0x1010)]
    utils.output_gadgets(gadgets, 'json')
    data = json.loads(capsys.readouterr().out)
    assert [g['vaddr'] for g in data] == ['0x1000', '0x1010']
    assert data[0]['gadget'] == 'pop rax ; ret'


def test_output_gadgets_csv(x64, capsys):
    gadgets = [make_gadget(b'\x58\xc3', 0x1000)]
    utils.output_gadgets(gadgets, 'csv')
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert rows[0]['vaddr'] == '0x1000'
    assert rows[0]['gadget'] == 'pop rax ; ret'
    assert rows[0]['bytes'] == '58c3'


def test_output_gadgets_text(x64, capsys, monkeypatch):
    monkeypatch.setattr('sys.stdout.isatty', lambda: False, raising=False)
    utils.output_gadgets([make_gadget(b'\x58\xc3', 0x1000)], 'text')
    out = capsys.readouterr().out
    assert 'pop rax ; ret' in out
    assert '\033' not in out


def test_output_ropchains_json(x64, capsys):
    chain = [make_gadget(b'\x58\xc3', 0x1000), make_gadget(b'\x5b\xc3', 0x1010)]
    utils.output_ropchains([chain], 'json', exhaustive=True)
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1 and len(data[0]) == 2


def test_output_ropchains_csv_has_chain_index(x64, capsys):
    chain = [make_gadget(b'\x58\xc3', 0x1000)]
    utils.output_ropchains([chain], 'csv', exhaustive=True)
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert rows[0]['chain'] == '1'


def test_output_ropchains_text_non_exhaustive_takes_first(x64, capsys):
    ''' Non-exhaustive text output consumes only the first chain (lazy). '''
    def gen():
        yield [make_gadget(b'\x58\xc3', 0x1000)]
        raise AssertionError('second chain should not be consumed')
    utils.output_ropchains(gen(), 'text', exhaustive=False)
    assert 'pop rax ; ret' in capsys.readouterr().out
