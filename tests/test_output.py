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


# --- Tuple format ---------------------------------------------------------

def test_gadget_tuple_repr_two_operand(x64):
    import rop3.operation as operation
    g = make_gadget(b'\x48\x89\xc7\xc3', 0x1000)          # mov rdi, rax ; ret
    matched = operation.Operation('mov', ['rdi', 'rax']).filter_gadgets([g])
    assert matched[0].tuple_repr() == '⟨mov, rdi, rax, {rdi}, {rax}⟩'


def test_gadget_tuple_repr_one_operand_omits_op2(x64):
    import rop3.operation as operation
    g = make_gadget(b'\x48\xf7\xd8\xc3', 0x1000)          # neg rax ; ret
    matched = operation.Operation('neg', ['rax']).filter_gadgets([g])
    # <neg, rax, {written}, {read}> -- exactly one operand before the sets.
    t = matched[0].tuple_repr()
    assert t.startswith('⟨neg, rax, {') and t.endswith('⟩')
    assert t.count('{') == 2                               # only the two reg sets


def test_gadget_tuple_repr_excludes_stack_pointer(x64):
    # pop rax ; ret writes rax (and rsp, which is excluded); reads nothing but rsp.
    t = make_gadget(b'\x58\xc3', 0x1000).tuple_repr()
    assert t == '⟨, {rax}, {}⟩'                  # unmatched: empty op/operands
    assert 'rsp' not in t


def test_gadget_tuple_repr_immediate_operand(x64):
    import rop3.operation as operation
    g = make_gadget(b'\x48\xc7\xc0\xff\xff\xff\xff\xc3', 0x1000)   # mov rax, -1 ; ret
    matched = operation.Operation('mov', ['rax']).filter_gadgets([g])
    # The immediate source shows as a literal, not a dropped/None operand.
    assert matched[0].tuple_repr() == '⟨mov, rax, -1, {rax}, {}⟩'


def test_output_gadgets_tuple(x64, capsys):
    import rop3.operation as operation
    g = make_gadget(b'\x48\x89\xc7\xc3', 0x1000)          # mov rdi, rax ; ret
    matched = operation.Operation('mov', ['rdi', 'rax']).filter_gadgets([g])
    utils.output_gadgets(matched, 'tuple')
    out = capsys.readouterr().out
    assert '@ 0x1000]: ⟨mov, rdi, rax, {rdi}, {rax}⟩' in out
