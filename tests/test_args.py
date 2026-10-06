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

from rop3.args import ArgumentParser


def _parse(argv):
    return ArgumentParser().parse_args(argv)


# --- F24: --tuple must not silently override a structured --output ---------

@pytest.mark.parametrize('fmt', ['json', 'csv'])
def test_tuple_with_structured_output_is_rejected(fmt):
    with pytest.raises(SystemExit):
        _parse(['--binary', '/bin/true', '--tuple', '--output', fmt])


def test_tuple_with_text_output_is_allowed():
    args = _parse(['--binary', '/bin/true', '--tuple', '--output', 'text'])
    assert args.tuple and args.output == 'text'


def test_tuple_without_output_is_allowed():
    args = _parse(['--binary', '/bin/true', '--tuple'])
    assert args.tuple and args.output == 'text'


# --- F29: --version must not dereference a missing --binary ----------------

def test_version_with_base_and_no_binary_does_not_crash():
    # Before the fix this raised TypeError (len(None)) instead of parsing cleanly.
    args = _parse(['--version', '--base', '0x1000'])
    assert args.version and args.binary is None


def test_version_alone():
    args = _parse(['--version'])
    assert args.version
