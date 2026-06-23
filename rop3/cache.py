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
import json
import hashlib
import tempfile

import rop3.debug as debug

''' Bump when the on-disk record format changes to invalidate old entries '''
CACHE_VERSION = 1


def default_cache_dir():
    base = os.environ.get('XDG_CACHE_HOME') or os.path.join(
        os.path.expanduser('~'), '.cache')
    return os.path.join(base, 'rop3')


class GadgetCache:
    '''
    Caches the raw gadget records (vaddr, hex-bytes) discovered for a binary so
    repeated runs over the same file and parameters skip the scan. The key
    binds the file content hash and every parameter that affects the record
    set, so a changed file or option misses cleanly.
    '''

    def __init__(self, cache_dir=None):
        self.cache_dir = cache_dir or default_cache_dir()

    def key(self, file_hash, params: dict) -> str:
        material = json.dumps(
            {'version': CACHE_VERSION, 'hash': file_hash, 'params': params},
            sort_keys=True)
        return hashlib.sha256(material.encode()).hexdigest()

    @staticmethod
    def file_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _path(self, key: str) -> str:
        return os.path.join(self.cache_dir, key + '.json')

    def load(self, key: str):
        ''' Return the cached records (list of [vaddr, hex]) or None on miss. '''
        try:
            with open(self._path(key), 'r') as f:
                return json.load(f)
        except (FileNotFoundError, ValueError):
            return None

    def store(self, key: str, records) -> None:
        ''' Persist records atomically; failures are non-fatal (just a warning). '''
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            path = self._path(key)
            fd, tmp = tempfile.mkstemp(dir=self.cache_dir, suffix='.tmp')
            with os.fdopen(fd, 'w') as f:
                json.dump(records, f)
            os.replace(tmp, path)
        except OSError as exc:
            debug.warning(f'could not write gadget cache: {exc}')
