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

from abc import ABC, abstractmethod
from typing import Optional, List, Any

class Architecture(ABC):
    """Abstract base class for all architectures"""
    
    @abstractmethod
    def get_rop_terminations(self, include_extra: bool = False) -> List[str]:
        pass

    @abstractmethod
    def get_jop_terminations(self, include_extra: bool = False) -> List[str]:
        pass

    @abstractmethod
    def is_valid_rop_gadget(self, decodes: Any, include_extra: bool = False, allow_undeterministic: bool = False) -> bool:
        pass

    @abstractmethod
    def is_valid_jop_gadget(self, decodes: Any, include_extra: bool = False, allow_undeterministic: bool = False) -> bool:
        pass

    @property
    @abstractmethod
    def arch(self) -> int:
        pass

    @property
    @abstractmethod
    def mode(self) -> int:
        pass

    @property
    @abstractmethod
    def op_reg(self) -> int:
        pass

    @property
    @abstractmethod
    def op_mem(self) -> int:
        pass

    @property
    @abstractmethod
    def op_imm(self) -> int:
        pass

    @property
    @abstractmethod
    def sp(self) -> str:
        pass

    @property
    @abstractmethod
    def bp(self) -> str:
        pass

    def normalize_reg(self, name: str | int) -> str:
        """
        Standard instance method. Base implementation just returns the name,
        but specific architectures can override this
        """
        return str(name)

    @abstractmethod
    def is_valid_abstract_reg(self, name: str | int) -> bool:
        """
        Returns whether a register can be used as an abstract one in the
        architecture
        """
        pass

    def first_insn_has_complex_mem(self, decodes) -> bool:
        """
        Returns True if the first instruction uses a complex memory addressing
        mode (e.g. base + index*scale). Default: False
        """
        return False

class ArchitectureSingleton:
    def __init__(self):
        self._arch = None

    def initialize(self, arch: Architecture):
        if self._arch is not None:
            return
        self._arch = arch

    def reset(self) -> None:
        ''' Clear the current architecture (mainly for tests / library use) '''
        self._arch = None

    def is_initialized(self) -> bool:
        return self._arch is not None

    def matches(self, arch: Architecture) -> bool:
        return self._arch is not None and \
            (self._arch.arch, self._arch.mode) == (arch.arch, arch.mode)

    @property
    def arch(self) -> Architecture:
        if self._arch is None:
            raise RuntimeError("Architecture context accessed before initialization.")
        return self._arch

arch_singleton = ArchitectureSingleton()
