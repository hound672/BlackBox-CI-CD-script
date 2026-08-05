from enum import Enum


class ProfileType(str, Enum):
    AUTHCHECK = 'authcheck'
    CUSTOM = 'custom'
    FAST = 'fast'
    FULL = 'full'
    OPTIMAL = 'optimal'
    SYSTEM = 'system'

    def __str__(self) -> str:
        return str(self.value)
