from enum import Enum


class AuthDataStatus(str, Enum):
    CHECKING = 'checking'
    FAILED = 'failed'
    NOT_CHECKED = 'not_checked'
    SUCCESS = 'success'

    def __str__(self) -> str:
        return str(self.value)
