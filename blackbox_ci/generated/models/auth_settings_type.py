from enum import Enum


class AuthSettingsType(str, Enum):
    CHAIN = 'chain'
    USER = 'user'

    def __str__(self) -> str:
        return str(self.value)
