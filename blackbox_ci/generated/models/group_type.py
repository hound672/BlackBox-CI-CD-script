from enum import Enum


class GroupType(str, Enum):
    PERSONAL = 'personal'
    PRODUCT = 'product'
    USER = 'user'

    def __str__(self) -> str:
        return str(self.value)
