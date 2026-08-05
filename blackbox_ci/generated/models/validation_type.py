from enum import Enum


class ValidationType(str, Enum):
    REGEXP = 'regexp'
    STRING = 'string'
    WILDCARD = 'wildcard'

    def __str__(self) -> str:
        return str(self.value)
