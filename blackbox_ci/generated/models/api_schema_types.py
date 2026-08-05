from enum import Enum


class APISchemaTypes(str, Enum):
    HAR = 'har'
    OPENAPI = 'openapi'

    def __str__(self) -> str:
        return str(self.value)
