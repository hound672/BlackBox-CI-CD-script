from enum import Enum


class APISchemaContentTypes(str, Enum):
    APPLICATIONJSON = 'application/json'
    APPLICATIONYAML = 'application/yaml'
    LINK = 'link'

    def __str__(self) -> str:
        return str(self.value)
