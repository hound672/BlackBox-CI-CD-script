from enum import Enum


class ScanScope(str, Enum):
    BASE_DOMAIN = 'base_domain'
    DOMAIN = 'domain'
    FOLDER = 'folder'
    PATH = 'path'
    SUBDOMAIN = 'subdomain'

    def __str__(self) -> str:
        return str(self.value)
