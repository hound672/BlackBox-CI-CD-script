from enum import Enum


class ReportLangEnum(str, Enum):
    EN = 'en'
    RU = 'ru'

    def __str__(self) -> str:
        return str(self.value)
