from enum import IntEnum


class SharedLinkTTL(IntEnum):
    VALUE_3 = 3
    VALUE_24 = 24
    VALUE_168 = 168
    VALUE_720 = 720
    VALUE_4320 = 4320

    def __str__(self) -> str:
        return str(self.value)
