from enum import Enum


class CrawlingType(str, Enum):
    FULL_CRAWLING_MODE = 'full_crawling_mode'
    SMART = 'smart'

    def __str__(self) -> str:
        return str(self.value)
