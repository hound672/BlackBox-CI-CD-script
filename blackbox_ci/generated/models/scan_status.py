from enum import Enum


class ScanStatus(str, Enum):
    CREATED = 'created'
    FINISHED = 'finished'
    SENT_START_TASK = 'sent_start_task'
    SENT_STOP_TASK = 'sent_stop_task'
    STARTED = 'started'
    STOPPED = 'stopped'

    def __str__(self) -> str:
        return str(self.value)
