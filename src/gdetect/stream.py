from typing import Protocol, Optional


class StreamReader(Protocol):
    def read(self, amount: int) -> Optional[bytes]: ...

    # buffer should be typed as WriteableBuffer
    # (see _typeshed or mypy.typeshed.stdlib._typeshed)
    # but I have not found how to import this type or redeclare it
    # without importing protected members
    def readinto(self, buffer) -> Optional[int]: ...


class StreamReaderSeeker(StreamReader, Protocol):
    def seek(self, offset: int, whence: int): ...
