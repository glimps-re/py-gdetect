"""
stream declare interface to be used for BufferIO or other kind of readers
"""
from typing import Protocol, Optional


class StreamReader(Protocol):
    """StreamReader implements read and readinto methods"""

    def read(self, amount: int) -> Optional[bytes]: ...
    # buffer should be typed as WriteableBuffer
    # (see _typeshed or mypy.typeshed.stdlib._typeshed)
    # but I have not found how to import this type or redeclare it
    # without importing protected members
    def readinto(self, buffer) -> Optional[int]: ...


class StreamReaderSeeker(StreamReader, Protocol):
    """StreamReaderSeeker implements read, readinto and seek methods"""
    def seek(self, offset: int, whence: int): ...
