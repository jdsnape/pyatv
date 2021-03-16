"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
from google.protobuf.descriptor import (
    Descriptor as google___protobuf___descriptor___Descriptor,
    FieldDescriptor as google___protobuf___descriptor___FieldDescriptor,
    FileDescriptor as google___protobuf___descriptor___FileDescriptor,
)

from google.protobuf.message import (
    Message as google___protobuf___message___Message,
)

from pyatv.mrp.protobuf.PlayerPath_pb2 import (
    PlayerPath as pyatv___mrp___protobuf___PlayerPath_pb2___PlayerPath,
)

from typing import (
    Optional as typing___Optional,
)

from typing_extensions import (
    Literal as typing_extensions___Literal,
)


builtin___bool = bool
builtin___bytes = bytes
builtin___float = float
builtin___int = int


DESCRIPTOR: google___protobuf___descriptor___FileDescriptor = ...

class SetNowPlayingPlayerMessage(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...

    @property
    def playerPath(self) -> pyatv___mrp___protobuf___PlayerPath_pb2___PlayerPath: ...

    def __init__(self,
        *,
        playerPath : typing___Optional[pyatv___mrp___protobuf___PlayerPath_pb2___PlayerPath] = None,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions___Literal[u"playerPath",b"playerPath"]) -> builtin___bool: ...
    def ClearField(self, field_name: typing_extensions___Literal[u"playerPath",b"playerPath"]) -> None: ...
type___SetNowPlayingPlayerMessage = SetNowPlayingPlayerMessage

setNowPlayingPlayerMessage: google___protobuf___descriptor___FieldDescriptor = ...
