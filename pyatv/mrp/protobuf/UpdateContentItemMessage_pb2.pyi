"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
from google.protobuf.descriptor import (
    Descriptor as google___protobuf___descriptor___Descriptor,
    FieldDescriptor as google___protobuf___descriptor___FieldDescriptor,
    FileDescriptor as google___protobuf___descriptor___FileDescriptor,
)

from google.protobuf.internal.containers import (
    RepeatedCompositeFieldContainer as google___protobuf___internal___containers___RepeatedCompositeFieldContainer,
)

from google.protobuf.message import (
    Message as google___protobuf___message___Message,
)

from pyatv.mrp.protobuf.ContentItem_pb2 import (
    ContentItem as pyatv___mrp___protobuf___ContentItem_pb2___ContentItem,
)

from pyatv.mrp.protobuf.PlayerPath_pb2 import (
    PlayerPath as pyatv___mrp___protobuf___PlayerPath_pb2___PlayerPath,
)

from typing import (
    Iterable as typing___Iterable,
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

class UpdateContentItemMessage(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...

    @property
    def contentItems(self) -> google___protobuf___internal___containers___RepeatedCompositeFieldContainer[pyatv___mrp___protobuf___ContentItem_pb2___ContentItem]: ...

    @property
    def playerPath(self) -> pyatv___mrp___protobuf___PlayerPath_pb2___PlayerPath: ...

    def __init__(self,
        *,
        contentItems : typing___Optional[typing___Iterable[pyatv___mrp___protobuf___ContentItem_pb2___ContentItem]] = None,
        playerPath : typing___Optional[pyatv___mrp___protobuf___PlayerPath_pb2___PlayerPath] = None,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions___Literal[u"playerPath",b"playerPath"]) -> builtin___bool: ...
    def ClearField(self, field_name: typing_extensions___Literal[u"contentItems",b"contentItems",u"playerPath",b"playerPath"]) -> None: ...
type___UpdateContentItemMessage = UpdateContentItemMessage

updateContentItemMessage: google___protobuf___descriptor___FieldDescriptor = ...
