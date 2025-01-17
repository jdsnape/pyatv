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
    RepeatedScalarFieldContainer as google___protobuf___internal___containers___RepeatedScalarFieldContainer,
)

from google.protobuf.message import (
    Message as google___protobuf___message___Message,
)

from typing import (
    Iterable as typing___Iterable,
    Optional as typing___Optional,
    Text as typing___Text,
)

from typing_extensions import (
    Literal as typing_extensions___Literal,
)


builtin___bool = bool
builtin___bytes = bytes
builtin___float = float
builtin___int = int


DESCRIPTOR: google___protobuf___descriptor___FileDescriptor = ...

class NotificationMessage(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    notification: google___protobuf___internal___containers___RepeatedScalarFieldContainer[typing___Text] = ...
    userInfo: google___protobuf___internal___containers___RepeatedScalarFieldContainer[builtin___bytes] = ...

    def __init__(self,
        *,
        notification : typing___Optional[typing___Iterable[typing___Text]] = None,
        userInfo : typing___Optional[typing___Iterable[builtin___bytes]] = None,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions___Literal[u"notification",b"notification",u"userInfo",b"userInfo"]) -> None: ...
type___NotificationMessage = NotificationMessage

notificationMessage: google___protobuf___descriptor___FieldDescriptor = ...
