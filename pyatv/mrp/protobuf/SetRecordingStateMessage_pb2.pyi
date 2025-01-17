"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
from google.protobuf.descriptor import (
    Descriptor as google___protobuf___descriptor___Descriptor,
    EnumDescriptor as google___protobuf___descriptor___EnumDescriptor,
    FieldDescriptor as google___protobuf___descriptor___FieldDescriptor,
    FileDescriptor as google___protobuf___descriptor___FileDescriptor,
)

from google.protobuf.internal.enum_type_wrapper import (
    _EnumTypeWrapper as google___protobuf___internal___enum_type_wrapper____EnumTypeWrapper,
)

from google.protobuf.message import (
    Message as google___protobuf___message___Message,
)

from typing import (
    NewType as typing___NewType,
    Optional as typing___Optional,
    cast as typing___cast,
)

from typing_extensions import (
    Literal as typing_extensions___Literal,
)


builtin___bool = bool
builtin___bytes = bytes
builtin___float = float
builtin___int = int


DESCRIPTOR: google___protobuf___descriptor___FileDescriptor = ...

class SetRecordingStateMessage(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    RecordingStateValue = typing___NewType('RecordingStateValue', builtin___int)
    type___RecordingStateValue = RecordingStateValue
    RecordingState: _RecordingState
    class _RecordingState(google___protobuf___internal___enum_type_wrapper____EnumTypeWrapper[SetRecordingStateMessage.RecordingStateValue]):
        DESCRIPTOR: google___protobuf___descriptor___EnumDescriptor = ...
        Unknown = typing___cast(SetRecordingStateMessage.RecordingStateValue, 0)
        Recording = typing___cast(SetRecordingStateMessage.RecordingStateValue, 1)
        NotRecording = typing___cast(SetRecordingStateMessage.RecordingStateValue, 2)
    Unknown = typing___cast(SetRecordingStateMessage.RecordingStateValue, 0)
    Recording = typing___cast(SetRecordingStateMessage.RecordingStateValue, 1)
    NotRecording = typing___cast(SetRecordingStateMessage.RecordingStateValue, 2)

    state: type___SetRecordingStateMessage.RecordingStateValue = ...

    def __init__(self,
        *,
        state : typing___Optional[type___SetRecordingStateMessage.RecordingStateValue] = None,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions___Literal[u"state",b"state"]) -> builtin___bool: ...
    def ClearField(self, field_name: typing_extensions___Literal[u"state",b"state"]) -> None: ...
type___SetRecordingStateMessage = SetRecordingStateMessage

setRecordingStateMessage: google___protobuf___descriptor___FieldDescriptor = ...
