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

from pyatv.mrp.protobuf.PlaybackQueueContext_pb2 import (
    PlaybackQueueContext as pyatv___mrp___protobuf___PlaybackQueueContext_pb2___PlaybackQueueContext,
)

from pyatv.mrp.protobuf.PlayerPath_pb2 import (
    PlayerPath as pyatv___mrp___protobuf___PlayerPath_pb2___PlayerPath,
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

class PlaybackQueueRequestMessage(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    location: builtin___int = ...
    length: builtin___int = ...
    includeMetadata: builtin___bool = ...
    artworkWidth: builtin___float = ...
    artworkHeight: builtin___float = ...
    includeLyrics: builtin___bool = ...
    includeSections: builtin___bool = ...
    includeInfo: builtin___bool = ...
    includeLanguageOptions: builtin___bool = ...
    requestID: typing___Text = ...
    contentItemIdentifiers: google___protobuf___internal___containers___RepeatedScalarFieldContainer[typing___Text] = ...
    returnContentItemAssetsInUserCompletion: builtin___bool = ...
    cachingPolicy: builtin___int = ...
    label: typing___Text = ...
    isLegacyNowPlayingInfoRequest: builtin___bool = ...

    @property
    def context(self) -> pyatv___mrp___protobuf___PlaybackQueueContext_pb2___PlaybackQueueContext: ...

    @property
    def playerPath(self) -> pyatv___mrp___protobuf___PlayerPath_pb2___PlayerPath: ...

    def __init__(self,
        *,
        location : typing___Optional[builtin___int] = None,
        length : typing___Optional[builtin___int] = None,
        includeMetadata : typing___Optional[builtin___bool] = None,
        artworkWidth : typing___Optional[builtin___float] = None,
        artworkHeight : typing___Optional[builtin___float] = None,
        includeLyrics : typing___Optional[builtin___bool] = None,
        includeSections : typing___Optional[builtin___bool] = None,
        includeInfo : typing___Optional[builtin___bool] = None,
        includeLanguageOptions : typing___Optional[builtin___bool] = None,
        context : typing___Optional[pyatv___mrp___protobuf___PlaybackQueueContext_pb2___PlaybackQueueContext] = None,
        requestID : typing___Optional[typing___Text] = None,
        contentItemIdentifiers : typing___Optional[typing___Iterable[typing___Text]] = None,
        returnContentItemAssetsInUserCompletion : typing___Optional[builtin___bool] = None,
        playerPath : typing___Optional[pyatv___mrp___protobuf___PlayerPath_pb2___PlayerPath] = None,
        cachingPolicy : typing___Optional[builtin___int] = None,
        label : typing___Optional[typing___Text] = None,
        isLegacyNowPlayingInfoRequest : typing___Optional[builtin___bool] = None,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions___Literal[u"artworkHeight",b"artworkHeight",u"artworkWidth",b"artworkWidth",u"cachingPolicy",b"cachingPolicy",u"context",b"context",u"includeInfo",b"includeInfo",u"includeLanguageOptions",b"includeLanguageOptions",u"includeLyrics",b"includeLyrics",u"includeMetadata",b"includeMetadata",u"includeSections",b"includeSections",u"isLegacyNowPlayingInfoRequest",b"isLegacyNowPlayingInfoRequest",u"label",b"label",u"length",b"length",u"location",b"location",u"playerPath",b"playerPath",u"requestID",b"requestID",u"returnContentItemAssetsInUserCompletion",b"returnContentItemAssetsInUserCompletion"]) -> builtin___bool: ...
    def ClearField(self, field_name: typing_extensions___Literal[u"artworkHeight",b"artworkHeight",u"artworkWidth",b"artworkWidth",u"cachingPolicy",b"cachingPolicy",u"contentItemIdentifiers",b"contentItemIdentifiers",u"context",b"context",u"includeInfo",b"includeInfo",u"includeLanguageOptions",b"includeLanguageOptions",u"includeLyrics",b"includeLyrics",u"includeMetadata",b"includeMetadata",u"includeSections",b"includeSections",u"isLegacyNowPlayingInfoRequest",b"isLegacyNowPlayingInfoRequest",u"label",b"label",u"length",b"length",u"location",b"location",u"playerPath",b"playerPath",u"requestID",b"requestID",u"returnContentItemAssetsInUserCompletion",b"returnContentItemAssetsInUserCompletion"]) -> None: ...
type___PlaybackQueueRequestMessage = PlaybackQueueRequestMessage

playbackQueueRequestMessage: google___protobuf___descriptor___FieldDescriptor = ...
