"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
from google.protobuf.descriptor import (
    Descriptor as google___protobuf___descriptor___Descriptor,
    FileDescriptor as google___protobuf___descriptor___FileDescriptor,
)

from google.protobuf.message import (
    Message as google___protobuf___message___Message,
)

from pyatv.mrp.protobuf.Common_pb2 import (
    RepeatMode as pyatv___mrp___protobuf___Common_pb2___RepeatMode,
    ShuffleMode as pyatv___mrp___protobuf___Common_pb2___ShuffleMode,
)

from typing import (
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

class CommandOptions(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    sourceId: typing___Text = ...
    mediaType: typing___Text = ...
    externalPlayerCommand: builtin___bool = ...
    skipInterval: builtin___float = ...
    playbackRate: builtin___float = ...
    rating: builtin___float = ...
    negative: builtin___bool = ...
    playbackPosition: builtin___float = ...
    repeatMode: pyatv___mrp___protobuf___Common_pb2___RepeatMode.EnumValue = ...
    shuffleMode: pyatv___mrp___protobuf___Common_pb2___ShuffleMode.EnumValue = ...
    trackID: builtin___int = ...
    radioStationID: builtin___int = ...
    radioStationHash: typing___Text = ...
    systemAppPlaybackQueueData: builtin___bytes = ...
    destinationAppDisplayID: typing___Text = ...
    sendOptions: builtin___int = ...
    requestDefermentToPlaybackQueuePosition: builtin___bool = ...
    contextID: typing___Text = ...
    shouldOverrideManuallyCuratedQueue: builtin___bool = ...
    stationURL: typing___Text = ...
    shouldBeginRadioPlayback: builtin___bool = ...
    playbackQueueInsertionPosition: builtin___int = ...
    contentItemID: typing___Text = ...
    playbackQueueOffset: builtin___int = ...
    playbackQueueDestinationOffset: builtin___int = ...
    languageOption: builtin___bytes = ...
    playbackQueueContext: builtin___bytes = ...
    insertAfterContentItemID: typing___Text = ...
    nowPlayingContentItemID: typing___Text = ...
    replaceIntent: builtin___int = ...

    def __init__(self,
        *,
        sourceId : typing___Optional[typing___Text] = None,
        mediaType : typing___Optional[typing___Text] = None,
        externalPlayerCommand : typing___Optional[builtin___bool] = None,
        skipInterval : typing___Optional[builtin___float] = None,
        playbackRate : typing___Optional[builtin___float] = None,
        rating : typing___Optional[builtin___float] = None,
        negative : typing___Optional[builtin___bool] = None,
        playbackPosition : typing___Optional[builtin___float] = None,
        repeatMode : typing___Optional[pyatv___mrp___protobuf___Common_pb2___RepeatMode.EnumValue] = None,
        shuffleMode : typing___Optional[pyatv___mrp___protobuf___Common_pb2___ShuffleMode.EnumValue] = None,
        trackID : typing___Optional[builtin___int] = None,
        radioStationID : typing___Optional[builtin___int] = None,
        radioStationHash : typing___Optional[typing___Text] = None,
        systemAppPlaybackQueueData : typing___Optional[builtin___bytes] = None,
        destinationAppDisplayID : typing___Optional[typing___Text] = None,
        sendOptions : typing___Optional[builtin___int] = None,
        requestDefermentToPlaybackQueuePosition : typing___Optional[builtin___bool] = None,
        contextID : typing___Optional[typing___Text] = None,
        shouldOverrideManuallyCuratedQueue : typing___Optional[builtin___bool] = None,
        stationURL : typing___Optional[typing___Text] = None,
        shouldBeginRadioPlayback : typing___Optional[builtin___bool] = None,
        playbackQueueInsertionPosition : typing___Optional[builtin___int] = None,
        contentItemID : typing___Optional[typing___Text] = None,
        playbackQueueOffset : typing___Optional[builtin___int] = None,
        playbackQueueDestinationOffset : typing___Optional[builtin___int] = None,
        languageOption : typing___Optional[builtin___bytes] = None,
        playbackQueueContext : typing___Optional[builtin___bytes] = None,
        insertAfterContentItemID : typing___Optional[typing___Text] = None,
        nowPlayingContentItemID : typing___Optional[typing___Text] = None,
        replaceIntent : typing___Optional[builtin___int] = None,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions___Literal[u"contentItemID",b"contentItemID",u"contextID",b"contextID",u"destinationAppDisplayID",b"destinationAppDisplayID",u"externalPlayerCommand",b"externalPlayerCommand",u"insertAfterContentItemID",b"insertAfterContentItemID",u"languageOption",b"languageOption",u"mediaType",b"mediaType",u"negative",b"negative",u"nowPlayingContentItemID",b"nowPlayingContentItemID",u"playbackPosition",b"playbackPosition",u"playbackQueueContext",b"playbackQueueContext",u"playbackQueueDestinationOffset",b"playbackQueueDestinationOffset",u"playbackQueueInsertionPosition",b"playbackQueueInsertionPosition",u"playbackQueueOffset",b"playbackQueueOffset",u"playbackRate",b"playbackRate",u"radioStationHash",b"radioStationHash",u"radioStationID",b"radioStationID",u"rating",b"rating",u"repeatMode",b"repeatMode",u"replaceIntent",b"replaceIntent",u"requestDefermentToPlaybackQueuePosition",b"requestDefermentToPlaybackQueuePosition",u"sendOptions",b"sendOptions",u"shouldBeginRadioPlayback",b"shouldBeginRadioPlayback",u"shouldOverrideManuallyCuratedQueue",b"shouldOverrideManuallyCuratedQueue",u"shuffleMode",b"shuffleMode",u"skipInterval",b"skipInterval",u"sourceId",b"sourceId",u"stationURL",b"stationURL",u"systemAppPlaybackQueueData",b"systemAppPlaybackQueueData",u"trackID",b"trackID"]) -> builtin___bool: ...
    def ClearField(self, field_name: typing_extensions___Literal[u"contentItemID",b"contentItemID",u"contextID",b"contextID",u"destinationAppDisplayID",b"destinationAppDisplayID",u"externalPlayerCommand",b"externalPlayerCommand",u"insertAfterContentItemID",b"insertAfterContentItemID",u"languageOption",b"languageOption",u"mediaType",b"mediaType",u"negative",b"negative",u"nowPlayingContentItemID",b"nowPlayingContentItemID",u"playbackPosition",b"playbackPosition",u"playbackQueueContext",b"playbackQueueContext",u"playbackQueueDestinationOffset",b"playbackQueueDestinationOffset",u"playbackQueueInsertionPosition",b"playbackQueueInsertionPosition",u"playbackQueueOffset",b"playbackQueueOffset",u"playbackRate",b"playbackRate",u"radioStationHash",b"radioStationHash",u"radioStationID",b"radioStationID",u"rating",b"rating",u"repeatMode",b"repeatMode",u"replaceIntent",b"replaceIntent",u"requestDefermentToPlaybackQueuePosition",b"requestDefermentToPlaybackQueuePosition",u"sendOptions",b"sendOptions",u"shouldBeginRadioPlayback",b"shouldBeginRadioPlayback",u"shouldOverrideManuallyCuratedQueue",b"shouldOverrideManuallyCuratedQueue",u"shuffleMode",b"shuffleMode",u"skipInterval",b"skipInterval",u"sourceId",b"sourceId",u"stationURL",b"stationURL",u"systemAppPlaybackQueueData",b"systemAppPlaybackQueueData",u"trackID",b"trackID"]) -> None: ...
type___CommandOptions = CommandOptions
