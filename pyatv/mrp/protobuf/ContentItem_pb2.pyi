"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
from google.protobuf.descriptor import (
    Descriptor as google___protobuf___descriptor___Descriptor,
    FileDescriptor as google___protobuf___descriptor___FileDescriptor,
)

from google.protobuf.internal.containers import (
    RepeatedCompositeFieldContainer as google___protobuf___internal___containers___RepeatedCompositeFieldContainer,
)

from google.protobuf.message import (
    Message as google___protobuf___message___Message,
)

from pyatv.mrp.protobuf.ContentItemMetadata_pb2 import (
    ContentItemMetadata as pyatv___mrp___protobuf___ContentItemMetadata_pb2___ContentItemMetadata,
)

from pyatv.mrp.protobuf.LanguageOption_pb2 import (
    LanguageOption as pyatv___mrp___protobuf___LanguageOption_pb2___LanguageOption,
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

class LanguageOptionGroup(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    allowEmptySelection: builtin___bool = ...

    @property
    def defaultLanguageOption(self) -> pyatv___mrp___protobuf___LanguageOption_pb2___LanguageOption: ...

    @property
    def languageOptions(self) -> google___protobuf___internal___containers___RepeatedCompositeFieldContainer[pyatv___mrp___protobuf___LanguageOption_pb2___LanguageOption]: ...

    def __init__(self,
        *,
        allowEmptySelection : typing___Optional[builtin___bool] = None,
        defaultLanguageOption : typing___Optional[pyatv___mrp___protobuf___LanguageOption_pb2___LanguageOption] = None,
        languageOptions : typing___Optional[typing___Iterable[pyatv___mrp___protobuf___LanguageOption_pb2___LanguageOption]] = None,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions___Literal[u"allowEmptySelection",b"allowEmptySelection",u"defaultLanguageOption",b"defaultLanguageOption"]) -> builtin___bool: ...
    def ClearField(self, field_name: typing_extensions___Literal[u"allowEmptySelection",b"allowEmptySelection",u"defaultLanguageOption",b"defaultLanguageOption",u"languageOptions",b"languageOptions"]) -> None: ...
type___LanguageOptionGroup = LanguageOptionGroup

class ContentItem(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    identifier: typing___Text = ...
    artworkData: builtin___bytes = ...
    info: typing___Text = ...
    parentIdentifier: typing___Text = ...
    ancestorIdentifier: typing___Text = ...
    queueIdentifier: typing___Text = ...
    requestIdentifier: typing___Text = ...
    artworkDataWidth: builtin___int = ...
    artworkDataHeight: builtin___int = ...

    @property
    def metadata(self) -> pyatv___mrp___protobuf___ContentItemMetadata_pb2___ContentItemMetadata: ...

    @property
    def availableLanguageOptions(self) -> google___protobuf___internal___containers___RepeatedCompositeFieldContainer[type___LanguageOptionGroup]: ...

    @property
    def currentLanguageOptions(self) -> google___protobuf___internal___containers___RepeatedCompositeFieldContainer[pyatv___mrp___protobuf___LanguageOption_pb2___LanguageOption]: ...

    def __init__(self,
        *,
        identifier : typing___Optional[typing___Text] = None,
        metadata : typing___Optional[pyatv___mrp___protobuf___ContentItemMetadata_pb2___ContentItemMetadata] = None,
        artworkData : typing___Optional[builtin___bytes] = None,
        info : typing___Optional[typing___Text] = None,
        availableLanguageOptions : typing___Optional[typing___Iterable[type___LanguageOptionGroup]] = None,
        currentLanguageOptions : typing___Optional[typing___Iterable[pyatv___mrp___protobuf___LanguageOption_pb2___LanguageOption]] = None,
        parentIdentifier : typing___Optional[typing___Text] = None,
        ancestorIdentifier : typing___Optional[typing___Text] = None,
        queueIdentifier : typing___Optional[typing___Text] = None,
        requestIdentifier : typing___Optional[typing___Text] = None,
        artworkDataWidth : typing___Optional[builtin___int] = None,
        artworkDataHeight : typing___Optional[builtin___int] = None,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions___Literal[u"ancestorIdentifier",b"ancestorIdentifier",u"artworkData",b"artworkData",u"artworkDataHeight",b"artworkDataHeight",u"artworkDataWidth",b"artworkDataWidth",u"identifier",b"identifier",u"info",b"info",u"metadata",b"metadata",u"parentIdentifier",b"parentIdentifier",u"queueIdentifier",b"queueIdentifier",u"requestIdentifier",b"requestIdentifier"]) -> builtin___bool: ...
    def ClearField(self, field_name: typing_extensions___Literal[u"ancestorIdentifier",b"ancestorIdentifier",u"artworkData",b"artworkData",u"artworkDataHeight",b"artworkDataHeight",u"artworkDataWidth",b"artworkDataWidth",u"availableLanguageOptions",b"availableLanguageOptions",u"currentLanguageOptions",b"currentLanguageOptions",u"identifier",b"identifier",u"info",b"info",u"metadata",b"metadata",u"parentIdentifier",b"parentIdentifier",u"queueIdentifier",b"queueIdentifier",u"requestIdentifier",b"requestIdentifier"]) -> None: ...
type___ContentItem = ContentItem
