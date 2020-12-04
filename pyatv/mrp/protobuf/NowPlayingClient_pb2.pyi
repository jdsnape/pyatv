# @generated by generate_proto_mypy_stubs.py.  Do not edit!
import sys
from google.protobuf.descriptor import (
    Descriptor as google___protobuf___descriptor___Descriptor,
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

class NowPlayingClient(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    processIdentifier: builtin___int = ...
    bundleIdentifier: typing___Text = ...
    parentApplicationBundleIdentifier: typing___Text = ...
    processUserIdentifier: builtin___int = ...
    nowPlayingVisibility: builtin___int = ...
    displayName: typing___Text = ...
    bundleIdentifierHierarchys: google___protobuf___internal___containers___RepeatedScalarFieldContainer[typing___Text] = ...

    def __init__(self,
        *,
        processIdentifier : typing___Optional[builtin___int] = None,
        bundleIdentifier : typing___Optional[typing___Text] = None,
        parentApplicationBundleIdentifier : typing___Optional[typing___Text] = None,
        processUserIdentifier : typing___Optional[builtin___int] = None,
        nowPlayingVisibility : typing___Optional[builtin___int] = None,
        displayName : typing___Optional[typing___Text] = None,
        bundleIdentifierHierarchys : typing___Optional[typing___Iterable[typing___Text]] = None,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions___Literal[u"bundleIdentifier",b"bundleIdentifier",u"displayName",b"displayName",u"nowPlayingVisibility",b"nowPlayingVisibility",u"parentApplicationBundleIdentifier",b"parentApplicationBundleIdentifier",u"processIdentifier",b"processIdentifier",u"processUserIdentifier",b"processUserIdentifier"]) -> builtin___bool: ...
    def ClearField(self, field_name: typing_extensions___Literal[u"bundleIdentifier",b"bundleIdentifier",u"bundleIdentifierHierarchys",b"bundleIdentifierHierarchys",u"displayName",b"displayName",u"nowPlayingVisibility",b"nowPlayingVisibility",u"parentApplicationBundleIdentifier",b"parentApplicationBundleIdentifier",u"processIdentifier",b"processIdentifier",u"processUserIdentifier",b"processUserIdentifier"]) -> None: ...
type___NowPlayingClient = NowPlayingClient
