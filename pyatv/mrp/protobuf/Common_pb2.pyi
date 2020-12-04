# @generated by generate_proto_mypy_stubs.py.  Do not edit!
import sys
from google.protobuf.descriptor import (
    Descriptor as google___protobuf___descriptor___Descriptor,
    EnumDescriptor as google___protobuf___descriptor___EnumDescriptor,
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
    cast as typing___cast,
)


builtin___int = int


DESCRIPTOR: google___protobuf___descriptor___FileDescriptor = ...

class RepeatMode(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    EnumValue = typing___NewType('EnumValue', builtin___int)
    type___EnumValue = EnumValue
    Enum: _Enum
    class _Enum(google___protobuf___internal___enum_type_wrapper____EnumTypeWrapper[RepeatMode.EnumValue]):
        DESCRIPTOR: google___protobuf___descriptor___EnumDescriptor = ...
        Unknown = typing___cast(RepeatMode.EnumValue, 0)
        Off = typing___cast(RepeatMode.EnumValue, 1)
        One = typing___cast(RepeatMode.EnumValue, 2)
        All = typing___cast(RepeatMode.EnumValue, 3)
    Unknown = typing___cast(RepeatMode.EnumValue, 0)
    Off = typing___cast(RepeatMode.EnumValue, 1)
    One = typing___cast(RepeatMode.EnumValue, 2)
    All = typing___cast(RepeatMode.EnumValue, 3)
    type___Enum = Enum


    def __init__(self,
        ) -> None: ...
type___RepeatMode = RepeatMode

class ShuffleMode(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    EnumValue = typing___NewType('EnumValue', builtin___int)
    type___EnumValue = EnumValue
    Enum: _Enum
    class _Enum(google___protobuf___internal___enum_type_wrapper____EnumTypeWrapper[ShuffleMode.EnumValue]):
        DESCRIPTOR: google___protobuf___descriptor___EnumDescriptor = ...
        Unknown = typing___cast(ShuffleMode.EnumValue, 0)
        Off = typing___cast(ShuffleMode.EnumValue, 1)
        Albums = typing___cast(ShuffleMode.EnumValue, 2)
        Songs = typing___cast(ShuffleMode.EnumValue, 3)
    Unknown = typing___cast(ShuffleMode.EnumValue, 0)
    Off = typing___cast(ShuffleMode.EnumValue, 1)
    Albums = typing___cast(ShuffleMode.EnumValue, 2)
    Songs = typing___cast(ShuffleMode.EnumValue, 3)
    type___Enum = Enum


    def __init__(self,
        ) -> None: ...
type___ShuffleMode = ShuffleMode

class DeviceClass(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    EnumValue = typing___NewType('EnumValue', builtin___int)
    type___EnumValue = EnumValue
    Enum: _Enum
    class _Enum(google___protobuf___internal___enum_type_wrapper____EnumTypeWrapper[DeviceClass.EnumValue]):
        DESCRIPTOR: google___protobuf___descriptor___EnumDescriptor = ...
        Invalid = typing___cast(DeviceClass.EnumValue, 0)
        iPhone = typing___cast(DeviceClass.EnumValue, 1)
        iPod = typing___cast(DeviceClass.EnumValue, 2)
        iPad = typing___cast(DeviceClass.EnumValue, 3)
        AppleTV = typing___cast(DeviceClass.EnumValue, 4)
        iFPGA = typing___cast(DeviceClass.EnumValue, 5)
        Watch = typing___cast(DeviceClass.EnumValue, 6)
        Accessory = typing___cast(DeviceClass.EnumValue, 7)
        Bridge = typing___cast(DeviceClass.EnumValue, 8)
        Mac = typing___cast(DeviceClass.EnumValue, 9)
    Invalid = typing___cast(DeviceClass.EnumValue, 0)
    iPhone = typing___cast(DeviceClass.EnumValue, 1)
    iPod = typing___cast(DeviceClass.EnumValue, 2)
    iPad = typing___cast(DeviceClass.EnumValue, 3)
    AppleTV = typing___cast(DeviceClass.EnumValue, 4)
    iFPGA = typing___cast(DeviceClass.EnumValue, 5)
    Watch = typing___cast(DeviceClass.EnumValue, 6)
    Accessory = typing___cast(DeviceClass.EnumValue, 7)
    Bridge = typing___cast(DeviceClass.EnumValue, 8)
    Mac = typing___cast(DeviceClass.EnumValue, 9)
    type___Enum = Enum


    def __init__(self,
        ) -> None: ...
type___DeviceClass = DeviceClass

class DeviceType(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    EnumValue = typing___NewType('EnumValue', builtin___int)
    type___EnumValue = EnumValue
    Enum: _Enum
    class _Enum(google___protobuf___internal___enum_type_wrapper____EnumTypeWrapper[DeviceType.EnumValue]):
        DESCRIPTOR: google___protobuf___descriptor___EnumDescriptor = ...
        Unknown = typing___cast(DeviceType.EnumValue, 0)
        AirPlay = typing___cast(DeviceType.EnumValue, 1)
        Bluetooth = typing___cast(DeviceType.EnumValue, 2)
        CarPlay = typing___cast(DeviceType.EnumValue, 3)
        BuiltIn = typing___cast(DeviceType.EnumValue, 4)
        Wired = typing___cast(DeviceType.EnumValue, 5)
    Unknown = typing___cast(DeviceType.EnumValue, 0)
    AirPlay = typing___cast(DeviceType.EnumValue, 1)
    Bluetooth = typing___cast(DeviceType.EnumValue, 2)
    CarPlay = typing___cast(DeviceType.EnumValue, 3)
    BuiltIn = typing___cast(DeviceType.EnumValue, 4)
    Wired = typing___cast(DeviceType.EnumValue, 5)
    type___Enum = Enum


    def __init__(self,
        ) -> None: ...
type___DeviceType = DeviceType

class DeviceSubType(google___protobuf___message___Message):
    DESCRIPTOR: google___protobuf___descriptor___Descriptor = ...
    EnumValue = typing___NewType('EnumValue', builtin___int)
    type___EnumValue = EnumValue
    Enum: _Enum
    class _Enum(google___protobuf___internal___enum_type_wrapper____EnumTypeWrapper[DeviceSubType.EnumValue]):
        DESCRIPTOR: google___protobuf___descriptor___EnumDescriptor = ...
        Default = typing___cast(DeviceSubType.EnumValue, 0)
        Speaker = typing___cast(DeviceSubType.EnumValue, 1)
        Headphones = typing___cast(DeviceSubType.EnumValue, 2)
        Headset = typing___cast(DeviceSubType.EnumValue, 3)
        Receiver = typing___cast(DeviceSubType.EnumValue, 4)
        LineOut = typing___cast(DeviceSubType.EnumValue, 5)
        USB = typing___cast(DeviceSubType.EnumValue, 6)
        DisplayPort = typing___cast(DeviceSubType.EnumValue, 7)
        HDMI = typing___cast(DeviceSubType.EnumValue, 8)
        LowEnergy = typing___cast(DeviceSubType.EnumValue, 9)
        SPDIF = typing___cast(DeviceSubType.EnumValue, 10)
        TV = typing___cast(DeviceSubType.EnumValue, 11)
        HomePod = typing___cast(DeviceSubType.EnumValue, 12)
        AppleTV = typing___cast(DeviceSubType.EnumValue, 13)
    Default = typing___cast(DeviceSubType.EnumValue, 0)
    Speaker = typing___cast(DeviceSubType.EnumValue, 1)
    Headphones = typing___cast(DeviceSubType.EnumValue, 2)
    Headset = typing___cast(DeviceSubType.EnumValue, 3)
    Receiver = typing___cast(DeviceSubType.EnumValue, 4)
    LineOut = typing___cast(DeviceSubType.EnumValue, 5)
    USB = typing___cast(DeviceSubType.EnumValue, 6)
    DisplayPort = typing___cast(DeviceSubType.EnumValue, 7)
    HDMI = typing___cast(DeviceSubType.EnumValue, 8)
    LowEnergy = typing___cast(DeviceSubType.EnumValue, 9)
    SPDIF = typing___cast(DeviceSubType.EnumValue, 10)
    TV = typing___cast(DeviceSubType.EnumValue, 11)
    HomePod = typing___cast(DeviceSubType.EnumValue, 12)
    AppleTV = typing___cast(DeviceSubType.EnumValue, 13)
    type___Enum = Enum


    def __init__(self,
        ) -> None: ...
type___DeviceSubType = DeviceSubType
