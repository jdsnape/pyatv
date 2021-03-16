# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pyatv/mrp/protobuf/UpdateEndPointsMessage.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from pyatv.mrp.protobuf import ProtocolMessage_pb2 as pyatv_dot_mrp_dot_protobuf_dot_ProtocolMessage__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='pyatv/mrp/protobuf/UpdateEndPointsMessage.proto',
  package='',
  syntax='proto2',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n/pyatv/mrp/protobuf/UpdateEndPointsMessage.proto\x1a(pyatv/mrp/protobuf/ProtocolMessage.proto\"\xc9\x01\n\x14\x41VEndpointDescriptor\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x18\n\x10uniqueIdentifier\x18\x02 \x01(\t\x12\x17\n\x0fisLocalEndpoint\x18\x05 \x01(\x08\x12\x1a\n\x12instanceIdentifier\x18\x06 \x01(\t\x12\x1a\n\x12isProxyGroupPlayer\x18\x07 \x01(\x08\x12\x16\n\x0e\x63onnectionType\x18\x08 \x01(\x05\x12 \n\x18\x63\x61nModifyGroupMembership\x18\t \x01(\x08\"\\\n\x16UpdateEndPointsMessage\x12(\n\tendpoints\x18\x01 \x01(\x0b\x32\x15.AVEndpointDescriptor\x12\x18\n\x10\x65ndpointFeatures\x18\x02 \x01(\x05:I\n\x16updateEndPointsMessage\x12\x10.ProtocolMessage\x18S \x01(\x0b\x32\x17.UpdateEndPointsMessage'
  ,
  dependencies=[pyatv_dot_mrp_dot_protobuf_dot_ProtocolMessage__pb2.DESCRIPTOR,])


UPDATEENDPOINTSMESSAGE_FIELD_NUMBER = 83
updateEndPointsMessage = _descriptor.FieldDescriptor(
  name='updateEndPointsMessage', full_name='updateEndPointsMessage', index=0,
  number=83, type=11, cpp_type=10, label=1,
  has_default_value=False, default_value=None,
  message_type=None, enum_type=None, containing_type=None,
  is_extension=True, extension_scope=None,
  serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key)


_AVENDPOINTDESCRIPTOR = _descriptor.Descriptor(
  name='AVEndpointDescriptor',
  full_name='AVEndpointDescriptor',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='AVEndpointDescriptor.name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='uniqueIdentifier', full_name='AVEndpointDescriptor.uniqueIdentifier', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='isLocalEndpoint', full_name='AVEndpointDescriptor.isLocalEndpoint', index=2,
      number=5, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='instanceIdentifier', full_name='AVEndpointDescriptor.instanceIdentifier', index=3,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='isProxyGroupPlayer', full_name='AVEndpointDescriptor.isProxyGroupPlayer', index=4,
      number=7, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='connectionType', full_name='AVEndpointDescriptor.connectionType', index=5,
      number=8, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='canModifyGroupMembership', full_name='AVEndpointDescriptor.canModifyGroupMembership', index=6,
      number=9, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=94,
  serialized_end=295,
)


_UPDATEENDPOINTSMESSAGE = _descriptor.Descriptor(
  name='UpdateEndPointsMessage',
  full_name='UpdateEndPointsMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='endpoints', full_name='UpdateEndPointsMessage.endpoints', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='endpointFeatures', full_name='UpdateEndPointsMessage.endpointFeatures', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=297,
  serialized_end=389,
)

_UPDATEENDPOINTSMESSAGE.fields_by_name['endpoints'].message_type = _AVENDPOINTDESCRIPTOR
DESCRIPTOR.message_types_by_name['AVEndpointDescriptor'] = _AVENDPOINTDESCRIPTOR
DESCRIPTOR.message_types_by_name['UpdateEndPointsMessage'] = _UPDATEENDPOINTSMESSAGE
DESCRIPTOR.extensions_by_name['updateEndPointsMessage'] = updateEndPointsMessage
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

AVEndpointDescriptor = _reflection.GeneratedProtocolMessageType('AVEndpointDescriptor', (_message.Message,), {
  'DESCRIPTOR' : _AVENDPOINTDESCRIPTOR,
  '__module__' : 'pyatv.mrp.protobuf.UpdateEndPointsMessage_pb2'
  # @@protoc_insertion_point(class_scope:AVEndpointDescriptor)
  })
_sym_db.RegisterMessage(AVEndpointDescriptor)

UpdateEndPointsMessage = _reflection.GeneratedProtocolMessageType('UpdateEndPointsMessage', (_message.Message,), {
  'DESCRIPTOR' : _UPDATEENDPOINTSMESSAGE,
  '__module__' : 'pyatv.mrp.protobuf.UpdateEndPointsMessage_pb2'
  # @@protoc_insertion_point(class_scope:UpdateEndPointsMessage)
  })
_sym_db.RegisterMessage(UpdateEndPointsMessage)

updateEndPointsMessage.message_type = _UPDATEENDPOINTSMESSAGE
pyatv_dot_mrp_dot_protobuf_dot_ProtocolMessage__pb2.ProtocolMessage.RegisterExtension(updateEndPointsMessage)

# @@protoc_insertion_point(module_scope)
