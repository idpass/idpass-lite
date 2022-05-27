# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: api.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import idpasslite_pb2 as idpasslite__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='api.proto',
  package='api',
  syntax='proto3',
  serialized_options=b'\n\rorg.api.protoP\001',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\tapi.proto\x12\x03\x61pi\x1a\x10idpasslite.proto\"\x9f\x01\n\tbyteArray\x12\x1f\n\x03typ\x18\x01 \x01(\x0e\x32\x12.api.byteArray.Typ\x12\x0b\n\x03val\x18\x02 \x01(\x0c\"d\n\x03Typ\x12\x08\n\x04\x42LOB\x10\x00\x12\x0b\n\x07\x41\x45\x41\x44KEY\x10\x01\x12\x11\n\rED25519PUBKEY\x10\x02\x12\x12\n\x0e\x45\x44\x32\x35\x35\x31\x39PRIVKEY\x10\x03\x12\x14\n\x10\x45\x44\x32\x35\x35\x31\x39SIGNATURE\x10\x04\x12\t\n\x05PHOTO\x10\x05\"*\n\nbyteArrays\x12\x1c\n\x04vals\x18\x01 \x03(\x0b\x32\x0e.api.byteArray\"_\n\x06KeySet\x12\x15\n\rencryptionKey\x18\x01 \x01(\x0c\x12\x14\n\x0csignatureKey\x18\x02 \x01(\x0c\x12(\n\x10verificationKeys\x18\x03 \x03(\x0b\x32\x0e.api.byteArray\"1\n\x0c\x43\x65rtificates\x12!\n\x04\x63\x65rt\x18\x01 \x03(\x0b\x32\x13.idpass.Certificate\"\xbf\x02\n\x05Ident\x12\x0f\n\x07surName\x18\x01 \x01(\t\x12\x11\n\tgivenName\x18\x02 \x01(\t\x12\x14\n\x0cplaceOfBirth\x18\x03 \x01(\t\x12\x0b\n\x03pin\x18\x04 \x01(\t\x12!\n\x0b\x64\x61teOfBirth\x18\x05 \x01(\x0b\x32\x0c.idpass.Date\x12\x1f\n\x06photos\x18\x06 \x01(\x0b\x32\x0f.api.byteArrays\x12\r\n\x05photo\x18\x07 \x01(\x0c\x12\x1f\n\tprivExtra\x18\x08 \x03(\x0b\x32\x0c.idpass.Pair\x12\x1e\n\x08pubExtra\x18\t \x03(\x0b\x32\x0c.idpass.Pair\x12\x0b\n\x03UIN\x18\n \x01(\t\x12\x10\n\x08\x66ullName\x18\x0b \x01(\t\x12\x0e\n\x06gender\x18\x0c \x01(\x05\x12,\n\rpostalAddress\x18\r \x01(\x0b\x32\x15.idpass.PostalAddress\"#\n\x06Idents\x12\x19\n\x05ident\x18\x01 \x03(\x0b\x32\n.api.IdentB\x11\n\rorg.api.protoP\x01\x62\x06proto3'
  ,
  dependencies=[idpasslite__pb2.DESCRIPTOR,])



_BYTEARRAY_TYP = _descriptor.EnumDescriptor(
  name='Typ',
  full_name='api.byteArray.Typ',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='BLOB', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='AEADKEY', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ED25519PUBKEY', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ED25519PRIVKEY', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='ED25519SIGNATURE', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PHOTO', index=5, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=96,
  serialized_end=196,
)
_sym_db.RegisterEnumDescriptor(_BYTEARRAY_TYP)


_BYTEARRAY = _descriptor.Descriptor(
  name='byteArray',
  full_name='api.byteArray',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='typ', full_name='api.byteArray.typ', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='val', full_name='api.byteArray.val', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _BYTEARRAY_TYP,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=37,
  serialized_end=196,
)


_BYTEARRAYS = _descriptor.Descriptor(
  name='byteArrays',
  full_name='api.byteArrays',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='vals', full_name='api.byteArrays.vals', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
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
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=198,
  serialized_end=240,
)


_KEYSET = _descriptor.Descriptor(
  name='KeySet',
  full_name='api.KeySet',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='encryptionKey', full_name='api.KeySet.encryptionKey', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='signatureKey', full_name='api.KeySet.signatureKey', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='verificationKeys', full_name='api.KeySet.verificationKeys', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
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
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=242,
  serialized_end=337,
)


_CERTIFICATES = _descriptor.Descriptor(
  name='Certificates',
  full_name='api.Certificates',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='cert', full_name='api.Certificates.cert', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
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
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=339,
  serialized_end=388,
)


_IDENT = _descriptor.Descriptor(
  name='Ident',
  full_name='api.Ident',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='surName', full_name='api.Ident.surName', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='givenName', full_name='api.Ident.givenName', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='placeOfBirth', full_name='api.Ident.placeOfBirth', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pin', full_name='api.Ident.pin', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='dateOfBirth', full_name='api.Ident.dateOfBirth', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='photos', full_name='api.Ident.photos', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='photo', full_name='api.Ident.photo', index=6,
      number=7, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='privExtra', full_name='api.Ident.privExtra', index=7,
      number=8, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pubExtra', full_name='api.Ident.pubExtra', index=8,
      number=9, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='UIN', full_name='api.Ident.UIN', index=9,
      number=10, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='fullName', full_name='api.Ident.fullName', index=10,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='gender', full_name='api.Ident.gender', index=11,
      number=12, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='postalAddress', full_name='api.Ident.postalAddress', index=12,
      number=13, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=391,
  serialized_end=710,
)


_IDENTS = _descriptor.Descriptor(
  name='Idents',
  full_name='api.Idents',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='ident', full_name='api.Idents.ident', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
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
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=712,
  serialized_end=747,
)

_BYTEARRAY.fields_by_name['typ'].enum_type = _BYTEARRAY_TYP
_BYTEARRAY_TYP.containing_type = _BYTEARRAY
_BYTEARRAYS.fields_by_name['vals'].message_type = _BYTEARRAY
_KEYSET.fields_by_name['verificationKeys'].message_type = _BYTEARRAY
_CERTIFICATES.fields_by_name['cert'].message_type = idpasslite__pb2._CERTIFICATE
_IDENT.fields_by_name['dateOfBirth'].message_type = idpasslite__pb2._DATE
_IDENT.fields_by_name['photos'].message_type = _BYTEARRAYS
_IDENT.fields_by_name['privExtra'].message_type = idpasslite__pb2._PAIR
_IDENT.fields_by_name['pubExtra'].message_type = idpasslite__pb2._PAIR
_IDENT.fields_by_name['postalAddress'].message_type = idpasslite__pb2._POSTALADDRESS
_IDENTS.fields_by_name['ident'].message_type = _IDENT
DESCRIPTOR.message_types_by_name['byteArray'] = _BYTEARRAY
DESCRIPTOR.message_types_by_name['byteArrays'] = _BYTEARRAYS
DESCRIPTOR.message_types_by_name['KeySet'] = _KEYSET
DESCRIPTOR.message_types_by_name['Certificates'] = _CERTIFICATES
DESCRIPTOR.message_types_by_name['Ident'] = _IDENT
DESCRIPTOR.message_types_by_name['Idents'] = _IDENTS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

byteArray = _reflection.GeneratedProtocolMessageType('byteArray', (_message.Message,), {
  'DESCRIPTOR' : _BYTEARRAY,
  '__module__' : 'api_pb2'
  # @@protoc_insertion_point(class_scope:api.byteArray)
  })
_sym_db.RegisterMessage(byteArray)

byteArrays = _reflection.GeneratedProtocolMessageType('byteArrays', (_message.Message,), {
  'DESCRIPTOR' : _BYTEARRAYS,
  '__module__' : 'api_pb2'
  # @@protoc_insertion_point(class_scope:api.byteArrays)
  })
_sym_db.RegisterMessage(byteArrays)

KeySet = _reflection.GeneratedProtocolMessageType('KeySet', (_message.Message,), {
  'DESCRIPTOR' : _KEYSET,
  '__module__' : 'api_pb2'
  # @@protoc_insertion_point(class_scope:api.KeySet)
  })
_sym_db.RegisterMessage(KeySet)

Certificates = _reflection.GeneratedProtocolMessageType('Certificates', (_message.Message,), {
  'DESCRIPTOR' : _CERTIFICATES,
  '__module__' : 'api_pb2'
  # @@protoc_insertion_point(class_scope:api.Certificates)
  })
_sym_db.RegisterMessage(Certificates)

Ident = _reflection.GeneratedProtocolMessageType('Ident', (_message.Message,), {
  'DESCRIPTOR' : _IDENT,
  '__module__' : 'api_pb2'
  # @@protoc_insertion_point(class_scope:api.Ident)
  })
_sym_db.RegisterMessage(Ident)

Idents = _reflection.GeneratedProtocolMessageType('Idents', (_message.Message,), {
  'DESCRIPTOR' : _IDENTS,
  '__module__' : 'api_pb2'
  # @@protoc_insertion_point(class_scope:api.Idents)
  })
_sym_db.RegisterMessage(Idents)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)