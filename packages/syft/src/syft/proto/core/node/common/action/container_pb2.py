# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: proto/core/node/common/action/container.proto
"""Generated protocol buffer code."""
# third party
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


# syft absolute
from syft.proto.core.io import address_pb2 as proto_dot_core_dot_io_dot_address__pb2
from syft.proto.core.node.common.action import (
    save_object_pb2 as proto_dot_core_dot_node_dot_common_dot_action_dot_save__object__pb2,
)

DESCRIPTOR = _descriptor.FileDescriptor(
    name="proto/core/node/common/action/container.proto",
    package="syft.core.node.common.action",
    syntax="proto3",
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
    serialized_pb=b'\n-proto/core/node/common/action/container.proto\x12\x1csyft.core.node.common.action\x1a/proto/core/node/common/action/save_object.proto\x1a\x1bproto/core/io/address.proto"v\n\x0f\x43ontainerAction\x12;\n\x03obj\x18\x01 \x03(\x0b\x32..syft.core.node.common.action.SaveObjectAction\x12&\n\x07\x61\x64\x64ress\x18\x02 \x01(\x0b\x32\x15.syft.core.io.Addressb\x06proto3',
    dependencies=[
        proto_dot_core_dot_node_dot_common_dot_action_dot_save__object__pb2.DESCRIPTOR,
        proto_dot_core_dot_io_dot_address__pb2.DESCRIPTOR,
    ],
)


_CONTAINERACTION = _descriptor.Descriptor(
    name="ContainerAction",
    full_name="syft.core.node.common.action.ContainerAction",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    create_key=_descriptor._internal_create_key,
    fields=[
        _descriptor.FieldDescriptor(
            name="obj",
            full_name="syft.core.node.common.action.ContainerAction.obj",
            index=0,
            number=1,
            type=11,
            cpp_type=10,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
            create_key=_descriptor._internal_create_key,
        ),
        _descriptor.FieldDescriptor(
            name="address",
            full_name="syft.core.node.common.action.ContainerAction.address",
            index=1,
            number=2,
            type=11,
            cpp_type=10,
            label=1,
            has_default_value=False,
            default_value=None,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
            create_key=_descriptor._internal_create_key,
        ),
    ],
    extensions=[],
    nested_types=[],
    enum_types=[],
    serialized_options=None,
    is_extendable=False,
    syntax="proto3",
    extension_ranges=[],
    oneofs=[],
    serialized_start=157,
    serialized_end=275,
)

_CONTAINERACTION.fields_by_name[
    "obj"
].message_type = (
    proto_dot_core_dot_node_dot_common_dot_action_dot_save__object__pb2._SAVEOBJECTACTION
)
_CONTAINERACTION.fields_by_name[
    "address"
].message_type = proto_dot_core_dot_io_dot_address__pb2._ADDRESS
DESCRIPTOR.message_types_by_name["ContainerAction"] = _CONTAINERACTION
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ContainerAction = _reflection.GeneratedProtocolMessageType(
    "ContainerAction",
    (_message.Message,),
    {
        "DESCRIPTOR": _CONTAINERACTION,
        "__module__": "proto.core.node.common.action.container_pb2"
        # @@protoc_insertion_point(class_scope:syft.core.node.common.action.ContainerAction)
    },
)
_sym_db.RegisterMessage(ContainerAction)


# @@protoc_insertion_point(module_scope)
