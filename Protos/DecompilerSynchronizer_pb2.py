# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: DecompilerSynchronizer.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1c\x44\x65\x63ompilerSynchronizer.proto\"\x13\n\x11\x45mptyRequestReply\"?\n\x19\x44\x65\x63ompiledModuleNameReply\x12\x0e\n\x06Status\x18\x01 \x01(\x08\x12\x12\n\nModuleName\x18\x02 \x01(\t\"J\n\x12\x46unctionBoundaries\x12\x1a\n\x12StartOfFunctionRva\x18\x01 \x01(\x04\x12\x18\n\x10\x45ndOfFunctionRva\x18\x02 \x01(\x04\"6\n\x1eGeneratePdbForCallstackRequest\x12\x14\n\x0c\x46unctionsRva\x18\x01 \x03(\x04\"`\n\x1cGeneratePdbForCallstackReply\x12\x0e\n\x06Status\x18\x01 \x01(\x08\x12\x30\n\x13\x46unctionsBoundaries\x18\x02 \x03(\x0b\x32\x13.FunctionBoundaries\"2\n\x0fGetPdbPathReply\x12\x0e\n\x06Status\x18\x01 \x01(\x08\x12\x0f\n\x07PdbPath\x18\x02 \x01(\t\"*\n\x18ShouldUpdateSymbolsReply\x12\x0e\n\x06Status\x18\x01 \x01(\x08\x32\xf8\x02\n\x16\x44\x65\x63ompilerSynchronizer\x12\x36\n\nInitialize\x12\x12.EmptyRequestReply\x1a\x12.EmptyRequestReply\"\x00\x12K\n\x17GetDecompiledModuleName\x12\x12.EmptyRequestReply\x1a\x1a.DecompiledModuleNameReply\"\x00\x12[\n\x17GeneratePdbForCallstack\x12\x1f.GeneratePdbForCallstackRequest\x1a\x1d.GeneratePdbForCallstackReply\"\x00\x12\x34\n\nGetPdbPath\x12\x12.EmptyRequestReply\x1a\x10.GetPdbPathReply\"\x00\x12\x46\n\x13ShouldUpdateSymbols\x12\x12.EmptyRequestReply\x1a\x19.ShouldUpdateSymbolsReply\"\x00\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'DecompilerSynchronizer_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _EMPTYREQUESTREPLY._serialized_start=32
  _EMPTYREQUESTREPLY._serialized_end=51
  _DECOMPILEDMODULENAMEREPLY._serialized_start=53
  _DECOMPILEDMODULENAMEREPLY._serialized_end=116
  _FUNCTIONBOUNDARIES._serialized_start=118
  _FUNCTIONBOUNDARIES._serialized_end=192
  _GENERATEPDBFORCALLSTACKREQUEST._serialized_start=194
  _GENERATEPDBFORCALLSTACKREQUEST._serialized_end=248
  _GENERATEPDBFORCALLSTACKREPLY._serialized_start=250
  _GENERATEPDBFORCALLSTACKREPLY._serialized_end=346
  _GETPDBPATHREPLY._serialized_start=348
  _GETPDBPATHREPLY._serialized_end=398
  _SHOULDUPDATESYMBOLSREPLY._serialized_start=400
  _SHOULDUPDATESYMBOLSREPLY._serialized_end=442
  _DECOMPILERSYNCHRONIZER._serialized_start=445
  _DECOMPILERSYNCHRONIZER._serialized_end=821
# @@protoc_insertion_point(module_scope)