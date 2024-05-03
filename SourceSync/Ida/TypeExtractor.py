import ida_typeinf
import ida_kernwin
import idaapi
import hashlib
import uuid
import PdbGeneratorPy

class TypeExtractor:
    def __init__(self):
        self.ComplexTypesData = PdbGeneratorPy.ComplexTypesData()
        self.EnumsData = PdbGeneratorPy.EnumsData()
        self.StructsData = PdbGeneratorPy.StructsData()

    def GatherData(self, ExecuteSync):
        self.ComplexTypesData.clear()
        self.EnumsData.clear()
        self.StructsData.clear()

        def GatherDataInternal():
            self.__InsertStructsData()
            self.__InsertEnumData()

        if ExecuteSync:
            ida_kernwin.execute_sync(GatherDataInternal, 0)
        else:
            GatherDataInternal()

    def GetStructsData(self):
        return self.StructsData
    
    def GetEnumsData(self):
        return self.EnumsData
    
    def GetComplexTypesData(self):
        return self.ComplexTypesData
    
    def __InsertEnumData(self):
        localTypeLibrary = ida_typeinf.get_idati()
        allocatedOrdinals = ida_typeinf.get_ordinal_qty(localTypeLibrary) + 1
        for i in range(1, allocatedOrdinals):
            typeInfo = ida_typeinf.tinfo_t()
            if not typeInfo.get_numbered_type(localTypeLibrary, i):
                continue

            name = typeInfo.get_type_name()
            if not name:
                continue

            enumData = ida_typeinf.enum_type_data_t()
            if not typeInfo.get_enum_details(enumData):
                continue

            enumerators = PdbGeneratorPy.EnumeratorsData()
            for enumMember in enumData:
                enumeratorData = PdbGeneratorPy.EnumeratorData()
                enumeratorData.Name = enumMember.name
                enumeratorData.Value = enumMember.value
                enumerators.append(enumeratorData)

            if not enumerators:
                continue
            
            data = PdbGeneratorPy.EnumData()
            data.Name = name
            data.UnderlyingType = f"__int{ enumData.calc_nbytes() << 3}"
            data.Enumerators = enumerators

            self.EnumsData.append(data)

    def __InsertStructsData(self):
        localTypeLibrary = idaapi.get_idati()
        allocatedOrdinals = idaapi.get_ordinal_qty(localTypeLibrary) + 1

        for i in range(1, allocatedOrdinals):
            typeInfo = ida_typeinf.tinfo_t()
            if not typeInfo.get_numbered_type(localTypeLibrary, i):
                continue

            structType = self.__GetStructType(typeInfo.get_realtype())
            if not structType:
                continue

            # Skip unnamed/anonymous structs as they will be added in __InsertUnnamedStructDataAndGetItsName
            name = typeInfo.get_type_name()
            if not name or "<unnamed" in name or "<anonymous" in name:
                continue

            size = typeInfo.get_size()
            if not size or size == idaapi.BADADDR:
                continue

            members = self.__GetStructMembersInfo(typeInfo)
            if not members:
                continue

            structData = PdbGeneratorPy.StructData()
            structData.Kind = structType
            structData.Name = name
            structData.StructSize = size
            structData.Members = members

            self.StructsData.append(structData)

    def __InsertUnnamedStructDataAndGetItsName(self, TypeInfo):
        result = "void"
        structType = self.__GetStructType(TypeInfo.get_realtype())
        if not structType:
            return result
                
        size = TypeInfo.get_size()
        if not size or size == idaapi.BADADDR:
            return result

        members = self.__GetStructMembersInfo(TypeInfo)
        if not members:
            return result

        result = "<unnamed-type-" + self.__GetUniqueNameForUnnamedStruct(self.__GetStructMembersInfo(TypeInfo)) + ">"

        structData = PdbGeneratorPy.StructData()
        structData.Kind = structType
        structData.Name = result
        structData.StructSize = size
        structData.Members = members
        self.StructsData.append(structData)
        
        return result

    def InsertTypeInfoData(self, TypeInfo):
        if TypeInfo.is_array():
            self.__InsertArrayTypeData(TypeInfo)
        elif TypeInfo.is_func():
            self.__InsertFunctionTypeData(TypeInfo)
        elif TypeInfo.is_ptr():
            self.__InsertPointerTypeData(TypeInfo)

    def __InsertFunctionTypeData(self, TypeInfo):
        functionTypeData = ida_typeinf.func_type_data_t()
        if not TypeInfo.get_func_details(functionTypeData):
            return

        typeName = self.GetTypeName(TypeInfo)
        if typeName in self.ComplexTypesData:
            return
        
        typeData = PdbGeneratorPy.FunctionTypeData()
        typeData.ReturnType = self.GetTypeName(functionTypeData.rettype)

        self.InsertTypeInfoData(functionTypeData.rettype)
        
        for functionArg in functionTypeData:
            self.InsertTypeInfoData(functionArg.type)
            typeData.Parameters.append(self.GetTypeName(functionArg.type))

        self.ComplexTypesData[typeName] = typeData
    
    def __InsertPointerTypeData(self, TypeInfo):
        pointerTypeData = ida_typeinf.ptr_type_data_t()
        if not TypeInfo.get_ptr_details(pointerTypeData):
            return

        typeName = self.GetTypeName(TypeInfo)
        if typeName in self.ComplexTypesData:
            return

        self.InsertTypeInfoData(pointerTypeData.obj_type)
        typeData = PdbGeneratorPy.PointerTypeData()
        typeData.ValueType = self.GetTypeName(pointerTypeData.obj_type)

        self.ComplexTypesData[typeName] = typeData

    def __InsertArrayTypeData(self, TypeInfo):
        arrayTypeData = ida_typeinf.array_type_data_t()
        if not TypeInfo.get_array_details(arrayTypeData):
            return

        typeName = self.GetTypeName(TypeInfo)
        if typeName in self.ComplexTypesData:
            return

        if arrayTypeData.elem_type.get_size() == 0xffffffffffffffff:
            return

        self.InsertTypeInfoData(arrayTypeData.elem_type)

        typeData = PdbGeneratorPy.ArrayTypeData()
        typeData.Size = arrayTypeData.nelems * arrayTypeData.elem_type.get_size()
        typeData.ValueType = self.GetTypeName(arrayTypeData.elem_type)

        self.ComplexTypesData[typeName] = typeData
    
    def __GetStructMembersInfo(self, TypeInfo):
        members = PdbGeneratorPy.MembersData()
        udtTypeData = ida_typeinf.udt_type_data_t()

        if not TypeInfo.get_udt_details(udtTypeData):
            return members

        for udtMember in udtTypeData:
            member = self.__CreateMember(udtMember)
            if member is not None:
                members.append(member)

        return members
    
    def __CreateMember(self, UdtMember):
        self.InsertTypeInfoData(UdtMember.type)
        if UdtMember.type.is_bitfield():
            return self.__CreateBitfieldMember(UdtMember)
        else:
            return self.__CreateSimpleTypeMember(UdtMember)
        
    def __CreateBitfieldMember(self, UdtMember):
        bitfieldTypeData = ida_typeinf.bitfield_type_data_t()
        if not UdtMember.type.get_bitfield_details(bitfieldTypeData):
            return None

        member = PdbGeneratorPy.MemberData()
        member.Name = UdtMember.name
        member.TypeName = f"{'unsigned ' if bitfieldTypeData.is_unsigned else ''}" + f"__int{bitfieldTypeData.nbytes * 8}"
        member.Offset = bitfieldTypeData.nbytes * (UdtMember.offset // (bitfieldTypeData.nbytes * 8))

        bitfieldData = PdbGeneratorPy.BitfieldTypeData()
        bitfieldData.Position = UdtMember.offset % (bitfieldTypeData.nbytes * 8)
        bitfieldData.Length = bitfieldTypeData.width
        member.Bitfield = bitfieldData

        return member
    
    def __CreateSimpleTypeMember(self, UdtMember):
        member = PdbGeneratorPy.MemberData()
        member.Name = "unnamed-" + str(uuid.uuid4()) if UdtMember.name == "" else UdtMember.name
        member.TypeName = self.GetTypeName(UdtMember.type)
        member.Offset = UdtMember.offset // 8
        return member
    
    def __GetStructType(self, Type):
        typeBase = Type & ida_typeinf.TYPE_BASE_MASK
        typeFlags = Type & ida_typeinf.TYPE_FLAGS_MASK

        if typeBase != ida_typeinf.BT_COMPLEX:
            return None

        if typeFlags == ida_typeinf.BTMT_STRUCT:
            return PdbGeneratorPy.StructKind.Structure
        elif typeFlags == ida_typeinf.BTMT_UNION:
            return PdbGeneratorPy.StructKind.Union

        return None
    
    def GetTypeName(self, TypeInfo):
        result = TypeInfo.dstr()

        if not TypeInfo.is_forward_decl():
            simpleType = self.__GetSimpleType(TypeInfo.get_realtype(True))
            
            if simpleType:
                # Since wchar_t is defined in Ida as __int16 we need to manually update it here
                if simpleType.endswith("__int16") and result.endswith(("wchar_t", "WCHAR")):
                    result = "wchar_t"
                else:
                    result = simpleType
            elif TypeInfo.is_typeref():
                finalTypeName = TypeInfo.get_final_type_name()
                if finalTypeName:
                    result = finalTypeName

            if result == "void *__ptr32":
                result = "void *"
            elif result.startswith("struct") or result.startswith("union") or "<unnamed" in result or "<anonymous" in result:
                result = self.__InsertUnnamedStructDataAndGetItsName(TypeInfo)
        
        return result
    
    def __GetSimpleType(self, Type):
        typeBase = Type & ida_typeinf.TYPE_BASE_MASK
        typeFlags = Type & ida_typeinf.TYPE_FLAGS_MASK

        if typeBase == ida_typeinf.BT_UNK:
            return self.__GetUnknownType(typeFlags)
        elif typeBase == ida_typeinf.BT_VOID:
            return self.__GetVoidType(typeFlags)
        elif typeBase in (ida_typeinf.BT_INT8, ida_typeinf.BT_INT16, ida_typeinf.BT_INT32, ida_typeinf.BT_INT64,
                          ida_typeinf.BT_INT128, ida_typeinf.BT_INT):
            return self.__GetIntegerType(typeBase, typeFlags)
        elif typeBase == ida_typeinf.BT_BOOL:
            return self.__GetBoolType(typeFlags)
        elif typeBase == ida_typeinf.BT_FLOAT:
            return self.__GetFloatType(typeFlags)

        return None
    
    def __GetUnknownType(self, TypeFlags):
        unknownTypes = {
            ida_typeinf.BTMT_SIZE0: "",
            ida_typeinf.BTMT_SIZE12: "unsigned __int16",
            ida_typeinf.BTMT_SIZE48: "unsigned __int64",
            ida_typeinf.BTMT_SIZE128: ""
        }
        
        return unknownTypes[TypeFlags]

    def __GetVoidType(self, TypeFlags):
        voidTypes = {
            ida_typeinf.BTMT_SIZE0: "void",
            ida_typeinf.BTMT_SIZE12: "unsigned __int8",
            ida_typeinf.BTMT_SIZE48: "unsigned __int32",
            ida_typeinf.BTMT_SIZE128: "unsigned __int128"
        }
        
        return voidTypes[TypeFlags]

    def __GetIntegerType(self, TypeBase, TypeFlags):
        integerTypes = {
            ida_typeinf.BT_INT8: "__int8",
            ida_typeinf.BT_INT16: "__int16",
            ida_typeinf.BT_INT32: "__int32",
            ida_typeinf.BT_INT: "__int32",
            ida_typeinf.BT_INT64: "__int64",
            ida_typeinf.BT_INT128: "__int128"
        }

        if TypeFlags == ida_typeinf.BTMT_UNSIGNED:
            return f"unsigned {integerTypes[TypeBase]}"
        elif TypeFlags == ida_typeinf.BTMT_SIGNED or TypeFlags == ida_typeinf.BTMT_UNKSIGN:
            return integerTypes[TypeBase]
        elif TypeFlags == ida_typeinf.BTMT_CHAR and TypeBase == ida_typeinf.BT_INT8:
            return "char"

        return None

    def __GetBoolType(self, TypeFlags):
        boolTypes = {
            ida_typeinf.BTMT_BOOL1: "_BOOL8",
            ida_typeinf.BTMT_BOOL2: "_BOOL64" if idaapi.inf_is_64bit() else "_BOOL16",
            ida_typeinf.BTMT_BOOL4: "_BOOL32"
        }

        return boolTypes.get(TypeFlags, None)

    def __GetFloatType(self, TypeFlags):
        floatTypes = {
            ida_typeinf.BTMT_FLOAT: "float",
            ida_typeinf.BTMT_DOUBLE: "double",
            ida_typeinf.BTMT_LNGDBL: "double"
        }

        return floatTypes.get(TypeFlags, None)
    
    def __GetUniqueNameForUnnamedStruct(self, Members):
        dataToHash = ""
        for member in Members:
            dataToHash += member.Name
            dataToHash += member.TypeName
            dataToHash += str(member.Offset)
            dataToHash += str(int(bool(member.Bitfield)))
            if member.Bitfield:
                dataToHash += str(member.Bitfield.Position)
                dataToHash += str(member.Bitfield.Length)
        
        return hashlib.md5(dataToHash.encode('utf-8')).hexdigest()