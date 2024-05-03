#pragma once
#pragma warning( push )
#pragma warning( disable : 4702 )
#include <llvm/DebugInfo/CodeView/ContinuationRecordBuilder.h>
#include <llvm/DebugInfo/CodeView/SimpleTypeSerializer.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#pragma warning( pop )
#include <vector>
#include "ComplexType.h"
#include "StructEnumData.h"
#include "PEData.h"

namespace srcsync
{
    class TpiBuilder
    {
    public:
        TpiBuilder(const StructsData& Structs, const EnumsData& Enums, const ComplexTypesData& ComplexTypes, CpuArchitectureType ArchType);

        void Build(llvm::pdb::TpiStreamBuilder& TpiStreamBuilder);

        llvm::codeview::TypeIndex GetTypeIndex(std::string_view TypeName);
    private:
        llvm::codeview::TypeIndex AddEnumMembers(const std::vector<EnumeratorData>& EnumMembers);

        llvm::codeview::TypeIndex AddEnumRecord(const EnumData& EnumData);

        llvm::codeview::TypeIndex AddBitfieldRecord(const BitfieldTypeData& BitfieldData, std::string_view Type);

        llvm::codeview::TypeIndex AddStructMembers(const std::vector<MemberData>& StructMembers);

        template<typename RecordType, llvm::codeview::TypeRecordKind RecordKind>
        llvm::codeview::TypeIndex AddStructRecord(const StructData& StructData, bool AsForwardReference)
        {
            RecordType structRecord(RecordKind);
            structRecord.Name = StructData.Name;

            if (AsForwardReference)
            {
                structRecord.Options = llvm::codeview::ClassOptions::ForwardReference;
                AddTypeIndex(structRecord.Name.data(), m_CurrentIndex);
            }
            else
            {
                structRecord.Size = StructData.StructSize;
                structRecord.MemberCount = static_cast<uint16_t>(StructData.Members.size());
                structRecord.FieldList = AddStructMembers(StructData.Members);
            }

            m_RecordsVector.emplace_back(m_TypeSerializer.serialize(structRecord));
            return m_CurrentIndex++;
        }

        llvm::codeview::TypeIndex AddArgumentList(const std::vector<std::string>& Arguments);

        llvm::codeview::TypeIndex AddComplexType(const ComplexType& TypeData, std::string_view TypeName);

        llvm::codeview::TypeIndex CreateTypeIndex(std::string_view TypeName);

        void AddTypeIndex(std::string_view TypeName, llvm::codeview::TypeIndex Index);

    private:
        llvm::codeview::TypeIndex m_CurrentIndex{ 0x1000 };
        llvm::codeview::SimpleTypeSerializer m_TypeSerializer{};
        llvm::codeview::ContinuationRecordBuilder m_ContinuationSerializer{};
        std::vector<std::vector<uint8_t>> m_RecordsVector;
        const StructsData& m_StructsData;
        const EnumsData& m_EnumsData;
        const ComplexTypesData& m_ComplexTypesData;
        const CpuArchitectureType m_ArchType;

        std::unordered_map<std::string, llvm::codeview::TypeIndex> m_TypeIndicesMap
        {
            {"float80", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Float80)},
            {"double", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Float64)},
            {"float", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Float32)},
            {"unsigned __int128", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::UInt128)},
            {"__int128", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Int128)},
            {"unsigned __int64", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::UInt64)},
            {"__int64", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Int64)},
            {"unsigned __int32", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::UInt32)},
            {"__int32", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Int32)},
            {"unsigned int", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::UInt32)},
            {"int", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Int32)},
            {"unsigned __int16", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::UInt16)},
            {"__int16", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Int16)},
            {"unsigned __int8", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Byte)},
            {"__int8", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::SByte)},
            {"unsigned char", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::UnsignedCharacter)},
            {"bool", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Boolean8)},
            {"_BOOL64", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Boolean64)},
            {"_BOOL32", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Boolean32)},
            {"_BOOL16", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Boolean16)},
            {"_BOOL8", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Boolean8)},
            {"char", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::NarrowCharacter)},
            {"wchar_t", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::WideCharacter)},
            {"void", llvm::codeview::TypeIndex(llvm::codeview::SimpleTypeKind::Void)},
        };
    };
}