#include "TpiBuilder.h"
#include <llvm/DebugInfo/PDB/Native/TpiHashing.h>
#include <ranges>

namespace srcsync
{
    template<class... Ts> struct overload : Ts... { using Ts::operator()...; };
    template<class... Ts> overload(Ts...) -> overload<Ts...>;

	TpiBuilder::TpiBuilder(const StructsData& Structs, const EnumsData& Enums, const ComplexTypesData& ComplexTypes, CpuArchitectureType ArchType) :
        m_StructsData(Structs), m_EnumsData(Enums), m_ComplexTypesData(ComplexTypes), m_ArchType(ArchType)
	{
	}

    void TpiBuilder::Build(llvm::pdb::TpiStreamBuilder& TpiStreamBuilder)
    {
        for (const auto& enumData : m_EnumsData)
        {
            AddEnumRecord(enumData);
        }

        for (const auto& structData : m_StructsData)
        {
            if (structData.Kind == StructKind::Structure)
            {
                AddStructRecord<llvm::codeview::ClassRecord, llvm::codeview::TypeRecordKind::Struct>(structData, true);
            }
            else
            {
                AddStructRecord<llvm::codeview::UnionRecord, llvm::codeview::TypeRecordKind::Union>(structData, true);
            }
        }

        for (const auto& typeData : m_ComplexTypesData)
        {
            AddComplexType(typeData.second, typeData.first);
        }

        for (const auto& structData : m_StructsData)
        {
            if (structData.Kind == StructKind::Structure)
            {
                AddStructRecord<llvm::codeview::ClassRecord, llvm::codeview::TypeRecordKind::Struct>(structData, false);
            }
            else
            {
                AddStructRecord<llvm::codeview::UnionRecord, llvm::codeview::TypeRecordKind::Union>(structData, false);
            }
        }

        TpiStreamBuilder.setVersionHeader(llvm::pdb::PdbTpiV80);
        for (const auto& recordBytes : m_RecordsVector)
        {
            TpiStreamBuilder.addTypeRecord(recordBytes, *llvm::pdb::hashTypeRecord(llvm::codeview::CVType(recordBytes)));
        }
    }

	llvm::codeview::TypeIndex TpiBuilder::AddEnumMembers(const std::vector<EnumeratorData>& EnumMembers)
	{
        m_ContinuationSerializer.begin(llvm::codeview::ContinuationRecordKind::FieldList);
        for (const auto& enumMember : EnumMembers)
        {
            llvm::APSInt value(sizeof(enumMember.Value) * 8, true);
            value = enumMember.Value;

            llvm::codeview::EnumeratorRecord enumeratorRecord(
                llvm::codeview::MemberAccess::Public,
                value,
                enumMember.Name
            );

            m_ContinuationSerializer.writeMemberType(enumeratorRecord);
        }
        const auto cvTypes = m_ContinuationSerializer.end(llvm::codeview::TypeIndex(m_CurrentIndex + 1));
        for (const auto& cvType : std::ranges::views::reverse(cvTypes))
        {
            m_RecordsVector.emplace_back(cvType.data());
            ++m_CurrentIndex;
        }

        return m_CurrentIndex - static_cast<uint32_t>(cvTypes.size());
	}

    llvm::codeview::TypeIndex TpiBuilder::AddEnumRecord(const EnumData& EnumData)
    {
        llvm::codeview::EnumRecord enumRecord(
            static_cast<uint16_t>(EnumData.Enumerators.size()),
            {},
            AddEnumMembers(EnumData.Enumerators),
            EnumData.Name,
            {},
            GetTypeIndex(EnumData.UnderlyingType)
        );

        AddTypeIndex(EnumData.Name, m_CurrentIndex);
        m_RecordsVector.emplace_back(m_TypeSerializer.serialize(enumRecord));
        return m_CurrentIndex++;
    }

    llvm::codeview::TypeIndex TpiBuilder::AddBitfieldRecord(const BitfieldTypeData& BitfieldData, std::string_view Type)
    {
        llvm::codeview::BitFieldRecord bitfieldRecord(
            GetTypeIndex(Type),
            BitfieldData.Length,
            BitfieldData.Position
        );

        m_RecordsVector.emplace_back(m_TypeSerializer.serialize(bitfieldRecord));
        return m_CurrentIndex++;
    }

    llvm::codeview::TypeIndex TpiBuilder::AddStructMembers(const std::vector<MemberData>& StructMembers)
    {
        m_ContinuationSerializer.begin(llvm::codeview::ContinuationRecordKind::FieldList);
        for (const auto& structMember : StructMembers)
        {
            llvm::codeview::DataMemberRecord memberRecord(llvm::codeview::MemberAccess::Public,
                structMember.Bitfield.has_value() ?
                AddBitfieldRecord(*structMember.Bitfield, structMember.TypeName) : GetTypeIndex(structMember.TypeName),
                structMember.Offset,
                structMember.Name
            );

            m_ContinuationSerializer.writeMemberType(memberRecord);
        }
        const auto cvTypes = m_ContinuationSerializer.end(llvm::codeview::TypeIndex(m_CurrentIndex + 1));
        for (const auto& cvType : std::ranges::views::reverse(cvTypes))
        {
            m_RecordsVector.emplace_back(cvType.data());
            ++m_CurrentIndex;
        }

        return m_CurrentIndex - static_cast<uint32_t>(cvTypes.size());
    }

    llvm::codeview::TypeIndex TpiBuilder::AddArgumentList(const std::vector<std::string>& Arguments)
    {
        llvm::codeview::ArgListRecord argListRecord(llvm::codeview::TypeRecordKind::ArgList);
        for (const auto& argTypeName : Arguments)
        {
            argListRecord.ArgIndices.push_back(llvm::codeview::TypeIndex(GetTypeIndex(argTypeName)));
        }
        m_RecordsVector.emplace_back(m_TypeSerializer.serialize(argListRecord));

        return m_CurrentIndex++;
    }

    llvm::codeview::TypeIndex TpiBuilder::AddComplexType(const ComplexType& TypeData, std::string_view TypeName)
    {
        return std::visit(overload{
            [&](const FunctionTypeData& FunctionTypeData) 
            {
                llvm::codeview::ProcedureRecord functionRecord(
                    GetTypeIndex(FunctionTypeData.ReturnType),
                    llvm::codeview::CallingConvention::NearC,
                    llvm::codeview::FunctionOptions::None,
                    static_cast<uint16_t>(FunctionTypeData.Parameters.size()),
                    AddArgumentList(FunctionTypeData.Parameters)
                );

                AddTypeIndex(TypeName, m_CurrentIndex);
                m_RecordsVector.emplace_back(m_TypeSerializer.serialize(functionRecord));

                return m_CurrentIndex++;
            },
            [&](const PointerTypeData& PointerTypeData)
            {
                const auto attributes = m_ArchType == CpuArchitectureType::X86_64 ? 65548 : 32778;
                llvm::codeview::PointerRecord pointerRecord(
                    GetTypeIndex(PointerTypeData.ValueType),
                    attributes
                );

                AddTypeIndex(TypeName, m_CurrentIndex);
                m_RecordsVector.emplace_back(m_TypeSerializer.serialize(pointerRecord));

                return m_CurrentIndex++;
            },
            [&](const ArrayTypeData& ArrayTypeData) 
            {
                llvm::codeview::ArrayRecord arrayRecord(
                    GetTypeIndex(ArrayTypeData.ValueType),
                    llvm::codeview::TypeIndex::UInt32(),
                    ArrayTypeData.Size,
                    ""
                );

                AddTypeIndex(TypeName, m_CurrentIndex);
                m_RecordsVector.emplace_back(m_TypeSerializer.serialize(arrayRecord));

                return m_CurrentIndex++;
            }
        }, TypeData);
    }

    llvm::codeview::TypeIndex TpiBuilder::GetTypeIndex(std::string_view TypeName)
    {
        const auto iter = m_TypeIndicesMap.find(TypeName.data());
        if (iter == m_TypeIndicesMap.end())
        {
            const auto typeIndex = CreateTypeIndex(TypeName);
            AddTypeIndex(TypeName, typeIndex);
            return typeIndex;
        }

        return iter->second;
    }

    llvm::codeview::TypeIndex TpiBuilder::CreateTypeIndex(std::string_view TypeName)
    {
        const auto iter = m_ComplexTypesData.find(TypeName.data());
        if (iter == m_ComplexTypesData.end())
        {
            return llvm::codeview::TypeIndex::Void();
        }

        return AddComplexType(iter->second, iter->first);
    }

    void TpiBuilder::AddTypeIndex(std::string_view TypeName, llvm::codeview::TypeIndex Index)
    {
        m_TypeIndicesMap[TypeName.data()] = Index;
    }
}