#pragma warning( push )
#pragma warning( disable : 4702 )
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/DebugInfo/CodeView/DebugLinesSubsection.h>
#include <llvm/DebugInfo/CodeView/DebugChecksumsSubsection.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/RawTypes.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/Object/COFF.h>
#pragma warning( pop )
#include <filesystem>
#include <ranges>
#include "PdbGenerator.h"

namespace fs = std::filesystem;

namespace srcsync
{
    PdbGenerator::PdbGenerator(const ComplexTypesData& ComplexTypes, const StructsData& Structs, const EnumsData& Enums,
        		const FunctionsData& FunctionsData, const PdbInfo& PdbInfo, const SectionsType& Sections,
        		const PublicSymbolsData& SymbolsData, const GlobalSymbolsData& GlobalSymbols, CpuArchitectureType ArchType) :
		m_FunctionsData(FunctionsData), m_PdbInfo(PdbInfo), m_Sections(Sections), m_PublicSymbols(SymbolsData),
        m_GlobalSymbols(GlobalSymbols), m_PdbBuilder(m_Allocator), m_ArchType(ArchType),
        m_TpiBuilder(Structs, Enums, ComplexTypes, ArchType)
    {
        m_StringsAndCheckSums.setStrings(std::make_shared<llvm::codeview::DebugStringTableSubsection>());
	}

    bool PdbGenerator::Generate()
    {
        if (m_PdbBuilder.initialize(m_BlockSize))
        {
            return false;
        }

        if (!AddPreDefinedEmptyStreams())
        {
            return false;
        }

        AddInfoStreamData();
		AddDbiStreamData();
        m_TpiBuilder.Build(m_PdbBuilder.getTpiBuilder());
        if (!AddSections())
        {
            return false;
        }
        AddPublics();
        AddGlobals();

        if (!AddModules())
        {
            return false;
        }

        m_PdbBuilder.getStringTableBuilder().setStrings(*m_StringsAndCheckSums.strings());

        std::error_code ec{};
        const auto oldPdbPath = (fs::current_path() / m_PdbInfo.Name).string() + ".old";
        fs::remove(oldPdbPath, ec);

        const auto newPdbPath = (fs::current_path() / m_PdbInfo.Name).string();
        fs::rename(newPdbPath, oldPdbPath, ec);

        llvm::codeview::GUID ignoredOutGuid{};
        return !m_PdbBuilder.commit(newPdbPath, &ignoredOutGuid);
    }

    void PdbGenerator::AddPublics()
    {
        std::vector<llvm::pdb::BulkPublic> publics{};

        for (const auto& symbolData : m_PublicSymbols)
        {
            const auto segmentAndOffset = RVAToSegmentAndOffset(symbolData.RelativeAddress);
            if (!segmentAndOffset.has_value())
            {
                continue;
            }

            llvm::pdb::BulkPublic bulkPublic{};
            bulkPublic.Name = symbolData.UniqueName.c_str();
            bulkPublic.NameLen = static_cast<uint32_t>(symbolData.UniqueName.size());
            bulkPublic.Segment = segmentAndOffset->first;
            bulkPublic.Offset = segmentAndOffset->second;
            bulkPublic.setFlags(symbolData.IsFunction ?
                llvm::codeview::PublicSymFlags::Function :
                llvm::codeview::PublicSymFlags::None);

            publics.emplace_back(std::move(bulkPublic));
        }

        m_PdbBuilder.getGsiBuilder().addPublicSymbols(std::move(publics));
    }

    void PdbGenerator::AddGlobals()
    {
        auto& gsiBuilder = m_PdbBuilder.getGsiBuilder();
        for (const auto& symbolData : m_GlobalSymbols)
        {
            const auto segmentAndOffset = RVAToSegmentAndOffset(symbolData.RelativeAddress);
            if (!segmentAndOffset.has_value())
            {
                continue;
            }

            llvm::codeview::DataSym dataSymbol(llvm::codeview::SymbolRecordKind::GlobalData);
            dataSymbol.Name = symbolData.ShortName;
            dataSymbol.DataOffset = segmentAndOffset->second;
            dataSymbol.Segment = segmentAndOffset->first;
            dataSymbol.Type = m_TpiBuilder.GetTypeIndex(symbolData.TypeName);

            gsiBuilder.addGlobalSymbol(llvm::codeview::SymbolSerializer::writeOneSymbol(
                dataSymbol, m_Allocator, llvm::codeview::CodeViewContainer::Pdb));
        }
    }

    bool PdbGenerator::AddModules()
    {
        auto& dbiBuilder = m_PdbBuilder.getDbiBuilder();
        for (const auto& functionData : m_FunctionsData)
        {
            if (functionData.FilePath.empty() || functionData.InstructionOffsetToPseudoCodeLine.empty())
            {
                continue;
            }

            auto moduleBuilder = dbiBuilder.addModuleInfo(functionData.FilePath);
            if (moduleBuilder.takeError())
            {
                return false;
            }

            moduleBuilder->setObjFileName(functionData.FilePath);
            if (dbiBuilder.addModuleSourceFile(*moduleBuilder, functionData.FilePath))
            {
                return false;
            }

            const auto segmentAndOffset = RVAToSegmentAndOffset(functionData.RelativeAddress);
            if (!segmentAndOffset.has_value())
			{
				return false;
			}

            AddFunctionSymbols(*moduleBuilder, *segmentAndOffset, functionData);

			AddSubSections(*moduleBuilder, *segmentAndOffset, functionData);

            AddSectionContributions(dbiBuilder, functionData.Size, *segmentAndOffset, static_cast<uint16_t>(moduleBuilder->getModuleIndex()));
        }

        return true;
    }

    namespace
    {
        struct ScopeRecord
        {
            llvm::codeview::ulittle32_t PtrParent;
            llvm::codeview::ulittle32_t PtrEnd;
        };

        // Given a pointer to a symbol record that opens a scope, return a pointer to
        // the scope fields.
        ScopeRecord* GetSymbolScopeFields(void* Symbol)
        {
            return reinterpret_cast<ScopeRecord*>(reinterpret_cast<char*>(Symbol) +
                sizeof(llvm::codeview::RecordPrefix));
        }
    }

    void PdbGenerator::AddFunctionSymbols(llvm::pdb::DbiModuleDescriptorBuilder& ModuleBuilder,
        SegmentAndOffset SegmentAndOffset, const FunctionData& FunctionData)
    {
        // S_GPROC32
        llvm::codeview::ProcSym processSymbol(llvm::codeview::SymbolRecordKind::GlobalProcSym);
        processSymbol.Name = FunctionData.FunctionName;
        processSymbol.Segment = SegmentAndOffset.first;
        processSymbol.CodeOffset = SegmentAndOffset.second;
        processSymbol.CodeSize = FunctionData.Size;
        processSymbol.DbgStart = FunctionData.InstructionOffsetToPseudoCodeLine.begin()->first;
        processSymbol.DbgEnd = FunctionData.InstructionOffsetToPseudoCodeLine.rbegin()->first;
        processSymbol.FunctionType = llvm::codeview::TypeIndex(m_TpiBuilder.GetTypeIndex(FunctionData.TypeName));

        const auto cvFunctionSymbol = llvm::codeview::SymbolSerializer::writeOneSymbol(
            processSymbol, m_Allocator, llvm::codeview::CodeViewContainer::Pdb);

        // Open function scope
        const auto functionSymScope = GetSymbolScopeFields(const_cast<uint8_t*>(cvFunctionSymbol.data().data()));

        ModuleBuilder.addSymbol(cvFunctionSymbol);

        for (const auto& localVariable : FunctionData.LocalVariables)
        {
            AddLocalVariableSymbol(ModuleBuilder, localVariable);
        }

        llvm::codeview::ScopeEndSym endSymbol(llvm::codeview::SymbolRecordKind::ScopeEndSym);
        const auto cvEndSymbol = llvm::codeview::SymbolSerializer::writeOneSymbol(
            endSymbol, m_Allocator, llvm::codeview::CodeViewContainer::Pdb);

        // Close function scope
        functionSymScope->PtrEnd = ModuleBuilder.getNextSymbolOffset();

        ModuleBuilder.addSymbol(cvEndSymbol);
    }

    void PdbGenerator::AddLocalVariableSymbol(llvm::pdb::DbiModuleDescriptorBuilder& ModuleBuilder, const LocalVariable& LocalVariable)
    {
        const auto registerId = GetRegisterId(LocalVariable.RegistryName);
        if (!registerId.has_value())
        {
            return;
        }

        if (LocalVariable.Offset.has_value())
        {
            llvm::codeview::RegRelativeSym stackVarSymbol(llvm::codeview::SymbolRecordKind::RegRelativeSym);
            stackVarSymbol.Name = LocalVariable.Name;
            stackVarSymbol.Type = m_TpiBuilder.GetTypeIndex(LocalVariable.TypeName);
            stackVarSymbol.Offset = static_cast<uint32_t>(*LocalVariable.Offset);
            stackVarSymbol.Register = *registerId;

            ModuleBuilder.addSymbol(llvm::codeview::SymbolSerializer::writeOneSymbol(
                stackVarSymbol, m_Allocator, llvm::codeview::CodeViewContainer::Pdb));
        }
        else
        {
            llvm::codeview::RegisterSym regVarSymbol(llvm::codeview::SymbolRecordKind::RegisterSym);
            regVarSymbol.Name = LocalVariable.Name;
            regVarSymbol.Index = m_TpiBuilder.GetTypeIndex(LocalVariable.TypeName);
            regVarSymbol.Register = *registerId;

            ModuleBuilder.addSymbol(llvm::codeview::SymbolSerializer::writeOneSymbol(
                regVarSymbol, m_Allocator, llvm::codeview::CodeViewContainer::Pdb));
        }
    }

    void PdbGenerator::AddSectionContributions(llvm::pdb::DbiStreamBuilder& DbiBuilder, uint32_t FunctionSize,
        SegmentAndOffset SegmentAndOffset, uint16_t ModuleIndex)
    {
        llvm::pdb::SectionContrib sectionContribution{};
        sectionContribution.ISect = SegmentAndOffset.first;
        sectionContribution.Off = SegmentAndOffset.second;
        sectionContribution.Size = FunctionSize;
        sectionContribution.Characteristics = m_Sections[SegmentAndOffset.first - 1].Characteristics;
        sectionContribution.Imod = ModuleIndex;
        DbiBuilder.addSectionContrib(std::move(sectionContribution));
    }

    void PdbGenerator::AddSubSections(llvm::pdb::DbiModuleDescriptorBuilder& ModuleBuilder,
        SegmentAndOffset SegmentAndOffset, const FunctionData& FunctionData)
    {
        auto checksumsSubsection = std::make_shared<llvm::codeview::DebugChecksumsSubsection>(*m_StringsAndCheckSums.strings());
        checksumsSubsection->addChecksum(FunctionData.FilePath, llvm::codeview::FileChecksumKind::MD5, {});

        auto linesSubsection = std::make_shared<llvm::codeview::DebugLinesSubsection>(*checksumsSubsection, *m_StringsAndCheckSums.strings());
        linesSubsection->createBlock(FunctionData.FilePath);
        linesSubsection->setCodeSize(FunctionData.Size);
        linesSubsection->setRelocationAddress(SegmentAndOffset.first, SegmentAndOffset.second);

        for (const auto& [offset, line] : FunctionData.InstructionOffsetToPseudoCodeLine)
        {
            linesSubsection->addLineInfo(offset, llvm::codeview::LineInfo(line, line, true));
        }

        m_StringsAndCheckSums.strings()->insert(FunctionData.FilePath);
        ModuleBuilder.addDebugSubsection(checksumsSubsection);
        ModuleBuilder.addDebugSubsection(linesSubsection);
    }

    bool PdbGenerator::AddPreDefinedEmptyStreams()
    {
        for (size_t i{}; i < std::to_underlying(llvm::pdb::kSpecialStreamCount); ++i)
        {
            // Create streams in MSF for predefined streams, namely PDB, TPI, DBI and IPI.
            if (m_PdbBuilder.getMsfBuilder().addStream(0).takeError())
            {
                return false;
            }
        }

        return true;
    }

    void PdbGenerator::AddInfoStreamData()
    {
        auto& infoBuilder = m_PdbBuilder.getInfoBuilder();
        infoBuilder.setVersion(llvm::pdb::PdbRaw_ImplVer::PdbImplVC70);
        infoBuilder.setHashPDBContentsToGUID(false);

        llvm::codeview::GUID guid{};
        std::memcpy(guid.Guid, m_PdbInfo.Guid.data(), m_PdbInfo.Guid.size());
        infoBuilder.setGuid(guid);
        infoBuilder.setAge(m_PdbInfo.Age);
    }

    void PdbGenerator::AddDbiStreamData()
    {
        auto& dbiBuilder = m_PdbBuilder.getDbiBuilder();
        dbiBuilder.setBuildNumber(36381);
        dbiBuilder.setVersionHeader(llvm::pdb::PdbDbiV70);
        if (m_ArchType == srcsync::CpuArchitectureType::X86_64)
        {
            dbiBuilder.setMachineType(llvm::pdb::PDB_Machine::Amd64);
        }
        else if (m_ArchType == srcsync::CpuArchitectureType::X86)
        {
            dbiBuilder.setMachineType(llvm::pdb::PDB_Machine::x86);
        }
        dbiBuilder.setAge(m_PdbInfo.Age);
        dbiBuilder.setPdbDllVersion(30148);
        dbiBuilder.setBuildNumber(14, 11);
    }

    bool PdbGenerator::AddSections()
    {
        const auto sectionsTable = llvm::ArrayRef<uint8_t>(
            reinterpret_cast<const uint8_t*>(m_Sections.data()),
            m_Sections.size() * sizeof(llvm::object::coff_section));

        auto& dbiBuilder = m_PdbBuilder.getDbiBuilder();
        if (dbiBuilder.addDbgStream(llvm::pdb::DbgHeaderType::SectionHdr, sectionsTable))
        {
            return false;
        }

        static_assert(sizeof(llvm::object::coff_section) == sizeof(CoffSection));
        std::vector<llvm::object::coff_section> coffSectionsCopy(m_Sections.size());
        std::memcpy(coffSectionsCopy.data(), m_Sections.data(), m_Sections.size() * sizeof(CoffSection));
        dbiBuilder.createSectionMap(coffSectionsCopy);

        return true;
    }

    std::optional<std::pair<uint16_t, uint32_t>> PdbGenerator::RVAToSegmentAndOffset(size_t VirtualAddress) const
    {
        for (const auto& [index, section] : std::views::enumerate(m_Sections))
        {
            if (VirtualAddress >= section.VirtualAddress && VirtualAddress < section.VirtualAddress + section.VirtualSize)
            {
                return std::pair<uint16_t, uint32_t>{ static_cast<uint16_t>(index + 1), static_cast<uint32_t>(VirtualAddress) - section.VirtualAddress };
            }
        }

        return {};
    }

    std::optional<llvm::codeview::RegisterId> PdbGenerator::GetRegisterId(std::string_view RegisterName)
    {
        const auto iter = m_RegisterMap.find(RegisterName.data());
        if (iter == m_RegisterMap.end())
        {
            return {};
        }

        return iter->second;
    }
}

