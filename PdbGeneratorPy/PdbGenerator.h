#pragma once
#pragma warning( push )
#pragma warning( disable : 4702 )
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/CodeView/StringsAndChecksums.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#pragma warning( pop )
#include "ComplexType.h"
#include "StructEnumData.h"
#include "PEData.h"
#include "FunctionData.h"
#include "SymbolData.h"
#include "TpiBuilder.h"

namespace srcsync
{
	class PdbGenerator
	{
	public:
		PdbGenerator(const ComplexTypesData& ComplexTypes, const StructsData& Structs, const EnumsData& Enums, 
			const FunctionsData& FunctionsData, const PdbInfo& PdbInfo, const SectionsType& Sections,
			const PublicSymbolsData& PublicSymbols, const GlobalSymbolsData& GlobalSymbols, CpuArchitectureType ArchType);

		bool Generate();
	private:
        bool AddPreDefinedEmptyStreams();
        void AddInfoStreamData();
        void AddDbiStreamData();
        bool AddSections();
        void AddPublics();
        void AddGlobals();
        bool AddModules();

        using SegmentAndOffset = std::pair<uint16_t, uint32_t>;
        void AddFunctionSymbols(llvm::pdb::DbiModuleDescriptorBuilder& ModuleBuilder, 
            SegmentAndOffset SegmentAndOffset, const FunctionData& FunctionData);
        void AddLocalVariableSymbol(llvm::pdb::DbiModuleDescriptorBuilder& ModuleBuilder, const LocalVariable& LocalVariable);
        void AddSectionContributions(llvm::pdb::DbiStreamBuilder& DbiBuilder, uint32_t FunctionSize,
            SegmentAndOffset SegmentAndOffset, uint16_t ModuleIndex);
        void AddSubSections(llvm::pdb::DbiModuleDescriptorBuilder& ModuleBuilder, 
            SegmentAndOffset SegmentAndOffset, const FunctionData& FunctionData);

        std::optional<SegmentAndOffset> RVAToSegmentAndOffset(size_t VirtualAddress) const;
        std::optional<llvm::codeview::RegisterId> GetRegisterId(std::string_view RegisterName);

		const FunctionsData& m_FunctionsData;
		const PdbInfo& m_PdbInfo;
		const SectionsType& m_Sections;
		const PublicSymbolsData& m_PublicSymbols;
		const GlobalSymbolsData& m_GlobalSymbols;
        TpiBuilder m_TpiBuilder;
        CpuArchitectureType m_ArchType;

		llvm::BumpPtrAllocator m_Allocator;
		llvm::pdb::PDBFileBuilder m_PdbBuilder;
        llvm::codeview::StringsAndChecksums m_StringsAndCheckSums{};

        const uint32_t m_BlockSize = 0x1000;

        const std::unordered_map<std::string, llvm::codeview::RegisterId> m_RegisterMap
        {
            {"rax", llvm::codeview::RegisterId::RAX},
            {"eax", llvm::codeview::RegisterId::EAX},
            {"ax", llvm::codeview::RegisterId::AX},
            {"ah", llvm::codeview::RegisterId::AH},
            {"al", llvm::codeview::RegisterId::AL},
            {"rcx", llvm::codeview::RegisterId::RCX},
            {"ecx", llvm::codeview::RegisterId::ECX},
            {"cx", llvm::codeview::RegisterId::CX},
            {"ch", llvm::codeview::RegisterId::CH},
            {"cl", llvm::codeview::RegisterId::CL},
            {"rdx", llvm::codeview::RegisterId::RDX},
            {"edx", llvm::codeview::RegisterId::EDX},
            {"dx", llvm::codeview::RegisterId::DX},
            {"dh ", llvm::codeview::RegisterId::DH},
            {"dl", llvm::codeview::RegisterId::DL},
            {"rbx", llvm::codeview::RegisterId::RBX},
            {"ebx", llvm::codeview::RegisterId::EBX},
            {"bx", llvm::codeview::RegisterId::BX},
            {"bh", llvm::codeview::RegisterId::BH},
            {"bl", llvm::codeview::RegisterId::BL},
            {"rsp", llvm::codeview::RegisterId::RSP},
            {"esp", llvm::codeview::RegisterId::ESP},
            {"sp", llvm::codeview::RegisterId::SP},
            {"spl", llvm::codeview::RegisterId::SPL},
            {"rbp", llvm::codeview::RegisterId::RBP},
            {"ebp", llvm::codeview::RegisterId::EBP},
            {"bp", llvm::codeview::RegisterId::BP},
            {"bpl", llvm::codeview::RegisterId::BPL},
            {"rsi", llvm::codeview::RegisterId::RSI},
            {"esi", llvm::codeview::RegisterId::ESI},
            {"si", llvm::codeview::RegisterId::SI},
            {"sil", llvm::codeview::RegisterId::SIL},
            {"rdi", llvm::codeview::RegisterId::RDI},
            {"edi", llvm::codeview::RegisterId::EDI},
            {"di", llvm::codeview::RegisterId::DI},
            {"dil", llvm::codeview::RegisterId::DIL},
            {"r8", llvm::codeview::RegisterId::R8},
            {"r8d", llvm::codeview::RegisterId::R8D},
            {"r8w", llvm::codeview::RegisterId::R8W},
            {"r8b", llvm::codeview::RegisterId::R8B},
            {"r9", llvm::codeview::RegisterId::R9},
            {"r9d", llvm::codeview::RegisterId::R9D},
            {"r9w", llvm::codeview::RegisterId::R9W},
            {"r9b", llvm::codeview::RegisterId::R9B},
            {"r10", llvm::codeview::RegisterId::R10},
            {"r10d", llvm::codeview::RegisterId::R10D},
            {"r10w", llvm::codeview::RegisterId::R10W},
            {"r10b", llvm::codeview::RegisterId::R10B},
            {"r11", llvm::codeview::RegisterId::R11},
            {"r11d", llvm::codeview::RegisterId::R11D},
            {"r11w", llvm::codeview::RegisterId::R11W},
            {"r11b", llvm::codeview::RegisterId::R11B},
            {"r12", llvm::codeview::RegisterId::R12},
            {"r12d", llvm::codeview::RegisterId::R12D},
            {"r12w", llvm::codeview::RegisterId::R12W},
            {"r12b", llvm::codeview::RegisterId::R12B},
            {"r13", llvm::codeview::RegisterId::R13},
            {"r13d", llvm::codeview::RegisterId::R13D},
            {"r13w", llvm::codeview::RegisterId::R13W},
            {"r13b", llvm::codeview::RegisterId::R13B},
            {"r14", llvm::codeview::RegisterId::R14},
            {"r14d", llvm::codeview::RegisterId::R14D},
            {"r14w", llvm::codeview::RegisterId::R14W},
            {"r14b", llvm::codeview::RegisterId::R14B},
            {"r15", llvm::codeview::RegisterId::R15},
            {"r15d", llvm::codeview::RegisterId::R15D},
            {"r15w", llvm::codeview::RegisterId::R15W},
            {"r15b", llvm::codeview::RegisterId::R15B},
            {"xmm0", llvm::codeview::RegisterId::XMM0},
            {"xmm1", llvm::codeview::RegisterId::XMM1},
            {"xmm2", llvm::codeview::RegisterId::XMM2},
            {"xmm3", llvm::codeview::RegisterId::XMM3},
            {"xmm4", llvm::codeview::RegisterId::XMM4},
            {"xmm5", llvm::codeview::RegisterId::XMM5},
            {"xmm6", llvm::codeview::RegisterId::XMM6},
            {"xmm7", llvm::codeview::RegisterId::XMM7},
            {"xmm8", llvm::codeview::RegisterId::XMM8},
            {"xmm9", llvm::codeview::RegisterId::XMM9},
            {"xmm10", llvm::codeview::RegisterId::XMM10},
            {"xmm11", llvm::codeview::RegisterId::XMM11},
            {"xmm12", llvm::codeview::RegisterId::XMM12},
            {"xmm13", llvm::codeview::RegisterId::XMM13},
            {"xmm14", llvm::codeview::RegisterId::XMM14},
            {"xmm15", llvm::codeview::RegisterId::XMM15},
            {"ymm0", llvm::codeview::RegisterId::AMD64_YMM0},
            {"ymm1", llvm::codeview::RegisterId::AMD64_YMM1},
            {"ymm2", llvm::codeview::RegisterId::AMD64_YMM2},
            {"ymm3", llvm::codeview::RegisterId::AMD64_YMM3},
            {"ymm4", llvm::codeview::RegisterId::AMD64_YMM4},
            {"ymm5", llvm::codeview::RegisterId::AMD64_YMM5},
            {"ymm6", llvm::codeview::RegisterId::AMD64_YMM6},
            {"ymm7", llvm::codeview::RegisterId::AMD64_YMM7},
            {"ymm8", llvm::codeview::RegisterId::AMD64_YMM8},
            {"ymm9", llvm::codeview::RegisterId::AMD64_YMM9},
            {"ymm10", llvm::codeview::RegisterId::AMD64_YMM10},
            {"ymm11", llvm::codeview::RegisterId::AMD64_YMM11},
            {"ymm12", llvm::codeview::RegisterId::AMD64_YMM12},
            {"ymm13", llvm::codeview::RegisterId::AMD64_YMM13},
            {"ymm14", llvm::codeview::RegisterId::AMD64_YMM14},
            {"ymm15", llvm::codeview::RegisterId::AMD64_YMM15},
        };
	};
}