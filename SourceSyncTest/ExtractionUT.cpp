#include <gtest/gtest.h>
#include <ranges>
#include <algorithm>
#include "Demangle/MicrosoftDemangle.h"
#include "DiaSymbols.h"

struct TestCaseData
{
	std::wstring_view OriginalPdb;
	std::wstring_view SourceSyncPdb;
	double DesiredEnumsSimilarity;
	double DesiredStructsSimilarity;
	double DesiredPublicsSimilarity;
	double DesiredFunctionsSimilarity;
};

class ExtractionParameterizedTestFixture : public ::testing::TestWithParam<TestCaseData>
{
};

TEST_P(ExtractionParameterizedTestFixture, ShouldExtractSameEnums)
{
	const auto testCaseData = GetParam();
	DiaSymbols ogDiaSymbols(testCaseData.OriginalPdb);
	DiaSymbols srcsyncDiaSymbols(testCaseData.SourceSyncPdb);
	const auto ogEnums = ogDiaSymbols.GetEnums();
	const auto srcSyncEnums = srcsyncDiaSymbols.GetEnums();

	size_t numberOfMatchingEnums{};
	for (const auto& ogEnum : ogEnums)
	{
		const auto srcSyncEnum = std::ranges::find_if(srcSyncEnums, [&](const auto& EnumData) { return EnumData.Name == ogEnum.Name; });
		if (srcSyncEnum == srcSyncEnums.end())
		{
			//std::cout << "Failed to find " << ogEnum.Name << " enum in srcsync enums\n";
			continue;
		}

		if (ogEnum.UnderlyingType != srcSyncEnum->UnderlyingType)
		{
			//std::cout << "Underlying type is not the same " << ogEnum.Name << "\n";
			continue;
		}

		if (ogEnum.Enumerators.size() != srcSyncEnum->Enumerators.size())
		{
			//std::cout << "Number of enumerators is not the same " << ogEnum.Name << "\n";
			continue;
		}

		const auto matchMembers = [&]() {
			for (const auto& [ogEnumMember, srcSyncEnumMember] : std::views::zip(ogEnum.Enumerators, srcSyncEnum->Enumerators))
			{
				if (ogEnumMember.Name != srcSyncEnumMember.Name)
				{
					//std::cout << "Enumerator name is not the same" << ogEnum.Name << "::" << ogEnumMember.Name << " vs "
					//	<< ogEnum.Name << "::" << srcSyncEnumMember.Name << "\n";

					return false;
				}

				if (ogEnumMember.Value != srcSyncEnumMember.Value)
				{
					//std::cout << "Enumerator value is not the same" << ogEnum.Name << "::" << ogEnumMember.Name << " = " << ogEnumMember.Value <<
					//	" vs " << ogEnum.Name << "::" << srcSyncEnumMember.Name << " = " << srcSyncEnumMember.Value << "\n";

					return false;
				}
			}

			return true;
		};

		if (matchMembers())
		{
			++numberOfMatchingEnums;
		}
	}
	
	const auto similarity = static_cast<double>(numberOfMatchingEnums) / ogEnums.size();
	std::wcout << L"Similarity for " << testCaseData.OriginalPdb.data() << L" is equal " << similarity << L"\n";
	ASSERT_GE(similarity, testCaseData.DesiredEnumsSimilarity);
}

TEST_P(ExtractionParameterizedTestFixture, ShouldExtractSameStructs)
{
	const auto testCaseData = GetParam();
	DiaSymbols ogDiaSymbols(testCaseData.OriginalPdb);
	DiaSymbols srcsyncDiaSymbols(testCaseData.SourceSyncPdb);
	auto ogStructs = ogDiaSymbols.GetStructs();
	const auto srcSyncStructs = srcsyncDiaSymbols.GetStructs();

	std::unordered_map<std::string_view, std::vector<srcsync::StructData*>> ogStructsDuplicatesMap{};
	for (auto& ogStruct : ogStructs)
	{
		ogStructsDuplicatesMap[ogStruct.Name].push_back(&ogStruct);
	}

	size_t numberOfMatchingStructs{};
	for (const auto& [_, ogStructsDuplicates] : ogStructsDuplicatesMap)
	{
		auto oneStructMatched = false;
		for (const auto& ogStructDuplicate : ogStructsDuplicates)
		{
			const auto srcSyncStruct = std::ranges::find_if(srcSyncStructs, [&](const auto& StructData) { return StructData.Name == ogStructDuplicate->Name; });
			if (srcSyncStruct == srcSyncStructs.end())
			{
				//std::cout << "Failed to find struct named " << ogStructDuplicate.Name << "\n";
				continue;
			}

			if (ogStructDuplicate->Kind != srcSyncStruct->Kind)
			{
				//std::cout << "Structs kind is not the same " << ogStructDuplicate.Name << "\n";
				continue;
			}

			if (ogStructDuplicate->StructSize != srcSyncStruct->StructSize)
			{
				//std::cout << "Structs size is not the same " << "Original: " << ogStructDuplicate.StructSize 
				//	<< " SourceSync: " << srcSyncStruct->StructSize << "\n";
				continue;
			}

			if (ogStructDuplicate->Members.size() != srcSyncStruct->Members.size())
			{
				//std::cout << " Structs number of members is not the same" << "Original: " << ogStructDuplicate.Members.size()
				//	<< " SourceSync: " << srcSyncStruct->Members.size() << "\n";
				continue;
			}

			const auto matchMembers = [&]() {
				for (const auto& [ogStructMember, srcSyncStructMember] : std::views::zip(ogStructDuplicate->Members, srcSyncStruct->Members))
				{
					if (ogStructMember.Name != srcSyncStructMember.Name)
					{
						return false;
					}
					if (ogStructMember.TypeName != srcSyncStructMember.TypeName)
					{
						return false;
					}
					if (ogStructMember.Offset != srcSyncStructMember.Offset)
					{
						return false;
					}
					if (ogStructMember.Bitfield.has_value() != srcSyncStructMember.Bitfield.has_value())
					{
						return false;
					}
					if (ogStructMember.Bitfield.has_value() && srcSyncStructMember.Bitfield.has_value())
					{
						if (ogStructMember.Bitfield->Position != srcSyncStructMember.Bitfield->Position)
						{
							return false;
						}
						if (ogStructMember.Bitfield->Length != srcSyncStructMember.Bitfield->Length)
						{
							return false;
						}
					}
				}
			};

			oneStructMatched |= matchMembers();
		}

		if (oneStructMatched)
		{
			++numberOfMatchingStructs;
		}
	}

	const auto similarity = static_cast<double>(numberOfMatchingStructs) / ogStructsDuplicatesMap.size();
	std::wcout << L"Similarity for " << testCaseData.OriginalPdb.data() << L" is equal " << similarity << L"\n";
	ASSERT_GE(similarity, testCaseData.DesiredStructsSimilarity);
}

TEST_P(ExtractionParameterizedTestFixture, ShouldExtractPublicSymbols)
{
	const auto testCaseData = GetParam();
	DiaSymbols ogDiaSymbols(testCaseData.OriginalPdb);
	DiaSymbols srcsyncDiaSymbols(testCaseData.SourceSyncPdb);
	auto srcSyncSymbols = srcsyncDiaSymbols.GetPublicSymbols();
	auto ogSymbols = ogDiaSymbols.GetPublicSymbols();

	std::unordered_map<size_t, std::vector<srcsync::PublicSymbolData*>> ogSymbolsDuplicatesMap{};
	for (auto& ogSymbol : ogSymbols)
	{
		ogSymbolsDuplicatesMap[ogSymbol.RelativeAddress].push_back(&ogSymbol);
	}

	size_t numberOfMatchingPublics{};
	for (const auto& [_, ogSymbolsDuplicates] : ogSymbolsDuplicatesMap)
	{
		const auto oneSymbolMatched = [&]() {
			for (const auto& ogSymbol : ogSymbolsDuplicates)
			{
				const auto srcSyncSymbol = std::ranges::find_if(srcSyncSymbols, [&](const auto Symbol) { return Symbol.UniqueName == ogSymbol->UniqueName; });
				if (srcSyncSymbol == srcSyncSymbols.end())
				{
					//std::cout << "Failed to find symbol " << ogSymbol.UniqueName << "\n";
					continue;
				}

				if (ogSymbol->RelativeAddress == srcSyncSymbol->RelativeAddress && ogSymbol->IsFunction == srcSyncSymbol->IsFunction)
				{
					return true;
				}
			}

			return false;
		};
		numberOfMatchingPublics += oneSymbolMatched();
	}

	const auto similarity = static_cast<double>(numberOfMatchingPublics) / ogSymbolsDuplicatesMap.size();
	std::wcout << L"Similarity for " << testCaseData.OriginalPdb.data() << L" is equal " << similarity << L"\n";
	ASSERT_GE(similarity, testCaseData.DesiredPublicsSimilarity);
}

std::string DemangleSymbolName(std::string_view SymbolName)
{
	const auto demangleFlag = static_cast<llvm::ms_demangle::OutputFlags>(
		std::to_underlying(llvm::ms_demangle::OutputFlags::OF_NoReturnType) |
		std::to_underlying(llvm::ms_demangle::OutputFlags::OF_NoMemberType) |
		std::to_underlying(llvm::ms_demangle::OutputFlags::OF_NoAccessSpecifier) |
		std::to_underlying(llvm::ms_demangle::OutputFlags::OF_NoTagSpecifier) |
		std::to_underlying(llvm::ms_demangle::OutputFlags::OF_NoCallingConvention));

	llvm::ms_demangle::Demangler demangler{};
	auto symbolNameViewCopy = SymbolName;
	const auto symbolNode = demangler.parse(symbolNameViewCopy);
	if (!symbolNode)
	{
		return SymbolName.data();
	}

	std::string demangled = symbolNode->toString(demangleFlag);
	const auto paramStart = demangled.find('(');

	if (paramStart != std::string::npos) 
	{
		demangled.erase(paramStart, demangled.size() - paramStart);
	}
	std::erase_if(demangled, isspace);

	return demangled;
}

TEST_P(ExtractionParameterizedTestFixture, ShouldExtractFunctionData)
{
	const auto testCaseData = GetParam();
	DiaSymbols ogDiaSymbols(testCaseData.OriginalPdb);
	DiaSymbols srcsyncDiaSymbols(testCaseData.SourceSyncPdb);
	auto srcSyncFunctions = srcsyncDiaSymbols.GetFunctionsData();
	auto ogFunctions = ogDiaSymbols.GetFunctionsData();

	for (auto& srcsyncFunction : srcSyncFunctions)
	{
		srcsyncFunction.FunctionName = DemangleSymbolName(srcsyncFunction.FunctionName);
	}

	size_t numberOfMatchingFunctions{};
	for (auto& ogFunction : ogFunctions)
	{
		std::erase_if(ogFunction.FunctionName, isspace);

		const auto srcSyncFunction = std::ranges::find_if(srcSyncFunctions, [&](const auto& FunctionData) { return FunctionData.FunctionName == ogFunction.FunctionName; });
		if (srcSyncFunction == srcSyncFunctions.end())
		{
			continue;
		}

		if (ogFunction.RelativeAddress != srcSyncFunction->RelativeAddress)
		{
			continue;
		}

		if (ogFunction.Size != srcSyncFunction->Size)
		{
			continue;
		}

		// We do not compare type names as ida is pretty bad at setting right types for function even with loaded symbols

		++numberOfMatchingFunctions;
	}

	const auto similarity = static_cast<double>(numberOfMatchingFunctions) / ogFunctions.size();
	std::wcout << L"Similarity for " << testCaseData.OriginalPdb.data() << L" is equal " << similarity << L"\n";
	ASSERT_GE(similarity, testCaseData.DesiredFunctionsSimilarity);
}

TEST_P(ExtractionParameterizedTestFixture, ShouldExtractSameSections)
{
	//GIVEN
	const auto testCaseData = GetParam();
	DiaSymbols ogDiaSymbols(testCaseData.OriginalPdb);
	DiaSymbols srcsyncDiaSymbols(testCaseData.SourceSyncPdb);

	//WHEN THEN
	const auto ogSections = ogDiaSymbols.GetSectionsData();
	const auto srcsyncSections = srcsyncDiaSymbols.GetSectionsData();
	ASSERT_EQ(ogSections.size(), srcsyncSections.size());

	for (const auto& [firstSection, secondSection] : std::views::zip(srcsyncSections, ogSections))
	{
		ASSERT_EQ(firstSection.Address, secondSection.Address);
		ASSERT_GE(firstSection.Size, secondSection.Size);
		ASSERT_EQ(firstSection.Read, secondSection.Read);
		ASSERT_EQ(firstSection.Write, secondSection.Write);
		ASSERT_EQ(firstSection.Execute, secondSection.Execute);
	}
}

INSTANTIATE_TEST_SUITE_P(
	ExtractionTests,
	ExtractionParameterizedTestFixture,
	::testing::Values(
		// Pdbs from c++ applications
		TestCaseData{.OriginalPdb = LR"(TestPdbs\x64_Release_Og_ProcMonX.pdb)", .SourceSyncPdb = LR"(TestPdbs\x64_Release_SrcSync_ProcMonX.pdb)",
		.DesiredEnumsSimilarity = 0.79, .DesiredStructsSimilarity = 0.85, .DesiredPublicsSimilarity = 0.95, .DesiredFunctionsSimilarity = 0.75 },

		TestCaseData{ .OriginalPdb = LR"(TestPdbs\x64_Debug_Og_ProcMonX.pdb)", .SourceSyncPdb = LR"(TestPdbs\x64_Debug_SrcSync_ProcMonX.pdb)",
		.DesiredEnumsSimilarity = 0.84, .DesiredStructsSimilarity = 0.81, .DesiredPublicsSimilarity = 0.96, .DesiredFunctionsSimilarity = 0.79 },

		TestCaseData{ .OriginalPdb = LR"(TestPdbs\x32_Release_Og_ProcMonX.pdb)", .SourceSyncPdb = LR"(TestPdbs\x32_Release_SrcSync_ProcMonX.pdb)",
		.DesiredEnumsSimilarity = 0.79, .DesiredStructsSimilarity = 0.84, .DesiredPublicsSimilarity = 0.99, .DesiredFunctionsSimilarity = 0.55 },

		TestCaseData{ .OriginalPdb = LR"(TestPdbs\x32_Debug_Og_ProcMonX.pdb)", .SourceSyncPdb = LR"(TestPdbs\x32_Debug_SrcSync_ProcMonX.pdb)",
		.DesiredEnumsSimilarity = 0.84, .DesiredStructsSimilarity = 0.82, .DesiredPublicsSimilarity = 0.99, .DesiredFunctionsSimilarity = 0.67 },

		// Pdbs from c applications
		TestCaseData{.OriginalPdb = LR"(TestPdbs\x64_Release_Og_ProcessHacker.pdb)", .SourceSyncPdb = LR"(TestPdbs\x64_Release_SrcSync_ProcessHacker.pdb)",
		.DesiredEnumsSimilarity = 0.92, .DesiredStructsSimilarity = 0.90, .DesiredPublicsSimilarity = 0.97, .DesiredFunctionsSimilarity = 0.96 },
		
		TestCaseData{ .OriginalPdb = LR"(TestPdbs\x64_Debug_Og_ProcessHacker.pdb)", .SourceSyncPdb = LR"(TestPdbs\x64_Debug_SrcSync_ProcessHacker.pdb)",
		.DesiredEnumsSimilarity = 0.90, .DesiredStructsSimilarity = 0.90, .DesiredPublicsSimilarity = 0.86, .DesiredFunctionsSimilarity = 0.99 },

		TestCaseData{ .OriginalPdb = LR"(TestPdbs\x32_Release_Og_ProcessHacker.pdb)", .SourceSyncPdb = LR"(TestPdbs\x32_Release_SrcSync_ProcessHacker.pdb)",
		.DesiredEnumsSimilarity = 0.92, .DesiredStructsSimilarity = 0.89, .DesiredPublicsSimilarity = 0.99, .DesiredFunctionsSimilarity = 0.17 },

		TestCaseData{ .OriginalPdb = LR"(TestPdbs\x32_Debug_Og_ProcessHacker.pdb)", .SourceSyncPdb = LR"(TestPdbs\x32_Debug_SrcSync_ProcessHacker.pdb)",
		.DesiredEnumsSimilarity = 0.90, .DesiredStructsSimilarity = 0.87, .DesiredPublicsSimilarity = 0.99, .DesiredFunctionsSimilarity = 0.14 },

		// Pdbs from rust applications
		TestCaseData{.OriginalPdb = LR"(TestPdbs\x64_Release_Og_alacritty.pdb)", .SourceSyncPdb = LR"(TestPdbs\x64_Release_SrcSync_alacritty.pdb)",
		.DesiredEnumsSimilarity = 0.74, .DesiredStructsSimilarity = 0.78, .DesiredPublicsSimilarity = 0.85, .DesiredFunctionsSimilarity = 0.0},

		TestCaseData{.OriginalPdb = LR"(TestPdbs\x32_Release_Og_alacritty.pdb)", .SourceSyncPdb = LR"(TestPdbs\x32_Release_SrcSync_alacritty.pdb)",
		.DesiredEnumsSimilarity = 0.74, .DesiredStructsSimilarity = 0.80, .DesiredPublicsSimilarity = 0.85, .DesiredFunctionsSimilarity = 0.0 }
	));