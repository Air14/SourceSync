#pragma once
#include <string>
#include <vector>
#include <optional>
#include <map>
#include <array>

namespace srcsync
{
	struct LocalVariable
	{
		std::string Name;
		std::string TypeName;
		std::string RegistryName;
		std::optional<int32_t> Offset;
	};

	using LocalVariables = std::vector<LocalVariable>;
	using InstructionsToLines = std::map<uint32_t, uint32_t>;

	struct FunctionData
	{
		std::string FilePath;
		std::string FunctionName;
		std::string TypeName;
		size_t RelativeAddress;
		uint32_t Size;
		InstructionsToLines InstructionOffsetToPseudoCodeLine;
		LocalVariables LocalVariables;
	};

	using FunctionsData = std::vector<FunctionData>;
}