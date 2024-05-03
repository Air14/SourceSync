#pragma once
#include <string>
#include <vector>
#include <variant>
#include <unordered_map>

namespace srcsync
{
	struct ArrayTypeData
	{
		std::string ValueType;
		size_t Size;
	};

	struct PointerTypeData
	{
		std::string ValueType;
	};

	struct FunctionTypeData
	{
		std::string ReturnType;
		std::vector<std::string> Parameters;
	};

	using ComplexType = std::variant<
		ArrayTypeData,
		PointerTypeData,
		FunctionTypeData
	>;

	using ComplexTypesData = std::unordered_map<std::string, ComplexType>;
}