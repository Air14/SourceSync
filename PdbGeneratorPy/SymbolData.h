#pragma once
#include <string>
#include <vector>

namespace srcsync
{
	struct PublicSymbolData
	{
		std::string UniqueName;
		size_t RelativeAddress;
		bool IsFunction;
	};

	struct GlobalSymbolData
	{
		std::string ShortName;
		std::string TypeName;
		size_t RelativeAddress;
	};

	using PublicSymbolsData = std::vector<PublicSymbolData>;
	using GlobalSymbolsData = std::vector<GlobalSymbolData>;
}