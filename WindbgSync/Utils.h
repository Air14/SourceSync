#pragma once
#include <vector>
#include <string>

namespace srcsync
{
	std::vector<size_t> GetCallstack();

	std::string GetSymbolsPath();

	bool PrependSymbolsPath(std::string_view PathToPrepend);

	std::pair<size_t, size_t> GetModuleAddressRange(std::string_view Name);

	std::string GetHostIpAndPort();
}