#include "Utils.h"
#include "InterfaceWrapper.h"
#include <DbgEng.h>
#include <ranges>
#include <algorithm>

namespace srcsync
{
	extern srcsync::InterfaceWrapper<PDEBUG_CONTROL> g_DebugControl;
	extern srcsync::InterfaceWrapper<PDEBUG_SYMBOLS> g_DebugSymbols;

	static bool ICharEquals(char a, char b)
	{
		return std::tolower(a) == std::tolower(b);
	}

	static bool IEqual(std::string_view First, std::string_view Second)
	{
		return std::ranges::equal(First, Second, ICharEquals);
	}

	std::vector<size_t> GetCallstack()
	{
		std::vector<size_t> result{};
		std::vector<DEBUG_STACK_FRAME> stackFrames(100);
		ULONG framesFilled{};

		g_DebugControl->GetStackTrace(0, 0, 0, stackFrames.data(), 100, &framesFilled);

		for (size_t i{}; i < framesFilled; ++i)
		{
			result.push_back(stackFrames[i].InstructionOffset);
		}

		return result;
	}

	std::string GetSymbolsPath()
	{
		ULONG pathSize{};
		g_DebugSymbols->GetSymbolPath(nullptr, 0, &pathSize);

		if (!pathSize)
		{
			return {};
		}

		std::string result(pathSize, '\x00');
		if (FAILED(g_DebugSymbols->GetSymbolPath(result.data(), static_cast<ULONG>(result.size()), &pathSize)))
		{
			return {};
		}

		return result;
	}

	bool PrependSymbolsPath(std::string_view PathToPrepend)
	{
		auto symbolPath = GetSymbolsPath();
		if (symbolPath.contains(PathToPrepend))
		{
			return true;
		}

		symbolPath = std::string{ PathToPrepend.data() } + ";" + symbolPath;

		return SUCCEEDED(g_DebugSymbols->SetSymbolPath(symbolPath.data()));
	}

	std::pair<size_t, size_t> GetModuleAddressRange(std::string_view Name)
	{
		ULONG loadedModules{};
		ULONG unloadedModules{};
		if (FAILED(g_DebugSymbols->GetNumberModules(&loadedModules, &unloadedModules)))
		{
			return {};
		}

		for (ULONG i{}; i < loadedModules; ++i)
		{
			std::string imageName(500, '\x00');
			std::string moduleName(500, '\x00');

			g_DebugSymbols->GetModuleNames(i, 0,
				imageName.data(), static_cast<ULONG>(imageName.size()), nullptr,
				moduleName.data(), static_cast<ULONG>(moduleName.size()), nullptr,
				nullptr, 0, nullptr);

			imageName.resize(std::strlen(imageName.data()));
			moduleName.resize(std::strlen(moduleName.data()));

			if (!IEqual(Name, imageName) && !IEqual(Name, moduleName))
			{
				continue;
			}

			size_t moduleBase{};
			if (FAILED(g_DebugSymbols->GetModuleByModuleName(moduleName.data(), 0, nullptr, &moduleBase)))
			{
				return {};
			}

			DEBUG_MODULE_PARAMETERS debugModuleParameters{};
			if (FAILED(g_DebugSymbols->GetModuleParameters(1, &moduleBase, 0, &debugModuleParameters)))
			{
				return {};
			}

			return { debugModuleParameters.Base, debugModuleParameters.Base + debugModuleParameters.Size };
		}

		return {};
	}

	std::string GetHostIpAndPort()
	{
		const std::string defaultIpAndPort{ "localhost:5111" };

		std::string userProfile(MAX_PATH, 0);
		auto count = GetEnvironmentVariableA("userprofile", userProfile.data(), static_cast<uint32_t>(userProfile.size()));
		if (!count || count >= MAX_PATH)
		{
			return defaultIpAndPort;
		}
		userProfile.resize(count);
		userProfile += R"(\.srcsync)";

		std::string ip(16, 0);
		count = GetPrivateProfileStringA("INTERFACE", "host", "127.0.0.1", ip.data(), MAX_PATH, userProfile.data());
		if (!count || count >= MAX_PATH)
		{
			return defaultIpAndPort;
		}
		ip.resize(count);

		std::string port(6, 0);
		count = GetPrivateProfileStringA("INTERFACE", "port", "5111", port.data(), MAX_PATH, userProfile.data());
		if (!count || count >= MAX_PATH)
		{
			return defaultIpAndPort;
		}
		port.resize(count);

		return ip + ":" + port;
	}

}