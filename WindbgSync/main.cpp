#include <windows.h>
#include <wdbgexts.h>
#include <dbgeng.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>
#include <SourceSync/SourceSyncClient.h>
#include "InterfaceWrapper.h"
#include "Utils.h"

// Must be named ExtensionApis
WINDBG_EXTENSION_APIS ExtensionApis{};

namespace srcsync
{
	srcsync::InterfaceWrapper<PDEBUG_CONTROL> g_DebugControl{};
	srcsync::InterfaceWrapper<PDEBUG_SYMBOLS> g_DebugSymbols{};
	std::unique_ptr<srcsync::SourceSyncClient> g_SourceSyncClient{};
	std::jthread g_SymbolUpdaterThread{};
	std::atomic<bool> g_ShouldQuerySymbolUpdate{};
	std::string g_ModuleName{};

	void SymbolsUpdater()
	{
		while (true)
		{
			Sleep(500);

			if (!g_SourceSyncClient || !g_ShouldQuerySymbolUpdate)
			{
				continue;
			}

			if (!g_SourceSyncClient->ShouldUpdateSymbols())
			{
				continue;
			}

			g_DebugSymbols->Reload(g_ModuleName.c_str());
		}
	}

	void SyncCallstackWithDecompiler()
	{
		const auto callstack = srcsync::GetCallstack();
		if (callstack.empty())
		{
			dprintf("[SourceSync] Cant get callstack\n");
			return;
		}

		if (!g_SourceSyncClient->GeneratePdbForCallstack(callstack))
		{
			dprintf("[SourceSync] Failed to generate pdb for callstack\n");
			return;
		}

		if (FAILED(g_DebugSymbols->Reload(g_ModuleName.c_str())))
		{
			dprintf("[SourceSync] Failed to reload pdb for module\n");
		}
	}

	bool QueryAllInterfaces(PDEBUG_CLIENT Client)
	{
		if (const auto status = Client->QueryInterface(__uuidof(IDebugSymbols), reinterpret_cast<void**>(&g_DebugSymbols)); FAILED(status))
		{
			return false;
		}
		if (const auto status = Client->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void**>(&g_DebugControl)); FAILED(status))
		{
			return false;
		}

		return true;
	}

	std::unique_ptr<SourceSyncClient> CreateClient()
	{
		auto channel = grpc::CreateChannel(GetHostIpAndPort(), grpc::InsecureChannelCredentials());
		if (!channel)
		{
			return {};
		}

		auto stub = DecompilerSynchronizer::NewStub(channel);
		if (!stub)
		{
			return {};
		}

		return std::make_unique<srcsync::SourceSyncClient>(std::move(stub));
	}

	bool SetupSyncServer(std::string_view UserSuppliedModuleName)
	{
		if (g_SourceSyncClient)
		{
			return true;
		}

		auto sourceSyncClient = CreateClient();
		if (!sourceSyncClient)
		{
			dprintf("[SourceSync] Failed to create client\n");
			return false;
		}
		sourceSyncClient->Initialize();

		if (!sourceSyncClient->FetchDecompiledModuleData())
		{
			dprintf("[SourceSync] Failed to fetch decompiled module data\n");
			return false;
		}

		const auto moduleImageName = sourceSyncClient->GetDecompiledModuleImageName();
		dprintf("[SourceSync] Module image name %s:\n", moduleImageName.c_str());

		g_ModuleName = UserSuppliedModuleName.empty() ? moduleImageName : UserSuppliedModuleName;

		const auto [moduleStart, moduleEnd] = srcsync::GetModuleAddressRange(g_ModuleName);
		if (!moduleStart || !moduleEnd)
		{
			dprintf("[SourceSync] Failed to get address of decompiled module\n");
			return false;
		}
		dprintf("[SourceSync] Start: 0x%X End: 0x%X\n", moduleStart, moduleEnd);

		sourceSyncClient->SetModuleAddressRange(moduleStart, moduleEnd);

		const auto pdbPath = sourceSyncClient->GetPdbPath();
		dprintf("[SourceSync] PdbPath: %s\n", pdbPath.c_str());

		if (!srcsync::PrependSymbolsPath(pdbPath))
		{
			dprintf("[SourceSync] Failed to add pdb path to windbg symbols path\n");
			return false;
		}

		if (!sourceSyncClient->GeneratePdbForCallstack({}))
		{
			dprintf("[SourceSync] Failed generate initial pdb\n");
			return false;
		}

		if (FAILED(g_DebugSymbols->Reload(g_ModuleName.c_str())))
		{
			dprintf("[SourceSync] Failed to reload module symbols\n");
			return false;
		}

		g_SourceSyncClient = std::move(sourceSyncClient);

		return true;
	}
}

extern "C"
__declspec(dllexport) void DebugExtensionNotify(ULONG Notify, ULONG64)
{
	srcsync::g_ShouldQuerySymbolUpdate = false;

	switch (Notify)
	{
	case DEBUG_NOTIFY_SESSION_ACCESSIBLE:
		if (srcsync::g_SourceSyncClient)
		{
			srcsync::SyncCallstackWithDecompiler();
		}
		srcsync::g_ShouldQuerySymbolUpdate = true;
		break;
	}
}

extern "C"
__declspec(dllexport) HRESULT DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
	*Version = DEBUG_EXTENSION_VERSION(0, 1);
	*Flags = 0;

	srcsync::InterfaceWrapper<PDEBUG_CLIENT> debugClient{};
	if (const auto status = DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(&debugClient)); FAILED(status))
	{
		return status;
	}

	srcsync::InterfaceWrapper<PDEBUG_CONTROL> debugControl{};
	if (const auto status = debugClient->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void**>(&debugControl)); FAILED(status))
	{
		return status;
	}

	ExtensionApis.nSize = sizeof(ExtensionApis);
	debugControl->GetWindbgExtensionApis64(reinterpret_cast<PWINDBG_EXTENSION_APIS64>(&ExtensionApis));

	srcsync::g_SymbolUpdaterThread = std::jthread(srcsync::SymbolsUpdater);

	dprintf("[SourceSync] Loaded\n");

	return S_OK;
}

extern "C"
__declspec(dllexport) void DebugExtensionUninitialize()
{
}

extern "C"
__declspec(dllexport) HRESULT EnableSync(PDEBUG_CLIENT Client, PCSTR UserSuppliedModuleName)
{
	if (!srcsync::QueryAllInterfaces(Client) || !srcsync::SetupSyncServer(UserSuppliedModuleName ? UserSuppliedModuleName : ""))
	{
		return S_FALSE;
	}

	dprintf("[SourceSync] Enabled\n");
	return S_OK;
}

extern "C"
__declspec(dllexport) HRESULT DisableSync(PDEBUG_CLIENT, PCSTR)
{
	srcsync::g_SourceSyncClient.reset();
	dprintf("[SourceSync] Disabled\n");
	return S_OK;
}

extern "C"
__declspec(dllexport) HRESULT RestartSync(PDEBUG_CLIENT Client, PCSTR UserSuppliedModuleName)
{
	srcsync::g_SourceSyncClient.reset();
	if (!srcsync::QueryAllInterfaces(Client) || srcsync::SetupSyncServer(UserSuppliedModuleName ? UserSuppliedModuleName : ""))
	{
		return S_FALSE;
	}

	dprintf("[SourceSync] Restarted\n");
	return S_OK;
}