#include "SourceSyncClient.h"

namespace srcsync
{
	srcsync::SourceSyncClient::SourceSyncClient(std::unique_ptr<DecompilerSynchronizer::Stub> Stub) :
		m_Stub(std::move(Stub)), m_ModuleImageName(), m_PdbPath(), m_ModuleAddressRange(), m_CallstackFunctionBoundariesRva()
	{
	}

	void SourceSyncClient::Initialize()
	{
		grpc::ClientContext context{};
		EmptyRequestReply request, reply;
		m_Stub->Initialize(&context, request, &reply);
	}

	bool SourceSyncClient::FetchDecompiledModuleData()
	{
		auto moduleName = FetchDecompiledModuleName();
		auto pdbPath = FetchPdbPath();
		if (moduleName.empty() || pdbPath.empty())
		{
			return false;
		}

		m_ModuleImageName = std::move(moduleName);
		m_PdbPath = std::move(pdbPath);

		return true;
	}

	std::string SourceSyncClient::GetDecompiledModuleImageName()
	{
		return m_ModuleImageName;
	}

	std::string SourceSyncClient::GetPdbPath()
	{
		return m_PdbPath;
	}

	void SourceSyncClient::SetModuleAddressRange(size_t Start, size_t End)
	{
		m_ModuleAddressRange.Start = Start;
		m_ModuleAddressRange.End = End;
	}

	bool SourceSyncClient::GeneratePdbForCallstack(std::span<const size_t> FunctionsVa)
	{
		if (!FunctionsVa.empty() && !m_CallstackFunctionBoundariesRva.empty())
		{
			if (CallstackContainedInPreviousOne(FunctionsVa))
			{
				return true;
			}
		}

		grpc::ClientContext context{};
		GeneratePdbForCallstackRequest request{};
		GeneratePdbForCallstackReply reply{};
		for (const auto functionVa : FunctionsVa)
		{
			if (m_ModuleAddressRange.IsInside(functionVa))
			{
				request.add_functionsrva(functionVa - m_ModuleAddressRange.Start);
			}
		}

		const auto status = m_Stub->GeneratePdbForCallstack(&context, request, &reply);
		if (!status.ok())
		{
			return false;
		}

		m_CallstackFunctionBoundariesRva.clear();
		for (int i{}; i < reply.functionsboundaries_size(); ++i)
		{
			const auto& functionBoundaries = reply.functionsboundaries(i);
			m_CallstackFunctionBoundariesRva.push_back({ functionBoundaries.startoffunctionrva(), functionBoundaries.endoffunctionrva() });
		}

		return true;
	}

	bool SourceSyncClient::ShouldUpdateSymbols()
	{
		grpc::ClientContext context{};
		EmptyRequestReply request{};
		ShouldUpdateSymbolsReply reply{};
		const auto status = m_Stub->ShouldUpdateSymbols(&context, request, &reply);
		if (!status.ok())
		{
			return {};
		}

		return reply.status();
	}

	std::string SourceSyncClient::FetchDecompiledModuleName()
	{
		grpc::ClientContext context{};
		EmptyRequestReply request{};
		DecompiledModuleNameReply reply{};
		const auto status = m_Stub->GetDecompiledModuleName(&context, request, &reply);
		if (!status.ok())
		{
			return {};
		}

		return reply.modulename();
	}

	std::string SourceSyncClient::FetchPdbPath()
	{
		grpc::ClientContext context{};
		EmptyRequestReply request{};
		GetPdbPathReply reply{};
		const auto status = m_Stub->GetPdbPath(&context, request, &reply);
		if (!status.ok())
		{
			return {};
		}

		return reply.pdbpath();
	}

	bool SourceSyncClient::CallstackContainedInPreviousOne(std::span<const size_t> FunctionsVa)
	{
		for (const auto functionVa : FunctionsVa)
		{
			if (!m_ModuleAddressRange.IsInside(functionVa))
			{
				continue;
			}

			const auto functionRva = functionVa - m_ModuleAddressRange.Start;
			if (!std::ranges::any_of(m_CallstackFunctionBoundariesRva, [functionRva](const auto& CallstackFunctionBoundarie) {
				return functionRva >= CallstackFunctionBoundarie.Start && functionRva < CallstackFunctionBoundarie.End;
			}))
			{
				return false;;
			}
		}

		return true;
	}
}