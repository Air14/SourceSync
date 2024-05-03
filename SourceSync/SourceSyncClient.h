#pragma once
#include <grpcpp/channel.h>
#include <Protos/DecompilerSynchronizer.grpc.pb.h>
#include <span>

namespace srcsync
{
	class SourceSyncClient
	{
	public:
		SourceSyncClient(std::unique_ptr<DecompilerSynchronizer::Stub> Stub);

		void Initialize();

		bool FetchDecompiledModuleData();

		std::string GetDecompiledModuleImageName();

		std::string GetPdbPath();

		void SetModuleAddressRange(size_t Start, size_t End);

		bool GeneratePdbForCallstack(std::span<const size_t> FunctionsVa);

		bool ShouldUpdateSymbols();

	private:
		std::string FetchDecompiledModuleName();

		std::string FetchPdbPath();

		bool CallstackContainedInPreviousOne(std::span<const size_t> FunctionsVa);

		std::unique_ptr<DecompilerSynchronizer::Stub> m_Stub;
		std::string m_ModuleImageName;
		std::string m_PdbPath;

		struct AddressRange 
		{
			bool IsInside(size_t Address)
			{
				return Address >= Start && Address < End;
			}

			size_t Start;
			size_t End;
		};
		AddressRange m_ModuleAddressRange;
		std::vector<AddressRange> m_CallstackFunctionBoundariesRva;
	};
}