#pragma once
#include <string>
#include <array>
#include <vector>

namespace srcsync
{
	enum class CpuArchitectureType
	{
		X86_64,
		X86,
	};

	struct PdbInfo
	{
		std::string Name;
		std::array<uint8_t, 16> Guid;
		uint32_t Age;
	};

	struct CoffSection
	{
		char Name[8];
		uint32_t VirtualSize;
		uint32_t VirtualAddress;
		uint32_t SizeOfRawData;
		uint32_t PointerToRawData;
		uint32_t PointerToRelocations;
		uint32_t PointerToLinenumbers;
		uint16_t NumberOfRelocations;
		uint16_t NumberOfLinenumbers;
		uint32_t Characteristics;
	};

	using SectionsType = std::vector<CoffSection>;
}