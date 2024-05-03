#pragma once
#include <string>
#include <vector>
#include <optional>

namespace srcsync
{
	enum class StructKind : uint8_t
	{
		Structure,
		Union,
	};

	struct BitfieldTypeData
	{
		uint8_t Position;
		uint8_t Length;
	};

	struct MemberData
	{
		std::string Name;
		std::string TypeName;
		size_t Offset;
		std::optional<BitfieldTypeData> Bitfield;
	};

	using MembersData = std::vector<MemberData>;

	struct StructData
	{
		StructKind Kind;
		std::string Name;
		size_t StructSize;
		MembersData Members;
	};

	struct EnumeratorData
	{
		std::string Name;
		size_t Value;
	};

	using EnumeratorsData = std::vector<EnumeratorData>;

	struct EnumData
	{
		std::string Name;
		std::string UnderlyingType;
		EnumeratorsData Enumerators;
	};

	using StructsData = std::vector<StructData>;
	using EnumsData = std::vector<EnumData>;
}