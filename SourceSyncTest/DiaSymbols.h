#pragma once
#include <string_view>
#include <dia2.h>
#include <optional>
#include <vector>
#include <atlbase.h>
#include "..\PdbGeneratorPy\SymbolData.h"
#include "..\PdbGeneratorPy\StructEnumData.h"
#include "..\PdbGeneratorPy\FunctionData.h"

class DiaSymbols
{
public:
	DiaSymbols(std::wstring_view PdbPath);

	srcsync::PublicSymbolsData GetPublicSymbols();
	srcsync::StructsData GetStructs();
	srcsync::EnumsData GetEnums();
	srcsync::FunctionsData GetFunctionsData();

	struct SectionData
	{
		ULONGLONG Address;
		DWORD Size;
		BOOL Read;
		BOOL Write;
		BOOL Execute;
	};

	std::vector<SectionData> GetSectionsData();
private:
	bool SetSessionAndGlobal(std::wstring_view PdbPath);

	std::optional<srcsync::PublicSymbolData> GetSymbol(CComPtr<IDiaSymbol>& DiaSymbol);

	std::optional<srcsync::StructData> GetStructWithMembers(CComPtr<IDiaSymbol>& Symbol);

	std::vector<srcsync::MemberData> GetStructMembers(CComPtr<IDiaEnumSymbols>& EnumSybols);

	std::optional<srcsync::BitfieldTypeData> GetBitfieldData(CComPtr<IDiaSymbol>& Symbol);

	std::optional<srcsync::EnumData> GetEnum(CComPtr<IDiaSymbol>& Symbol);

	std::vector<srcsync::EnumeratorData> GetEnumMembers(CComPtr<IDiaEnumSymbols>& EnumSybols);

	std::optional<srcsync::FunctionData> GetFunctionData(CComPtr<IDiaSymbol>& Symbol);

	bool IsTypeAnonymous(std::wstring_view StructName);

	bool SkipSymbol(std::string_view SymbolName);

	std::string GetTypeName(CComPtr<IDiaSymbol>& Symbol, bool IgnoreSign);

	std::string GetSymbolName(CComPtr<IDiaSymbol>& Symbol);

	std::string_view BasicTypeToString(BasicType BasicType, size_t Size, bool IgnoreSign);

	CComPtr<IDiaSession> m_Session{};
	CComPtr<IDiaSymbol> m_GlobalSymbol{};
	DWORD m_MachineType{};
};