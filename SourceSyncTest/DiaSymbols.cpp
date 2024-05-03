#include <format>
#include <ranges>
#include <regex>
#include "DiaSymbols.h"
#include "RegistersMapping.h"

HRESULT NoRegCoCreate(std::wstring_view DllName, REFCLSID Rclsid, REFIID Riid, void** Ppv)
{
	const auto mod = LoadLibraryW(DllName.data());
	if (!mod)
	{
		return REASON_UNKNOWN;
	}

	const auto dllGetClassObject = reinterpret_cast<HRESULT(__stdcall*)(REFCLSID, REFIID, LPVOID*)>(GetProcAddress(mod, "DllGetClassObject"));
	if (!dllGetClassObject)
	{
		return REASON_UNKNOWN;
	}

	IClassFactory* classFactory{};
	if (FAILED(dllGetClassObject(Rclsid, IID_IClassFactory, reinterpret_cast<void**>(&classFactory))))
	{
		return REASON_UNKNOWN;
	}

	const auto result = classFactory->CreateInstance(nullptr, Riid, Ppv);
	classFactory->AddRef();
	return result;
}

DiaSymbols::DiaSymbols(std::wstring_view PdbPath)
{
	if (!SetSessionAndGlobal(PdbPath))
	{
		throw;
	}

	m_GlobalSymbol->get_machineType(&m_MachineType);
}

bool DiaSymbols::SetSessionAndGlobal(std::wstring_view PdbPath)
{
	auto status = CoInitialize(nullptr);
	if (FAILED(status))
	{
		return false;
	}

	CComPtr<IDiaDataSource> dataSource{};
	status = NoRegCoCreate(L"msdia140.dll", __uuidof(DiaSource), __uuidof(IDiaDataSource), reinterpret_cast<void**>(&dataSource));
	if (FAILED(status))
	{
		return false;
	}

	status = dataSource->loadDataFromPdb(PdbPath.data());
	if (FAILED(status))
	{
		return false;
	}

	if (FAILED(dataSource->openSession(&m_Session)))
	{
		return false;
	}

	return SUCCEEDED(m_Session->get_globalScope(&m_GlobalSymbol));
}

std::vector<DiaSymbols::SectionData> DiaSymbols::GetSectionsData()
{
	std::vector<DiaSymbols::SectionData> sections{};

	CComPtr<IDiaEnumTables> enumTables{};
	if (FAILED(m_Session->getEnumTables(&enumTables)))
	{
		return {};
	}

	IDiaTable* tmpPointer{};
	ULONG celt{};
	while (SUCCEEDED(enumTables->Next(1, &tmpPointer, &celt)) && celt == 1)
	{
		CComPtr<IDiaTable> diaTable{ tmpPointer };
		BSTR name{};
		if (FAILED(diaTable->get_name(&name)) || !name)
		{
			continue;
		}

		if (std::wstring_view{ name } != L"SegmentMap")
		{
			continue;
		}

		CComPtr<IDiaEnumSegments> enumSegments{};
		if (FAILED(diaTable->QueryInterface(_uuidof(IDiaEnumSegments), reinterpret_cast<void**>(&enumSegments))))
		{
			continue;
		}

		IDiaSegment* tmpPointer{};
		while (SUCCEEDED(enumSegments->Next(1, &tmpPointer, &celt)) && celt == 1)
		{
			CComPtr<IDiaSegment> diaSegment{ tmpPointer };
			SectionData section{};

			if (FAILED(diaSegment->get_virtualAddress(&section.Address)) || FAILED(diaSegment->get_length(&section.Size)) ||
				FAILED(diaSegment->get_read(&section.Read)) || FAILED(diaSegment->get_write(&section.Write)) || FAILED(diaSegment->get_execute(&section.Execute)))
			{
				return {};
			}

			if (!section.Address && section.Size == -1)
			{
				continue;
			}

			if (section.Address % 0x1000)
			{
				sections.rbegin()->Size += section.Size;
			}
			else
			{
				sections.emplace_back(std::move(section));
			}
		}
	}

	return sections;
}

srcsync::PublicSymbolsData DiaSymbols::GetPublicSymbols()
{
	CComPtr<IDiaEnumSymbols> enumSymbols{};
	if (FAILED(m_GlobalSymbol->findChildren(SymTagPublicSymbol, NULL, nsNone, &enumSymbols)))
	{
		return {};
	}

	srcsync::PublicSymbolsData result{};
	IDiaSymbol* tmpPointer{};
	ULONG celt{};
	while (SUCCEEDED(enumSymbols->Next(1, &tmpPointer, &celt)) && celt == 1)
	{
		CComPtr<IDiaSymbol> symbol{ tmpPointer };
		if (auto symbolData = GetSymbol(symbol); symbolData.has_value())
		{
			result.emplace_back(std::move(*symbolData));
		}
	}

	return result;
}

srcsync::StructsData DiaSymbols::GetStructs()
{
	CComPtr<IDiaEnumSymbols> enumSymbols{};
	if (FAILED(m_GlobalSymbol->findChildren(SymTagUDT, NULL, nsNone, &enumSymbols)))
	{
		return {};
	}

	IDiaSymbol* tmpPointer{};
	ULONG celt{};
	srcsync::StructsData result{};
	while (SUCCEEDED(enumSymbols->Next(1, &tmpPointer, &celt)) && celt == 1)
	{
		CComPtr<IDiaSymbol> symbol{ tmpPointer };
		auto structWithMembers = GetStructWithMembers(symbol);
		if (!structWithMembers.has_value())
		{
			continue;
		}

		result.emplace_back(std::move(*structWithMembers));
	}

	return result;
}

srcsync::EnumsData DiaSymbols::GetEnums()
{
	srcsync::EnumsData enums{};

	CComPtr<IDiaEnumSymbols> enumSymbols{};
	if (FAILED(m_GlobalSymbol->findChildren(SymTagEnum, NULL, nsNone, &enumSymbols)))
	{
		return {};
	}

	IDiaSymbol* tmpPointer{};
	ULONG celt{};
	while (SUCCEEDED(enumSymbols->Next(1, &tmpPointer, &celt)) && celt == 1)
	{
		CComPtr<IDiaSymbol> symbol{ tmpPointer };
		auto enumWithMembers = GetEnum(symbol);
		if (!enumWithMembers.has_value())
		{
			continue;
		}

		enums.emplace_back(std::move(*enumWithMembers));
	}

	return enums;
}

srcsync::FunctionsData DiaSymbols::GetFunctionsData()
{
	srcsync::FunctionsData functionsData{};

	auto addFunctionData = [&](const auto& EnumSymbols) {
		IDiaSymbol* tmpPointer{};
		ULONG celt{};
		while (SUCCEEDED(EnumSymbols->Next(1, &tmpPointer, &celt)) && celt == 1)
		{
			CComPtr<IDiaSymbol> symbol{ tmpPointer };
			auto functionData = GetFunctionData(symbol);
			if (!functionData.has_value())
			{
				continue;
			}

			const auto iter = std::ranges::find_if(functionsData, [&](const auto& FunctionData) { return FunctionData.FunctionName == functionData->FunctionName; });
			if (iter == functionsData.end())
			{
				functionsData.emplace_back(std::move(*functionData));
			}
		}
	};

	CComPtr<IDiaEnumSymbols> enumSymbols{};
	if (SUCCEEDED(m_GlobalSymbol->findChildren(SymTagFunction, NULL, nsNone, &enumSymbols)))
	{
		addFunctionData(enumSymbols);
	}

	enumSymbols.Release();
	if (SUCCEEDED(m_GlobalSymbol->findChildren(SymTagCompiland, NULL, nsNone, &enumSymbols)))
	{
		ULONG celt{};
		IDiaSymbol* tmpPointer{};
		while (SUCCEEDED(enumSymbols->Next(1, reinterpret_cast<IDiaSymbol**>(&tmpPointer), &celt)) && celt == 1)
		{
			CComPtr<IDiaSymbol> compiland{ tmpPointer };
			CComPtr<IDiaEnumSymbols> enumChildren{};
			if (FAILED(compiland->findChildren(SymTagNull, NULL, nsNone, &enumChildren)))
			{				
				continue;
			}

			addFunctionData(enumChildren);
		}
	}

	return functionsData;
}

std::optional<srcsync::PublicSymbolData> DiaSymbols::GetSymbol(CComPtr<IDiaSymbol>& DiaSymbol)
{
	DWORD symTag{};
	if (FAILED(DiaSymbol->get_symTag(&symTag)) || symTag == SymTagLabel || symTag == SymTagCoffGroup || symTag == SymTagCompilandEnv)
	{
		return {};
	}

	auto symbolName = GetSymbolName(DiaSymbol);
	if (symbolName.empty() || SkipSymbol(symbolName))
	{
		return {};
	}

	ULONG offset{};
	if (FAILED(DiaSymbol->get_relativeVirtualAddress(&offset)) || offset == 0)
	{
		return {};
	}

	BOOL isFunction{};
	if (FAILED(DiaSymbol->get_function(&isFunction)))
	{
		return {};
	}

	return srcsync::PublicSymbolData{ std::move(symbolName), offset, static_cast<bool>(isFunction) };
}

std::optional<srcsync::StructData> DiaSymbols::GetStructWithMembers(CComPtr<IDiaSymbol>& Symbol)
{
	BSTR wideName{};
	if (FAILED(Symbol->get_name(&wideName)) || !wideName || IsTypeAnonymous(wideName))
	{
		return {};
	}

	CComPtr<IDiaEnumSymbols> enumSymbols{};
	if (FAILED(Symbol->findChildren(SymTagNull, NULL, nsNone, &enumSymbols)))
	{
		return {};
	}

	DWORD structSize{};
	if (FAILED(Symbol->get_sizeInUdt(&structSize)))
	{
		return {};
	}

	std::wstring_view wideNameView = wideName;
	std::string name{ wideNameView.begin(), wideNameView.end() };
	if (!name.starts_with("_"))
	{
		name = "_" + name;
	}

	auto members = GetStructMembers(enumSymbols);
	if (members.empty())
	{
		return {};
	}

	return srcsync::StructData{ srcsync::StructKind::Structure, std::move(name), structSize, std::move(members) };
}

std::vector<srcsync::MemberData> DiaSymbols::GetStructMembers(CComPtr<IDiaEnumSymbols>& EnumSybols)
{
	std::vector<srcsync::MemberData> members{};

	ULONG celt{};
	IDiaSymbol* tmpPointer{};
	while (SUCCEEDED(EnumSybols->Next(1, &tmpPointer, &celt)) && celt == 1)
	{
		CComPtr<IDiaSymbol> memberSymbol{ tmpPointer };
		DWORD symTag{};
		if (FAILED(memberSymbol->get_symTag(&symTag)) || symTag == SymTagFunction || symTag == SymTagTypedef ||
			symTag == SymTagBaseClass || symTag == SymTagEnum || symTag == SymTagUDT)
		{
			continue;
		}

		DWORD dataKind{};
		if (FAILED(memberSymbol->get_dataKind(&dataKind)) || dataKind == DataIsStaticMember)
		{
			continue;
		}

		LONG offset{};
		if (FAILED(memberSymbol->get_offset(&offset)))
		{
			continue;
		}

		auto memberName = GetSymbolName(memberSymbol);
		if (memberName.empty())
		{
			continue;
		}

		const auto typeName = GetTypeName(memberSymbol, false);
		if (IsTypeAnonymous(std::wstring{ typeName.begin(), typeName.end() }))
		{
			// It means we must add data recursively
			IDiaSymbol* tmpPointer{};
			if (FAILED(memberSymbol->get_type(&tmpPointer)))
			{
				return {};
			}
			CComPtr<IDiaSymbol> typeSymbol{ tmpPointer };

			CComPtr<IDiaEnumSymbols> enumSymbols{};
			if (FAILED(typeSymbol->findChildren(SymTagNull, NULL, nsNone, &enumSymbols)))
			{
				return {};
			}

			auto unnamedStructMembers = GetStructMembers(enumSymbols);
			for (auto& unnamedStructMember : unnamedStructMembers)
			{
				unnamedStructMember.Offset += offset;
			}

			members.append_range(unnamedStructMembers);
			continue;
		}

		members.emplace_back(srcsync::MemberData{ std::move(memberName), std::move(typeName), static_cast<size_t>(offset), GetBitfieldData(memberSymbol)});
	}

	return members;
}

std::optional<srcsync::BitfieldTypeData> DiaSymbols::GetBitfieldData(CComPtr<IDiaSymbol>& Symbol)
{
	ULONG locationType{};
	if (FAILED(Symbol->get_locationType(&locationType)))
	{
		return {};
	}

	std::optional<srcsync::BitfieldTypeData> bitfieldData{};
	if (LocIsBitField != locationType)
	{
		return {};
	}

	ULONG bitPosition{};
	if (FAILED(Symbol->get_bitPosition(&bitPosition)))
	{
		return {};
	}

	ULONGLONG len{};
	if (FAILED(Symbol->get_length(&len)))
	{
		return {};
	}

	return srcsync::BitfieldTypeData{ static_cast<uint8_t>(bitPosition), static_cast<uint8_t>(len) };
}

std::optional<srcsync::EnumData> DiaSymbols::GetEnum(CComPtr<IDiaSymbol>& Symbol)
{
	DWORD symTag{};
	if (FAILED(Symbol->get_symTag(&symTag)) || symTag != SymTagEnum)
	{
		return {};
	}

	BSTR wideName{};
	if (FAILED(Symbol->get_name(&wideName)) || !wideName || !std::wcslen(wideName))
	{
		return {};
	}

	CComPtr<IDiaEnumSymbols> enumSymbols{};
	if (FAILED(Symbol->findChildren(SymTagNull, NULL, nsNone, &enumSymbols)))
	{
		return {};
	}

	auto members = GetEnumMembers(enumSymbols);
	if (members.empty())
	{
		return {};
	}

	std::wstring_view wideNameView = wideName;
	std::string name{ wideNameView.begin(), wideNameView.end() };
	if (!name.starts_with("_"))
	{
		name = "_" + name;
	}

	return srcsync::EnumData{ std::move(name), GetTypeName(Symbol, true), std::move(members)};
}

std::vector<srcsync::EnumeratorData> DiaSymbols::GetEnumMembers(CComPtr<IDiaEnumSymbols>& EnumSybols)
{
	std::vector<srcsync::EnumeratorData> members{};

	ULONG celt{};
	IDiaSymbol* tmpPointer{};
	while (SUCCEEDED(EnumSybols->Next(1, &tmpPointer, &celt)) && celt == 1)
	{
		CComPtr<IDiaSymbol> memberSymbol{ tmpPointer };
		DWORD symTag{};
		if (FAILED(memberSymbol->get_symTag(&symTag)))
		{
			continue;
		}

		auto memberName = GetSymbolName(memberSymbol);
		if (memberName.empty())
		{
			continue;
		}

		LONG offset{};
		if (FAILED(memberSymbol->get_offset(&offset)))
		{
			continue;
		}

		VARIANT variant{};
		if (FAILED(memberSymbol->get_value(&variant)))
		{
			continue;
		}

		size_t value{};
		switch (variant.vt)
		{
			case VT_UI1: 
				value = variant.bVal;
				break;
			case VT_UI2: 
				value = variant.uiVal;
				break;
			case VT_UI4: 
				value = variant.ulVal;
				break;
			case VT_UI8:
				value = variant.ullVal;
				break;
			case VT_UINT:
				value = variant.uintVal;
				break;
			case VT_INT:
				value = variant.intVal;
				break;
			case VT_I1:
				value = variant.cVal;
				break;
			case VT_I2:
				value = variant.iVal;
				break;
			case VT_I4:
				value = variant.lVal;
				break;
			case VT_I8:
				value = variant.llVal;
				break;
		}

		members.emplace_back(srcsync::EnumeratorData{ std::move(memberName), value });
	}

	return members;
}

std::optional<srcsync::FunctionData> DiaSymbols::GetFunctionData(CComPtr<IDiaSymbol>& Symbol)
{
	srcsync::FunctionData functionData{};

	DWORD symTag{};
	if (FAILED(Symbol->get_symTag(&symTag)) || symTag != SymTagFunction)
	{
		return {};
	}

	auto functionName = GetSymbolName(Symbol);
	if (functionName.empty() || SkipSymbol(functionName)) 
	{
		return {};
	}
	functionData.FunctionName = std::move(functionName);

	auto typeName = GetTypeName(Symbol, false);
	if (typeName.empty())
	{
		return {};
	}
	functionData.TypeName = std::move(typeName);

	DWORD relativeVirtualAddress{};
	if (FAILED(Symbol->get_relativeVirtualAddress(&relativeVirtualAddress)))
	{
		return {};
	}
	functionData.RelativeAddress = relativeVirtualAddress;

	ULONGLONG size{};
	if (FAILED(Symbol->get_length(&size)))
	{
		return {};
	}
	functionData.Size = size;

	return functionData;
}

std::string DiaSymbols::GetTypeName(CComPtr<IDiaSymbol>& Symbol, bool IgnoreSign)
{
	IDiaSymbol* tmpPointer{};
	if (FAILED(Symbol->get_type(&tmpPointer)))
	{
		return {};
	}
	CComPtr<IDiaSymbol> typeSymbol{ tmpPointer };

	DWORD symTag{};
	if (FAILED(typeSymbol->get_symTag(&symTag)))
	{
		return {};
	}

	if (symTag == SymTagBaseType)
	{
		BasicType baseType{};
		if (FAILED(typeSymbol->get_baseType(reinterpret_cast<DWORD*>(&baseType))))
		{
			return {};
		}

		ULONGLONG size{};
		typeSymbol->get_length(&size);

		return BasicTypeToString(baseType, size, IgnoreSign).data();
	}
	else if (symTag == SymTagUDT || symTag == SymTagEnum)
	{
		ULONGLONG len{};
		if (FAILED(typeSymbol->get_length(&len)))
		{
			return {};
		}

		BSTR typeWideName{};
		if (FAILED(typeSymbol->get_name(&typeWideName)) || !typeWideName || !wcslen(typeWideName))
		{
			return {};
		}

		if (!len)
		{
			return "void";
		}

		std::wstring_view typeName{ typeWideName };
		return std::string{ typeName.begin(), typeName.end() };
	}
	else if (symTag == SymTagPointerType)
	{
		return GetTypeName(typeSymbol, false) + "*";
	}
	else if (symTag == SymTagArrayType)
	{
		DWORD count{};
		if (FAILED(typeSymbol->get_count(&count)))
		{
			return {};
		}

		return std::format("{}[{}]", GetTypeName(typeSymbol, false), count);
	}
	else if (symTag == SymTagFunctionType)
	{
		CComPtr<IDiaEnumSymbols> enumSymbols;
		if (FAILED(typeSymbol->findChildren(SymTagNull, NULL, nsNone, &enumSymbols)))
		{
			return "(*)()";
		}

		LONG numberOfFunctionParameters{};
		if (FAILED(enumSymbols->get_Count(&numberOfFunctionParameters)) || !numberOfFunctionParameters)
		{
			return "(*)()";
		}

		ULONG celt{};
		std::string functionParameters{};
		while (SUCCEEDED(enumSymbols->Next(1, &tmpPointer, &celt)) && (celt == 1))
		{
			CComPtr<IDiaSymbol> functionParameterSymbol{ tmpPointer };
			functionParameters += GetTypeName(functionParameterSymbol, false) + ",";
		}

		return std::format("(*)({})", functionParameters);
	}

	return {};
}

std::string DiaSymbols::GetSymbolName(CComPtr<IDiaSymbol>& Symbol)
{
	BSTR wideName{};
	if (FAILED(Symbol->get_name(&wideName)) || !wideName)
	{
		return {};
	}

	std::wstring_view wideNameView{ wideName };
	return std::string{ wideNameView.begin(), wideNameView.end() };
}

std::string_view DiaSymbols::BasicTypeToString(BasicType BasicType, size_t Size, bool IgnoreSign)
{
	switch (BasicType)
	{
	case btNoType: return "";
	case btVoid: return "void";
	case btChar: return "char";
	case btWChar: return "wchar";
	case btInt:
		// No idea how to distinguish if enum underlying type is signed or not with ida pro api
		if (!IgnoreSign)
		{
			switch (Size)
			{
			case 1:
				return "int8";
			case 2:
				return "int16";
			case 4:
				return "int32";
			case 8:
				return "int64";
			}
			break;
		}
	case btUInt:
		switch (Size)
		{
		case 1:
			return "uint8";
		case 2:
			return "uint16";
		case 4:
			return "uint32";
		case 8:
			return "uint64";
		}
		break;
	case btFloat:
		switch (Size)
		{
		case 4:
			return "float";
		case 8:
			return "double";
		}
		break;
	case btBCD:
		return "<BCD>";
	case btBool:
		return "bool";
	case btLong:
		return "int32";
	case btULong:
		return "uint32";
	case btCurrency:
		return "<currency>";
	case btDate:
		return "<date>";
	case btVariant:
		return "<variant>";
	case btComplex:
		return "<complex>";
	case btBit:
		return "<bit>";
	case btBSTR:
		return "BSTR";
	case btHresult:
		return "int32";
	case btChar16:
		return "char16_t";
	case btChar32:
		return "char32_t";
	case btChar8:
		return "char8_t";
	}

	return "";
}

bool DiaSymbols::IsTypeAnonymous(std::wstring_view TypeName)
{
	static std::wregex anonymousStructRegex(L"\\$[0-9A-F]{32}", std::regex_constants::extended | std::regex_constants::icase);

	return TypeName.contains(L"<anonymous-tag") ||
		TypeName.contains(L"<unnamed-tag") ||
		TypeName.contains(L"__unnamed") ||
		TypeName.contains(L"<unnamed-type") ||
		TypeName.contains(L"<unnamed_type") ||
		std::regex_search(TypeName.data(), anonymousStructRegex);
}

bool DiaSymbols::SkipSymbol(std::string_view SymbolName)
{
	return SymbolName.empty() ||
		SymbolName.contains("??_C@") ||
		SymbolName.contains("__imp_") ||
		SymbolName.contains("NULL_THUNK_DATA") ||
		SymbolName.contains("NULL_IMPORT_DESCRIPTOR");
}
