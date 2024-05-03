#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>
#include <pybind11/numpy.h>
#include <pybind11/complex.h>
#include <pybind11/pytypes.h>

#include "ComplexType.h"
#include "FunctionData.h"
#include "PEData.h"
#include "StructEnumData.h"
#include "SymbolData.h"
#include "PdbGenerator.h"

namespace py = pybind11;

PYBIND11_MAKE_OPAQUE(srcsync::LocalVariables)
PYBIND11_MAKE_OPAQUE(srcsync::InstructionsToLines)
PYBIND11_MAKE_OPAQUE(srcsync::FunctionsData)
PYBIND11_MAKE_OPAQUE(srcsync::MembersData)
PYBIND11_MAKE_OPAQUE(srcsync::EnumeratorsData)
PYBIND11_MAKE_OPAQUE(srcsync::StructsData)
PYBIND11_MAKE_OPAQUE(srcsync::EnumsData)
PYBIND11_MAKE_OPAQUE(srcsync::PublicSymbolsData)
PYBIND11_MAKE_OPAQUE(srcsync::GlobalSymbolsData)
PYBIND11_MAKE_OPAQUE(srcsync::ComplexTypesData)
PYBIND11_MAKE_OPAQUE(srcsync::SectionsType)

PYBIND11_MODULE(PdbGeneratorPy, m)
{
    m.doc() = "PdbGeneratorPy";

    py::bind_vector<srcsync::LocalVariables>(m, "LocalVariables");
    py::bind_map<srcsync::InstructionsToLines>(m, "InstructionsToLines")
        .def("get", [](srcsync::InstructionsToLines& Self, uint32_t Key) { 
            const auto iter = Self.find(Key); 
            return iter == Self.end() ? 0 : iter->second;
        })
        .def("insert", [](srcsync::InstructionsToLines& Self, uint32_t Key, uint32_t Value) { return Self.insert({ Key, Value }).second; })
        .def("update_key", [](srcsync::InstructionsToLines& Self, uint32_t OldKey, uint32_t NewKey) {
            auto node = Self.extract(OldKey);
            node.key() = NewKey;
            Self.insert(std::move(node));
        });
    py::bind_vector<srcsync::FunctionsData>(m, "FunctionsData");
    py::bind_vector<srcsync::MembersData>(m, "MembersData");
    py::bind_vector<srcsync::EnumeratorsData>(m, "EnumeratorsData");
    py::bind_vector<srcsync::StructsData>(m, "StructsData");
    py::bind_vector<srcsync::EnumsData>(m, "EnumsData");
    py::bind_vector<srcsync::PublicSymbolsData>(m, "PublicSymbolsData");
    py::bind_vector<srcsync::GlobalSymbolsData>(m, "GlobalSymbolsData");
    py::bind_vector<srcsync::SectionsType>(m, "SectionsType");
    py::bind_map<srcsync::ComplexTypesData>(m, "ComplexTypesData")
        .def("clear", [](srcsync::ComplexTypesData& Self) { Self.clear(); });

    py::class_<srcsync::ArrayTypeData>(m, "ArrayTypeData")
        .def(py::init())
        .def_readwrite("ValueType", &srcsync::ArrayTypeData::ValueType)
        .def_readwrite("Size", &srcsync::ArrayTypeData::Size);

    py::class_<srcsync::PointerTypeData>(m, "PointerTypeData")
        .def(py::init())
        .def_readwrite("ValueType", &srcsync::PointerTypeData::ValueType);

    py::class_<srcsync::FunctionTypeData>(m, "FunctionTypeData")
        .def(py::init())
        .def_readwrite("ReturnType", &srcsync::FunctionTypeData::ReturnType)
        .def_readwrite("Parameters", &srcsync::FunctionTypeData::Parameters);

    py::class_<srcsync::LocalVariable>(m, "LocalVariable")
        .def(py::init())
        .def_readwrite("Name", &srcsync::LocalVariable::Name)
        .def_readwrite("TypeName", &srcsync::LocalVariable::TypeName)
        .def_readwrite("RegistryName", &srcsync::LocalVariable::RegistryName)
        .def_readwrite("Offset", &srcsync::LocalVariable::Offset);    
    
    py::class_<srcsync::FunctionData>(m, "FunctionData")
        .def(py::init())
        .def_readwrite("FilePath", &srcsync::FunctionData::FilePath)
        .def_readwrite("FunctionName", &srcsync::FunctionData::FunctionName)
        .def_readwrite("TypeName", &srcsync::FunctionData::TypeName)
        .def_readwrite("Size", &srcsync::FunctionData::Size)
        .def_readwrite("RelativeAddress", &srcsync::FunctionData::RelativeAddress)
        .def_readwrite("InstructionOffsetToPseudoCodeLine", &srcsync::FunctionData::InstructionOffsetToPseudoCodeLine)
        .def_readwrite("LocalVariables", &srcsync::FunctionData::LocalVariables);
    
    py::class_<srcsync::CoffSection>(m, "CoffSection")
        .def(py::init())
        .def_property("Name",
            [](srcsync::CoffSection& CoffSection)
            {
                for (size_t i{}; i < sizeof(CoffSection.Name); ++i)
                {
                    if (CoffSection.Name[i] == 0)
                    {
                        return py::str(std::string_view{ CoffSection.Name, i });
                    }
                }

                return py::str(std::string_view{ CoffSection.Name, sizeof(CoffSection.Name) });
            },
            [](srcsync::CoffSection& CoffSection, const std::string& Name)
            { 
                std::memcpy(CoffSection.Name, Name.data(), std::min(Name.size(), sizeof(CoffSection.Name))); 
            })
        .def_readwrite("VirtualSize", &srcsync::CoffSection::VirtualSize)
        .def_readwrite("VirtualAddress", &srcsync::CoffSection::VirtualAddress)
        .def_readwrite("SizeOfRawData", &srcsync::CoffSection::SizeOfRawData)
        .def_readwrite("PointerToRawData", &srcsync::CoffSection::PointerToRawData)
        .def_readwrite("PointerToRelocations", &srcsync::CoffSection::PointerToRelocations)
        .def_readwrite("PointerToLinenumbers", &srcsync::CoffSection::PointerToLinenumbers)
        .def_readwrite("NumberOfRelocations", &srcsync::CoffSection::NumberOfRelocations)
        .def_readwrite("NumberOfLinenumbers", &srcsync::CoffSection::NumberOfLinenumbers)
        .def_readwrite("Characteristics", &srcsync::CoffSection::Characteristics);

    py::enum_<srcsync::CpuArchitectureType>(m, "CpuArchitectureType", py::arithmetic())
        .value("X86_64", srcsync::CpuArchitectureType::X86_64)
        .value("X86", srcsync::CpuArchitectureType::X86);

    py::class_<srcsync::PdbInfo>(m, "PdbInfo")
        .def(py::init())
        .def_readwrite("Name", &srcsync::PdbInfo::Name)
        .def_readwrite("Guid", &srcsync::PdbInfo::Guid)
        .def_readwrite("Age", &srcsync::PdbInfo::Age);

    py::enum_<srcsync::StructKind>(m, "StructKind", py::arithmetic())
        .value("Structure", srcsync::StructKind::Structure)
        .value("Union", srcsync::StructKind::Union);

    py::class_<srcsync::BitfieldTypeData>(m, "BitfieldTypeData")
        .def(py::init())
        .def_readwrite("Position", &srcsync::BitfieldTypeData::Position)
        .def_readwrite("Length", &srcsync::BitfieldTypeData::Length);

    py::class_<srcsync::MemberData>(m, "MemberData")
        .def(py::init())
        .def_readwrite("Name", &srcsync::MemberData::Name)
        .def_readwrite("TypeName", &srcsync::MemberData::TypeName)
        .def_readwrite("Offset", &srcsync::MemberData::Offset)
        .def_readwrite("Bitfield", &srcsync::MemberData::Bitfield);

    py::class_<srcsync::StructData>(m, "StructData")
        .def(py::init())
        .def_readwrite("Kind", &srcsync::StructData::Kind)
        .def_readwrite("Name", &srcsync::StructData::Name)
        .def_readwrite("StructSize", &srcsync::StructData::StructSize)
        .def_readwrite("Members", &srcsync::StructData::Members);

    py::class_<srcsync::EnumeratorData>(m, "EnumeratorData")
        .def(py::init())
        .def_readwrite("Name", &srcsync::EnumeratorData::Name)
        .def_readwrite("Value", &srcsync::EnumeratorData::Value);

    py::class_<srcsync::EnumData>(m, "EnumData")
        .def(py::init())
        .def_readwrite("Name", &srcsync::EnumData::Name)
        .def_readwrite("UnderlyingType", &srcsync::EnumData::UnderlyingType)
        .def_readwrite("Enumerators", &srcsync::EnumData::Enumerators);

    py::class_<srcsync::PublicSymbolData>(m, "PublicSymbolData")
        .def(py::init())
        .def_readwrite("UniqueName", &srcsync::PublicSymbolData::UniqueName)
        .def_readwrite("RelativeAddress", &srcsync::PublicSymbolData::RelativeAddress)
        .def_readwrite("IsFunction", &srcsync::PublicSymbolData::IsFunction);

    py::class_<srcsync::GlobalSymbolData>(m, "GlobalSymbolData")
        .def(py::init())
        .def_readwrite("ShortName", &srcsync::GlobalSymbolData::ShortName)
        .def_readwrite("TypeName", &srcsync::GlobalSymbolData::TypeName)
        .def_readwrite("RelativeAddress", &srcsync::GlobalSymbolData::RelativeAddress);

    py::class_<srcsync::PdbGenerator>(m, "PdbGenerator")
        .def(py::init<const srcsync::ComplexTypesData&, const srcsync::StructsData&, const srcsync::EnumsData&,
            const srcsync::FunctionsData&, const srcsync::PdbInfo&, const srcsync::SectionsType&,
            const srcsync::PublicSymbolsData&, const srcsync::GlobalSymbolsData&, srcsync::CpuArchitectureType>())
        .def("Generate", &srcsync::PdbGenerator::Generate);
}