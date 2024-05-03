import ida_bytes
import ida_nalt
import ida_netnode
import ida_idp
import ctypes
import PdbGeneratorPy
import windows.generated_def as windef

IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DEBUG_TYPE_CODEVIEW = 2

class IMAGE_DEBUG_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("Characteristics", ctypes.c_uint),
        ("TimeDateStamp", ctypes.c_uint),
        ("MajorVersion", ctypes.c_ushort),
        ("MinorVersion", ctypes.c_ushort),
        ("Type", ctypes.c_uint),
        ("SizeOfData", ctypes.c_uint),
        ("AddressOfRawData", ctypes.c_uint),
        ("PointerToRawData", ctypes.c_uint)
    ]

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ("e_magic", ctypes.c_ushort),
        ("e_cblp", ctypes.c_ushort),
        ("e_cp", ctypes.c_ushort),
        ("e_crlc", ctypes.c_ushort),
        ("e_cparhdr", ctypes.c_ushort),
        ("e_minalloc", ctypes.c_ushort),
        ("e_maxalloc", ctypes.c_ushort),
        ("e_ss", ctypes.c_ushort),
        ("e_sp", ctypes.c_ushort),
        ("e_csum", ctypes.c_ushort),
        ("e_ip", ctypes.c_ushort),
        ("e_cs", ctypes.c_ushort),
        ("e_lfarlc", ctypes.c_ushort),
        ("e_ovno", ctypes.c_ushort),
        ("e_res", ctypes.c_ushort * 4),
        ("e_oemid", ctypes.c_ushort),
        ("e_oeminfo", ctypes.c_ushort),
        ("e_res2", ctypes.c_ushort * 10),
        ("e_lfanew", ctypes.c_uint),
    ]

class PEDataExtractor():

    # To make it work change "PE_LOAD_ALL_SECTIONS" to "YES" in cfg/pe.cfg
    def GetSectionsData(self):
        sectionsData = PdbGeneratorPy.SectionsType()

        imageDosHeaderBytes = ida_bytes.get_bytes(ida_nalt.get_imagebase(), ctypes.sizeof(IMAGE_DOS_HEADER))
        imageDosHeader = IMAGE_DOS_HEADER.from_buffer_copy(imageDosHeaderBytes)
        if imageDosHeader.e_magic != 0x5A4D:
            print("[SourceSync] Failed due to lack of dos header, it is either erased or idb was generated with PE_LOAD_ALL_SECTIONS set to NO")
            return sectionsData

        peHeaderBytes = ida_bytes.get_bytes(ida_nalt.get_imagebase() + imageDosHeader.e_lfanew, ctypes.sizeof(windef.IMAGE_NT_HEADERS32))
        peHeader = windef.IMAGE_NT_HEADERS32.from_buffer_copy(peHeaderBytes)
        
        for i in range(peHeader.FileHeader.NumberOfSections):
            coffSection = PdbGeneratorPy.CoffSection()
            
            imageSectionHeaderBytes = ida_bytes.get_bytes(ida_nalt.get_imagebase() + imageDosHeader.e_lfanew + peHeader.FileHeader.SizeOfOptionalHeader + 24 + i * ctypes.sizeof(windef.IMAGE_SECTION_HEADER), ctypes.sizeof(windef.IMAGE_SECTION_HEADER))
            imageSectionHeader = windef.IMAGE_SECTION_HEADER.from_buffer_copy(imageSectionHeaderBytes)
            coffSection.Name = ''.join(map(chr, imageSectionHeader.Name[:]))
            coffSection.VirtualSize = imageSectionHeader.VirtualSize
            coffSection.VirtualAddress = imageSectionHeader.VirtualAddress
            coffSection.SizeOfRawData = imageSectionHeader.SizeOfRawData
            coffSection.PointerToRawData = imageSectionHeader.PointerToRawData
            coffSection.PointerToRelocations = imageSectionHeader.PointerToRelocations
            coffSection.PointerToLinenumbers = imageSectionHeader.PointerToLinenumbers
            coffSection.Characteristics = imageSectionHeader.Characteristics
            sectionsData.append(coffSection)
            
        return sectionsData
            
    def GetPdbInfo(self):
        peHeaderNode = ida_netnode.netnode()
        peHeaderNode.create("$ PE header")
        peHeader = windef.IMAGE_NT_HEADERS32.from_buffer_copy(peHeaderNode.valobj())

        imageDirDebug = peHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
        if not imageDirDebug.Size:
            return None

        debugDirectoryBytes = ida_bytes.get_bytes(imageDirDebug.VirtualAddress + ida_nalt.get_imagebase(), imageDirDebug.Size)
        debugDirectoryCount = imageDirDebug.Size // ctypes.sizeof(IMAGE_DEBUG_DIRECTORY)
        debugDirectories = [IMAGE_DEBUG_DIRECTORY.from_buffer_copy(debugDirectoryBytes[i * ctypes.sizeof(IMAGE_DEBUG_DIRECTORY): (i + 1) * ctypes.sizeof(IMAGE_DEBUG_DIRECTORY)]) for i in range(debugDirectoryCount)]

        for i in range(debugDirectoryCount):
            debugDirectoryEntry = debugDirectories[i]
            if debugDirectoryEntry.Type != IMAGE_DEBUG_TYPE_CODEVIEW:
                continue

            debugInfo = bytearray(ida_bytes.get_bytes(debugDirectoryEntry.AddressOfRawData + ida_nalt.get_imagebase(), debugDirectoryEntry.SizeOfData))

            if len(debugInfo) > 4 and debugInfo[:4] == b"RSDS":
                pdbInfo = PdbGeneratorPy.PdbInfo()
                pdbInfo.Name = debugInfo[24:].decode("utf-8").split('\\')[-1]
                pdbInfo.Age = int.from_bytes(debugInfo[20:24], byteorder="little")
                pdbInfo.Guid = list(debugInfo[4:20])

                return pdbInfo

        return None
    
    def GetImageBase(self):
        return ida_nalt.get_imagebase()
    
    def GetImageName(self):
        return ida_nalt.get_root_filename()
    
    def GetCpuArchitecture(self):
        if ida_idp.ph.id == ida_idp.PLFM_386 and ida_idp.ph.flag & ida_idp.PR_USE64:
            return PdbGeneratorPy.CpuArchitectureType.X86_64
        elif ida_idp.ph.id == ida_idp.PLFM_386 and not ida_idp.ph.flag & ida_idp.PR_USE64:
            return PdbGeneratorPy.CpuArchitectureType.X86
        
        return None
