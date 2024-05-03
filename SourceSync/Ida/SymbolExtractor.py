import ida_name
import ida_funcs
import ida_nalt
import ida_bytes
import ida_typeinf
import ida_kernwin
import ida_strlist
import PdbGeneratorPy

class SymbolExtractor():
    def __init__(self, TypeExtractor):
        self.TypeExtractor = TypeExtractor

    def GetPublics(self, ExecuteSync):
        publicSymbolsData = PdbGeneratorPy.PublicSymbolsData()

        def GetPublicsInternal():
            stringsAddresses = self.__GetStringsAddresses()
            imageBase = ida_nalt.get_imagebase()
            for i in range(0, ida_name.get_nlist_size()):
                effectiveAddress = ida_name.get_nlist_ea(i)
                if effectiveAddress in stringsAddresses:
                    continue

                uniqueName = ida_name.get_nlist_name(i)
                if not uniqueName or uniqueName.startswith("__imp") or uniqueName.startswith("$LN"):
                    continue

                symbolData = PdbGeneratorPy.PublicSymbolData()
                symbolData.RelativeAddress = effectiveAddress - imageBase
                symbolData.UniqueName = uniqueName
                symbolData.IsFunction = ida_funcs.get_func(effectiveAddress) is not None
                publicSymbolsData.append(symbolData)

        if ExecuteSync:
            ida_kernwin.execute_sync(GetPublicsInternal, 0)
        else:
            GetPublicsInternal()

        return publicSymbolsData

    def GetGlobals(self, ExecuteSync):
        globalSymbolsData = PdbGeneratorPy.GlobalSymbolsData()

        def GetGlobalsInternal():
            stringsAddresses = self.__GetStringsAddresses()
            imageBase = ida_nalt.get_imagebase()

            for i in range(0, ida_name.get_nlist_size()):
                effectiveAddress = ida_name.get_nlist_ea(i)
                if effectiveAddress in stringsAddresses:
                    continue
            
                uniqueName = ida_name.get_nlist_name(i)
                if not uniqueName or uniqueName.startswith("__imp") or uniqueName.startswith("$LN"):
                    continue

                if ida_funcs.get_func(effectiveAddress):
                    continue

                demangledName = ida_name.get_demangled_name(effectiveAddress, 8, 0)
                if not demangledName:
                    continue

                itemSize = ida_bytes.get_item_size(effectiveAddress)
                globalSymbolType = ida_typeinf.tinfo_t()
                if not ida_nalt.get_tinfo(globalSymbolType, effectiveAddress) and itemSize != 1 and itemSize != 2 and itemSize != 4 and itemSize != 8:
                    continue

                if globalSymbolType.empty():
                    if itemSize == 1:
                        typeName = "unsigned __int8"
                    if itemSize == 2:
                        typeName = "unsigned __int16"
                    if itemSize == 4:
                        typeName = "unsigned __int32"
                    if itemSize == 8:
                        typeName = "unsigned __int64"
                else:
                    self.TypeExtractor.InsertTypeInfoData(globalSymbolType)
                    typeName = self.TypeExtractor.GetTypeName(globalSymbolType)

                symbolData = PdbGeneratorPy.GlobalSymbolData() 
                symbolData.ShortName = demangledName
                symbolData.TypeName = typeName
                symbolData.RelativeAddress = effectiveAddress - imageBase
                globalSymbolsData.append(symbolData)
        
        if ExecuteSync:
            ida_kernwin.execute_sync(GetGlobalsInternal, 0)
        else:
            GetGlobalsInternal()

        return globalSymbolsData
    
    def __GetStringsAddresses(self):
        stringsAddresses = []
        for i in range(0, ida_strlist.get_strlist_qty()):
            stringInfo = ida_strlist.string_info_t()
            if ida_strlist.get_strlist_item(stringInfo, i):
                stringsAddresses.append(stringInfo.ea)
                
        return stringsAddresses