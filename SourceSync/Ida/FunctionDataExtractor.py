from dataclasses import dataclass
from pathlib import Path
import hashlib
import idaapi
import ida_hexrays
import ida_funcs
import ida_range
import ida_ua
import ida_allins
import ida_idp
import ida_nalt
import ida_typeinf
import ida_kernwin
import PdbGeneratorPy
from idautils import Functions

class Registers64bit():
    REG_RAX = 0
    REG_RCX = 1
    REG_RDX = 2
    REG_RBX = 3
    REG_RSP = 4
    REG_RBP = 5
    REG_RSI = 6
    REG_RDI = 7
    REG_R8 = 8
    REG_R9 = 9
    REG_R10 = 10
    REG_R11 = 11
    REG_R12 = 12
    REG_R13 = 13
    REG_R14 = 14
    REG_R15 = 15

@dataclass
class DiscardedRange:
    StartEa: int
    EndEa: int
    PseudoCodeLineNumber: int

class FunctionDataExtractor:
    def __init__(Self, TypeExtractor):
        Self.TypeExtractor = TypeExtractor
        Self.SourceCodeOutputPath = Path.cwd() / "DecompiledSourceCode"
        Self.SourceCodeOutputPath.mkdir(exist_ok=True)

    def GetFunctionsData(self):
        functionsData = PdbGeneratorPy.FunctionsData()

        for functionEa in Functions():
            functionData = self.GetFunctionData(functionEa, ExecuteSync=False)
            if functionData:
                functionsData.append(functionData)

        return functionsData

    def GetFunctionData(self, FunctionEa, ExecuteSync):
        functionData = PdbGeneratorPy.FunctionData()

        def GetFunctionDataInternal():
            function = ida_funcs.get_func(FunctionEa)
            if not function:
                return

            if function.flags & ida_funcs.FUNC_THUNK:
                return

            functionData.Size = function.size()
            functionData.RelativeAddress = function.start_ea - ida_nalt.get_imagebase()

            try:
                decompiledFunction = ida_hexrays.decompile(function, ida_hexrays.hexrays_failure_t(), ida_hexrays.DECOMP_NO_WAIT)
                if not decompiledFunction:
                    return
            except:
                return

            functionName = ida_funcs.get_func_name(decompiledFunction.entry_ea)
            if not functionName:
                return

            functionType = ida_typeinf.tinfo_t()
            if not decompiledFunction.get_func_type(functionType):
                return

            self.TypeExtractor.InsertTypeInfoData(functionType)
            
            functionData.FunctionName = functionName
            functionData.FilePath = self.__CreateFilePath(functionName)
            functionData.TypeName = self.TypeExtractor.GetTypeName(functionType)
            pseudoCode = self.__GetPseudoCode(decompiledFunction.get_pseudocode())
            functionData.LocalVariables = self.__GetFunctionLocalVariables(decompiledFunction, function)
            functionData.InstructionOffsetToPseudoCodeLine = self.__GetInstructionsOffsetToPseudoCodeLines(
                decompiledFunction, pseudoCode.split("\r\n"))
            
            if not functionData.InstructionOffsetToPseudoCodeLine:
                return

            with open(functionData.FilePath, "wb") as sourceFile:
                sourceFile.write(bytes(pseudoCode, "utf-8"))

        if ExecuteSync:
            ida_kernwin.execute_sync(GetFunctionDataInternal, 0)
        else:
            GetFunctionDataInternal()

        if not functionData.Size and not functionData.RelativeAddress:
            return None
        else:
            return functionData

    def __GetPseudoCode(self, PseudoCode):
        pseudoCode = ""
        for lineOfCode in PseudoCode:
            pseudoCode += idaapi.tag_remove(lineOfCode.line) + "\r\n"
        return pseudoCode

    def __GetInstructionsOffsetToPseudoCodeLines(self, DecompiledFunction, PseudoCodeLines):
        instructionOffsetsToPseudoCodeLines = PdbGeneratorPy.InstructionsToLines()
        discardedRanges = []
        addedPsuedoCodeLines = set()
        mappedRanges = ida_range.rangeset_t()

        boundaries = DecompiledFunction.get_boundaries()
        for instruction, addressRanges in boundaries.items():
            mappedRanges.add(addressRanges)

        for instruction, addressRanges in boundaries.items():
            lineNumber = DecompiledFunction.find_item_coords(instruction)[1] + 1

            if lineNumber in addedPsuedoCodeLines:
                continue

            addedPsuedoCodeLines.add(lineNumber)

            # Ignore mapping with last pseudocode line i.e. '}' 
            if lineNumber == len(PseudoCodeLines) - 1:
                continue

            # Used to map the first instruction of a function to psuedocode line with '{'
            # as sometimes first instructions may not have mapping at all
            if not PseudoCodeLines[lineNumber - 1]:
                for index, line in enumerate(PseudoCodeLines):
                    if line.startswith("{"):
                        instructionOffsetsToPseudoCodeLines.insert(0, index + 1)
                        break
                continue
                
            adjustedRanges = ida_range.rangeset_t(addressRanges)
            for index, currentRange in enumerate(addressRanges):
                if index == 0:
                    continue
                    
                # In some cases, some assembler instructions may not have a mapping to the psuedocode line,
                # so we need to merge two ranges with unmapped instructions in between.
                previousRange = addressRanges[index - 1]
                if not mappedRanges.includes(ida_range.range_t(previousRange.end_ea, currentRange.start_ea)):
                    adjustedRanges.add(ida_range.range_t(previousRange.start_ea, currentRange.end_ea))

            address = self.__GetAddressOfInstructionForPseudoCodeLineMapping(
                    adjustedRanges,
                    discardedRanges,
                    lineNumber,
                ) - DecompiledFunction.entry_ea

            # In some cases a pseudocode line may refer to an assembly instruction that is below the function address 
            # Unfortunately pdb does not support such situations, i.e. all addresses must be above the function address.
            if address < 0:
                continue
                
            instructionOffsetsToPseudoCodeLines.insert(address, lineNumber)

        for discardedRange in discardedRanges:
            startOfNextInstruction = instructionOffsetsToPseudoCodeLines.get(discardedRange.EndEa - DecompiledFunction.entry_ea)
            if startOfNextInstruction is None:
                continue

            distance = discardedRange.PseudoCodeLineNumber - startOfNextInstruction
            if distance == 1:
                instructionOffsetsToPseudoCodeLines.update_key(discardedRange.EndEa - DecompiledFunction.entry_ea, discardedRange.StartEa - DecompiledFunction.entry_ea)

        return instructionOffsetsToPseudoCodeLines
    
    def __GetAddressOfInstructionForPseudoCodeLineMapping(self, RangeSet, DiscardedRanges, PseudoCodeLineNumber):
        # We are looking for the first call instruction because sometimes the pseudocode line refers
        # to non-contiguous assembly instructions, so mapping the pseudocode line
        # to the first call instruction should be the most optimal solution
        for index, addressRange in enumerate(RangeSet):
            currentAddress = addressRange.start_ea
            while currentAddress < addressRange.end_ea:
                ins = ida_ua.insn_t()
                if ida_ua.decode_insn(ins, currentAddress) == 0:
                    break
                
                currentAddress += ins.size

                if ins.itype == ida_allins.NN_call or ins.itype == ida_allins.NN_callfi or ins.itype == ida_allins.NN_callni:
                    return addressRange.start_ea

            if index < RangeSet.nranges() - 1:
                DiscardedRanges.append(DiscardedRange(addressRange.start_ea, addressRange.end_ea, PseudoCodeLineNumber))

        # If there is no call instruction, return the first instruction from the last range
        return RangeSet.lastrange().start_ea

    def __GetFunctionShadowSpaceArguments(self, DecompiledFunction, Function):
        shadowSpaceArguments = PdbGeneratorPy.LocalVariables()
        if not DecompiledFunction.argidx or not self.__IsX86_64():
            return shadowSpaceArguments

        numberOfArgumentsOnShadowSpace = min(len(DecompiledFunction.argidx), 4)

        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, Function.start_ea) == 0:
            return shadowSpaceArguments

        if insn.itype == ida_allins.NN_mov and insn.Op1.type == ida_ua.o_displ and insn.Op1.reg == Registers64bit.REG_RSP \
                and insn.Op1.addr == 8 * numberOfArgumentsOnShadowSpace and insn.Op2.type == ida_ua.o_reg:
            
            if (numberOfArgumentsOnShadowSpace == 1 and insn.Op2.reg != Registers64bit.REG_RCX) or \
                    (numberOfArgumentsOnShadowSpace == 2 and insn.Op2.reg != Registers64bit.REG_RDX) or \
                    (numberOfArgumentsOnShadowSpace == 3 and insn.Op2.reg != Registers64bit.REG_R8) or \
                    (numberOfArgumentsOnShadowSpace == 4 and insn.Op2.reg != Registers64bit.REG_R9):
                return shadowSpaceArguments

            for i in range(numberOfArgumentsOnShadowSpace):
                lvar = DecompiledFunction.get_lvars()[i]
                self.TypeExtractor.InsertTypeInfoData(lvar.type())

                shadowSpaceArgument = PdbGeneratorPy.LocalVariable()
                shadowSpaceArgument.Name = lvar.name
                shadowSpaceArgument.TypeName = self.TypeExtractor.GetTypeName(lvar.type())
                shadowSpaceArgument.RegistryName = "rsp"
                shadowSpaceArgument.Offset = 8 * (i + 1) + Function.frsize

                shadowSpaceArguments.append(shadowSpaceArgument)

        return shadowSpaceArguments

    def __GetFunctionLocalVariables(self, DecompiledFunction, Function):
        lvars = DecompiledFunction.get_lvars()
        if not lvars:
            return PdbGeneratorPy.LocalVariables()

        localVariables = self.__GetFunctionShadowSpaceArguments(DecompiledFunction, Function)
        for index, lvar in enumerate(lvars):
            if index < len(localVariables) or not lvar.name:
                continue

            self.TypeExtractor.InsertTypeInfoData(lvar.type())

            localVariable = PdbGeneratorPy.LocalVariable()
            localVariable.Name = lvar.name
            localVariable.TypeName = self.TypeExtractor.GetTypeName(lvar.type())

            if lvar.is_reg_var():
                registryName = ida_idp.get_reg_name(ida_hexrays.mreg2reg(lvar.get_reg1(), lvar.width), lvar.width)
                if not registryName:
                    continue
                
                localVariable.RegistryName = registryName

            elif lvar.is_stk_var():
                stackOffset = lvar.get_stkoff()
                if Function.flags & ida_funcs.FUNC_FRAME:
                    localVariable.Offset = stackOffset - (Function.frsize - Function.fpd) - DecompiledFunction.get_stkoff_delta()
                    
                    if self.__IsX86_64():
                        localVariable.RegistryName = "rbp"
                    else:
                        localVariable.RegistryName = "ebp"
                else:
                    localVariable.Offset = stackOffset - DecompiledFunction.get_stkoff_delta()
                    
                    if self.__IsX86_64():
                        localVariable.RegistryName = "rsp"
                    else:
                        localVariable.RegistryName = "esp"
            else:
                continue

            localVariables.append(localVariable)

        return localVariables

    def __CreateFilePath(self, FunctionName):
        # Characters '?' and ':' are illegal to use inside file name so replace them
        FunctionName = FunctionName.replace("?", "!")
        FunctionName = FunctionName.replace("::", "++")
        functionPath = str(self.SourceCodeOutputPath / f"{FunctionName}.c")
        
        # Guard for windows maximum file path
        if len(functionPath) >= 240:
            functionPath = functionPath[:205] + "_" + self.__GetMD5HashAsString(FunctionName) + ".c"

        return functionPath
    
    def __GetMD5HashAsString(self, Data):
        md5 = hashlib.md5()
        md5.update(Data.encode())
        return md5.hexdigest()

    def __IsX86_64(self):
        return ida_idp.ph.id == ida_idp.PLFM_386 and ida_idp.ph.flag & ida_idp.PR_USE64