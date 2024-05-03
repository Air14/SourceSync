import PdbGeneratorPy
import threading
import os
from srcsync.DecompilerSynchronizer_pb2 import (EmptyRequestReply, DecompiledModuleNameReply, GeneratePdbForCallstackReply, GetPdbPathReply, ShouldUpdateSymbolsReply, FunctionBoundaries)
from srcsync.DecompilerSynchronizer_pb2_grpc import DecompilerSynchronizerServicer

class SourceSyncServer(DecompilerSynchronizerServicer):
    def __init__(self, TypeExtractor, PEDataExtractor, SymbolExtractor, FunctionDataExtractor):
        self.TypeExtractor = TypeExtractor
        self.PEDataExtractor = PEDataExtractor
        self.SymbolExtractor = SymbolExtractor
        self.FunctionDataExtractor = FunctionDataExtractor
    
        self.Mutex = threading.Lock()
        self.CallstackFunctionAddresses = []
        self.LastFunctionChanged = False
        self.TypesChanged = False
        self.PublicSymbolsChanged = False
        
        self.PdbInfo = self.PEDataExtractor.GetPdbInfo()
        self.SectionsData = self.PEDataExtractor.GetSectionsData()
        self.ImageBase = self.PEDataExtractor.GetImageBase()
        self.ImageName = self.PEDataExtractor.GetImageName()
        self.CpuArchitecture = self.PEDataExtractor.GetCpuArchitecture()

    def OnFunctionChanged(self, FunctionAddress):
        if FunctionAddress in self.CallstackFunctionAddresses:
            self.LastFunctionChanged = True

    def OnPublicSymbolChanged(self):
        self.PublicSymbolsChanged = True

    def OnTypesChanged(self):
        self.TypesChanged = True

    def Initialize(self, Request, Context):
        self.TypeExtractor.GatherData(ExecuteSync = True)
        self.PublicSymbolsData = self.SymbolExtractor.GetPublics(ExecuteSync = True)
        self.GlobalSymbolsData = self.SymbolExtractor.GetGlobals(ExecuteSync = True)
        return EmptyRequestReply()

    def GetDecompiledModuleName(self, Request, Context):
        reply = DecompiledModuleNameReply()
        if not self.ImageName:
            return reply
        
        reply.ModuleName = self.ImageName
        reply.Status = True
        return reply

    def GeneratePdbForCallstack(self, Request, Context):
        reply = GeneratePdbForCallstackReply()
        with self.Mutex:
            functionsData = PdbGeneratorPy.FunctionsData()

            Request.FunctionsRva.sort()
            for functionRva in Request.FunctionsRva:
                functionData = self.FunctionDataExtractor.GetFunctionData(self.ImageBase + functionRva, ExecuteSync=True)
                if not functionData:
                    continue

                functionsData.append(functionData)
                functionBoundaries = FunctionBoundaries()
                functionBoundaries.StartOfFunctionRva = functionData.RelativeAddress
                functionBoundaries.EndOfFunctionRva = functionData.RelativeAddress + functionData.Size
                reply.FunctionsBoundaries.extend([functionBoundaries])

            reply.Status = self.__GeneratePdb(functionsData)
            if reply.Status:
                self.CallstackFunctionAddresses.clear()
                for functionBoundary in reply.FunctionsBoundaries:
                    self.CallstackFunctionAddresses.append(functionBoundary.StartOfFunctionRva + self.ImageBase)

            return reply

    def GetPdbPath(self, Request, Context):
        reply = GetPdbPathReply()
        reply.Status = True
        reply.PdbPath = os.getcwd()
        return reply

    def ShouldUpdateSymbols(self, Request, Context):
        reply = ShouldUpdateSymbolsReply()
        with self.Mutex:
            if self.TypesChanged or self.PublicSymbolsChanged or self.LastFunctionChanged:
                if self.TypesChanged:
                    self.TypeExtractor.GatherData(ExecuteSync = True)
                    self.TypesChanged = False

                if self.PublicSymbolsChanged:
                    self.PublicSymbolsData = self.SymbolExtractor.GetPublics(ExecuteSync = True)
                    self.GlobalSymbolsData = self.SymbolExtractor.GetGlobals(ExecuteSync = True)
                    self.PublicSymbolsChanged = False

                functionsData = PdbGeneratorPy.FunctionsData()
                for functionAddress in self.CallstackFunctionAddresses:
                    if functionData := self.FunctionDataExtractor.GetFunctionData(functionAddress, ExecuteSync=True):
                        functionsData.append(functionData)
                self.LastFunctionChanged = False

                reply.Status = self.__GeneratePdb(functionsData)

            return reply

    def __GeneratePdb(self, FunctionsData):
        if len(self.SectionsData) == 0:
            return False

        pdbGenerator = PdbGeneratorPy.PdbGenerator(
            self.TypeExtractor.GetComplexTypesData(), self.TypeExtractor.GetStructsData(),
            self.TypeExtractor.GetEnumsData(), FunctionsData, self.PdbInfo, self.SectionsData, 
            self.PublicSymbolsData, self.GlobalSymbolsData, self.CpuArchitecture)

        return pdbGenerator.Generate()