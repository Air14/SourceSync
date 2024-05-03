import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), "srcsync"))

import grpc
import threading
import ida_hexrays
import ida_idp
import ida_bytes
import ida_funcs
import idaapi
import ctypes
import configparser
import PdbGeneratorPy
from srcsync.TypeExtractor import TypeExtractor
from srcsync.PEDataExtractor import PEDataExtractor
from srcsync.SymbolExtractor import SymbolExtractor
from srcsync.FunctionDataExtractor import FunctionDataExtractor
from srcsync.SourceSyncServer import SourceSyncServer
from srcsync.DecompilerSynchronizer_pb2_grpc import add_DecompilerSynchronizerServicer_to_server
from concurrent import futures
from PyQt5 import QtCore, QtWidgets

HookCb = ctypes.WINFUNCTYPE(
    # return type
    ctypes.c_int,      # int idaapi

    # argument types
    ctypes.c_void_p,   # void       *user_data
    ctypes.c_int,      # int         notification_code
    ctypes.c_void_p,   # va_list     va 
)

class HOOK_TYPES:
    # Hook to the processor module.
    HT_IDP = 0
    # Hook to the user interface.
    HT_UI = 1
    # Hook to the debugger.
    HT_DBG = 2
    # Hook to the database events.
    HT_IDB = 3
    # Internal debugger events.
    HT_DEV = 4
    # Custom/IDA views notifications.
    HT_VIEW = 5
    # Output window notifications.
    HT_OUTPUT = 6
    HT_LAST = 7

def HookToNotificationPoint(Dll, HookType, CallBack, UserData):
    hook = Dll.hook_to_notification_point
    hook.argtypes = [
        ctypes.c_int,      # hook_type_t hook_type
        HookCb,            # hook_cb_t  *cb
        ctypes.c_void_p,   # void       *user_data
    ]

    hook(HookType, CallBack, UserData)

def RemoveHookToNotificationPoint(Dll, HookType, CallBack, UserData):
    removeHook = Dll.unhook_from_notification_point
    removeHook.argtypes = [
        ctypes.c_int,      # hook_type_t hook_type
        HookCb,            # hook_cb_t  *cb
        ctypes.c_void_p,   # void       *user_data
    ]

    removeHook(HookType, CallBack, UserData)

def GetHostIpAndPort():
    for location in (os.path.dirname(os.path.realpath(idaapi.get_path(idaapi.PATH_TYPE_IDB))), os.environ["USERPROFILE"]):
        configPath = os.path.join(location, '.srcsync')
        if os.path.exists(configPath):
            config = configparser.ConfigParser()
            config.read(configPath)
            if config.has_section('INTERFACE'):
                return config.get('INTERFACE', 'host') + ":" + config.get('INTERFACE', 'port')

    return "localhost:5111"

class CheckBoxActionHandler(idaapi.action_handler_t):
    def __init__(self, Cb):
        idaapi.action_handler_t.__init__(self)
        self.Cb = Cb

    def activate(self, Ctx):
        self.Cb.toggle()
        return 1

    def update(self, Ctx):
        return idaapi.AST_ENABLE_ALWAYS

class SourceSyncForm(idaapi.PluginForm):
    def __init__(self):
        super().__init__()
        self.InitIdbEventHook()
        
    def InitIdbEventHook(self):
        def IdbEventCallback(UserData, NotificationCode, VaList):
            VaList = ctypes.cast(VaList, ctypes.POINTER(ctypes.c_ulonglong))
        
            if self.SourceSyncServer is None:
                return 0

            if NotificationCode == ida_idp.renamed:
                address = VaList[0]
                if not ida_bytes.is_loaded(address):
                    return 0
        
                if function := ida_funcs.get_func(address):
                    self.SourceSyncServer.OnFunctionChanged(function.start_ea)
                else:
                    self.SourceSyncServer.OnPublicSymbolChanged()
        
            elif NotificationCode == ida_idp.local_types_changed:
                self.SourceSyncServer.OnTypesChanged()
        
            elif NotificationCode == ida_idp.ti_changed:
                address = VaList[0]
                if ida_funcs.get_func(address) or not ida_bytes.is_loaded(address):
                    return 0
        
                self.SourceSyncServer.OnPublicSymbolChanged()
        
            return 0
        
        self.Dll = ctypes.windll["ida64.dll"]

        # Need to keep a ref around, or the function gets garbage collected
        self.IdbEventCallback = HookCb(IdbEventCallback)

        # Need to keep a ref around, or the param gets garbage collected
        self.UserData = ctypes.c_long(10)

    def StartServer(self):
        typeExtractor = TypeExtractor()
        self.SourceSyncServer = SourceSyncServer(typeExtractor, PEDataExtractor(), SymbolExtractor(typeExtractor), FunctionDataExtractor(typeExtractor))
        serverAddress = GetHostIpAndPort()
        
        def SourceSyncServerThread():
            self.Server = grpc.server(futures.ThreadPoolExecutor())
            add_DecompilerSynchronizerServicer_to_server(self.SourceSyncServer, self.Server)
            self.Server.add_insecure_port(serverAddress)

            self.Server.start()
            self.Server.wait_for_termination()

        sourceSyncServerThread = threading.Thread(target=SourceSyncServerThread)
        sourceSyncServerThread.start()

    def StopServer(self):
        if self.Server is not None:
            self.Server.stop(None)

    def InstallHexraysHooks(self):
        class LvarHooks(ida_hexrays.Hexrays_Hooks):
            def lvar_name_changed(_, *Args):
                vdui = Args[0]
                self.SourceSyncServer.OnFunctionChanged(vdui.cfunc.entry_ea)
                return 0
            
            def lvar_type_changed(_, *Args):
                vdui = Args[0]
                self.SourceSyncServer.OnFunctionChanged(vdui.cfunc.entry_ea)
                return 0
            
            def lvar_type_changed(_, *Args):
                vdui = Args[0]
                self.SourceSyncServer.OnFunctionChanged(vdui.cfunc.entry_ea)
                return 0

        self.LvarHooks = LvarHooks()
        self.LvarHooks.hook()

    def RemoveHexraysHooks(self):
        self.LvarHooks.unhook()

    def CbChangeSourceSyncState(self, State):
        if State == QtCore.Qt.Checked:
            self.StartServer()
            self.InstallHexraysHooks()
            HookToNotificationPoint(self.Dll, HOOK_TYPES.HT_IDB, self.IdbEventCallback, ctypes.byref(self.UserData))
        else:
            RemoveHookToNotificationPoint(self.Dll, HOOK_TYPES.HT_IDB, self.IdbEventCallback, ctypes.byref(self.UserData))
            self.RemoveHexraysHooks()
            self.StopServer()
            
    def CbRestartSourceSyncServer(self):
        self.StopServer()
        self.StartServer()

    def CbGeneratePdb(self):
        print("[SourceSync] Generating pdb")
        typeExtractor = TypeExtractor()
        typeExtractor.GatherData(ExecuteSync = False)
        
        symbolExtractor = SymbolExtractor(typeExtractor)
        publicSymbolsData = symbolExtractor.GetPublics(ExecuteSync = False)
        globalSymbolsData = symbolExtractor.GetGlobals(ExecuteSync = False)
        
        functionDataExtractor = FunctionDataExtractor(typeExtractor)
        functionsData = functionDataExtractor.GetFunctionsData()
        
        enumsData = typeExtractor.GetEnumsData()
        structsData = typeExtractor.GetStructsData()
        complexTypes = typeExtractor.GetComplexTypesData()
        
        peDataExtractor = PEDataExtractor()
        pdbInfo = peDataExtractor.GetPdbInfo()
        sectionsData = peDataExtractor.GetSectionsData()
        if len(sectionsData) == 0:
            print("[SourceSync] Failed to get sections")       
            return

        if ida_idp.ph.id == ida_idp.PLFM_386 and ida_idp.ph.flag & ida_idp.PR_USE64:
            cpuArchitectureType = PdbGeneratorPy.CpuArchitectureType.X86_64
        else:
            cpuArchitectureType = PdbGeneratorPy.CpuArchitectureType.X86
            
        pdbGenerator = PdbGeneratorPy.PdbGenerator(
            complexTypes, structsData, enumsData, functionsData,
            pdbInfo, sectionsData, publicSymbolsData, globalSymbolsData, cpuArchitectureType)
        
        if pdbGenerator.Generate():
            print("[SourceSync] Pdb generated")       
        else:
            print("[SourceSync] Failed to generate pdb")       

    def OnCreate(self, Form):
        parent = self.FormToPyQtWidget(Form)
        
        self.SyncBox = QtWidgets.QCheckBox('Synchronization enable')
        self.SyncBox.move(20, 20)
        self.SyncBox.stateChanged.connect(self.CbChangeSourceSyncState)
        
        self.RestartButton = QtWidgets.QPushButton('Restart', parent)
        self.RestartButton.setToolTip('Restart SourceSync server')
        self.RestartButton.clicked.connect(self.CbRestartSourceSyncServer)
        
        self.GeneratePdbButton = QtWidgets.QPushButton('Generate Pdb', parent)
        self.GeneratePdbButton.setToolTip('Generate pdb for current idb inside idb directory')
        self.GeneratePdbButton.clicked.connect(self.CbGeneratePdb)

        layout = QtWidgets.QGridLayout()
        layout.addWidget(self.SyncBox)
        layout.addWidget(self.RestartButton)
        layout.addWidget(self.GeneratePdbButton)
        layout.setColumnStretch(4, 1)
        layout.setRowStretch(4, 1)
        parent.setLayout(layout)
        
        # Enable source sync server by default
        self.SyncBox.toggle()
        
        actionDesc = idaapi.action_desc_t(
            'SyncToogle:action',
            'Toggle syncing',
            CheckBoxActionHandler(self.SyncBox),
            'Ctrl+Shift+D',
            'Toggle syncing',
            203)

        idaapi.register_action(actionDesc)
        idaapi.attach_action_to_toolbar("AnalysisToolBar", 'SyncToogle:action')
        
    def OnClose(self, Form):
        self.SyncBox.toggle()
        idaapi.unregister_action('SyncToogle:action')
        idaapi.detach_action_from_toolbar("DebugToolBar", 'SyncToogle:action')
        
        global sourceSyncForm
        sourceSyncForm = None
        
    def Show(Self):
        return idaapi.PluginForm.Show(Self, "SourceSync", options=idaapi.PluginForm.WOPN_PERSIST)

class SourceSyncPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "This is comment"
    help = "This is help"
    wanted_name = "SourceSync plugin"
    wanted_hotkey = "Alt-Shift-D"
    global sourceSyncForm
    sourceSyncForm = None
    
    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, Arg):
        if ida_idp.ph.id != ida_idp.PLFM_386:
            print("[SourceSync] Only x86_64/x86 architecture is supported.")
            return

        if "portable executable" not in idaapi.get_file_type_name().lower():
            print("[SourceSync] Only PE files are supported.")
            return
        
        global sourceSyncForm
        if not sourceSyncForm:
            sourceSyncForm = SourceSyncForm()
            sourceSyncForm.Show()
    
    def term(self):
        pass

def PLUGIN_ENTRY():
    return SourceSyncPlugin()