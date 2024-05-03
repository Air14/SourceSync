# Overview

**SourceSync** is both a set of plugins for synchronisation between debugger and decompiler and a library for generating pdb from decompiler data. In the case of plugins, it establishes a connection between the debugger (Windbg, client) and the decompiler (Ida Pro, server) to dynamically generate pdb for functions in the current thread call stack that belong to the decompiled module. 

Generated pdb contains information about:

* Structs/Unions/Enums
* Public symbols
* Global variables and their types
* Mapping between assembly and decompiler function pseudo code lines
* Function variables from pseudo code and their types

In case of library it provides both c++ and python api to generate pdb from arbitrary data. 

The entire project consists of:

#### PdbGeneratorPy

PdbGeneratorPy is python wrapper for c++ code used to generate pdb based on provided data.

#### SourceSync

`SourceSync\Ida` is python based plugin for IDA Pro which extracts required data to generate pdb.

`SourceSync\SourceSyncServer.py` is python (decompiler independent) grpc server which is responsible for whole communication/synchronisation between debugger and decompiler.

`SourceSync\SourceSyncClient.cpp` is c++ (debugger independent) grpc client which is responsible for sending and fetching necessary data for generating a pdb for thread callstack.

#### WindbgSync

Is c++ plugin for windbg used for synchronisation with decompiler.

# Example of use

This short video shows how SourceSync works when reverse engineering the **ntoskrnl.exe!MiReadWriteVirtualMemory** function

[Example.webm](https://github.com/Air14/SourceSync/assets/34422030/055aa8ce-5001-419b-9bc9-34920516086e)

# Support

Supported architectures:

* x86_64
* x86

Supported decompilers:

* IDA Pro

Supported debuggers:

* Windbg

# Installation

#### IDA Extension

1) Copy content of **IdaPlugin** folder into `C:\Program Files\IDA Pro xxx\plugins` directory

2. Change `PE_LOAD_ALL_SECTIONS` in `C:\Program Files\IDA Pro xxx\cfg\pe.cfg` form `NO` to `YES`. For idb that have already been generated without this SourceSync will not work. If you want it to work without re-generating the whole idb, use the `Tools\PeHeaderCreator.py` script inside IDA (the original .exe file must be in the same directory as the idb).

3) Install python requirements `pip install -r requirements.txt`
3) Rename one of existing versions of `PdbGeneratorPy.python_version.pyd` to `PdbGeneratorPy.pyd` to match the currently selected python version used in IDA Pro.

#### Windbg Extension

Copy **WindbgSync.dll** into `%localappdata%\Microsoft\WindowsApps`

# Usage

#### Windbg

1. Launch/Attach to target
2. Load extension `.load WindbgSync`
3. Synchronise with decompiler `!EnableSync`

Supported commands:

1. `!EnableSync` - Try to synchronise with decompiler
2. `!EnableSync 'ModuleName'`  - Used when decompiled .exe file name is different from module name in windbg, e.g. in ntoskrnl.exe
3. `!DisableSync` - Disable synchronisation
4. `!RestartSync`- Restart synchornisation i.e. perform disable and enable sync.
5. `!RestartSync 'ModuleName'` - Used when decompiled .exe file name is different from module name in windbg, e.g. in ntoskrnl.exe

There is also an optional configuration file called **.srcsync** where the host IP address and port can be defined. This should be located in the **%userprofile%** directory. If there is no configuration file, windbg will try to connect to the server using localhost as the host ip and 5111 as the port.

#### IDA Pro

Open `Edit/Plugins/SourceSync Plugin`

If check box `Synchronisation enable` is checked that means that synchronisation server is running and nothing more is needed to do.

In order to restart server you can click on `Restart` button.

In order to generate pdb for whole file with all functions click `Generate Pdb` (In case of large pe files it may take some time).

There is also an optional configuration file called **.srcsync** where the host IP address and port can be defined. This should be located in the idb or **%userprofile%** directory (the former takes precedence over the latter). If there is no configuration file, IDA Pro will create the server using localhost as the host ip and 5111 as the port.

# Limitations

Currently, the main limitation is that you can only have one server (one decompiler with running SourceSync), so if you want to change what is synchronised with the debugger, you need to disable the previous synchronisation before enabling the new one.

# Building

In order to build you need to:

1) Create environment variable named %IDA_PYTHON% which value should point to location of python directory used by IDA Pro, in my case it is `%localappdata%\Programs\Python\Python311`
2) Download and configure [vcpkg](https://vcpkg.io/en/) as c++ projects dependencies are managed with [vcpkg manifests](https://learn.microsoft.com/en-us/vcpkg/concepts/manifest-mode)
3) Select desired configuration and click **Build Solution**
4) Go to build directory and follow [Installation](#installation) 

# License

SourceSync is under Apache Version 2.0 license.
