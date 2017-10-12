ClamAV for Win32
================

News
----

In order to support more advanced features planned in future releases, ClamAV has switched to using OpenSSL for hashing. The ClamAV Visual Studio project included with ClamAV's source code requires the OpenSSL distributables to be placed in a specific directory. This article will teach you how to compile OpenSSL on a Microsoft Windows system and how to link ClamAV against OpenSSL.

[Read More here](http://blog.clamav.net/2014/07/compiling-openssl-for-windows.html "ClamAV Blog")

Starting from version 0.98 the windows version of ClamAV requires all the input to be UTF-8 encoded.

This affects:

- the API, notably the cl_scanfile() function
- clamd socket input, e.g. the commands SCAN, CONTSCAN, MUTLISCAN, etc.
- clamd socket output, i.e replies to the above queries

For legacy reasons ANSI (i.e. CP_ACP) input will still be accepted and processed as before, but with two important remarks:
First, socket replies to ANSI queries will still be UTF-8 encoded.
Second, ANSI sequences which are also valid UTF-8 sequences will be handled as UTF-8.

As a side note, console output (stdin and stderr) will always be OEM encoded,
even when redirected to a file.

Requirements
------------

To build the source code you will need:

- [Git for Windows](https://git-scm.com/download/win "Git SCM Windows Downloads") with a git "shell"
- [Microsoft Visual Studio 2015](https://www.visualstudio.com/vs/older-downloads/ "Visual Studio Downloads"): the community version is just fine.
  You will need the Microsoft Visual Studio Installer Projects extension
  in order to load and build the Setup x86 and Setup x64 projects that
  build the .msi installers.

To build the installer, you also need:

- [Microsoft Visual Studio 2015 Installer Projects plugin](https://marketplace.visualstudio.com/items?itemName=VisualStudioProductTeam.MicrosoftVisualStudio2015InstallerProjects "VS2015 Installer Plugin Download")

ClamAV is supported for Windows 7+, but Windows 10 is recommended.
Visual Studio 2017 should work fine, but we currently work with Visual Studio 2015.

Getting the code
----------------

ClamAV source code is freely available via github at https://github.com/vrtadmin/clamav-devel

To obtain a copy of the code, open a Git Bash terminal.  Navigate to a directory where you want to store the code, eg "workspace" and clone the repository using the https web URL.  For example:

1. cd
2. mkdir workspace
3. cd workspace
4. git clone https://github.com/vrtadmin/clamav-devel.git

Step into the win32 directory and open an Explorer window.

1. cd clamav-devel
2. cd win32
3. explorer .

ClamAV for Windows uses the same code base as Unix/Linux based operating systems.  However, Windows specific files for building ClamAV are found under the win32 directory.

Code configuration
------------------

After downloading the source code, minimal configuration is required:

1. Run the win32/configure.bat script *from within the git shell*. Skip this step if you are building from an official release tarball.
2. Obtain OpenSSL V1.1.0 or higher.  You will need the headers, libs, and bins for the platform (Win32 or x64) that you're targeting.
3. Place the headers and binaries in a directory with the following structure:
├───Win32
│   ├───include
│   │   └───openssl  <-- openssl headers in here
│   └───lib          <-- .DLLs and .LIBs in here
└───x64
    ├───include
    │   └───openssl  <-- openssl headers in here
    └───lib          <-- .DLLs and .LIBs in here
4. Add an environment variable with the name CLAM_DEPENDENCIES and set the value to the path of the above directory.

Compilation
-----------

Open win32/ClamAV.sln in Visual Studio and build all.
The output directory for the binaries is either /win32/(Win32|x64)/Debug or
/win32/(Win32|x64)/Release depending on the configuration you pick.

Note: at the time of writing Batch Build is broken in Visual Studio. Use MSBuild instead.

Special notes
------

The ClamAV tools in win32 are the same as in unix, so refer to their respective
manpage for general usage.
The major differences are listed below:

- Config files path search order:
  1. The content of the registry key
     "HKEY_LOCAL_MACHINE/Software/ClamAV/ConfDir"
  2. The directory where libclamav.dll is located
  3. "C:\ClamAV"

- Database files path search order:
  1. The content of the registry key
     "HKEY_LOCAL_MACHINE/Software/ClamAV/DataDir"
  2. The directory "database" inside the directory where libclamav.dll is
     located
  3. "C:\ClamAV\db"

- Globbing
Since the Windows command prompt doesn't take care of wildcard expansion,
minimal emulation of unix glob() is performed internally.
It supports "*" and "?" only.

- File paths
Please always use the backslash as the path separator.
SMB Network shares and UNC paths are supported.

- Debug builds
Malloc in debug (as opposed to release) mode fails after allocating some 90k
chunks; such builds won't be able to handle large databases.
Just do yourself a favour and always build in release mode.

Special thanks
--------------

Special thanks to Gianluigi Tiesi and Mark Pizzolato for their valuable help in
coding and testing.