# Win32 ClamAV Build Instructions

This document describes how to build ClamAV on Windows using Visual Studio.
For information on how to use ClamAV, please refer to our [User Manual](https://docs.clamav.net/Introduction.html).

**Table of Contents**

- [Win32 ClamAV Build Instructions](#win32-clamav-build-instructions)
  - [News](#news)
    - [0.102](#0102)
      - [External Library Dependencies](#external-library-dependencies)
    - [0.101](#0101)
      - [Installer Projects](#installer-projects)
    - [0.98](#098)
      - [Socket and libclamav API Input](#socket-and-libclamav-api-input)
  - [Requirements](#requirements)
  - [Getting the code](#getting-the-code)
  - [Code configuration](#code-configuration)
  - [Compilation](#compilation)
  - [Special notes](#special-notes)
    - [Config files path search order](#config-files-path-search-order)
    - [Database files path search order](#database-files-path-search-order)
    - [Globbing](#globbing)
    - [File paths](#file-paths)
    - [Debug builds](#debug-builds)
  - [Special thanks](#special-thanks)

## News

### 0.102

#### External Library Dependencies

ClamAV relies on a handful of 3rd party libraries. In previous versions of ClamAV, most of these were copy-pasted into the win32/3rdparty directory, with the exception being OpenSSL. In ClamAV 0.102, all of these libraries are now external to ClamAV and must be compiled ahead of time as DLLs (or for zlib, a static lib) and placed in the %CLAM_DEPENDENCIES% (typically C:\clam_dependencies) directory so the ClamAV Visual Studio project files can find them.

To build each of these libraries, we recommend using [Mussels](https://github.com/Cisco-Talos/Mussels).  Mussels is an open source application dependency management tool that can build the correct version of each dependency using the build tools intended by the original library authors.  At the time of writing, Mussels has not yet been made public, but should be available soon.

### 0.101

#### Installer Projects

ClamAV 0.101 removed the old Visual Studio Installer Projects files (Setup-x64.vdproj, Setup-x86.vdproj). In their place we now build an installer using Inno Setup that is capable of installing ClamAV on both 32-bit and 64-bit architectures with one installer.

For more details, see the instructions below on how to build ClamAV.

### 0.98

#### Socket and libclamav API Input

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

## Requirements

To build the source code you will need:

- [Microsoft Visual Studio 2017](https://www.visualstudio.com/vs/older-downloads/): the community version is just fine. Visual Studio 2019 should also work fine, provided you install the platform toolkit for 2017.
- [Git for Windows](https://git-scm.com/download/win): required for the `.\configure.bat` step, *only needed if building from a Github clone/download*.
- External library dependencies with interface header files.  See the [Code configuration](#code-configuration) section below for details.

To build the installer, you also need:

- [Inno Setup 5](http://www.jrsoftware.org/isdl.php "Inno Setup installer creation tool")

ClamAV is supported for Windows 7+, but Windows 10 is recommended.

## Getting the code

ClamAV source release materials are available for download on [ClamAV.net](https://www.clamav.net/downloads/latest).  The code under active development is freely available on [GitHub](https://github.com/Cisco-Talos/clamav-devel).

To obtain a copy of the code using Git, open a Git Bash terminal. Navigate to a directory where you want to store the code, eg "workspace" and clone the repository using the https web URL.  For example:

```cmd
cd
mkdir workspace
cd workspace
git clone https://github.com/vrtadmin/clamav-devel.git
```

ClamAV for Windows uses the same code base as Unix/Linux based operating systems. However, Windows specific files for building ClamAV are found under the `win32` directory.

## Code configuration

After downloading the source code, some configuration is required:

1. Run the `win32/configure.bat` script.

   Note: If you aren't building from an official release tarball, you'll need to do this from a terminal that has Git.exe in the PATH (eg. Git-Bash).

2. ClamAV depends on the following 3rd party libraries:
   - bzip2
   - libcurl
   - json-c
   - libxml2
   - openssl
   - pcre2
   - pthread-win32
   - zlib

   The libcurl dependency may be configured a variety of ways.  At present, we choose to build it with the following dependencies: libssh2, nghttp2, openssl, and zlib.  Nghttp2 in turn may depend on libxml2, zlib, and openssl.  Openssh2 may also depend on openssl and zlib.  Openssl also may depend on zlib.

   As you can see, the above dependency chain is non-trivial to build by hand.  You may wish to build these using a dependency management tool.  To automate our build process, we chose to create a lightweight dependency manager that we named Mussels.  Mussels will be open-sourced soon, and will be made available on Github at Cisco-Talos/[Mussels](https://github.com/Cisco-Talos/mussels).

   If Mussels is available and you are using Mussels, build the `clamav_deps` recipe to generate the above dependencies.

3. The ClamAV Visual Studio project files and the `ClamAV-Installer.iss` InnoSetup 5 script require that the 3rd party dependency headers and library binaries are placed in a directory structure that like this:

   ```
   C:\clam_dependencies
   ├───vcredist
   │   ├───vc_redist.x64.exe <-- VS 2017 Redistributables installer (x64)
   │   └───vc_redist.x86.exe <-- VS 2017 Redistributables installer (x86)
   ├───Win32
   │   ├───include           <-- 32-bit library headers here
   │   └───lib               <-- 32-bit .DLLs and .LIBs here
   └───x64
       ├───include           <-- 64-bit library headers here
       └───lib               <-- 64-bit .DLLs and .LIBs here
   ```

   If using Mussels, the "install" directory structure, located in `~\.mussels`, is very similar to the above. Simply copy `~\.mussels\install` to `C:\clam_dependencies` and rename `C:\clam_dependencies\x86` to `C:\clam_dependencies\Win32`.  Then, if you plan to use InnoSetup and ClamAV-Installer.iss to generate the installer program, create a vcredist directory with the files listed above.  You can download the vc_redist 2017 installers from Microsoft.

4. Add an environment variable with the name `CLAM_DEPENDENCIES` and set the value to `C:\clam_dependencies`.

   Note: At present, the Inno Setup script `ClamAV-Installer.iss` requires the dependencies directory to be located specifically at `C:\clam_dependencies` in order to build the installer. If you aren't using `ClamAV-Installer.iss`, you're free to place the dependencies directory anywhere you like so long as you set the `CLAM_DEPENDENCIES` environment variable accordingly.

## Compilation

Open `win32/ClamAV.sln` in Visual Studio and build all. The output directory for the binaries is either `/win32/(Win32|x64)/Debug` or
`/win32/(Win32|x64)/Release` depending on the configuration you pick.

Alternatively, you can build from the command line (aka `cmd.exe`) by following these steps:

x64:

```cmd
call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64
setx CLAM_DEPENDENCIES "C:\\clam_dependencies"
call configure.bat
devenv ClamAV.sln /Clean "Release|x64" /useenv /ProjectConfig "Release|x64"
devenv ClamAV.sln /Rebuild "Release|x64" /useenv /ProjectConfig "Release|x64"'''
```

x86:

```cmd
reg Query "HKLM\\Hardware\\Description\\System\\CentralProcessor\\0" | find /i "x86" > NUL && set OS=32BIT || set OS=64BIT
if %OS%==32BIT call "C:\\Program Files\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" x86
if %OS%==64BIT call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Auxiliary\\Build\\vcvarsall.bat" x86
setx CLAM_DEPENDENCIES "C:\\clam_dependencies"
call configure.bat
devenv ClamAV.sln /Clean "Release|Win32" /useenv /ProjectConfig "Release|Win32"
devenv ClamAV.sln /Rebuild "Release|Win32" /useenv /ProjectConfig "Release|Win32"'''
```

To build the installer:

1. Build ClamAV for both `x64` **and** `Win32`. The installer requires both versions to be available.
2. Open `win32\ClamAV-Installer.iss` using Inno Setup 5.
3. Run "Compile".

Alternatively, you can invoke the Inno Setup command line installer from cmd.exe:

```cmd
"C:\Program Files (x86)\Inno Setup 5\ISCC.exe" .\ClamAV-Installer.iss
```

After compilation, the installer will be located at `win32\ClamAV-<version>.exe`

## Special notes

The ClamAV tools in `win32` are the same as in unix, so refer to their respective manpage for general usage.
The major differences are listed below:

### Config files path search order

1. The content of the registry key:
   "HKEY_LOCAL_MACHINE/Software/ClamAV/ConfDir"
2. The directory where libclamav.dll is located:
   "C:\Program Files\ClamAV"
3. "C:\ClamAV"

### Database files path search order

1. The content of the registry key:
  "HKEY_LOCAL_MACHINE/Software/ClamAV/DataDir"
2. The directory "database" inside the directory where libclamav.dll is located:
  "C:\Program Files\ClamAV\database"
3. "C:\ClamAV\db"

### Globbing

Since the Windows command prompt doesn't take care of wildcard expansion, minimal emulation of unix glob() is performed internally. It supports "*" and "?" only.

### File paths

Please always use the backslash as the path separator. SMB Network shares and UNC paths are supported.

### Debug builds

Malloc in Debug (as opposed to release) mode fails after allocating some 90k chunks; such builds won't be able to handle large databases. Just do yourself a favour and always build in Release mode.

## Special thanks

Special thanks to Gianluigi Tiesi and Mark Pizzolato for their valuable help in coding and testing.
