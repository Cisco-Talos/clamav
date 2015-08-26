#include <winver.h>
#include "../../../libclamav/version.h"
#ifndef REPO_VERSION
#define __PLATFORM_H
#include "clamav-config.h"
#define REPO_VERSION VERSION
#endif

#define RES_VER_Q 3,1,0,0
#define RES_VER_S "ClamAV for Windows 3.0"
#define RES_FNAME "clamav.dll"
#define RES_NAME "interface"
#define RES_FDESC "ClamAV for Windows - Scan interface"

VS_VERSION_INFO VERSIONINFO
    FILEVERSION RES_VER_Q
    PRODUCTVERSION RES_VER_Q
    FILEFLAGSMASK VS_FF_DEBUG|VS_FF_PRERELEASE
#ifdef _DEBUG
    FILEFLAGS VS_FF_DEBUG|VS_FF_PRERELEASE
#else
    FILEFLAGS VS_FF_PRERELEASE
#endif
    FILEOS VOS_NT_WINDOWS32
    FILETYPE VFT_DLL
    FILESUBTYPE 0
BEGIN

    BLOCK "StringFileInfo" {
	BLOCK "040904B0" {
	    VALUE "CompanyName", "SourceFire, Inc."
	    VALUE "FileDescription", RES_FDESC
	    VALUE "FileVersion", REPO_VERSION
	    VALUE "InternalName", RES_NAME
	    VALUE "OriginalFilename", RES_FNAME
	    VALUE "ProductName", "ClamAV for Windows"
	    VALUE "ProductVersion", RES_VER_S " ("  REPO_VERSION ")"
	    VALUE "LegalCopyright", "(C) 2010 Sourcefire, Inc."
	    VALUE "LegalTrademarks", "License: Lesser General Public License, version 2.1"
	    VALUE "Comments", REPO_VERSION
	}
    }
    BLOCK "VarFileInfo" {
	VALUE "Translation", 0x409, 0x4b0
    }
END
