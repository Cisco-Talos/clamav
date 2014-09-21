///////////////////////////////////////////////////////////////////////////////
// Name:        src/msw/version.rc
// Purpose:     contains version info resource for wxMSW DLL build
// Author:      Vadim Zeitlin
// Modified by:
// Created:     09.07.00
// RCS-ID:      $Id$
// Copyright:   (c) 2000 Vadim Zeitlin
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#include "wx/version.h"

// see http://msdn.microsoft.com/library/psdk/winui/rc_7x2d.htm for values: we
// don't use symbolic constants because older compilers might not have them
#ifdef WXMAKINGDLL
    #define wxVFT 2 // VFT_DLL
#else
    #define wxVFT 1 // VFT_APP
#endif

#ifdef _DEBUG
    #define DLL_FLAGS 0x1L
#else
    #define DLL_FLAGS 0x0L
#endif

// 0x0409 is US English, 0x04b0 is Unicode and 0x0000 is 7 bit ASCII. see
// http://msdn.microsoft.com/en-us/library/aa381049(VS.85).aspx for the full
// list of languages and charsets
#define LANG 0x0409
#ifdef _UNICODE
    #define CHARSET 0x4b0
    #define LANG_WITH_CHARSET "040904b0"
#else
    #define CHARSET 0
    #define LANG_WITH_CHARSET "04090000"
#endif

1 VERSIONINFO
 FILEVERSION wxMAJOR_VERSION,wxMINOR_VERSION,wxRELEASE_NUMBER,wxSUBRELEASE_NUMBER
 PRODUCTVERSION wxMAJOR_VERSION,wxMINOR_VERSION,wxRELEASE_NUMBER,wxSUBRELEASE_NUMBER
 FILEFLAGSMASK 0x3fL
 FILEFLAGS DLL_FLAGS
 FILEOS 0x40004L // VOS_NT_WINDOWS32
 FILETYPE wxVFT
 FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK LANG_WITH_CHARSET
        BEGIN
            VALUE "Comments", "wxWidgets cross-platform GUI framework\0"
            VALUE "CompanyName", "wxWidgets development team\0"
            VALUE "FileDescription", "wxWidgets for MSW\0"
            VALUE "FileVersion", "wxWidgets Library " wxVERSION_NUM_DOT_STRING "\0"
            VALUE "InternalName", "wxMSW\0"
            VALUE "LegalCopyright", "Copyright 1993-2010 wxWidgets development team\0"
            VALUE "LegalTrademarks", "\0"
            VALUE "OriginalFilename", wxSTRINGIZE(WXDLLNAME) ".dll\0"
            VALUE "PrivateBuild", "\0"
            VALUE "ProductName", "wxWidgets\0"
            VALUE "ProductVersion", wxVERSION_NUM_DOT_STRING "\0"
            VALUE "SpecialBuild", "\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
            VALUE "Translation", LANG, CHARSET
    END
END
