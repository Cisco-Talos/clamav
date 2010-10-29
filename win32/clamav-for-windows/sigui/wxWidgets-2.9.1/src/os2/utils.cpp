/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/utils.cpp
// Purpose:     Various utilities
// Author:      David Webster
// Modified by:
// Created:     09/17/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/utils.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
#endif  //WX_PRECOMP

#include "wx/os2/private.h"
#include "wx/apptrait.h"
#include "wx/filename.h"

#include <ctype.h>
#ifdef __EMX__
#include <dirent.h>
#endif


#include <io.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#define PURE_32

#if defined(__WATCOMC__)
extern "C"
{
    #include <upm.h>
}
#elif !defined(__EMX__)
    #include <upm.h>
    #include <netcons.h>
    #include <netbios.h>
#endif

static const wxChar WX_SECTION[] = wxT("wxWidgets");
static const wxChar eHOSTNAME[]  = wxT("HostName");

// For the following functions we SHOULD fill in support
// for Windows-NT (which I don't know) as I assume it begin
// a POSIX Unix (so claims MS) that it has some special
// functions beyond those provided by WinSock

// Get full hostname (eg. DoDo.BSn-Germany.crg.de)
bool wxGetHostName( wxChar* zBuf, int nMaxSize )
{
    if (!zBuf) return false;

#if defined(wxUSE_NET_API) && wxUSE_NET_API
    char           zServer[256];
    char           zComputer[256];
    unsigned long  ulLevel = 0;
    unsigned char* zBuffer = NULL;
    unsigned long  ulBuffer = 256;
    unsigned long* pulTotalAvail = NULL;

    NetBios32GetInfo( (const unsigned char*)zServer
                     ,(const unsigned char*)zComputer
                     ,ulLevel
                     ,zBuffer
                     ,ulBuffer
                     ,pulTotalAvail
                    );
    strcpy(zBuf, zServer);
#else
    wxChar*        zSysname;
    const wxChar*  zDefaultHost = wxT("noname");

    if ((zSysname = wxGetenv(wxT("SYSTEM_NAME"))) == NULL &&
            (zSysname = wxGetenv(wxT("HOSTNAME"))) == NULL)
    {
        ::PrfQueryProfileString( HINI_PROFILE
                                ,(PSZ)WX_SECTION
                                ,(PSZ)eHOSTNAME
                                ,(PSZ)zDefaultHost
                                ,(void*)zBuf
                                ,(ULONG)nMaxSize - 1
                               );
        zBuf[nMaxSize] = wxT('\0');
    }
    else
    {
        wxStrlcpy(zBuf, zSysname, nMaxSize);
    }
#endif

    return *zBuf ? true : false;
}

// Get user ID e.g. jacs
bool wxGetUserId(wxChar* zBuf, int nType)
{
#if defined(__VISAGECPP__) || defined(__WATCOMC__)
    // UPM procs return 0 on success
    long lrc = U32ELOCU((PUCHAR)zBuf, (PULONG)&nType);
    if (lrc == 0) return true;
#endif
    return false;
}

bool wxGetUserName( wxChar* zBuf, int nMaxSize )
{
#ifdef USE_NET_API
    wxGetUserId( zBuf, nMaxSize );
#else
    wxStrlcpy(zBuf, wxT("Unknown User"), nMaxSize);
#endif
    return true;
}

int wxKill(long         lPid,
           wxSignal     WXUNUSED(eSig),
           wxKillError* WXUNUSED(peError),
           int          WXUNUSED(flags))
{
    return((int)::DosKillProcess(0, (PID)lPid));
}

//
// Execute a program in an Interactive Shell
//
bool wxShell( const wxString& rCommand )
{
    wxChar*     zShell = wxT("CMD.EXE");
    wxString    sInputs;
    STARTDATA   SData = {0};
    PSZ         PgmTitle = "Command Shell";
    APIRET      rc;
    PID         vPid = 0;
    ULONG       ulSessID = 0;
    UCHAR       achObjBuf[256] = {0}; //error data if DosStart fails
    RESULTCODES vResult;

    SData.Length   = sizeof(STARTDATA);
    SData.Related  = SSF_RELATED_INDEPENDENT;
    SData.FgBg     = SSF_FGBG_FORE;
    SData.TraceOpt = SSF_TRACEOPT_NONE;
    SData.PgmTitle = PgmTitle;
    SData.PgmName  = (char*)zShell;

    sInputs = wxT("/C ") + rCommand;
    SData.PgmInputs     = (BYTE*)sInputs.wx_str();
    SData.TermQ         = 0;
    SData.Environment   = 0;
    SData.InheritOpt    = SSF_INHERTOPT_SHELL;
    SData.SessionType   = SSF_TYPE_WINDOWABLEVIO;
    SData.IconFile      = 0;
    SData.PgmHandle     = 0;
    SData.PgmControl    = SSF_CONTROL_VISIBLE | SSF_CONTROL_MAXIMIZE;
    SData.InitXPos      = 30;
    SData.InitYPos      = 40;
    SData.InitXSize     = 200;
    SData.InitYSize     = 140;
    SData.Reserved      = 0;
    SData.ObjectBuffer  = (char*)achObjBuf;
    SData.ObjectBuffLen = (ULONG)sizeof(achObjBuf);

    rc = ::DosStartSession(&SData, &ulSessID, &vPid);
    if (rc == 0 || rc == 457) // NO_ERROR or SMG_START_IN_BACKGROUND
    {
        PTIB                            ptib;
        PPIB                            ppib;

        ::DosGetInfoBlocks(&ptib, &ppib);

        ::DosWaitChild( DCWA_PROCESS
                       ,DCWW_WAIT
                       ,&vResult
                       ,&ppib->pib_ulpid
                       ,vPid
                      );
    }
    return (rc != 0);
}

// Shutdown or reboot the PC
bool wxShutdown(wxShutdownFlags WXUNUSED(wFlags))
{
    // TODO
    return false;
}

// Get free memory in bytes, or -1 if cannot determine amount (e.g. on UNIX)
wxMemorySize wxGetFreeMemory()
{
    void* pMemptr = NULL;
    LONG  lSize;
    ULONG lMemFlags;
    APIRET rc;

    lMemFlags = PAG_FREE;
    rc = ::DosQueryMem(pMemptr, (PULONG)&lSize, &lMemFlags);
    if (rc != 0)
        lSize = -1L;
    return (wxMemorySize)lSize;
}

// Get Process ID
unsigned long wxGetProcessId()
{
    return (unsigned long)getpid();
}

// ----------------------------------------------------------------------------
// env vars
// ----------------------------------------------------------------------------

bool wxGetEnv(const wxString& var, wxString *value)
{
    // wxGetenv is defined as getenv()
    wxChar *p = wxGetenv((const wxChar *)var);
    if ( !p )
        return false;

    if ( value )
    {
        *value = p;
    }

    return true;
}

static bool wxDoSetEnv(const wxString& variable, const char *value)
{
#if defined(HAVE_SETENV)
    if ( !value )
    {
#ifdef HAVE_UNSETENV
        return unsetenv(variable.mb_str()) == 0;
#else
        value = wxT(""); // mustn't pass NULL to setenv()
#endif
    }
    return setenv(variable.mb_str(), value, 1 /* overwrite */) == 0;
#elif defined(HAVE_PUTENV)
    wxString s = variable;
    if ( value )
        s << wxT('=') << value;

    // transform to ANSI
    const char *p = s.mb_str();

    // the string will be free()d by libc
    char *buf = (char *)malloc(strlen(p) + 1);
    strcpy(buf, p);

    return putenv(buf) == 0;
#else // no way to set an env var
    wxUnusedVar(variable);
    wxUnusedVar(value);
    return false;
#endif
}

bool wxSetEnv(const wxString& variable, const wxString& value)
{
    return wxDoSetEnv(variable, value.mb_str());
}

bool wxUnsetEnv(const wxString& variable)
{
    return wxDoSetEnv(variable, NULL);
}

void wxMilliSleep(
  unsigned long                     ulMilliseconds
)
{
    ::DosSleep(ulMilliseconds);
}

void wxMicroSleep(
  unsigned long                     ulMicroseconds
)
{
    ::DosSleep(ulMicroseconds/1000);
}

void wxSleep(
  int                               nSecs
)
{
    ::DosSleep(1000 * nSecs);
}

// Consume all events until no more left
void wxFlushEvents()
{
//  wxYield();
}

// Emit a beeeeeep
void wxBell()
{
    DosBeep(1000,1000); // 1kHz during 1 sec.
}

wxString wxGetOsDescription()
{
    wxString strVer(wxT("OS/2"));
    ULONG ulSysInfo = 0;

    if (::DosQuerySysInfo( QSV_VERSION_MINOR,
                           QSV_VERSION_MINOR,
                           (PVOID)&ulSysInfo,
                           sizeof(ULONG)
                         ) == 0L )
    {
        wxString ver;
        ver.Printf( wxT(" ver. %d.%d"),
                    int(ulSysInfo / 10),
                    int(ulSysInfo % 10)
                  );
        strVer += ver;
    }

    return strVer;
}

bool wxIsPlatform64Bit()
{
    // FIXME: No idea how to test for 64 bit processor
    //        (Probably irrelevant anyhow, though).
    return false;
}

void wxAppTraits::InitializeGui(unsigned long &WXUNUSED(ulHab))
{
}

void wxAppTraits::TerminateGui(unsigned long WXUNUSED(ulHab))
{
}

wxOperatingSystemId wxGetOsVersion(int *verMaj, int *verMin)
{
    ULONG                 ulSysInfo = 0;
    APIRET                ulrc;

    ulrc = ::DosQuerySysInfo( QSV_VERSION_MINOR,
                              QSV_VERSION_MINOR,
                              (PVOID)&ulSysInfo,
                              sizeof(ULONG)
                            );

    if (ulrc == 0L)
    {
        if ( verMaj )
            *verMaj = ulSysInfo / 10;
        if ( verMin )
            *verMin = ulSysInfo % 10;
    }

    return wxOS_OS2;
}


// ---------------------------------------------------------------------------
const wxChar* wxGetHomeDir(
  wxString*                         pStr
)
{
    wxString&                       rStrDir = *pStr;

    // OS/2 has no idea about home,
    // so use the working directory instead.
    // However, we might have a valid HOME directory,
    // as is used on many machines that have unix utilities
    // on them, so we should use that, if available.

    // 256 was taken from os2def.h
#ifndef MAX_PATH
#  define MAX_PATH  256
#endif

    const wxChar *szHome = wxGetenv((wxChar*)"HOME");
    if ( szHome == NULL ) {
      // we're homeless, use current directory.
      rStrDir = wxT(".");
    }
    else
       rStrDir = szHome;

    return rStrDir.c_str();
}

wxString wxGetUserHome ( const wxString &rUser )
{
    wxChar*    zHome;
    wxString   sUser(rUser);

    wxString home;

#ifndef __EMX__
    if (!sUser.empty())
    {
        const wxString currentUser = wxGetUserId();

        // Guests belong in the temp dir
        if ( currentUser == "annonymous" )
        {
            zHome = wxGetenv(wxT("TMP"));
            if ( !zHome )
                zHome = wxGetenv(wxT("TMPDIR"));
            if ( !zHome )
                zHome = wxGetenv(wxT("TEMP"));

            if ( zHome && *zHome )
                return zHome;
        }

        if ( sUser == currentUser )
            sUser.clear();
    }
#endif
    if (sUser.empty())
    {
        if ((zHome = wxGetenv(wxT("HOME"))) != NULL)
        {
            home = zHome;
            home.Replace("/", "\\");
        }
    }

    return home;
}

bool wxGetDiskSpace(const wxString& path,
                    wxDiskspaceSize_t *pTotal,
                    wxDiskspaceSize_t *pFree)
{
    if (path.empty())
        return false;

    wxFileName fn(path);
    FSALLOCATE fsaBuf = {0};
    APIRET rc = NO_ERROR;
    ULONG disknum = 0;

    fn.MakeAbsolute();

    if (wxDirExists(fn.GetFullPath()) == false)
        return false;

    disknum = wxToupper(fn.GetVolume().GetChar(0)) - wxT('A') + 1;

    rc = ::DosQueryFSInfo(disknum,             // 1 = A, 2 = B, 3 = C, ...
                          FSIL_ALLOC,          // allocation info
                          (PVOID)&fsaBuf,
                          sizeof(FSALLOCATE));

    if (rc != NO_ERROR)
        return false;
    else
    {
        if(pTotal)
        {
           // to try to avoid 32-bit overflow, let's not multiply right away
            // (num of alloc units)
            *pTotal = fsaBuf.cUnit;
            // * (num of sectors per alloc unit) * (num of bytes per sector)
            (*pTotal) *= fsaBuf.cSectorUnit * fsaBuf.cbSector;
        }
        if(pFree)
        {
            *pFree = fsaBuf.cUnitAvail;
            (*pFree) *= fsaBuf.cSectorUnit * fsaBuf.cbSector;
        }
        return true;
    }
}

wxString wxPMErrorToStr(ERRORID vError)
{
    wxString sError;

    //
    // Remove the high order byte -- it is useless
    //
    vError &= 0x0000ffff;
    switch(vError)
    {
        case PMERR_INVALID_HWND:
            sError = wxT("Invalid window handle specified");
            break;

        case PMERR_INVALID_FLAG:
            sError = wxT("Invalid flag bit set");
            break;

        case PMERR_NO_MSG_QUEUE:
            sError = wxT("No message queue available");
            break;

        case PMERR_INVALID_PARM:
            sError = wxT("Parameter contained invalid data");
            break;

        case PMERR_INVALID_PARAMETERS:
            sError = wxT("Parameter value is out of range");
            break;

        case PMERR_PARAMETER_OUT_OF_RANGE:
            sError = wxT("Parameter value is out of range");
            break;

        case PMERR_INVALID_INTEGER_ATOM:
            sError = wxT("Not a valid atom");
            break;

        case PMERR_INVALID_HATOMTBL:
            sError = wxT("Atom table handle is invalid");
            break;

        case PMERR_INVALID_ATOM_NAME:
            sError = wxT("Not a valid atom name");
            break;

        case PMERR_ATOM_NAME_NOT_FOUND:
            sError = wxT("Valid name format, but cannot find name in atom table");
            break;

        case PMERR_INV_HPS:
            sError = wxT("PMERR_INV_HPS");
            break;

        case PMERR_PS_BUSY:
            sError = wxT("PMERR_PS_BUSY");
            break;

        case PMERR_INV_PRIMITIVE_TYPE:
            sError = wxT("PMERR_INV_PRIMITIVE_TYPE");
            break;

        case PMERR_UNSUPPORTED_ATTR:
            sError = wxT("PMERR_UNSUPPORTED_ATTR");
            break;

        case PMERR_INV_COLOR_ATTR:
            sError = wxT("PMERR_INV_COLOR_ATTR");
            break;

        case PMERR_INV_BACKGROUND_COL_ATTR:
            sError = wxT("PMERR_INV_BACKGROUND_COL_ATTR");
            break;

        case PMERR_INV_MIX_ATTR:
            sError = wxT("PMERR_INV_MIX_ATTR");
            break;

        case PMERR_INV_LINE_WIDTH_ATTR:
            sError = wxT("PMERR_INV_LINE_WIDTH_ATTR");
            break;

        case PMERR_INV_GEOM_LINE_WIDTH_ATTR:
            sError = wxT("PMERR_INV_GEOM_LINE_WIDTH_ATTR");
            break;

        case PMERR_INV_LINE_TYPE_ATTR:
            sError = wxT("PMERR_INV_LINE_TYPE_ATTR");
            break;

        case PMERR_INV_LINE_END_ATTR:
            sError = wxT("PMERR_INV_LINE_END_ATTR");
            break;

        case PMERR_INV_LINE_JOIN_ATTR:
            sError = wxT("PMERR_INV_LINE_JOIN_ATTR");
            break;

        case PMERR_INV_CHAR_SET_ATTR:
            sError = wxT("PMERR_INV_CHAR_SET_ATTR");
            break;

        case PMERR_INV_CHAR_MODE_ATTR:
            sError = wxT("PMERR_INV_CHAR_MODE_ATTR");
            break;

        case PMERR_INV_CHAR_DIRECTION_ATTR:
            sError = wxT("PMERR_INV_CHAR_DIRECTION_ATTR");
            break;

        case PMERR_INV_CHAR_SHEAR_ATTR:
            sError = wxT("PMERR_INV_CHAR_SHEAR_ATTR");
            break;

        case PMERR_INV_CHAR_ANGLE_ATTR:
            sError = wxT("PMERR_INV_CHAR_ANGLE_ATTR");
            break;

        case PMERR_INV_MARKER_SET_ATTR:
            sError = wxT("PMERR_INV_MARKER_SET_ATTR");
            break;

        case PMERR_INV_MARKER_SYMBOL_ATTR:
            sError = wxT("PMERR_INV_MARKER_SYMBOL_ATTR");
            break;

        case PMERR_INV_PATTERN_SET_ATTR:
            sError = wxT("PMERR_INV_PATTERN_SET_ATTR");
            break;

        case PMERR_INV_PATTERN_ATTR:
            sError = wxT("PMERR_INV_PATTERN_ATTR");
            break;

        case PMERR_INV_COORDINATE:
            sError = wxT("PMERR_INV_COORDINATE");
            break;

        case PMERR_UNSUPPORTED_ATTR_VALUE:
            sError = wxT("PMERR_UNSUPPORTED_ATTR_VALUE");
            break;

        case PMERR_INV_PATTERN_SET_FONT:
            sError = wxT("PMERR_INV_PATTERN_SET_FONT");
            break;

        case PMERR_HUGE_FONTS_NOT_SUPPORTED:
            sError = wxT("PMERR_HUGE_FONTS_NOT_SUPPORTED");
            break;

        default:
            sError = wxT("Unknown error");
    }
    return sError;
} // end of wxPMErrorToStr

// replacement for implementation in unix/utilsunx.cpp,
// to be used by all X11 based ports.
struct wxEndProcessData;

void wxHandleProcessTermination(wxEndProcessData *WXUNUSED(proc_data))
{
    // For now, just do nothing. To be filled in as needed.
}
