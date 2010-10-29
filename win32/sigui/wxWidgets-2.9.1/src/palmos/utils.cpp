/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/utils.cpp
// Purpose:     Various utilities
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - real functionality
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/timer.h"
#endif  //WX_PRECOMP

#include "wx/apptrait.h"
#include "wx/dynload.h"
#include "wx/confbase.h"
#include "wx/power.h"

#include <PalmTypes.h>
#include <MemoryMgr.h>
#include <DLServer.h>
#include <SoundMgr.h>
#include <SystemMgr.h> // SysDoze()...
#include <SysUtils.h>

#ifdef __WXPALMOS6__
extern void SysReset (void);
extern UInt32 SysTaskID (void);
#endif

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// get host name and related
// ----------------------------------------------------------------------------

// Get hostname only (without domain name)
bool wxGetHostName(wxChar *buf, int maxSize)
{
    return false;
}

// get full hostname (with domain name if possible)
bool wxGetFullHostName(wxChar *buf, int maxSize)
{
    return false;
}

// Get user ID e.g. jacs
bool wxGetUserId(wxChar *buf, int maxSize)
{
    return wxGetUserName(buf, maxSize);
}

// Get user name e.g. Julian Smart
bool wxGetUserName(wxChar *buf, int maxSize)
{
    *buf = wxT('\0');

    // buffer allocation
    MemHandle handle = MemHandleNew(maxSize-1);
    if( handle == NULL )
        return false;

    // lock the buffer
    char *id = (char *)MemHandleLock(handle);
    if( id == NULL )
        return false;

    // get user's name
    if( DlkGetSyncInfo(NULL, NULL, NULL, id, NULL, NULL) != errNone )
    {
        MemPtrUnlock(id);
        return false;
    }

    wxStrlcpy(buf, wxSafeConvertMB2WX(id), maxSize);

    // free the buffer
    MemPtrUnlock(id);

    return true;
}

const wxChar* wxGetHomeDir(wxString *pstr)
{
    if (NULL != pstr) {
        *pstr = "/palmos";
    }
    return wxT("/palmos");
}

wxString wxGetUserHome(const wxString& WXUNUSED(user))
{
    return wxString("/palmos");
}

bool wxGetDiskSpace(const wxString& path, wxDiskspaceSize_t *pTotal, wxDiskspaceSize_t *pFree)
{
    return false;
}

// ----------------------------------------------------------------------------
// env vars
// ----------------------------------------------------------------------------

bool wxGetEnv(const wxString& var, wxString *value)
{
    return false;
}

#if ! WXWIN_COMPATIBILITY_2_8
bool wxSetEnv(const wxString& var, const wxChar *value)
{
    return false;
}
#endif // ! WXWIN_COMPATIBILITY_2_8

bool wxUnsetEnv(const wxString& var)
{
    return false;
}

// ----------------------------------------------------------------------------
// process management
// ----------------------------------------------------------------------------

int wxKill(long pid, wxSignal sig, wxKillError *krc, int flags)
{
    return 0;
}

// Execute a program in an Interactive Shell
bool wxShell(const wxString& command)
{
    return false;
}

// Shutdown or reboot the PC
bool wxShutdown(wxShutdownFlags wFlags)
{
    switch (wFlags) {
    case wxSHUTDOWN_POWEROFF:
        // TODO: turn off lamps
#ifdef __WXPALMOS6__
        //extern void SysReset (void);
        //extern UInt32 SysTaskID (void);
        #define SysReset()
        #define SysTaskID() (0)
        SysSleep ();
#else
        //SysSleep (false, false);// undocument API
        SysDoze (true);
#endif
        break;
    case wxSHUTDOWN_REBOOT:
        SysReset ();
        break;
    }
    return false;
}

// ----------------------------------------------------------------------------
// power management
// ----------------------------------------------------------------------------

wxPowerType wxGetPowerType()
{
    //SysBatteryKind kind;
    //POS_SysBatteryInfo (false, NULL, NULL, NULL, NULL, NULL, &kind, NULL);
     //return wxPOWER_SOCKET;
    return wxPOWER_BATTERY;
}

wxBatteryState wxGetBatteryState()
{
    //#include "SystemMgr.h"
    UInt8 percent;
    POS_SysBatteryInfo (false, NULL, NULL, NULL, NULL, NULL, NULL, &percent);
    if (percent < 3)
        return wxBATTERY_SHUTDOWN_STATE;
    else if (percent < 5)
        return wxBATTERY_CRITICAL_STATE;
    else if (percent < 15)
        return wxBATTERY_LOW_STATE;
    //return wxBATTERY_UNKNOWN_STATE;
    return wxBATTERY_NORMAL_STATE;
}

// ----------------------------------------------------------------------------
// misc
// ----------------------------------------------------------------------------

// Get free memory in bytes, or -1 if cannot determine amount (e.g. on UNIX)
wxMemorySize wxGetFreeMemory()
{
    uint32_t freeTotal = 0;
    uint32_t freeHeap;
    uint32_t freeChunk;

    // executed twice: for the dynamic heap, and for the non-secure RAM storage heap
    for ( uint16_t i = 0; i < POS_MemNumRAMHeaps(); i ++)
    {
        status_t err = MemHeapFreeBytes(i, &freeHeap, &freeChunk);
        if( err != errNone )
            return -1;
        freeTotal+=freeHeap;
    }

    return (wxMemorySize)freeTotal;
}

unsigned long wxGetProcessId()
{
    return SysTaskID ();
}

// Emit a beeeeeep
void wxBell()
{
    SndPlaySystemSound(sndWarning);
}

bool wxIsPlatform64Bit()
{
    return false;
}

wxString wxGetOsDescription()
{
    wxString strOS = wxT("PalmOS");

    //err = FtrGet(sysFtrCreator, sysFtrNumROMVersion, &romVersion);
    //if (romVersion >= 0x02000000) v20 = true;
    char *version = SysGetOSVersionString();
    if(version)
    {
        wxString str = wxString::FromAscii(version);
        MemPtrFree(version);
        if(!str.empty())
        {
            strOS << _(" ") << str;
        }
    }

    return strOS;
}

wxOperatingSystemId wxGetOsVersion(int *verMaj, int *verMin)
{
    // TODO
    return wxOS_PALM_OS;
}

// ----------------------------------------------------------------------------
// sleep functions
// ----------------------------------------------------------------------------

void wxMilliSleep(unsigned long milliseconds)
{
    UInt16 ticks_sec;
    Int32 delay;
    ticks_sec = SysTicksPerSecond ();
    delay = milliseconds * ticks_sec / 1000;
    if (delay > 0) {
        SysTaskDelay (delay);
    }
}

void wxMicroSleep(unsigned long microseconds)
{
    UInt16 ticks_sec;
    Int32 delay;
    ticks_sec = SysTicksPerSecond ();
    delay = microseconds * ticks_sec / 1000000;
    if (delay > 0) {
        SysTaskDelay (delay);
    }
}

void wxSleep(int nSecs)
{
    UInt16 ticks_sec;
    Int32 delay;
    ticks_sec = SysTicksPerSecond ();
    delay = nSecs * ticks_sec;
    if (delay > 0) {
        SysTaskDelay (delay);
    }
}

// ----------------------------------------------------------------------------
// font encoding <-> Win32 codepage conversion functions
// ----------------------------------------------------------------------------

extern WXDLLIMPEXP_BASE long wxEncodingToCharset(wxFontEncoding encoding)
{
    return 0;
}

// we have 2 versions of wxCharsetToCodepage(): the old one which directly
// looks up the vlaues in the registry and the new one which is more
// politically correct and has more chances to work on other Windows versions
// as well but the old version is still needed for !wxUSE_FONTMAP case
#if wxUSE_FONTMAP

#include "wx/fontmap.h"

extern WXDLLIMPEXP_BASE long wxEncodingToCodepage(wxFontEncoding encoding)
{
    return 0;
}

extern long wxCharsetToCodepage(const wxChar *name)
{
    return 0;
}

#else // !wxUSE_FONTMAP

// this should work if Internet Exploiter is installed
extern long wxCharsetToCodepage(const wxChar *name)
{
    return 0;
}

#endif // wxUSE_FONTMAP/!wxUSE_FONTMAP
