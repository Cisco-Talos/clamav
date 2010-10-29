/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/app.h
// Purpose:     wxApp class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/17/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_APP_H_
#define _WX_APP_H_

#include "wx/event.h"
#include "wx/icon.h"

class WXDLLIMPEXP_FWD_CORE wxFrame;
class WXDLLIMPEXP_FWD_CORE wxWindow;
class WXDLLIMPEXP_FWD_CORE wxApp;
class WXDLLIMPEXP_FWD_CORE wxKeyEvent;
class WXDLLIMPEXP_FWD_BASE wxLog;

// Represents the application. Derive OnInit and declare
// a new App object to start application
class WXDLLIMPEXP_CORE wxApp : public wxAppBase
{
    DECLARE_DYNAMIC_CLASS(wxApp)

public:
    wxApp();
    virtual ~wxApp();

    // override base class (pure) virtuals
    virtual bool Initialize(int& argc, wxChar **argv);
    virtual void CleanUp();

    virtual void WakeUpIdle();

    virtual void SetPrintMode(int mode) { m_printMode = mode; }
    virtual int GetPrintMode() const { return m_printMode; }

    // implementation only
    void OnEndSession(wxCloseEvent& event);
    void OnQueryEndSession(wxCloseEvent& event);

#if wxUSE_EXCEPTIONS
    virtual bool OnExceptionInMainLoop();
#endif // wxUSE_EXCEPTIONS

protected:
    int    m_printMode; // wxPRINT_WINDOWS, wxPRINT_POSTSCRIPT

public:
    // Implementation
    static bool RegisterWindowClasses();
    static bool UnregisterWindowClasses();

#if wxUSE_RICHEDIT
    // initialize the richedit DLL of (at least) given version, return true if
    // ok (Win95 has version 1, Win98/NT4 has 1 and 2, W2K has 3)
    static bool InitRichEdit(int version = 2);
#endif // wxUSE_RICHEDIT

    // returns 400, 470, 471 for comctl32.dll 4.00, 4.70, 4.71 or 0 if it
    // wasn't found at all
    static int GetComCtl32Version();

    // the SW_XXX value to be used for the frames opened by the application
    // (currently seems unused which is a bug -- TODO)
    static int m_nCmdShow;

protected:
    DECLARE_EVENT_TABLE()
    wxDECLARE_NO_COPY_CLASS(wxApp);
};

// ----------------------------------------------------------------------------
// Palm OS specific wxEntry() overload and IMPLEMENT_WXWIN_MAIN definition
// ----------------------------------------------------------------------------

#ifndef SW_SHOWNORMAL
    #define SW_SHOWNORMAL 1
#endif

extern WXDLLIMPEXP_CORE int wxEntry();

#define wxIMPLEMENT_WXWIN_MAIN                                            \
                                                                          \
    extern "C" {                                                          \
                                                                          \
    uint32_t PilotMain(uint16_t cmd, MemPtr cmdPBP, uint16_t launchFlags) \
    {                                                                     \
        switch (cmd) {                                                    \
            case 0 /* sysAppLaunchCmdNormalLaunch */ :                    \
                wxEntry();                                                \
                break;                                                    \
            default:                                                      \
                break;                                                    \
        }                                                                 \
        return 0 /* errNone */ ;                                          \
    }                                                                     \
                                                                          \
    }

#endif // _WX_APP_H_

