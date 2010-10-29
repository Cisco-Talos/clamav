/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/app.cpp
// Purpose:     wxApp
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/08/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if defined(__BORLANDC__)
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/frame.h"
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/gdicmn.h"
    #include "wx/pen.h"
    #include "wx/brush.h"
    #include "wx/cursor.h"
    #include "wx/icon.h"
    #include "wx/palette.h"
    #include "wx/dc.h"
    #include "wx/dialog.h"
    #include "wx/msgdlg.h"
    #include "wx/intl.h"
    #include "wx/crt.h"
    #include "wx/log.h"
    #include "wx/module.h"
#endif

#include "wx/apptrait.h"
#include "wx/filename.h"
#include "wx/dynlib.h"
#include "wx/evtloop.h"

#if wxUSE_TOOLTIPS
    #include "wx/tooltip.h"
#endif // wxUSE_TOOLTIPS

// We don't support OLE
#undef wxUSE_OLE
#define  wxUSE_OLE 0

#include <string.h>
#include <ctype.h>

// ---------------------------------------------------------------------------
// global variables
// ---------------------------------------------------------------------------

// NB: all "NoRedraw" classes must have the same names as the "normal" classes
//     with NR suffix - wxWindow::MSWCreate() supposes this
const wxChar *wxCanvasClassName        = wxT("wxWindowClass");
const wxChar *wxCanvasClassNameNR      = wxT("wxWindowClassNR");
const wxChar *wxMDIFrameClassName      = wxT("wxMDIFrameClass");
const wxChar *wxMDIFrameClassNameNoRedraw = wxT("wxMDIFrameClassNR");
const wxChar *wxMDIChildFrameClassName = wxT("wxMDIChildFrameClass");
const wxChar *wxMDIChildFrameClassNameNoRedraw = wxT("wxMDIChildFrameClassNR");

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// ===========================================================================
// wxGUIAppTraits implementation
// ===========================================================================

// private class which we use to pass parameters from BeforeChildWaitLoop() to
// AfterChildWaitLoop()
struct ChildWaitLoopData
{
    ChildWaitLoopData(wxWindowDisabler *wd_, wxWindow *winActive_)
    {
        wd = wd_;
        winActive = winActive_;
    }

    wxWindowDisabler *wd;
    wxWindow *winActive;
};

void *wxGUIAppTraits::BeforeChildWaitLoop()
{
    return NULL;
}

void wxGUIAppTraits::AfterChildWaitLoop(void *dataOrig)
{
}

bool wxGUIAppTraits::DoMessageFromThreadWait()
{
    return false;
}

wxPortId wxGUIAppTraits::GetToolkitVersion(int *majVer, int *minVer) const
{
    // TODO: how to get PalmOS GUI system version ?
    return wxPORT_PALMOS;
}

#if wxUSE_TIMER
wxTimerImpl* wxGUIAppTraits::CreateTimerImpl(wxTimer *timer)
{
    return new wxPalmOSTimerImpl(timer);
};
#endif // wxUSE_TIMER

wxEventLoopBase* wxGUIAppTraits::CreateEventLoop()
{
    return new wxEventLoop;
}
// ===========================================================================
// wxApp implementation
// ===========================================================================

int wxApp::m_nCmdShow = 0;

// ---------------------------------------------------------------------------
// wxWin macros
// ---------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxApp, wxEvtHandler)

BEGIN_EVENT_TABLE(wxApp, wxEvtHandler)
    EVT_END_SESSION(wxApp::OnEndSession)
    EVT_QUERY_END_SESSION(wxApp::OnQueryEndSession)
END_EVENT_TABLE()

// class to ensure that wxAppBase::CleanUp() is called if our Initialize()
// fails
class wxCallBaseCleanup
{
public:
    wxCallBaseCleanup(wxApp *app) : m_app(app) { }
    ~wxCallBaseCleanup() { if ( m_app ) m_app->wxAppBase::CleanUp(); }

    void Dismiss() { m_app = NULL; }

private:
    wxApp *m_app;
};

//// Initialize
bool wxApp::Initialize(int& argc, wxChar **argv)
{
    if ( !wxAppBase::Initialize(argc, argv) )
        return false;

    // ensure that base cleanup is done if we return too early
    wxCallBaseCleanup callBaseCleanup(this);

    wxWinHandleHash = new wxWinHashTable(wxKEY_INTEGER, 100);

    callBaseCleanup.Dismiss();

    return true;
}

// ---------------------------------------------------------------------------
// RegisterWindowClasses
// ---------------------------------------------------------------------------

// TODO we should only register classes really used by the app. For this it
//      would be enough to just delay the class registration until an attempt
//      to create a window of this class is made.
bool wxApp::RegisterWindowClasses()
{
    return true;
}

// ---------------------------------------------------------------------------
// UnregisterWindowClasses
// ---------------------------------------------------------------------------

bool wxApp::UnregisterWindowClasses()
{
    bool retval = true;
    return retval;
}

void wxApp::CleanUp()
{
    // all objects pending for deletion must be deleted first, otherwise we
    // would crash when they use wxWinHandleHash (and UnregisterWindowClasses()
    // call wouldn't succeed as long as any windows still exist), so call the
    // base class method first and only then do our clean up
    wxAppBase::CleanUp();

    // for an EXE the classes are unregistered when it terminates but DLL may
    // be loaded several times (load/unload/load) into the same process in
    // which case the registration will fail after the first time if we don't
    // unregister the classes now
    UnregisterWindowClasses();

    wxDELETE(wxWinHandleHash);
}

// ----------------------------------------------------------------------------
// wxApp ctor/dtor
// ----------------------------------------------------------------------------

wxApp::wxApp()
{
    m_printMode = wxPRINT_WINDOWS;
}

wxApp::~wxApp()
{
    wxChar **argv_tmp;
    argv_tmp = argv;
    // src/palmos/main.cpp
    // our cmd line arguments are allocated inside wxEntry(HINSTANCE), they
    // don't come from main(), so we have to free them
    while ( argc )
    {
        // m_argv elements were allocated by wxStrdup()
        if (argv_tmp[--argc]) {
            free((void *)(argv_tmp[--argc]));
        }
    }
    // but m_argv itself -- using new[]
    delete [] argv_tmp;
    //argv = NULL;
}

// ----------------------------------------------------------------------------
// wxApp idle handling
// ----------------------------------------------------------------------------

void wxApp::WakeUpIdle()
{
}

// ----------------------------------------------------------------------------
// other wxApp event hanlders
// ----------------------------------------------------------------------------

void wxApp::OnEndSession(wxCloseEvent& WXUNUSED(event))
{
    if (GetTopWindow())
        GetTopWindow()->Close(true);
}

// Default behaviour: close the application with prompts. The
// user can veto the close, and therefore the end session.
void wxApp::OnQueryEndSession(wxCloseEvent& event)
{
    if (GetTopWindow())
    {
        if (!GetTopWindow()->Close(!event.CanVeto()))
            event.Veto(true);
    }
}

// ----------------------------------------------------------------------------
// miscellaneous
// ----------------------------------------------------------------------------

/* static */
int wxApp::GetComCtl32Version()
{
    return 0;
}

#if wxUSE_EXCEPTIONS

// ----------------------------------------------------------------------------
// exception handling
// ----------------------------------------------------------------------------

bool wxApp::OnExceptionInMainLoop()
{
    return true;
}

#endif // wxUSE_EXCEPTIONS
