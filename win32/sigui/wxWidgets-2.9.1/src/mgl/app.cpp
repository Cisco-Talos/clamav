/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/app.cpp
// Author:      Vaclav Slavik
//              based on GTK and MSW implementations
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/app.h"

#ifndef WX_PRECOMP
    #include "wx/settings.h"
    #include "wx/frame.h"
    #include "wx/dialog.h"
    #include "wx/log.h"
    #include "wx/intl.h"
    #include "wx/module.h"
#endif

#include "wx/evtloop.h"
#include "wx/fontutil.h"
#include "wx/univ/theme.h"
#include "wx/univ/renderer.h"
#include "wx/univ/colschem.h"
#include "wx/sysopt.h"
#include "wx/mgl/private.h"
#include "wx/private/fontmgr.h"

//-----------------------------------------------------------------------------
// wxApp::Exit()
//-----------------------------------------------------------------------------

void wxApp::Exit()
{
    MGL_exit();
    exit(0);
}


//-----------------------------------------------------------------------------
// wxWakeUpIdle
//-----------------------------------------------------------------------------

void wxApp::WakeUpIdle()
{
#if wxUSE_THREADS
    if (!wxThread::IsMain())
        wxMutexGuiEnter();
#endif

    while (wxTheApp->ProcessIdle())
        ;

#if wxUSE_THREADS
    if (!wxThread::IsMain())
        wxMutexGuiLeave();
#endif
}

//-----------------------------------------------------------------------------
// Root window
//-----------------------------------------------------------------------------

class wxRootWindow : public wxWindow
{
    public:
        wxRootWindow() : wxWindow(NULL, wxID_ANY)
        {
            SetMGLwindow_t(MGL_wmGetRootWindow(g_winMng));
            SetBackgroundColour(wxTHEME_COLOUR(DESKTOP));
        }
        virtual ~wxRootWindow()
        {
            // we don't want to delete MGL_WM's rootWnd
            m_wnd = NULL;
        }

        virtual bool AcceptsFocus() const { return false; }

        DECLARE_DYNAMIC_CLASS(wxRootWindow)
};

IMPLEMENT_DYNAMIC_CLASS(wxRootWindow, wxWindow)

static wxRootWindow *gs_rootWindow = NULL;

//-----------------------------------------------------------------------------
// MGL initialization
//-----------------------------------------------------------------------------

static bool wxCreateMGL_WM(const wxVideoMode& displayMode)
{
    int mode;
    int refresh = MGL_DEFAULT_REFRESH;

#if wxUSE_SYSTEM_OPTIONS
    if ( wxSystemOptions::HasOption(wxT("mgl.screen-refresh")) )
        refresh = wxSystemOptions::GetOptionInt(wxT("mgl.screen-refresh"));
#endif

    mode = MGL_findMode(displayMode.GetWidth(),
                        displayMode.GetHeight(),
                        displayMode.GetDepth());
    if ( mode == -1 )
    {
        wxLogError(_("Mode %ix%i-%i not available."),
                     displayMode.GetWidth(),
                     displayMode.GetHeight(),
                     displayMode.GetDepth());
        return false;
    }
    g_displayDC = new MGLDisplayDC(mode, 1, refresh);
    if ( !g_displayDC->isValid() )
    {
        wxDELETE(g_displayDC);
        return false;
    }

    g_winMng = MGL_wmCreate(g_displayDC->getDC());
    if (!g_winMng)
        return false;

    return true;
}

static void wxDestroyMGL_WM()
{
    if ( g_winMng )
    {
        MGL_wmDestroy(g_winMng);
        g_winMng = NULL;
    }
    wxDELETE(g_displayDC);
}

//-----------------------------------------------------------------------------
// wxApp
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxApp,wxEvtHandler)

wxApp::wxApp()
{
}

wxApp::~wxApp()
{
}

wxVideoMode wxGetDefaultDisplayMode()
{
    wxString mode;
    unsigned w, h, bpp;

    if ( !wxGetEnv(wxT("WXMODE"), &mode) ||
         (wxSscanf(mode.c_str(), wxT("%ux%u-%u"), &w, &h, &bpp) != 3) )
    {
        w = 640, h = 480, bpp = 16;
    }

    return wxVideoMode(w, h, bpp);
}

bool wxApp::SetDisplayMode(const wxVideoMode& mode)
{
    if ( !mode.IsOk() )
    {
        return false;
    }
    if ( g_displayDC != NULL )
    {
        // FIXME_MGL -- we currently don't allow to switch video mode
        // more than once. This can hopefully be changed...
        wxFAIL_MSG(wxT("Can't change display mode after intialization!"));
        return false;
    }

    if ( !wxCreateMGL_WM(mode) )
        return false;
    gs_rootWindow = new wxRootWindow;

    m_displayMode = mode;

    return true;
}

bool wxApp::OnInitGui()
{
    if ( !wxAppBase::OnInitGui() )
        return false;

    // MGL redirects stdout and stderr to physical console, so lets redirect
    // it to file if WXSTDERR environment variable is set to be able to see
    // wxLogDebug() output
    wxString redirect;
    if ( wxGetEnv(wxT("WXSTDERR"), &redirect) )
        freopen(redirect.mb_str(), "wt", stderr);

    wxLog *oldLog = wxLog::SetActiveTarget(new wxLogGui);
    if ( oldLog ) delete oldLog;

    return true;
}

bool wxApp::Initialize(int& argc, wxChar **argv)
{
#ifdef __DJGPP__
    // VS: disable long filenames under DJGPP as the very first thing,
    //     since SciTech MGL doesn't like them much...
    wxSetEnv(wxT("LFN"), wxT("N"));
#endif

    // intialize MGL before creating wxFontsManager since it uses MGL funcs
    if ( MGL_init(".", NULL) == 0 )
    {
        wxLogError(_("Cannot initialize SciTech MGL!"));
        return false;
    }

    if ( !wxAppBase::Initialize(argc, argv) )
    {
        MGL_exit();
        return false;
    }

#if wxUSE_INTL
    wxFont::SetDefaultEncoding(wxLocale::GetSystemEncoding());
#endif

    return true;
}

// Modules are cleaned up after wxApp::CleanUp(), and some modules may
// require MGL to still be alive, e.g. the stock fonts need the fonts
// manager. So append this module last minute in wxApp::CleanUp() to close
// down MGL after all the other modules have been cleaned up.
//
struct wxMGLFinalCleanup: public wxModule
{
    bool OnInit() { return true; }

    void OnExit()
    {
        wxFontsManager::CleanUp();

        wxDestroyMGL_WM();
        MGL_exit();
    }
};

void wxApp::CleanUp()
{
    delete gs_rootWindow;

    wxAppBase::CleanUp();

    wxModule::RegisterModule(new wxMGLFinalCleanup);
}
