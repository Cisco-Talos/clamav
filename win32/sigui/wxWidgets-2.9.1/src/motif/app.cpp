/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/app.cpp
// Purpose:     wxApp
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/app.h"

#ifndef WX_PRECOMP
    #include "wx/hash.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/utils.h"
    #include "wx/memory.h"
    #include "wx/font.h"
#endif

#include "wx/evtloop.h"

#if wxUSE_THREADS
    #include "wx/thread.h"
#endif

#ifdef __VMS__
    #pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xresource.h>
#include <X11/Xatom.h>
#ifdef __VMS__
    #pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

#include <string.h>

struct wxPerDisplayData
{
    wxPerDisplayData()
    {
        m_visualInfo = NULL;
        m_topLevelWidget = NULL;
        m_topLevelRealizedWidget = NULL;
    }

    wxXVisualInfo* m_visualInfo;
    Widget         m_topLevelWidget, m_topLevelRealizedWidget;
};

static void wxTLWidgetDestroyCallback(Widget w, XtPointer clientData,
                                      XtPointer ptr);
static WXWidget wxCreateTopLevelWidget( WXDisplay* display );

extern bool wxAddIdleCallback();

wxHashTable *wxWidgetHashTable = NULL;

IMPLEMENT_DYNAMIC_CLASS(wxApp, wxEvtHandler)

extern "C"
{
    typedef int (*XErrorHandlerFunc)(Display *, XErrorEvent *);
}

XErrorHandlerFunc gs_pfnXErrorHandler = 0;

extern "C"
{

static int wxXErrorHandler(Display *dpy, XErrorEvent *xevent)
{
    // just forward to the default handler for now
    return gs_pfnXErrorHandler(dpy, xevent);
}

}

bool wxApp::Initialize(int& argc_, wxChar **argv_)
{
#if wxUSE_INTL
    wxFont::SetDefaultEncoding(wxLocale::GetSystemEncoding());
#endif

    if ( !wxAppBase::Initialize(argc_, argv_) )
        return false;

    wxWidgetHashTable = new wxHashTable(wxKEY_INTEGER);

#ifdef __HPUX__
    // under HP-UX creating XmFontSet fails when the system locale is C and
    // we're using a remote DISPLAY, presumably because HP-UX uses its own
    // names for C and ISO locales (roman8 and iso8859n respectively) and so
    // its Motif libraries have troubles with non-HP X server
    //
    // whatever the reason, the fact is that without this hack any wxMotif
    // program crashes on startup because it can't create any font (HP programs
    // still work but they do spit out messages about failing to create font
    // sets and failing back on "fixed" font too)
    //
    // notice that calling setlocale() here is not enough because X(m) init
    // functions call setlocale() later so we really have to change environment
    bool fixAll = false; // tweak LC_ALL (or just LC_CTYPE)?
    const char *loc = getenv("LC_CTYPE");
    if ( !loc )
    {
        loc = getenv("LC_ALL");
        if ( loc )
            fixAll = true;
    }

    if ( !loc ||
            (loc[0] == 'C' && loc[1] == '\0') ||
                strcmp(loc, "POSIX") == 0 )
    {
        // we're using C locale, "fix" it
        wxLogDebug(wxT("HP-UX fontset hack: forcing locale to en_US.iso88591"));
        putenv(fixAll ? "LC_ALL=en_US.iso88591" : "LC_CTYPE=en_US.iso88591");
    }
#endif // __HPUX__

    XtSetLanguageProc(NULL, NULL, NULL);
    XtToolkitInitialize() ;
    wxTheApp->m_appContext = (WXAppContext) XtCreateApplicationContext();

    static char *fallbackResources[] = {
        // better defaults for CDE under Irix
        //
        // TODO: do something similar for the other systems, the hardcoded defaults
        //       below are ugly
#ifdef __SGI__
        wxMOTIF_STR("*sgiMode: True"),
        wxMOTIF_STR("*useSchemes: all"),
#else // !__SGI__
#if !wxMOTIF_USE_RENDER_TABLE
        wxMOTIF_STR("*.fontList: -*-helvetica-medium-r-normal-*-*-120-*-*-*-*-*-*"),
#else
        wxMOTIF_STR("*wxDefaultRendition.fontName: -*-helvetica-medium-r-normal-*-*-120-*-*-*-*-*-*"),
        wxMOTIF_STR("*wxDefaultRendition.fontType: FONT_IS_FONTSET"),
        wxMOTIF_STR("*.renderTable: wxDefaultRendition"),
#endif
        wxMOTIF_STR("*listBox.background: white"),
        wxMOTIF_STR("*text.background: white"),
        wxMOTIF_STR("*comboBox.Text.background: white"),
        wxMOTIF_STR("*comboBox.List.background: white"),
#endif // __SGI__/!__SGI__
        NULL
    };
    XtAppSetFallbackResources((XtAppContext) wxTheApp->m_appContext, fallbackResources);

    // we shouldn't pass empty application/class name as it results in
    // immediate crash inside XOpenIM() (if XIM is used) under IRIX
    wxString appname = wxTheApp->GetAppName();
    if ( appname.empty() )
        appname = wxT("wxapp");
    wxString clsname = wxTheApp->GetClassName();
    if ( clsname.empty() )
        clsname = wxT("wx");

    // FIXME-UTF8: This code is taken from wxGTK and duplicated here. This
    //             is just a temporary fix to make wxX11 compile in Unicode
    //             build, the real fix is to change Initialize()'s signature
    //             to use char* on Unix.
#if wxUSE_UNICODE
    // XtOpenDisplay() wants char*, not wchar_t*, so convert
    int i;
    char **argvX11 = new char *[argc + 1];
    for ( i = 0; i < argc; i++ )
    {
        argvX11[i] = strdup(wxConvLibc.cWX2MB(argv_[i]));
    }

    argvX11[argc] = NULL;

    int argcX11 = argc;

    Display *dpy = XtOpenDisplay((XtAppContext) wxTheApp->m_appContext,
        (String)NULL,
        appname.c_str(),
        clsname.c_str(),
        NULL, 0,    // no options
# if XtSpecificationRelease < 5
        (Cardinal*) &argcX11,
# else
        &argcX11,
# endif
        argvX11);

    if ( argcX11 != argc )
    {
        // we have to drop the parameters which were consumed by X11+
        for ( i = 0; i < argcX11; i++ )
        {
            while ( strcmp(wxConvLibc.cWX2MB(argv_[i]), argvX11[i]) != 0 )
            {
                memmove(argv_ + i, argv_ + i + 1, (argc - i)*sizeof(*argv_));
            }
        }

        argc = argcX11;

        // update internal arg[cv] as X11 may have removed processed options:
        argc = argc_;
        argv = argv_;
    }
    //else: XtOpenDisplay() didn't modify our parameters

    // free our copy
    for ( i = 0; i < argcX11; i++ )
    {
        free(argvX11[i]);
    }

    delete [] argvX11;

#else // ANSI

    Display *dpy = XtOpenDisplay((XtAppContext) wxTheApp->m_appContext,
        (String)NULL,
        appname.c_str(),
        clsname.c_str(),
        NULL, 0,    // no options
# if XtSpecificationRelease < 5
        (Cardinal*) &argc,
# else
        &argc,
# endif
        argv);

#endif // Unicode/ANSI

    if (!dpy) {
         // if you don't log to stderr, nothing will be shown...
        delete wxLog::SetActiveTarget(new wxLogStderr);
        wxString className(wxTheApp->GetClassName());
        wxLogError(_("wxWidgets could not open display for '%s': exiting."),
                   className.c_str());
        exit(-1);
    }
    m_initialDisplay = (WXDisplay*) dpy;

    // install the X error handler
    gs_pfnXErrorHandler = XSetErrorHandler(wxXErrorHandler);

    // Add general resize proc
    XtActionsRec rec;
    rec.string = wxMOTIF_STR("resize");
    rec.proc = (XtActionProc)wxWidgetResizeProc;
    XtAppAddActions((XtAppContext) wxTheApp->m_appContext, &rec, 1);

    GetMainColormap(dpy);

    wxAddIdleCallback();

    return true;
}

void wxApp::CleanUp()
{
    wxAppBase::CleanUp();

    wxDELETE(wxWidgetHashTable);

    delete m_mainLoop;

    for( wxPerDisplayDataMap::iterator it  = m_perDisplayData->begin(),
                                       end = m_perDisplayData->end();
         it != end; ++it )
    {
        delete it->second->m_visualInfo;
        // On Solaris 10 calling XtDestroyWidget on the top level widget
        // dumps core if the locale is set to something other than "C"
#ifndef __SUN__
        XtDestroyWidget( it->second->m_topLevelWidget );
#endif
        delete it->second;
    }
}

void wxApp::Exit()
{
    wxApp::CleanUp();

    wxAppConsole::Exit();
}

// ============================================================================
// wxApp
// ============================================================================

wxApp::wxApp()
{
    m_mainLoop = new wxEventLoop;
    m_mainColormap = (WXColormap) NULL;
    m_appContext = (WXAppContext) NULL;
    m_initialDisplay = (WXDisplay*) 0;
    m_perDisplayData = new wxPerDisplayDataMap;
}

wxApp::~wxApp()
{
    delete m_perDisplayData;
}

int wxApp::MainLoop()
{
    /*
    * Sit around forever waiting to process X-events. Property Change
    * event are handled special, because they have to refer to
    * the root window rather than to a widget. therefore we can't
    * use an Xt-eventhandler.
    */

    XSelectInput(XtDisplay((Widget) wxTheApp->GetTopLevelWidget()),
        XDefaultRootWindow(XtDisplay((Widget) wxTheApp->GetTopLevelWidget())),
        PropertyChangeMask);

    m_mainLoop->Run();

    return 0;
}

// This should be redefined in a derived class for
// handling property change events for XAtom IPC.
void wxApp::HandlePropertyChange(WXEvent *event)
{
    // by default do nothing special
    XtDispatchEvent((XEvent*) event); /* let Motif do the work */
}

WXColormap wxApp::GetMainColormap(WXDisplay* display)
{
    if (!display) /* Must be called first with non-NULL display */
        return m_mainColormap;

    int defaultScreen = DefaultScreen((Display*) display);
    Screen* screen = XScreenOfDisplay((Display*) display, defaultScreen);

    Colormap c = DefaultColormapOfScreen(screen);

    if (!m_mainColormap)
        m_mainColormap = (WXColormap) c;

    return (WXColormap) c;
}

static inline wxPerDisplayData& GetOrCreatePerDisplayData
    ( wxPerDisplayDataMap& m, WXDisplay* display )
{
    wxPerDisplayDataMap::iterator it = m.find( display );
    if( it != m.end() && it->second != NULL )
        return *(it->second);

    wxPerDisplayData* nData = new wxPerDisplayData();
    m[display] = nData;

    return *nData;
}

wxXVisualInfo* wxApp::GetVisualInfo( WXDisplay* display )
{
    wxPerDisplayData& data = GetOrCreatePerDisplayData( *m_perDisplayData,
                                                        display );
    if( data.m_visualInfo )
        return data.m_visualInfo;

    wxXVisualInfo* vi = new wxXVisualInfo;
    wxFillXVisualInfo( vi, (Display*)display );

    data.m_visualInfo = vi;

    return vi;
}

static void wxTLWidgetDestroyCallback(Widget w, XtPointer WXUNUSED(clientData),
                                      XtPointer WXUNUSED(ptr))
{
    if( wxTheApp )
    {
        wxTheApp->SetTopLevelWidget( (WXDisplay*)XtDisplay(w),
                                     (WXWidget)NULL );
        wxTheApp->SetTopLevelRealizedWidget( (WXDisplay*)XtDisplay(w),
                                             (WXWidget)NULL );
    }
}

WXWidget wxCreateTopLevelWidget( WXDisplay* display )
{
    Widget tlw = XtAppCreateShell( (String)NULL,
                                   wxTheApp->GetClassName().c_str(),
                                   applicationShellWidgetClass,
                                   (Display*)display,
                                   NULL, 0 );
    XtVaSetValues( tlw,
                   XmNoverrideRedirect, True,
                   NULL );

    XtAddCallback( tlw, XmNdestroyCallback,
                   (XtCallbackProc)wxTLWidgetDestroyCallback,
                   (XtPointer)NULL );

    return (WXWidget)tlw;
}

WXWidget wxCreateTopLevelRealizedWidget( WXDisplay* WXUNUSED(display) )
{
    Widget rTlw = XtVaCreateWidget( "dummy_widget", topLevelShellWidgetClass,
                                    (Widget)wxTheApp->GetTopLevelWidget(),
                                     NULL );
    XtSetMappedWhenManaged( rTlw, False );
    XtRealizeWidget( rTlw );

    return (WXWidget)rTlw;
}

WXWidget wxApp::GetTopLevelWidget()
{
    WXDisplay* display = wxGetDisplay();
    wxPerDisplayData& data = GetOrCreatePerDisplayData( *m_perDisplayData,
                                                        display );
    if( data.m_topLevelWidget )
        return (WXWidget)data.m_topLevelWidget;

    WXWidget tlw = wxCreateTopLevelWidget( display );
    SetTopLevelWidget( display, tlw );

    return tlw;
}

WXWidget wxApp::GetTopLevelRealizedWidget()
{
    WXDisplay* display = wxGetDisplay();
    wxPerDisplayDataMap::iterator it = m_perDisplayData->find( display );

    if( it != m_perDisplayData->end() && it->second->m_topLevelRealizedWidget )
        return (WXWidget)it->second->m_topLevelRealizedWidget;

    WXWidget rTlw = wxCreateTopLevelRealizedWidget( display );
    SetTopLevelRealizedWidget( display, rTlw );

    return rTlw;
}

void wxApp::SetTopLevelWidget(WXDisplay* display, WXWidget widget)
{
    GetOrCreatePerDisplayData( *m_perDisplayData, display )
        .m_topLevelWidget = (Widget)widget;
}

void wxApp::SetTopLevelRealizedWidget(WXDisplay* display, WXWidget widget)
{
    GetOrCreatePerDisplayData( *m_perDisplayData, display )
        .m_topLevelRealizedWidget = (Widget)widget;
}


// ----------------------------------------------------------------------------
// accessors for C modules
// ----------------------------------------------------------------------------

extern "C" XtAppContext wxGetAppContext()
{
    return (XtAppContext)wxTheApp->GetAppContext();
}
