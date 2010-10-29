/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/app.cpp
// Purpose:     wxApp
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/app.h"

#ifndef WX_PRECOMP
    #include "wx/hash.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/utils.h"
    #include "wx/frame.h"
    #include "wx/icon.h"
    #include "wx/dialog.h"
    #include "wx/memory.h"
    #include "wx/gdicmn.h"
    #include "wx/module.h"
    #include "wx/crt.h"
#endif

#include "wx/evtloop.h"
#include "wx/filename.h"

#include "wx/univ/theme.h"
#include "wx/univ/renderer.h"
#include "wx/generic/private/timer.h"

#if wxUSE_THREADS
    #include "wx/thread.h"
#endif

#include "wx/x11/private.h"

#include <string.h>

//------------------------------------------------------------------------
//   global data
//------------------------------------------------------------------------

wxWindowHash *wxWidgetHashTable = NULL;
wxWindowHash *wxClientWidgetHashTable = NULL;

static bool g_showIconic = false;
static wxSize g_initialSize = wxDefaultSize;

// This is required for wxFocusEvent::SetWindow(). It will only
// work for focus events which we provoke ourselves (by calling
// SetFocus()). It will not work for those events, which X11
// generates itself.
static wxWindow *g_nextFocus = NULL;
static wxWindow *g_prevFocus = NULL;

//------------------------------------------------------------------------
//   X11 error handling
//------------------------------------------------------------------------

typedef int (*XErrorHandlerFunc)(Display *, XErrorEvent *);

XErrorHandlerFunc gs_pfnXErrorHandler = 0;

static int wxXErrorHandler(Display *dpy, XErrorEvent *xevent)
{
    // just forward to the default handler for now
    if (gs_pfnXErrorHandler)
        return gs_pfnXErrorHandler(dpy, xevent);
    else
        return 0;
}

//------------------------------------------------------------------------
//   wxApp
//------------------------------------------------------------------------

long wxApp::sm_lastMessageTime = 0;

IMPLEMENT_DYNAMIC_CLASS(wxApp, wxEvtHandler)

bool wxApp::Initialize(int& argC, wxChar **argV)
{
#if !wxUSE_NANOX
    // install the X error handler
    gs_pfnXErrorHandler = XSetErrorHandler( wxXErrorHandler );
#endif

    wxString displayName;
    bool syncDisplay = false;

    int argCOrig = argC;
    for ( int i = 0; i < argCOrig; i++ )
    {
        if (wxStrcmp( argV[i], wxT("-display") ) == 0)
        {
            if (i < (argCOrig - 1))
            {
                argV[i++] = NULL;

                displayName = argV[i];

                argV[i] = NULL;
                argC -= 2;
            }
        }
        else if (wxStrcmp( argV[i], wxT("-geometry") ) == 0)
        {
            if (i < (argCOrig - 1))
            {
                argV[i++] = NULL;

                int w, h;
                if (wxSscanf(argV[i], wxT("%dx%d"), &w, &h) != 2)
                {
                    wxLogError( _("Invalid geometry specification '%s'"),
                                wxString(argV[i]).c_str() );
                }
                else
                {
                    g_initialSize = wxSize(w, h);
                }

                argV[i] = NULL;
                argC -= 2;
            }
        }
        else if (wxStrcmp( argV[i], wxT("-sync") ) == 0)
        {
            syncDisplay = true;

            argV[i] = NULL;
            argC--;
        }
        else if (wxStrcmp( argV[i], wxT("-iconic") ) == 0)
        {
            g_showIconic = true;

            argV[i] = NULL;
            argC--;
        }
    }

    if ( argC != argCOrig )
    {
        // remove the arguments we consumed
        for ( int i = 0; i < argC; i++ )
        {
            while ( !argV[i] )
            {
                memmove(argV + i, argV + i + 1, (argCOrig - i)*sizeof(wxChar *));
            }
        }
    }

    // open and set up the X11 display
    if ( !wxSetDisplay(displayName) )
    {
        wxLogError(_("wxWidgets could not open display. Exiting."));
        return false;
    }

    Display *dpy = wxGlobalDisplay();
    if (syncDisplay)
        XSynchronize(dpy, True);

    XSelectInput(dpy, XDefaultRootWindow(dpy), PropertyChangeMask);

    wxSetDetectableAutoRepeat( true );


    if ( !wxAppBase::Initialize(argC, argV) )
        return false;

#if wxUSE_UNICODE
    // Glib's type system required by Pango
    g_type_init();
#endif

#if wxUSE_INTL
    wxFont::SetDefaultEncoding(wxLocale::GetSystemEncoding());
#endif

    wxWidgetHashTable = new wxWindowHash;
    wxClientWidgetHashTable = new wxWindowHash;

    return true;
}

void wxApp::CleanUp()
{
    wxDELETE(wxWidgetHashTable);
    wxDELETE(wxClientWidgetHashTable);

    wxAppBase::CleanUp();
}

wxApp::wxApp()
{
    m_mainColormap = NULL;
    m_topLevelWidget = NULL;
    m_maxRequestSize = 0;
    m_showIconic = false;
    m_initialSize = wxDefaultSize;

#if !wxUSE_NANOX
    m_visualInfo = NULL;
#endif
}

wxApp::~wxApp()
{
#if !wxUSE_NANOX
    delete m_visualInfo;
#endif
}

#if !wxUSE_NANOX

//-----------------------------------------------------------------------
// X11 predicate function for exposure compression
//-----------------------------------------------------------------------

struct wxExposeInfo
{
    Window window;
    Bool found_non_matching;
};

extern "C"
Bool wxX11ExposePredicate (Display *WXUNUSED(display), XEvent *xevent, XPointer arg)
{
    wxExposeInfo *info = (wxExposeInfo*) arg;

    if (info->found_non_matching)
       return FALSE;

    if (xevent->xany.type != Expose)
    {
        info->found_non_matching = true;
        return FALSE;
    }

    if (xevent->xexpose.window != info->window)
    {
        info->found_non_matching = true;
        return FALSE;
    }

    return TRUE;
}

#endif // wxUSE_NANOX

//-----------------------------------------------------------------------
// Processes an X event, returning true if the event was processed.
//-----------------------------------------------------------------------

bool wxApp::ProcessXEvent(WXEvent* _event)
{
    XEvent* event = (XEvent*) _event;

    wxWindow* win = NULL;
    Window window = XEventGetWindow(event);
#if 0
    Window actualWindow = window;
#endif

    // Find the first wxWindow that corresponds to this event window
    // Because we're receiving events after a window
    // has been destroyed, assume a 1:1 match between
    // Window and wxWindow, so if it's not in the table,
    // it must have been destroyed.

    win = wxGetWindowFromTable(window);
    if (!win)
    {
#if wxUSE_TWO_WINDOWS
        win = wxGetClientWindowFromTable(window);
        if (!win)
#endif
            return false;
    }


    switch (event->type)
    {
        case Expose:
        {
#if wxUSE_TWO_WINDOWS && !wxUSE_NANOX
            if (event->xexpose.window != (Window)win->GetClientAreaWindow())
            {
                XEvent tmp_event;
                wxExposeInfo info;
                info.window = event->xexpose.window;
                info.found_non_matching = false;
                while (XCheckIfEvent( wxGlobalDisplay(), &tmp_event, wxX11ExposePredicate, (XPointer) &info ))
                {
                    // Don't worry about optimizing redrawing the border etc.
                }
                win->NeedUpdateNcAreaInIdle();
            }
            else
#endif
            {
                win->GetUpdateRegion().Union( XExposeEventGetX(event), XExposeEventGetY(event),
                                              XExposeEventGetWidth(event), XExposeEventGetHeight(event));
                win->GetClearRegion().Union( XExposeEventGetX(event), XExposeEventGetY(event),
                                         XExposeEventGetWidth(event), XExposeEventGetHeight(event));

#if !wxUSE_NANOX
                XEvent tmp_event;
                wxExposeInfo info;
                info.window = event->xexpose.window;
                info.found_non_matching = false;
                while (XCheckIfEvent( wxGlobalDisplay(), &tmp_event, wxX11ExposePredicate, (XPointer) &info ))
                {
                    win->GetUpdateRegion().Union( tmp_event.xexpose.x, tmp_event.xexpose.y,
                                                  tmp_event.xexpose.width, tmp_event.xexpose.height );

                    win->GetClearRegion().Union( tmp_event.xexpose.x, tmp_event.xexpose.y,
                                                 tmp_event.xexpose.width, tmp_event.xexpose.height );
                }
#endif

                // This simplifies the expose and clear areas to simple
                // rectangles.
                win->GetUpdateRegion() = win->GetUpdateRegion().GetBox();
                win->GetClearRegion() = win->GetClearRegion().GetBox();

                // If we only have one X11 window, always indicate
                // that borders might have to be redrawn.
                if (win->X11GetMainWindow() == win->GetClientAreaWindow())
                    win->NeedUpdateNcAreaInIdle();

                // Only erase background, paint in idle time.
                win->SendEraseEvents();

                // EXPERIMENT
                //win->Update();
            }

            return true;
        }

#if !wxUSE_NANOX
        case GraphicsExpose:
        {
            wxLogTrace( wxT("expose"), wxT("GraphicsExpose from %s"), win->GetName().c_str());

            win->GetUpdateRegion().Union( event->xgraphicsexpose.x, event->xgraphicsexpose.y,
                                          event->xgraphicsexpose.width, event->xgraphicsexpose.height);

            win->GetClearRegion().Union( event->xgraphicsexpose.x, event->xgraphicsexpose.y,
                                         event->xgraphicsexpose.width, event->xgraphicsexpose.height);

            if (event->xgraphicsexpose.count == 0)
            {
                // Only erase background, paint in idle time.
                win->SendEraseEvents();
                // win->Update();
            }

            return true;
        }
#endif

        case KeyPress:
        {
            if (!win->IsEnabled())
                return false;

            wxKeyEvent keyEvent(wxEVT_KEY_DOWN);
            wxTranslateKeyEvent(keyEvent, win, window, event);

            // wxLogDebug( "OnKey from %s", win->GetName().c_str() );

            // We didn't process wxEVT_KEY_DOWN, so send wxEVT_CHAR
            if (win->HandleWindowEvent( keyEvent ))
                return true;

            keyEvent.SetEventType(wxEVT_CHAR);
            // Do the translation again, retaining the ASCII
            // code.
            if (wxTranslateKeyEvent(keyEvent, win, window, event, true) &&
                win->HandleWindowEvent( keyEvent ))
                return true;

            if ( (keyEvent.m_keyCode == WXK_TAB) &&
                 win->GetParent() && (win->GetParent()->HasFlag( wxTAB_TRAVERSAL)) )
            {
                wxNavigationKeyEvent new_event;
                new_event.SetEventObject( win->GetParent() );
                /* GDK reports GDK_ISO_Left_Tab for SHIFT-TAB */
                new_event.SetDirection( (keyEvent.m_keyCode == WXK_TAB) );
                /* CTRL-TAB changes the (parent) window, i.e. switch notebook page */
                new_event.SetWindowChange( keyEvent.ControlDown() );
                new_event.SetCurrentFocus( win );
                return win->GetParent()->HandleWindowEvent( new_event );
            }

            return false;
        }
        case KeyRelease:
        {
            if (!win->IsEnabled())
                return false;

            wxKeyEvent keyEvent(wxEVT_KEY_UP);
            wxTranslateKeyEvent(keyEvent, win, window, event);

            return win->HandleWindowEvent( keyEvent );
        }
        case ConfigureNotify:
        {
#if wxUSE_NANOX
            if (event->update.utype == GR_UPDATE_SIZE)
#endif
            {
                wxTopLevelWindow *tlw = wxDynamicCast(win, wxTopLevelWindow);
                if ( tlw )
                {
                    tlw->SetConfigureGeometry( XConfigureEventGetX(event), XConfigureEventGetY(event),
                        XConfigureEventGetWidth(event), XConfigureEventGetHeight(event) );
                }

                if ( tlw && tlw->IsShown() )
                {
                    tlw->SetNeedResizeInIdle();
                }
                else
                {
                    wxSizeEvent sizeEvent( wxSize(XConfigureEventGetWidth(event), XConfigureEventGetHeight(event)), win->GetId() );
                    sizeEvent.SetEventObject( win );

                    return win->HandleWindowEvent( sizeEvent );
                }
            }
            return false;
        }
#if !wxUSE_NANOX
        case PropertyNotify:
            return HandlePropertyChange(_event);

        case ClientMessage:
        {
            if (!win->IsEnabled())
                return false;

            Atom wm_delete_window = XInternAtom(wxGlobalDisplay(), "WM_DELETE_WINDOW", True);
            Atom wm_protocols = XInternAtom(wxGlobalDisplay(), "WM_PROTOCOLS", True);

            if (event->xclient.message_type == wm_protocols)
            {
                if ((Atom) (event->xclient.data.l[0]) == wm_delete_window)
                {
                    win->Close(false);
                    return true;
                }
            }
            return false;
        }
#if 0
        case DestroyNotify:
        {
            printf( "destroy from %s\n", win->GetName().c_str() );
            break;
        }
        case CreateNotify:
        {
            printf( "create from %s\n", win->GetName().c_str() );
            break;
        }
        case MapRequest:
        {
            printf( "map request from %s\n", win->GetName().c_str() );
            break;
        }
        case ResizeRequest:
        {
            printf( "resize request from %s\n", win->GetName().c_str() );

            Display *disp = (Display*) wxGetDisplay();
            XEvent report;

            //  to avoid flicker
            report = * event;
            while( XCheckTypedWindowEvent (disp, actualWindow, ResizeRequest, &report));

            wxSize sz = win->GetSize();
            wxSizeEvent sizeEvent(sz, win->GetId());
            sizeEvent.SetEventObject(win);

            return win->HandleWindowEvent( sizeEvent );
        }
#endif
#endif
#if wxUSE_NANOX
        case GR_EVENT_TYPE_CLOSE_REQ:
        {
            if (win)
            {
                win->Close(false);
                return true;
            }
            return false;
            break;
        }
#endif
        case EnterNotify:
        case LeaveNotify:
        case ButtonPress:
        case ButtonRelease:
        case MotionNotify:
        {
            if (!win->IsEnabled())
                return false;

            // Here we check if the top level window is
            // disabled, which is one aspect of modality.
            wxWindow *tlw = win;
            while (tlw && !tlw->IsTopLevel())
                tlw = tlw->GetParent();
            if (tlw && !tlw->IsEnabled())
                return false;

            if (event->type == ButtonPress)
            {
                if ((win != wxWindow::FindFocus()) && win->CanAcceptFocus())
                {
                    // This might actually be done in wxWindow::SetFocus()
                    // and not here. TODO.
                    g_prevFocus = wxWindow::FindFocus();
                    g_nextFocus = win;

                    wxLogTrace( wxT("focus"), wxT("About to call SetFocus on %s of type %s due to button press"), win->GetName().c_str(), win->GetClassInfo()->GetClassName() );

                    // Record the fact that this window is
                    // getting the focus, because we'll need to
                    // check if its parent is getting a bogus
                    // focus and duly ignore it.
                    // TODO: may need to have this code in SetFocus, too.
                    extern wxWindow* g_GettingFocus;
                    g_GettingFocus = win;
                    win->SetFocus();
                }
            }

#if !wxUSE_NANOX
            if (event->type == LeaveNotify || event->type == EnterNotify)
            {
                // Throw out NotifyGrab and NotifyUngrab
                if (event->xcrossing.mode != NotifyNormal)
                    return false;
            }
#endif
            wxMouseEvent wxevent;
            wxTranslateMouseEvent(wxevent, win, window, event);
            return win->HandleWindowEvent( wxevent );
        }
        case FocusIn:
#if !wxUSE_NANOX
            if ((event->xfocus.detail != NotifyPointer) &&
                (event->xfocus.mode == NotifyNormal))
#endif
            {
                wxLogTrace( wxT("focus"), wxT("FocusIn from %s of type %s"), win->GetName().c_str(), win->GetClassInfo()->GetClassName() );

                extern wxWindow* g_GettingFocus;
                if (g_GettingFocus && g_GettingFocus->GetParent() == win)
                {
                    // Ignore this, this can be a spurious FocusIn
                    // caused by a child having its focus set.
                    g_GettingFocus = NULL;
                    wxLogTrace( wxT("focus"), wxT("FocusIn from %s of type %s being deliberately ignored"), win->GetName().c_str(), win->GetClassInfo()->GetClassName() );
                    return true;
                }
                else
                {
                    wxFocusEvent focusEvent(wxEVT_SET_FOCUS, win->GetId());
                    focusEvent.SetEventObject(win);
                    focusEvent.SetWindow( g_prevFocus );
                    g_prevFocus = NULL;

                    return win->HandleWindowEvent(focusEvent);
                }
            }
            return false;

        case FocusOut:
#if !wxUSE_NANOX
            if ((event->xfocus.detail != NotifyPointer) &&
                (event->xfocus.mode == NotifyNormal))
#endif
            {
                wxLogTrace( wxT("focus"), wxT("FocusOut from %s of type %s"), win->GetName().c_str(), win->GetClassInfo()->GetClassName() );

                wxFocusEvent focusEvent(wxEVT_KILL_FOCUS, win->GetId());
                focusEvent.SetEventObject(win);
                focusEvent.SetWindow( g_nextFocus );
                g_nextFocus = NULL;
                return win->HandleWindowEvent(focusEvent);
            }
            return false;
    }

    return false;
}

// This should be redefined in a derived class for
// handling property change events for XAtom IPC.
bool wxApp::HandlePropertyChange(WXEvent *WXUNUSED(event))
{
    // by default do nothing special
    // TODO: what to do for X11
    // XtDispatchEvent((XEvent*) event);
    return false;
}

void wxApp::WakeUpIdle()
{
    // TODO: use wxMotif implementation?

    // Wake up the idle handler processor, even if it is in another thread...
}


// Create display, and other initialization
bool wxApp::OnInitGui()
{
#if wxUSE_LOG
    // Eventually this line will be removed, but for
    // now we don't want to try popping up a dialog
    // for error messages.
    delete wxLog::SetActiveTarget(new wxLogStderr);
#endif

    if (!wxAppBase::OnInitGui())
        return false;

    Display *dpy = wxGlobalDisplay();
    GetMainColormap(dpy);

    m_maxRequestSize = XMaxRequestSize(dpy);

#if !wxUSE_NANOX
    m_visualInfo = new wxXVisualInfo;
    wxFillXVisualInfo(m_visualInfo, dpy);
#endif

    return true;
}

#if wxUSE_UNICODE

#include <pango/pango.h>
#include <pango/pangox.h>
#ifdef HAVE_PANGO_XFT
    #include <pango/pangoxft.h>
#endif

PangoContext* wxApp::GetPangoContext()
{
    static PangoContext *s_pangoContext = NULL;
    if ( !s_pangoContext )
    {
        Display *dpy = wxGlobalDisplay();

#ifdef HAVE_PANGO_XFT
        int xscreen = DefaultScreen(dpy);
        static int use_xft = -1;
        if (use_xft == -1)
        {
            wxString val = wxGetenv( L"GDK_USE_XFT" );
            use_xft = val == L"1";
        }

        if (use_xft)
            s_pangoContext = pango_xft_get_context(dpy, xscreen);
        else
#endif // HAVE_PANGO_XFT
            s_pangoContext = pango_x_get_context(dpy);

        if (!PANGO_IS_CONTEXT(s_pangoContext))
        {
            wxLogError( wxT("No pango context.") );
        }
    }

    return s_pangoContext;
}

#endif // wxUSE_UNICODE

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

Window wxGetWindowParent(Window window)
{
    wxASSERT_MSG( window, wxT("invalid window") );

    return (Window) 0;

#ifndef __VMS
   // VMS chokes on unreacheable code
   Window parent, root = 0;
#if wxUSE_NANOX
    int noChildren = 0;
#else
    unsigned int noChildren = 0;
#endif
    Window* children = NULL;

    // #define XQueryTree(d,w,r,p,c,nc)     GrQueryTree(w,p,c,nc)
    int res = 1;
#if !wxUSE_NANOX
    res =
#endif
        XQueryTree((Display*) wxGetDisplay(), window, & root, & parent,
             & children, & noChildren);
    if (children)
        XFree(children);
    if (res)
        return parent;
    else
        return (Window) 0;
#endif
}

void wxApp::Exit()
{
    wxApp::CleanUp();

    wxAppConsole::Exit();
}

