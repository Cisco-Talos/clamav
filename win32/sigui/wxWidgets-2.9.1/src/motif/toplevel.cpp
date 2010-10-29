/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/toplevel.cpp
// Purpose:     wxTopLevelWindow Motif implementation
// Author:      Mattia Barbon
// Modified by:
// Created:     12/10/2002
// RCS-ID:      $Id$
// Copyright:   (c) Mattia Barbon
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

#include "wx/toplevel.h"
#include "wx/settings.h"
#include "wx/app.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif

#include <Xm/Xm.h>
#include <X11/Shell.h>
#include <X11/Core.h>
#if XmVersion >= 1002
    #include <Xm/XmAll.h>
#else
    #include <Xm/Frame.h>
#endif

#ifdef __VMS__
    #pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

wxList wxModelessWindows;  // Frames and modeless dialogs

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

static void wxCloseTLWCallback( Widget widget, XtPointer client_data,
                                XmAnyCallbackStruct *cbs );
static void wxTLWEventHandler( Widget wid,
                               XtPointer client_data,
                               XEvent* event,
                               Boolean *continueToDispatch );

// ===========================================================================
// wxTopLevelWindowMotif implementation
// ===========================================================================

void wxTopLevelWindowMotif::PreDestroy()
{
    wxModelessWindows.DeleteObject(this);

    DestroyChildren();

    // MessageDialog and FileDialog do not have a client widget
    if( GetClientWidget() )
    {
        XtRemoveEventHandler( (Widget)GetClientWidget(),
                              ButtonPressMask | ButtonReleaseMask |
                              PointerMotionMask | KeyPressMask,
                              False,
                              wxTLWEventHandler,
                              (XtPointer)this );
    }
}

wxTopLevelWindowMotif::~wxTopLevelWindowMotif()
{
    SetMainWidget( (WXWidget)0 );
}

void wxTopLevelWindowMotif::Init()
{
    m_isShown = false;
}

bool wxTopLevelWindowMotif::Create( wxWindow *parent, wxWindowID id,
                                    const wxString& title,
                                    const wxPoint& pos,
                                    const wxSize& size,
                                    long style,
                                    const wxString& name )
{
    SetName(name);
    m_windowStyle = style;

    if ( parent )
        parent->AddChild(this);

    wxTopLevelWindows.Append(this);

    m_windowId = ( id > -1 ) ? id : NewControlId();
    // MBN: More backward compatible, but uglier
    m_font = wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT);
    m_inheritFont = true;

    bool retval = XmDoCreateTLW( parent, id, title, pos, size, style, name );

    if( !retval ) return false;

    // Intercept CLOSE messages from the window manager
    Widget shell = (Widget)GetShellWidget();
    Atom WM_DELETE_WINDOW = XmInternAtom( XtDisplay( shell ),
                                          "WM_DELETE_WINDOW", False );

    // Remove and add WM_DELETE_WINDOW so ours is only handler
    // This only appears to be necessary for wxDialog, but does not hurt
    // for wxFrame
    XmRemoveWMProtocols( shell, &WM_DELETE_WINDOW, 1 );
    XmAddWMProtocols( shell, &WM_DELETE_WINDOW, 1 );
    XmActivateWMProtocol( shell, WM_DELETE_WINDOW );

    // Modified Steve Hammes for Motif 2.0
#if (XmREVISION > 1 || XmVERSION > 1)
    XmAddWMProtocolCallback( shell, WM_DELETE_WINDOW,
                             (XtCallbackProc)wxCloseTLWCallback,
                             (XtPointer)this );
#elif XmREVISION == 1
    XmAddWMProtocolCallback( shell, WM_DELETE_WINDOW,
                             (XtCallbackProc)wxCloseTLWCallback,
                             (caddr_t)this );
#else
    XmAddWMProtocolCallback( shell, WM_DELETE_WINDOW,
                             (void (*)())wxCloseTLWCallback, (caddr_t)this );
#endif

    // This patch come from Torsten Liermann lier@lier1.muc.de
    if( XmIsMotifWMRunning( shell ) )
    {
        int decor = 0 ;
        if( !(m_windowStyle & wxNO_BORDER) )
            decor |= MWM_DECOR_BORDER;
        if( m_windowStyle & wxRESIZE_BORDER )
            decor |= MWM_DECOR_RESIZEH;
        if( m_windowStyle & wxSYSTEM_MENU )
            decor |= MWM_DECOR_MENU;
        if( ( m_windowStyle & wxCAPTION ) ||
            ( m_windowStyle & wxTINY_CAPTION) )
            decor |= MWM_DECOR_TITLE;
        if( m_windowStyle & wxRESIZE_BORDER )
            decor |= MWM_DECOR_BORDER;
        if( m_windowStyle & wxMINIMIZE_BOX )
            decor |= MWM_DECOR_MINIMIZE;
        if( m_windowStyle & wxMAXIMIZE_BOX )
            decor |= MWM_DECOR_MAXIMIZE;

        XtVaSetValues( shell,
                       XmNmwmDecorations, decor,
                       NULL );
    }
    else
    {
        // This allows non-Motif window managers to support at least the
        // no-decorations case.
        if( ( m_windowStyle & wxCAPTION ) != wxCAPTION )
            XtVaSetValues( shell,
                           XmNoverrideRedirect, True,
                           NULL );
    }

    XtAddEventHandler( (Widget)GetClientWidget(),
                       ButtonPressMask | ButtonReleaseMask |
                       PointerMotionMask | KeyPressMask,
                       False,
                       wxTLWEventHandler,
                       (XtPointer)this );

    return retval;
}

void wxTopLevelWindowMotif::DoGetPosition(int *x, int *y) const
{
    Widget top = (Widget) GetTopWidget();
    Window parent_window = XtWindow((Widget) top),
        next_parent   = XtWindow((Widget) top),
        root          = RootWindowOfScreen(XtScreen((Widget) top));

    // search for the parent that is child of ROOT, because the WM may
    // reparent twice and notify only the next parent (like FVWM)
    while (next_parent != root) {
        Window *theChildren; unsigned int n;
        parent_window = next_parent;
        XQueryTree(XtDisplay((Widget) top), parent_window, &root,
            &next_parent, &theChildren, &n);
        XFree(theChildren); // not needed
    }
    int xx, yy; unsigned int dummy;
    XGetGeometry(XtDisplay((Widget) top), parent_window, &root,
        &xx, &yy, &dummy, &dummy, &dummy, &dummy);
    if (x) *x = xx;
    if (y) *y = yy;
}

void wxTopLevelWindowMotif::Raise()
{
    Widget top = (Widget) GetTopWidget();
    Window parent_window = XtWindow( top ),
        next_parent   = XtWindow( top ),
        root          = RootWindowOfScreen( XtScreen( top ) );
    // search for the parent that is child of ROOT, because the WM may
    // reparent twice and notify only the next parent (like FVWM)
    while( next_parent != root )
    {
        Window *theChildren;
        unsigned int n;

        parent_window = next_parent;
        XQueryTree( XtDisplay( top ), parent_window, &root,
            &next_parent, &theChildren, &n );
        XFree( theChildren ); // not needed
    }
    XRaiseWindow( XtDisplay( top ), parent_window );
}

void wxTopLevelWindowMotif::Lower()
{
    Widget top = (Widget) GetTopWidget();
    Window parent_window = XtWindow( top ),
        next_parent   = XtWindow( top ),
        root          = RootWindowOfScreen( XtScreen( top ) );
    // search for the parent that is child of ROOT, because the WM may
    // reparent twice and notify only the next parent (like FVWM)
    while( next_parent != root )
    {
        Window *theChildren;
        unsigned int n;

        parent_window = next_parent;
        XQueryTree( XtDisplay( top ), parent_window, &root,
            &next_parent, &theChildren, &n );
        XFree( theChildren ); // not needed
    }
    XLowerWindow( XtDisplay( top ), parent_window );
}

static inline Widget GetShell( const wxTopLevelWindowMotif* tlw )
{
    Widget main = (Widget) tlw->GetMainWidget();
    if( !main ) return (Widget) NULL;

    return XtParent( main );
}

WXWidget wxTopLevelWindowMotif::GetShellWidget() const
{
    return (WXWidget) GetShell( this );
}

bool wxTopLevelWindowMotif::ShowFullScreen( bool WXUNUSED(show),
                                            long WXUNUSED(style) )
{
    // TODO, see wxGTK
    return false;
}

bool wxTopLevelWindowMotif::IsFullScreen() const
{
    // TODO, see wxGTK
    return false;
}

void wxTopLevelWindowMotif::Restore()
{
    Widget shell = GetShell( this );

    if( shell )
        XtVaSetValues( shell,
                       XmNiconic, False,
                       NULL );
}

void wxTopLevelWindowMotif::Iconize( bool iconize )
{
    Widget shell = GetShell( this );
    if( !shell ) return;

    if( !iconize )
        Show( true );

    XtVaSetValues( shell,
                   XmNiconic, (Boolean)iconize,
                   NULL );
}

bool wxTopLevelWindowMotif::IsIconized() const
{
    Widget shell = GetShell( this );

    if( !shell )
        return false;

    Boolean iconic;
    XtVaGetValues( shell,
                   XmNiconic, &iconic,
                   NULL );

    return (iconic == True);
}

void wxTopLevelWindowMotif::Maximize( bool maximize )
{
    Show( true );

    if( maximize )
        Restore();
}

bool wxTopLevelWindowMotif::IsMaximized() const
{
    return false;
}

void wxTopLevelWindowMotif::DoSetSizeHints( int minW, int minH,
                                            int maxW, int maxH,
                                            int incW, int incH )
{
    wxTopLevelWindowBase::DoSetSizeHints( minW, minH, maxW, maxH, incW, incH );

    int count = 0;
    Arg args[6];

    if( minW > -1 ) { XtSetArg( args[count], XmNminWidth,  minW ); ++count; }
    if( minH > -1 ) { XtSetArg( args[count], XmNminHeight, minH ); ++count; }
    if( maxW > -1 ) { XtSetArg( args[count], XmNmaxWidth,  maxW ); ++count; }
    if( maxH > -1 ) { XtSetArg( args[count], XmNmaxHeight, maxH ); ++count; }
    if( incW > -1 ) { XtSetArg( args[count], XmNwidthInc,  incW ); ++count; }
    if( incH > -1 ) { XtSetArg( args[count], XmNheightInc, incH ); ++count; }

    XtSetValues( (Widget)GetShellWidget(), args, count );
}

bool wxTopLevelWindowMotif::SetShape( const wxRegion& region )
{
    return wxDoSetShape( (Display*)GetXDisplay(),
                         XtWindow( (Widget)GetShellWidget() ),
                         region );
}

// ---------------------------------------------------------------------------
// Callback definition
// ---------------------------------------------------------------------------

// Handle a close event from the window manager
static void wxCloseTLWCallback( Widget WXUNUSED(widget), XtPointer client_data,
                                XmAnyCallbackStruct *WXUNUSED(cbs) )
{
    wxTopLevelWindowMotif* tlw = (wxTopLevelWindowMotif*)client_data;
    wxCloseEvent closeEvent( wxEVT_CLOSE_WINDOW, tlw->GetId() );
    closeEvent.SetEventObject( tlw );

    // May delete the dialog (with delayed deletion)
    tlw->HandleWindowEvent(closeEvent);
}

void wxTLWEventHandler( Widget wid,
                        XtPointer WXUNUSED(client_data),
                        XEvent* event,
                        Boolean* continueToDispatch)
{
    wxTopLevelWindowMotif* tlw =
        (wxTopLevelWindowMotif*)wxGetWindowFromTable( wid );

    if( tlw )
    {
        wxMouseEvent wxevent( wxEVT_NULL );

        if( wxTranslateMouseEvent( wxevent, tlw, wid, event ) )
        {
            wxevent.SetEventObject( tlw );
            wxevent.SetId( tlw->GetId() );
            tlw->HandleWindowEvent( wxevent );
        }
        else
        {
            // An attempt to implement OnCharHook by calling OnCharHook first;
            // if this returns true, set continueToDispatch to False
            // (don't continue processing).
            // Otherwise set it to True and call OnChar.
            wxKeyEvent keyEvent( wxEVT_CHAR );
            if( wxTranslateKeyEvent( keyEvent, tlw, wid, event ))
            {
                keyEvent.SetEventObject( tlw );
                keyEvent.SetId( tlw->GetId() );
                keyEvent.SetEventType( wxEVT_CHAR_HOOK );
                if( tlw->HandleWindowEvent( keyEvent ) )
                {
                    *continueToDispatch = False;
                    return;
                }
                else
                {
                    // For simplicity, OnKeyDown is the same as OnChar
                    // TODO: filter modifier key presses from OnChar
                    keyEvent.SetEventType( wxEVT_KEY_DOWN );

                    // Only process OnChar if OnKeyDown didn't swallow it
                    if( !tlw->HandleWindowEvent( keyEvent ) )
                    {
                        keyEvent.SetEventType( wxEVT_CHAR );
                        tlw->HandleWindowEvent( keyEvent );
                    }
                }
            }
        }
    }

    *continueToDispatch = True;
}
