/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/frame.cpp
// Purpose:     wxFrame
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
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

#include "wx/frame.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/menu.h"
    #include "wx/icon.h"
    #include "wx/settings.h"
    #include "wx/toolbar.h"
    #include "wx/statusbr.h"
#endif

#ifdef __VMS__
    #pragma message disable nosimpint
#endif

#if defined(__ultrix) || defined(__sgi)
    #include <Xm/Frame.h>
#endif

#include <Xm/Xm.h>
#include <X11/Shell.h>
#include <X11/Core.h>
#if XmVersion >= 1002
    #include <Xm/XmAll.h>
#else
    #include <Xm/Frame.h>
#endif
#include <Xm/MwmUtil.h>
#include <Xm/BulletinB.h>
#include <Xm/Form.h>
#include <Xm/MainW.h>
#include <Xm/RowColumn.h>
#include <Xm/Label.h>
#include <Xm/AtomMgr.h>
#include <Xm/LabelG.h>
#include <Xm/Frame.h>
#if   XmVersion > 1000
    #include <Xm/Protocols.h>
#endif

#ifdef __VMS__
    #pragma message enable nosimpint
#endif

#include "wx/motif/private.h"
#include "wx/unix/utilsx11.h"

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

static void wxFrameMapProc(Widget frameShell, XtPointer clientData,
                           XCrossingEvent* event);

// ----------------------------------------------------------------------------
// globals
// ----------------------------------------------------------------------------

extern wxList wxModelessWindows;

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

BEGIN_EVENT_TABLE(wxFrame, wxFrameBase)
    EVT_ACTIVATE(wxFrame::OnActivate)
    EVT_SYS_COLOUR_CHANGED(wxFrame::OnSysColourChanged)
END_EVENT_TABLE()

IMPLEMENT_DYNAMIC_CLASS(wxFrame, wxTopLevelWindow)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// frame construction
// ----------------------------------------------------------------------------

void wxFrame::Init()
{
    m_iconized = false;

    //// Motif-specific
    m_frameShell = (WXWidget) NULL;
    m_mainWidget = (WXWidget) NULL;
    m_workArea = (WXWidget) NULL;
    m_clientArea = (WXWidget) NULL;
}

bool wxFrame::Create(wxWindow *parent,
                     wxWindowID id,
                     const wxString& title,
                     const wxPoint& pos,
                     const wxSize& size,
                     long style,
                     const wxString& name)
{
    if( !wxTopLevelWindow::Create( parent, id, title, pos, size, style,
                                   name ) )
        return false;

    int x = pos.x, y = pos.y;
    int width = size.x, height = size.y;

    // Set reasonable values for position and size if defaults have been
    // requested
    //
    // MB TODO: something better than these arbitrary values ?
    // VZ       should use X resources for this...
    if ( width == -1 )
        width = 400;
    if ( height == -1 )
        height = 400;

    int displayW, displayH;
    wxDisplaySize( &displayW, &displayH );

    if ( x == -1 )
    {
        x = (displayW - width) / 2;
        if (x < 10) x = 10;
    }
    if ( y == -1 )
    {
        y = (displayH - height) / 2;
        if (y < 10) y = 10;
    }

    SetTitle( title );

    wxLogTrace(wxTRACE_Messages,
               "Created frame (0x%p) with work area 0x%p and client "
               "area 0x%p", m_mainWidget, m_workArea, m_clientArea);

    XtAddEventHandler((Widget) m_clientArea, ExposureMask,False,
        wxUniversalRepaintProc, (XtPointer) this);

    if (x > -1)
        XtVaSetValues((Widget) m_frameShell, XmNx, x, NULL);
    if (y > -1)
        XtVaSetValues((Widget) m_frameShell, XmNy, y, NULL);
    if (width > -1)
        XtVaSetValues((Widget) m_frameShell, XmNwidth, width, NULL);
    if (height > -1)
        XtVaSetValues((Widget) m_frameShell, XmNheight, height, NULL);

    PostCreation();
    PreResize();

    wxSize newSize(width, height);
    wxSizeEvent sizeEvent(newSize, GetId());
    sizeEvent.SetEventObject(this);

    HandleWindowEvent(sizeEvent);

    return true;
}

bool wxFrame::XmDoCreateTLW(wxWindow* WXUNUSED(parent),
                            wxWindowID WXUNUSED(id),
                            const wxString& WXUNUSED(title),
                            const wxPoint& WXUNUSED(pos),
                            const wxSize& WXUNUSED(size),
                            long style,
                            const wxString& name)
{
    Widget frameShell;

    frameShell = XtCreatePopupShell( name, topLevelShellWidgetClass,
                                     (Widget)wxTheApp->GetTopLevelWidget(),
                                     NULL, 0 );

    XtVaSetValues(frameShell,
        // Allows menu to resize
        XmNallowShellResize, True,
        XmNdeleteResponse, XmDO_NOTHING,
        XmNmappedWhenManaged, False,
        XmNiconic, (style & wxICONIZE) ? True : False,
        NULL);

    m_frameShell = (WXWidget)frameShell;

    m_mainWidget = (WXWidget) XtVaCreateManagedWidget("main_window",
        xmMainWindowWidgetClass, frameShell,
        XmNresizePolicy, XmRESIZE_NONE,
        NULL);

    m_workArea = (WXWidget) XtVaCreateWidget("form",
        xmFormWidgetClass, (Widget) m_mainWidget,
        XmNresizePolicy, XmRESIZE_NONE,
        NULL);

    m_clientArea = (WXWidget) XtVaCreateWidget("client",
        xmBulletinBoardWidgetClass, (Widget) m_workArea,
        XmNmarginWidth, 0,
        XmNmarginHeight, 0,
        XmNrightAttachment, XmATTACH_FORM,
        XmNleftAttachment, XmATTACH_FORM,
        XmNtopAttachment, XmATTACH_FORM,
        XmNbottomAttachment, XmATTACH_FORM,
        NULL);

    XtVaSetValues((Widget) m_mainWidget,
        XmNworkWindow, (Widget) m_workArea,
        NULL);

    XtManageChild((Widget) m_clientArea);
    XtManageChild((Widget) m_workArea);

    XtTranslations ptr = XtParseTranslationTable( "<Configure>: resize()" );
    XtOverrideTranslations( (Widget) m_workArea, ptr );
    XtFree( (char *)ptr );

    /* Part of show-&-hide fix */
    XtAddEventHandler( frameShell, StructureNotifyMask,
                       False, (XtEventHandler)wxFrameMapProc,
                       (XtPointer)this );

    XtRealizeWidget(frameShell);

    wxAddWindowToTable( (Widget)m_workArea, this);
    wxAddWindowToTable( (Widget)m_clientArea, this);

    wxModelessWindows.Append( this );

    return true;
}

wxFrame::~wxFrame()
{
    SendDestroyEvent();

    if (m_clientArea)
    {
      XtRemoveEventHandler((Widget) m_clientArea, ExposureMask, False,
          wxUniversalRepaintProc, (XtPointer) this);
    }

    if (GetMainWidget())
        Show(false);

    if (m_frameMenuBar)
    {
        m_frameMenuBar->DestroyMenuBar();
        wxDELETE(m_frameMenuBar);
    }

    wxDELETE(m_frameStatusBar);

    PreDestroy();

    Widget frameShell = (Widget)GetShellWidget();

    if( frameShell )
        XtRemoveEventHandler( frameShell, StructureNotifyMask,
                              False, (XtEventHandler)wxFrameMapProc,
                              (XtPointer)this );

    if( m_clientArea )
    {
        wxDeleteWindowFromTable( (Widget)m_clientArea );
        XtDestroyWidget( (Widget)m_clientArea );
    }

    if( m_workArea )
    {
        XtVaSetValues( (Widget)m_mainWidget,
                       XmNworkWindow, (Widget)NULL,
                       NULL );

        wxDeleteWindowFromTable( (Widget)m_workArea );
        XtDestroyWidget( (Widget)m_workArea );
    }

    if( m_mainWidget )
        XtDestroyWidget( (Widget)m_mainWidget );

    if( frameShell )
        XtDestroyWidget( frameShell );
}

// Get size *available for subwindows* i.e. excluding menu bar, toolbar etc.
void wxFrame::DoGetClientSize(int *x, int *y) const
{
    Dimension xx, yy;
    XtVaGetValues((Widget) m_workArea, XmNwidth, &xx, XmNheight, &yy, NULL);

    if (m_frameStatusBar)
    {
        int sbw, sbh;
        m_frameStatusBar->GetSize(& sbw, & sbh);
        yy = (Dimension)(yy - sbh);
    }
#if wxUSE_TOOLBAR
    if (m_frameToolBar)
    {
        int tbw, tbh;
        m_frameToolBar->GetSize(& tbw, & tbh);
        if (m_frameToolBar->GetWindowStyleFlag() & wxTB_VERTICAL)
            xx = (Dimension)(xx - tbw);
        else
            yy = (Dimension)(yy - tbh);
    }
#endif // wxUSE_TOOLBAR

//CE found a call here with NULL y pointer
    if (x)
        *x = xx;
    if (y)
        *y = yy;
}

// Set the client size (i.e. leave the calculation of borders etc.
// to wxWidgets)
void wxFrame::DoSetClientSize(int width, int height)
{
    // Calculate how large the new main window should be
    // by finding the difference between the client area and the
    // main window area, and adding on to the new client area
    if (width > -1)
        XtVaSetValues((Widget) m_workArea, XmNwidth, width, NULL);

    if (height > -1)
    {
        if (m_frameStatusBar)
        {
            int sbw, sbh;
            m_frameStatusBar->GetSize(& sbw, & sbh);
            height += sbh;
        }
#if wxUSE_TOOLBAR
        if (m_frameToolBar)
        {
            int tbw, tbh;
            m_frameToolBar->GetSize(& tbw, & tbh);
            if (m_frameToolBar->GetWindowStyleFlag() & wxTB_VERTICAL)
                width += tbw;
            else
                height += tbh;
        }
#endif // wxUSE_TOOLBAR

        XtVaSetValues((Widget) m_workArea, XmNheight, height, NULL);
    }
    PreResize();

    wxSize newSize(width, height);
    wxSizeEvent sizeEvent(newSize, GetId());
    sizeEvent.SetEventObject(this);

    HandleWindowEvent(sizeEvent);

}

void wxFrame::DoGetSize(int *width, int *height) const
{
    if (!m_frameShell)
    {
        *width = -1; *height = -1;
        return;
    }

    Dimension xx, yy;
    XtVaGetValues((Widget) m_frameShell, XmNwidth, &xx, XmNheight, &yy, NULL);
    *width = xx; *height = yy;
}

void wxFrame::DoSetSize(int x, int y, int width, int height, int WXUNUSED(sizeFlags))
{
    if (x > -1)
        XtVaSetValues((Widget) m_frameShell, XmNx, x, NULL);
    if (y > -1)
        XtVaSetValues((Widget) m_frameShell, XmNy, y, NULL);
    if (width > -1)
        XtVaSetValues((Widget) m_mainWidget, XmNwidth, width, NULL);
    if (height > -1)
        XtVaSetValues((Widget) m_mainWidget, XmNheight, height, NULL);

    if (!(height == -1 && width == -1))
    {
        PreResize();
    }
}

bool wxFrame::Show( bool show )
{
    if( !wxWindowBase::Show( show ) )
        return false;

    m_isShown = show;

    Widget shell = (Widget)GetShellWidget();
    if (!shell)
        return wxWindow::Show(show);

    SetVisibleStatus(show);
    if (show)
    {
        XtPopup(shell, XtGrabNone);
    }
    else
    {
        XtPopdown(shell);
    }

    return true;
}

void wxFrame::SetTitle(const wxString& title)
{
    wxString oldTitle = GetTitle();
    if( title == oldTitle )
        return;

    wxTopLevelWindow::SetTitle( title );

    if( !title.empty() )
        XtVaSetValues( (Widget)m_frameShell,
                       XmNtitle, (const char*)title.mb_str(),
                       XmNiconName, (const char*)title.mb_str(),
                       NULL );
}

void wxFrame::DoSetIcon(const wxIcon& icon)
{
    if (!m_frameShell)
        return;

    if (!icon.Ok() || !icon.GetDrawable())
        return;

    XtVaSetValues((Widget) m_frameShell,
                  XtNiconPixmap, icon.GetDrawable(),
                  NULL);
}

void wxFrame::SetIcons(const wxIconBundle& icons)
{
    wxFrameBase::SetIcons( icons );

    if (!m_frameShell)
        return;

    DoSetIcon( m_icons.GetIcon( -1 ) );
    wxSetIconsX11(GetXDisplay(),
                  (WXWindow) XtWindow( (Widget) m_frameShell ), icons);
}

void wxFrame::PositionStatusBar()
{
    if (!m_frameStatusBar)
        return;

    int w, h;
    GetClientSize(&w, &h);
    int sw, sh;
    m_frameStatusBar->GetSize(&sw, &sh);

    // Since we wish the status bar to be directly under the client area,
    // we use the adjusted sizes without using wxSIZE_NO_ADJUSTMENTS.
    m_frameStatusBar->SetSize(0, h, w, sh);
}

WXWidget wxFrame::GetMenuBarWidget() const
{
    if (GetMenuBar())
        return GetMenuBar()->GetMainWidget();
    else
        return (WXWidget) NULL;
}

void wxFrame::SetMenuBar(wxMenuBar *menuBar)
{
    if (!menuBar)
    {
        m_frameMenuBar = NULL;
        return;
    }

    // Currently can't set it twice
    //    wxASSERT_MSG( (m_frameMenuBar == NULL), "Cannot set the menubar more than once");

    if (m_frameMenuBar)
    {
        m_frameMenuBar->DestroyMenuBar();
        delete m_frameMenuBar;
    }

    m_frameMenuBar = menuBar;
    m_frameMenuBar->CreateMenuBar(this);
}

// Responds to colour changes, and passes event on to children.
void wxFrame::OnSysColourChanged(wxSysColourChangedEvent& event)
{
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_APPWORKSPACE));
    Refresh();

    if ( m_frameStatusBar )
    {
        wxSysColourChangedEvent event2;
        event2.SetEventObject( m_frameStatusBar );
        m_frameStatusBar->HandleWindowEvent(event2);
    }

    // Propagate the event to the non-top-level children
    wxWindow::OnSysColourChanged(event);
}

// Default activation behaviour - set the focus for the first child
// subwindow found.
void wxFrame::OnActivate(wxActivateEvent& event)
{
    if (!event.GetActive())
        return;

    for(wxWindowList::compatibility_iterator node = GetChildren().GetFirst(); node;
        node = node->GetNext())
    {
        // Find a child that's a subwindow, but not a dialog box.
        wxWindow *child = node->GetData();
        if (!child->IsTopLevel())
        {
            child->SetFocus();
            return;
        }
    }
}

#if wxUSE_TOOLBAR

wxToolBar* wxFrame::CreateToolBar(long style,
                                  wxWindowID id,
                                  const wxString& name)
{
    if ( wxFrameBase::CreateToolBar(style, id, name) )
    {
        PositionToolBar();
    }

    return m_frameToolBar;
}

void wxFrame::SetToolBar(wxToolBar *toolbar)
{
    wxFrameBase::SetToolBar(toolbar);
    SendSizeEvent();
}

void wxFrame::PositionToolBar()
{
    wxToolBar* tb = GetToolBar();
    if (tb)
    {
        int cw, ch;
        GetClientSize(& cw, &ch);

        int tw, th;
        tb->GetSize(& tw, & th);

        if (tb->GetWindowStyleFlag() & wxTB_VERTICAL)
        {
            // Use the 'real' position. wxSIZE_NO_ADJUSTMENTS
            // means, pretend we don't have toolbar/status bar, so we
            // have the original client size.
            th = ch + th;
        }
        else
        {
            // Use the 'real' position
            tw = cw;
        }

        tb->SetSize(0, 0, -1, -1, wxSIZE_NO_ADJUSTMENTS);
    }
}
#endif // wxUSE_TOOLBAR

//// Motif-specific
bool wxFrame::PreResize()
{
#if wxUSE_TOOLBAR
    PositionToolBar();
#endif // wxUSE_TOOLBAR

#if wxUSE_STATUSBAR
    PositionStatusBar();
#endif // wxUSE_STATUSBAR

    return true;
}

WXWidget wxFrame::GetClientWidget() const
{
    return m_clientArea;
}

void wxFrame::ChangeFont(bool WXUNUSED(keepOriginalSize))
{
    // TODO
}

void wxFrame::ChangeBackgroundColour()
{
    if (GetClientWidget())
        wxDoChangeBackgroundColour(GetClientWidget(), m_backgroundColour);
}

void wxFrame::ChangeForegroundColour()
{
    if (GetClientWidget())
        wxDoChangeForegroundColour(GetClientWidget(), m_foregroundColour);
}

/* MATTEW: Used to insure that hide-&-show within an event cycle works */
static void wxFrameMapProc( Widget frameShell, XtPointer clientData,
                            XCrossingEvent* event )
{
    wxFrame *tli = (wxFrame*)clientData;

    XEvent *e = (XEvent *)event;

    if( e->xany.type == MapNotify )
    {
        // Iconize fix
        XtVaSetValues( frameShell, XmNiconic, (Boolean)False, NULL );
        if( !tli->GetVisibleStatus() )
        {
            /* We really wanted this to be hidden! */
            XtUnmapWidget( frameShell );
        }
    }
    else if( e->xany.type == UnmapNotify )
        // Iconize fix
        XtVaSetValues( frameShell, XmNiconic, (Boolean)True, NULL );
}
