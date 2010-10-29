/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/frame.cpp
// Purpose:     wxFrame
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - more than minimal functionality
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

#include "wx/frame.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/menu.h"
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/settings.h"
    #include "wx/dcclient.h"
    #include "wx/mdi.h"
    #include "wx/panel.h"
    #include "wx/log.h"
    #include "wx/toolbar.h"
    #include "wx/statusbr.h"
    #include "wx/menuitem.h"
#endif // WX_PRECOMP

#ifdef __WXUNIVERSAL__
    #include "wx/univ/theme.h"
    #include "wx/univ/colschem.h"
#endif // __WXUNIVERSAL__

#include <Event.h>
#include <Form.h>

// ----------------------------------------------------------------------------
// globals
// ----------------------------------------------------------------------------

#if wxUSE_MENUS_NATIVE
    extern wxMenu *wxCurrentPopupMenu;
#endif // wxUSE_MENUS_NATIVE

// ----------------------------------------------------------------------------
// event tables
// ----------------------------------------------------------------------------

BEGIN_EVENT_TABLE(wxFrame, wxFrameBase)
    EVT_PAINT(wxFrame::OnPaint)
END_EVENT_TABLE()

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxFrameStyle )

wxBEGIN_FLAGS( wxFrameStyle )
    // new style border flags, we put them first to
    // use them for streaming out
    wxFLAGS_MEMBER(wxBORDER_SIMPLE)
    wxFLAGS_MEMBER(wxBORDER_SUNKEN)
    wxFLAGS_MEMBER(wxBORDER_DOUBLE)
    wxFLAGS_MEMBER(wxBORDER_RAISED)
    wxFLAGS_MEMBER(wxBORDER_STATIC)
    wxFLAGS_MEMBER(wxBORDER_NONE)

    // old style border flags
    wxFLAGS_MEMBER(wxSIMPLE_BORDER)
    wxFLAGS_MEMBER(wxSUNKEN_BORDER)
    wxFLAGS_MEMBER(wxDOUBLE_BORDER)
    wxFLAGS_MEMBER(wxRAISED_BORDER)
    wxFLAGS_MEMBER(wxSTATIC_BORDER)
    wxFLAGS_MEMBER(wxBORDER)

    // standard window styles
    wxFLAGS_MEMBER(wxTAB_TRAVERSAL)
    wxFLAGS_MEMBER(wxCLIP_CHILDREN)
    wxFLAGS_MEMBER(wxTRANSPARENT_WINDOW)
    wxFLAGS_MEMBER(wxWANTS_CHARS)
    wxFLAGS_MEMBER(wxFULL_REPAINT_ON_RESIZE)
    wxFLAGS_MEMBER(wxALWAYS_SHOW_SB )
    wxFLAGS_MEMBER(wxVSCROLL)
    wxFLAGS_MEMBER(wxHSCROLL)

    // frame styles
    wxFLAGS_MEMBER(wxSTAY_ON_TOP)
    wxFLAGS_MEMBER(wxCAPTION)
#if WXWIN_COMPATIBILITY_2_6
    wxFLAGS_MEMBER(wxTHICK_FRAME)
#endif // WXWIN_COMPATIBILITY_2_6
    wxFLAGS_MEMBER(wxSYSTEM_MENU)
    wxFLAGS_MEMBER(wxRESIZE_BORDER)
#if WXWIN_COMPATIBILITY_2_6
    wxFLAGS_MEMBER(wxRESIZE_BOX)
#endif // WXWIN_COMPATIBILITY_2_6
    wxFLAGS_MEMBER(wxCLOSE_BOX)
    wxFLAGS_MEMBER(wxMAXIMIZE_BOX)
    wxFLAGS_MEMBER(wxMINIMIZE_BOX)

    wxFLAGS_MEMBER(wxFRAME_TOOL_WINDOW)
    wxFLAGS_MEMBER(wxFRAME_FLOAT_ON_PARENT)

    wxFLAGS_MEMBER(wxFRAME_SHAPED)

wxEND_FLAGS( wxFrameStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxFrame, wxTopLevelWindow,"wx/frame.h")

wxBEGIN_PROPERTIES_TABLE(wxFrame)
    wxEVENT_PROPERTY( Menu , wxEVT_COMMAND_MENU_SELECTED , wxCommandEvent)

    wxPROPERTY( Title,wxString, SetTitle, GetTitle, wxString() , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxFrameStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
    wxPROPERTY( MenuBar , wxMenuBar * , SetMenuBar , GetMenuBar , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxFrame)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_6( wxFrame , wxWindow* , Parent , wxWindowID , Id , wxString , Title , wxPoint , Position , wxSize , Size , long , WindowStyle)

#else
IMPLEMENT_DYNAMIC_CLASS(wxFrame, wxTopLevelWindow)
#endif

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// creation/destruction
// ----------------------------------------------------------------------------

void wxFrame::Init()
{
}

bool wxFrame::Create(wxWindow *parent,
                     wxWindowID id,
                     const wxString& title,
                     const wxPoint& pos,
                     const wxSize& size,
                     long style,
                     const wxString& name)
{
    if ( !wxTopLevelWindow::Create(parent, id, title, pos, size, style, name) )
        return false;

    return true;
}

wxFrame::~wxFrame()
{
}

// ----------------------------------------------------------------------------
// wxFrame client size calculations
// ----------------------------------------------------------------------------

void wxFrame::DoSetClientSize(int width, int height)
{
}

// Get size *available for subwindows* i.e. excluding menu bar, toolbar etc.
void wxFrame::DoGetClientSize(int *x, int *y) const
{
    wxSize size = GetSize();
    wxPoint pos = GetClientAreaOrigin();
    *x = size.x - pos.x - 1;
    *y = size.y - pos.y - 1;
}

// ----------------------------------------------------------------------------
// wxFrame: various geometry-related functions
// ----------------------------------------------------------------------------

void wxFrame::Raise()
{
}

#if wxUSE_MENUS_NATIVE

void wxFrame::InternalSetMenuBar()
{
}

bool wxFrame::HandleMenuOpen()
{
    if(!m_frameMenuBar)
        return false;

    m_frameMenuBar->LoadMenu();
    return true;
}

bool wxFrame::HandleMenuSelect(WXEVENTPTR event)
{
    const EventType *palmEvent = (EventType *)event;
    const int ItemID = palmEvent->data.menu.itemID;

    if (!m_frameMenuBar)
        return false;

    const int item = m_frameMenuBar->ProcessCommand(ItemID);
    if (item==-1)
        return false;

    wxCommandEvent commandEvent(wxEVT_COMMAND_MENU_SELECTED, item);
    commandEvent.SetEventObject(this);

    HandleWindowEvent(commandEvent);
    return true;
}

#endif // wxUSE_MENUS_NATIVE

void wxFrame::OnPaint(wxPaintEvent& event)
{
#if wxUSE_STATUSBAR
    if( m_frameStatusBar )
        m_frameStatusBar->DrawStatusBar();
#endif // wxUSE_STATUSBAR
}

// Pass true to show full screen, false to restore.
bool wxFrame::ShowFullScreen(bool show, long style)
{
    return false;
}

// ----------------------------------------------------------------------------
// tool/status bar stuff
// ----------------------------------------------------------------------------

#if wxUSE_TOOLBAR

wxToolBar* wxFrame::CreateToolBar(long style, wxWindowID id, const wxString& name)
{
    return NULL;
}

void wxFrame::PositionToolBar()
{
}

#endif // wxUSE_TOOLBAR

// ----------------------------------------------------------------------------
// frame state (iconized/maximized/...)
// ----------------------------------------------------------------------------

// propagate our state change to all child frames: this allows us to emulate X
// Windows behaviour where child frames float independently of the parent one
// on the desktop, but are iconized/restored with it
void wxFrame::IconizeChildFrames(bool bIconize)
{
}

// ----------------------------------------------------------------------------
// wxFrame size management: we exclude the areas taken by menu/status/toolbars
// from the client area, so the client area is what's really available for the
// frame contents
// ----------------------------------------------------------------------------

// get the origin of the client area in the client coordinates
wxPoint wxFrame::GetClientAreaOrigin() const
{
    // there is no API to get client area but we know
    // it starts after titlebar and 1 pixel of form border
    Coord maxY = wxSystemSettings::GetMetric(wxSYS_SCREEN_Y),
          X = 1,
          Y = 0;
    while ( Y < maxY )
    {
        if(!FrmPointInTitle((FormType*)GetForm(),X,Y))
            return wxPoint(X,Y+1);
        Y++;
    }

    return wxPoint(X,0);
}
