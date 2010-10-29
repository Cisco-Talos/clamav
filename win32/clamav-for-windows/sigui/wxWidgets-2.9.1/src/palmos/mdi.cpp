/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/mdi.cpp
// Purpose:     MDI classes for wx
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
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

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_MDI

#include "wx/mdi.h"

#ifndef WX_PRECOMP
    #include "wx/frame.h"
    #include "wx/menu.h"
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/statusbr.h"
    #include "wx/settings.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/toolbar.h"
#endif

#include "wx/palmos/private.h"

#if wxUSE_STATUSBAR && wxUSE_NATIVE_STATUSBAR
    #include "wx/palmos/statbr95.h"
#endif

#include <string.h>

// ---------------------------------------------------------------------------
// global variables
// ---------------------------------------------------------------------------

extern wxMenu *wxCurrentPopupMenu;

extern const wxChar *wxMDIFrameClassName;   // from app.cpp
extern const wxChar *wxMDIChildFrameClassName;
extern const wxChar *wxMDIChildFrameClassNameNoRedraw;
extern void wxAssociateWinWithHandle(HWND hWnd, wxWindow *win);
extern void wxRemoveHandleAssociation(wxWindow *win);


// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

static const int IDM_WINDOWTILE  = 4001;
static const int IDM_WINDOWTILEHOR  = 4001;
static const int IDM_WINDOWCASCADE = 4002;
static const int IDM_WINDOWICONS = 4003;
static const int IDM_WINDOWNEXT = 4004;
static const int IDM_WINDOWTILEVERT = 4005;
static const int IDM_WINDOWPREV = 4006;

// This range gives a maximum of 500 MDI children. Should be enough :-)
static const int wxFIRST_MDI_CHILD = 4100;
static const int wxLAST_MDI_CHILD = 4600;

// Status border dimensions
static const int wxTHICK_LINE_BORDER = 3;
static const int wxTHICK_LINE_WIDTH  = 1;

// ---------------------------------------------------------------------------
// private functions
// ---------------------------------------------------------------------------

// set the MDI menus (by sending the WM_MDISETMENU message) and update the menu
// of the parent of win (which is supposed to be the MDI client window)
static void MDISetMenu(wxWindow *win, HMENU hmenuFrame, HMENU hmenuWindow);

// insert the window menu (subMenu) into menu just before "Help" submenu or at
// the very end if not found
static void InsertWindowMenu(wxWindow *win, WXHMENU menu, HMENU subMenu);

// Remove the window menu
static void RemoveWindowMenu(wxWindow *win, WXHMENU menu);

// is this an id of an MDI child?
inline bool IsMdiCommandId(int id)
{
    return (id >= wxFIRST_MDI_CHILD) && (id <= wxLAST_MDI_CHILD);
}

// unpack the parameters of WM_MDIACTIVATE message
static void UnpackMDIActivate(WXWPARAM wParam, WXLPARAM lParam,
                              WXWORD *activate, WXHWND *hwndAct, WXHWND *hwndDeact);

// return the HMENU of the MDI menu
static inline HMENU GetMDIWindowMenu(wxMDIParentFrame *frame)
{
    wxMenu *menu = frame->GetWindowMenu();
    return menu ? GetHmenuOf(menu) : 0;
}

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// wxWin macros
// ---------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxMDIParentFrame, wxFrame)
IMPLEMENT_DYNAMIC_CLASS(wxMDIChildFrame, wxFrame)
IMPLEMENT_DYNAMIC_CLASS(wxMDIClientWindow, wxWindow)

BEGIN_EVENT_TABLE(wxMDIParentFrame, wxFrame)
    EVT_SIZE(wxMDIParentFrame::OnSize)
END_EVENT_TABLE()

BEGIN_EVENT_TABLE(wxMDIChildFrame, wxFrame)
    EVT_IDLE(wxMDIChildFrame::OnIdle)
END_EVENT_TABLE()

BEGIN_EVENT_TABLE(wxMDIClientWindow, wxWindow)
    EVT_SCROLL(wxMDIClientWindow::OnScroll)
END_EVENT_TABLE()

// ===========================================================================
// wxMDIParentFrame: the frame which contains the client window which manages
// the children
// ===========================================================================

wxMDIParentFrame::wxMDIParentFrame()
{
}

bool wxMDIParentFrame::Create(wxWindow *parent,
                              wxWindowID id,
                              const wxString& title,
                              const wxPoint& pos,
                              const wxSize& size,
                              long style,
                              const wxString& name)
{
  return false;
}

wxMDIParentFrame::~wxMDIParentFrame()
{
}

#if wxUSE_MENUS_NATIVE

void wxMDIParentFrame::InternalSetMenuBar()
{
}

#endif // wxUSE_MENUS_NATIVE

void wxMDIParentFrame::SetWindowMenu(wxMenu* menu)
{
}

void wxMDIParentFrame::OnSize(wxSizeEvent&)
{
}

// Returns the active MDI child window
wxMDIChildFrame *wxMDIParentFrame::GetActiveChild() const
{
    return NULL;
}

// Create the client window class (don't Create the window, just return a new
// class)
wxMDIClientWindow *wxMDIParentFrame::OnCreateClient()
{
    return new wxMDIClientWindow;
}

WXHICON wxMDIParentFrame::GetDefaultIcon() const
{
    // we don't have any standard icons (any more)
    return (WXHICON)0;
}

// ---------------------------------------------------------------------------
// MDI operations
// ---------------------------------------------------------------------------

void wxMDIParentFrame::Cascade()
{
}

void wxMDIParentFrame::Tile()
{
}

void wxMDIParentFrame::ArrangeIcons()
{
}

void wxMDIParentFrame::ActivateNext()
{
}

void wxMDIParentFrame::ActivatePrevious()
{
}

// ---------------------------------------------------------------------------
// the MDI parent frame window proc
// ---------------------------------------------------------------------------

WXLRESULT wxMDIParentFrame::MSWWindowProc(WXUINT message,
                                     WXWPARAM wParam,
                                     WXLPARAM lParam)
{
    return 0;
}

WXLRESULT wxMDIParentFrame::MSWDefWindowProc(WXUINT message,
                                        WXWPARAM wParam,
                                        WXLPARAM lParam)
{
    return 0;
}

bool wxMDIParentFrame::MSWTranslateMessage(WXMSG* msg)
{
    return false;
}

// ===========================================================================
// wxMDIChildFrame
// ===========================================================================

void wxMDIChildFrame::Init()
{
}

bool wxMDIChildFrame::Create(wxMDIParentFrame *parent,
                             wxWindowID id,
                             const wxString& title,
                             const wxPoint& pos,
                             const wxSize& size,
                             long style,
                             const wxString& name)
{
  return false;
}

wxMDIChildFrame::~wxMDIChildFrame()
{
}

// Set the client size (i.e. leave the calculation of borders etc.
// to wxWidgets)
void wxMDIChildFrame::DoSetClientSize(int width, int height)
{
}

void wxMDIChildFrame::DoGetPosition(int *x, int *y) const
{
}

void wxMDIChildFrame::InternalSetMenuBar()
{
}

WXHICON wxMDIChildFrame::GetDefaultIcon() const
{
    // we don't have any standard icons (any more)
    return (WXHICON)0;
}

// ---------------------------------------------------------------------------
// MDI operations
// ---------------------------------------------------------------------------

void wxMDIChildFrame::Maximize(bool maximize)
{
}

void wxMDIChildFrame::Restore()
{
}

void wxMDIChildFrame::Activate()
{
}

// ---------------------------------------------------------------------------
// MDI window proc and message handlers
// ---------------------------------------------------------------------------

WXLRESULT wxMDIChildFrame::MSWWindowProc(WXUINT message,
                                    WXWPARAM wParam,
                                    WXLPARAM lParam)
{
    return 0;
}

bool wxMDIChildFrame::HandleMDIActivate(long WXUNUSED(activate),
                                        WXHWND hwndAct,
                                        WXHWND hwndDeact)
{
    return false;
}

bool wxMDIChildFrame::HandleWindowPosChanging(void *pos)
{
    return false;
}

// ---------------------------------------------------------------------------
// MDI specific message translation/preprocessing
// ---------------------------------------------------------------------------

WXLRESULT wxMDIChildFrame::MSWDefWindowProc(WXUINT message, WXWPARAM wParam, WXLPARAM lParam)
{
    return 0;
}

bool wxMDIChildFrame::MSWTranslateMessage(WXMSG* msg)
{
    return false;
}

// ---------------------------------------------------------------------------
// misc
// ---------------------------------------------------------------------------

void wxMDIChildFrame::MSWDestroyWindow()
{
}

// Change the client window's extended style so we don't get a client edge
// style when a child is maximised (a double border looks silly.)
bool wxMDIChildFrame::ResetWindowStyle(void *vrect)
{
    return false;
}

// ===========================================================================
// wxMDIClientWindow: the window of predefined (by Windows) class which
// contains the child frames
// ===========================================================================

bool wxMDIClientWindow::CreateClient(wxMDIParentFrame *parent, long style)
{
    return false;
}

// Explicitly call default scroll behaviour
void wxMDIClientWindow::OnScroll(wxScrollEvent& event)
{
    event.Skip();
}

void wxMDIClientWindow::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
}

void wxMDIChildFrame::OnIdle(wxIdleEvent& event)
{
    event.Skip();
}

// ---------------------------------------------------------------------------
// non member functions
// ---------------------------------------------------------------------------

static void MDISetMenu(wxWindow *win, HMENU hmenuFrame, HMENU hmenuWindow)
{
}

static void InsertWindowMenu(wxWindow *win, WXHMENU menu, HMENU subMenu)
{
}

static void RemoveWindowMenu(wxWindow *win, WXHMENU menu)
{
}

static void UnpackMDIActivate(WXWPARAM wParam, WXLPARAM lParam,
                              WXWORD *activate, WXHWND *hwndAct, WXHWND *hwndDeact)
{
}

#endif // wxUSE_MDI
