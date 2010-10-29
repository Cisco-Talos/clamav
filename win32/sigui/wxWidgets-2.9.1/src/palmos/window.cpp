/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/window.cpp
// Purpose:     wxWindow
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - more than minimal functionality
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
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

#include "wx/window.h"

#ifndef WX_PRECOMP
    #include "wx/accel.h"
    #include "wx/menu.h"
    #include "wx/dc.h"
    #include "wx/dcclient.h"
    #include "wx/dcmemory.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/layout.h"
    #include "wx/dialog.h"
    #include "wx/frame.h"
    #include "wx/listbox.h"
    #include "wx/button.h"
    #include "wx/msgdlg.h"
    #include "wx/settings.h"
    #include "wx/statbox.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/textctrl.h"
    #include "wx/menuitem.h"
    #include "wx/module.h"
#endif

#if wxUSE_OWNER_DRAWN && !defined(__WXUNIVERSAL__)
    #include "wx/ownerdrw.h"
#endif

#if wxUSE_DRAG_AND_DROP
    #include "wx/dnd.h"
#endif

#if wxUSE_ACCESSIBILITY
    #include "wx/access.h"
#endif

#if wxUSE_TOOLTIPS
    #include "wx/tooltip.h"
#endif

#if wxUSE_CARET
    #include "wx/caret.h"
#endif // wxUSE_CARET

#if wxUSE_SPINCTRL
    #include "wx/spinctrl.h"
#endif // wxUSE_SPINCTRL

#include "wx/notebook.h"
#include "wx/listctrl.h"

#ifndef __WXUNIVERSAL__
#include <Window.h>

// ---------------------------------------------------------------------------
// global variables
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// private functions
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// event tables
// ---------------------------------------------------------------------------

// in wxUniv/Palm this class is abstract because it doesn't have DoPopupMenu()
// method
#ifdef __WXUNIVERSAL__
    IMPLEMENT_ABSTRACT_CLASS(wxWindowPalm, wxWindowBase)
#else // __WXPalm__
#if wxUSE_EXTENDED_RTTI

// windows that are created from a parent window during its Create method, eg. spin controls in a calendar controls
// must never been streamed out separately otherwise chaos occurs. Right now easiest is to test for negative ids, as
// windows with negative ids never can be recreated anyway

bool wxWindowStreamingCallback( const wxObject *object, wxWriter * , wxPersister * , wxxVariantArray & )
{
    return false;
}

IMPLEMENT_DYNAMIC_CLASS_XTI_CALLBACK(wxWindow, wxWindowBase,"wx/window.h", wxWindowStreamingCallback)

// make wxWindowList known before the property is used

wxCOLLECTION_TYPE_INFO( wxWindow* , wxWindowList ) ;

template<> void wxCollectionToVariantArray( wxWindowList const &theList, wxxVariantArray &value)
{
    wxListCollectionToVariantArray<wxWindowList::compatibility_iterator>( theList , value ) ;
}

WX_DEFINE_FLAGS( wxWindowStyle )

wxBEGIN_FLAGS( wxWindowStyle )
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

wxEND_FLAGS( wxWindowStyle )

wxBEGIN_PROPERTIES_TABLE(wxWindow)
    wxEVENT_PROPERTY( Close , wxEVT_CLOSE_WINDOW , wxCloseEvent)
    wxEVENT_PROPERTY( Create , wxEVT_CREATE , wxWindowCreateEvent )
    wxEVENT_PROPERTY( Destroy , wxEVT_DESTROY , wxWindowDestroyEvent )
    // Always constructor Properties first

    wxREADONLY_PROPERTY( Parent,wxWindow*, GetParent, EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Id,wxWindowID, SetId, GetId, wxID_ANY, 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxPROPERTY( Position,wxPoint, SetPosition , GetPosition, wxDefaultPosition , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // pos
    wxPROPERTY( Size,wxSize, SetSize, GetSize, wxDefaultSize , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // size
    wxPROPERTY( WindowStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style

    // Then all relations of the object graph

    wxREADONLY_PROPERTY_COLLECTION( Children , wxWindowList , wxWindowBase* , GetWindowChildren , wxPROP_OBJECT_GRAPH /*flags*/ , wxT("Helpstring") , wxT("group"))

   // and finally all other properties

    wxPROPERTY( ExtraStyle , long , SetExtraStyle , GetExtraStyle , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // extstyle
    wxPROPERTY( BackgroundColour , wxColour , SetBackgroundColour , GetBackgroundColour , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // bg
    wxPROPERTY( ForegroundColour , wxColour , SetForegroundColour , GetForegroundColour , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // fg
    wxPROPERTY( Enabled , bool , Enable , IsEnabled , wxxVariant((bool)true) , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Shown , bool , Show , IsShown , wxxVariant((bool)true) , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
#if 0
    // possible property candidates (not in xrc) or not valid in all subclasses
    wxPROPERTY( Title,wxString, SetTitle, GetTitle, wxT("") )
    wxPROPERTY( Font , wxFont , SetFont , GetWindowFont  , )
    wxPROPERTY( Label,wxString, SetLabel, GetLabel, wxT("") )
    // MaxHeight, Width , MinHeight , Width
    // TODO switch label to control and title to toplevels

    wxPROPERTY( ThemeEnabled , bool , SetThemeEnabled , GetThemeEnabled , )
    //wxPROPERTY( Cursor , wxCursor , SetCursor , GetCursor , )
    // wxPROPERTY( ToolTip , wxString , SetToolTip , GetToolTipText , )
    wxPROPERTY( AutoLayout , bool , SetAutoLayout , GetAutoLayout , )



#endif
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxWindow)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_DUMMY(wxWindow)

#else
    IMPLEMENT_DYNAMIC_CLASS(wxWindow, wxWindowBase)
#endif
#endif // __WXUNIVERSAL__/__WXPalm__

BEGIN_EVENT_TABLE(wxWindowPalm, wxWindowBase)
    EVT_ERASE_BACKGROUND(wxWindowPalm::OnEraseBackground)
    EVT_INIT_DIALOG(wxWindowPalm::OnInitDialog)
END_EVENT_TABLE()

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// wxWindow utility functions
// ---------------------------------------------------------------------------

// Find an item given the MS Windows id
wxWindow *wxWindowPalm::FindItem(long id) const
{
    return NULL;
}

// Find an item given the MS Windows handle
wxWindow *wxWindowPalm::FindItemByWinHandle(WXWINHANDLE handle, bool controlOnly) const
{
    // TODO
    return NULL;
}

bool wxGetKeyState(wxKeyCode key)
{
    wxASSERT_MSG(key != WXK_LBUTTON && key != WXK_RBUTTON && key !=
        WXK_MBUTTON, wxT("can't use wxGetKeyState() for mouse buttons"));

    // TODO

    return false;
}

// ----------------------------------------------------------------------------
// constructors and such
// ----------------------------------------------------------------------------

void wxWindowPalm::Init()
{
    m_hWnd = 0;
}

// Destructor
wxWindowPalm::~wxWindowPalm()
{
}

// real construction (Init() must have been called before!)
bool wxWindowPalm::Create(wxWindow *parent,
                          wxWindowID id,
                          const wxPoint& pos,
                          const wxSize& size,
                          long style,
                          const wxString& name)
{
    wxCHECK_MSG( parent, false, wxT("can't create wxWindow without parent") );

    if ( !CreateBase(parent, id, pos, size, style, wxDefaultValidator, name) )
        return false;

    parent->AddChild(this);

    InheritAttributes();

    return true;
}

WXFORMPTR wxWindowPalm::GetFormPtr()
{
    return FrameForm;
}
void wxWindowPalm::SetFormPtr(WXFORMPTR FormPtr)
{
    FrameForm = FormPtr;
}

// ---------------------------------------------------------------------------
// basic operations
// ---------------------------------------------------------------------------

void wxWindowPalm::SetFocus()
{
}

void wxWindowPalm::SetFocusFromKbd()
{
}

// Get the window with the focus
wxWindow *wxWindowBase::DoFindFocus()
{
    return NULL;
}

bool wxWindowPalm::Enable(bool enable)
{
    return false;
}

bool wxWindowPalm::Show(bool show)
{
    return false;
}

// Raise the window to the top of the Z order
void wxWindowPalm::Raise()
{
}

// Lower the window to the bottom of the Z order
void wxWindowPalm::Lower()
{
}

void wxWindowPalm::SetLabel( const wxString& WXUNUSED(label))
{
}

wxString wxWindowPalm::GetLabel() const
{
    return wxEmptyString;
}

void wxWindowPalm::DoCaptureMouse()
{
}

void wxWindowPalm::DoReleaseMouse()
{
}

/* static */ wxWindow *wxWindowBase::GetCapture()
{
    return NULL;
}

bool wxWindowPalm::SetFont(const wxFont& font)
{
    return false;
}
bool wxWindowPalm::SetCursor(const wxCursor& cursor)
{
    return false;
}

void wxWindowPalm::WarpPointer (int x, int y)
{
}

// ---------------------------------------------------------------------------
// scrolling stuff
// ---------------------------------------------------------------------------

// convert wxHORIZONTAL/wxVERTICAL to SB_HORZ/SB_VERT
static inline int wxDirToWinStyle(int orient)
{
    return 0;
}

int wxWindowPalm::GetScrollPos(int orient) const
{
    return 0;
}

// This now returns the whole range, not just the number
// of positions that we can scroll.
int wxWindowPalm::GetScrollRange(int orient) const
{
    return 0;
}

int wxWindowPalm::GetScrollThumb(int orient) const
{
    return 0;
}

void wxWindowPalm::SetScrollPos(int orient, int pos, bool refresh)
{
}

// New function that will replace some of the above.
void wxWindowPalm::SetScrollbar(int orient,
                               int pos,
                               int pageSize,
                               int range,
                               bool refresh)
{
}

void wxWindowPalm::ScrollWindow(int dx, int dy, const wxRect *prect)
{
}

bool wxWindowPalm::ScrollLines(int lines)
{
    return false;
}

bool wxWindowPalm::ScrollPages(int pages)
{
    return false;
}

// ----------------------------------------------------------------------------
// Style handling
// ----------------------------------------------------------------------------

WXDWORD wxWindowPalm::PalmGetStyle(long flags, WXDWORD *exstyle) const
{
    return 0;
}

// Setup background and foreground colours correctly
void wxWindowPalm::SetupColours()
{
}

void wxWindowPalm::OnInternalIdle()
{
}

// Set this window to be the child of 'parent'.
bool wxWindowPalm::Reparent(wxWindowBase *parent)
{
    return false;
}

void wxWindowPalm::Refresh(bool eraseBack, const wxRect *rect)
{
    WinHandle handle = (WinHandle)GetHWND();
    if(handle)
    {
#ifdef __WXPALMOS6__
        if(rect)
        {
            RectangleType dirtyRect;
            dirtyRect.topLeft.x = rect->GetX() - 1;
            dirtyRect.topLeft.y = rect->GetY() - 1;
            dirtyRect.extent.x = rect->GetWidth() + 1;
            dirtyRect.extent.y = rect->GetHeight() + 1;
            WinInvalidateRect(handle, &dirtyRect);
        }
        else
        {
            WinInvalidateWindow(handle);
        }
#else // __WXPALMOS5__
        WinSetActiveWindow (handle);
#endif

    }
}

void wxWindowPalm::Update()
{
}

// ---------------------------------------------------------------------------
// drag and drop
// ---------------------------------------------------------------------------


#if wxUSE_DRAG_AND_DROP
void wxWindowPalm::SetDropTarget(wxDropTarget *pDropTarget)
{
}
#endif // wxUSE_DRAG_AND_DROP

// old style file-manager drag&drop support: we retain the old-style
// DragAcceptFiles in parallel with SetDropTarget.
void wxWindowPalm::DragAcceptFiles(bool accept)
{
}

// ----------------------------------------------------------------------------
// tooltips
// ----------------------------------------------------------------------------

#if wxUSE_TOOLTIPS

void wxWindowPalm::DoSetToolTip(wxToolTip *tooltip)
{
}

#endif // wxUSE_TOOLTIPS

// ---------------------------------------------------------------------------
// moving and resizing
// ---------------------------------------------------------------------------

// Get total size
void wxWindowPalm::DoGetSize(int *x, int *y) const
{
}

// Get size *available for subwindows* i.e. excluding menu bar etc.
void wxWindowPalm::DoGetClientSize(int *x, int *y) const
{
}

void wxWindowPalm::DoGetPosition(int *x, int *y) const
{
    if(x)
        *x = 0;
    if(y)
        *y = 0;
}

void wxWindowPalm::DoScreenToClient(int *x, int *y) const
{
}

void wxWindowPalm::DoClientToScreen(int *x, int *y) const
{
}

void wxWindowPalm::DoMoveWindow(int x, int y, int width, int height)
{
}

// set the size of the window: if the dimensions are positive, just use them,
// but if any of them is equal to -1, it means that we must find the value for
// it ourselves (unless sizeFlags contains wxSIZE_ALLOW_MINUS_ONE flag, in
// which case -1 is a valid value for x and y)
//
// If sizeFlags contains wxSIZE_AUTO_WIDTH/HEIGHT flags (default), we calculate
// the width/height to best suit our contents, otherwise we reuse the current
// width/height
void wxWindowPalm::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
    // get the current size and position...
    int currentX, currentY;
    GetPosition(&currentX, &currentY);
    int currentW,currentH;
    GetSize(&currentW, &currentH);

    // ... and don't do anything (avoiding flicker) if it's already ok
    if ( x == currentX && y == currentY &&
         width == currentW && height == currentH )
    {
        return;
    }

    if ( x == wxDefaultCoord && !(sizeFlags & wxSIZE_ALLOW_MINUS_ONE) )
        x = currentX;
    if ( y == wxDefaultCoord && !(sizeFlags & wxSIZE_ALLOW_MINUS_ONE) )
        y = currentY;

    AdjustForParentClientOrigin(x, y, sizeFlags);

    wxSize size = wxDefaultSize;
    if ( width == wxDefaultCoord )
    {
        if ( sizeFlags & wxSIZE_AUTO_WIDTH )
        {
            size = DoGetBestSize();
            width = size.x;
        }
        else
        {
            // just take the current one
            width = currentW;
        }
    }

    if ( height == wxDefaultCoord )
    {
        if ( sizeFlags & wxSIZE_AUTO_HEIGHT )
        {
            if ( size.x == wxDefaultCoord )
            {
                size = DoGetBestSize();
            }
            //else: already called DoGetBestSize() above

            height = size.y;
        }
        else
        {
            // just take the current one
            height = currentH;
        }
    }

    DoMoveWindow(x, y, width, height);
}

void wxWindowPalm::DoSetClientSize(int width, int height)
{
}

// ---------------------------------------------------------------------------
// text metrics
// ---------------------------------------------------------------------------

int wxWindowPalm::GetCharHeight() const
{
    return 0;
}

int wxWindowPalm::GetCharWidth() const
{
    return 0;
}

void wxWindowPalm::DoGetTextExtent(const wxString& string,
                                   int *x, int *y,
                                   int *descent,
                                   int *externalLeading,
                                   const wxFont *theFont) const
{
}

// ---------------------------------------------------------------------------
// popup menu
// ---------------------------------------------------------------------------

#if wxUSE_MENUS_NATIVE

// yield for WM_COMMAND events only, i.e. process all WM_COMMANDs in the queue
// immediately, without waiting for the next event loop iteration
//
// NB: this function should probably be made public later as it can almost
//     surely replace wxYield() elsewhere as well
static void wxYieldForCommandsOnly()
{
}

bool wxWindowPalm::DoPopupMenu(wxMenu *menu, int x, int y)
{
    return false;
}

#endif // wxUSE_MENUS_NATIVE

// ----------------------------------------------------------------------------
// wxWindow <-> HWND map
// ----------------------------------------------------------------------------

wxWinHashTable *wxWinHandleHash = NULL;

wxWindow *wxFindWinFromWinHandle(WXWINHANDLE handle)
{
    // TODO
    return NULL;
}

void wxRemoveHandleAssociation(wxWindowPalm *win)
{
}

// ----------------------------------------------------------------------------
// various Palm specific class dependent functions
// ----------------------------------------------------------------------------

bool wxWindowPalm::PalmGetCreateWindowCoords(const wxPoint& pos,
                                             const wxSize& size,
                                             int& x, int& y,
                                             int& w, int& h) const
{
    return false;
}

bool wxWindowPalm::PalmCreate(const wxChar *wclass,
                              const wxChar *title,
                              const wxPoint& pos,
                              const wxSize& size,
                              WXDWORD style,
                              WXDWORD extendedStyle)
{
    return false;
}

// ===========================================================================
// Palm message handlers
// ===========================================================================

// ---------------------------------------------------------------------------
// painting
// ---------------------------------------------------------------------------

// Can be called from an application's OnPaint handler
void wxWindowPalm::OnPaint(wxPaintEvent& event)
{
}

void wxWindowPalm::OnEraseBackground(wxEraseEvent& event)
{
}

// ---------------------------------------------------------------------------
// moving and resizing
// ---------------------------------------------------------------------------

bool wxWindowPalm::HandleMove(int x, int y)
{
    return false;
}

bool wxWindowPalm::HandleMoving(wxRect& rect)
{
    return false;
}

// ---------------------------------------------------------------------------
// joystick
// ---------------------------------------------------------------------------

bool wxWindowPalm::HandleJoystickEvent(WXUINT msg, int x, int y, WXUINT flags)
{
    return false;
}

// ---------------------------------------------------------------------------
// scrolling
// ---------------------------------------------------------------------------

bool wxWindowPalm::PalmOnScroll(int orientation, WXWORD wParam,
                                WXWORD pos, WXWINHANDLE control)
{
    // TODO
    return false;
}

// ===========================================================================
// global functions
// ===========================================================================

void wxGetCharSize(WXWINHANDLE wnd, int *x, int *y, const wxFont *the_font)
{
    // TODO
}

#if wxUSE_HOTKEY

bool wxWindowPalm::RegisterHotKey(int hotkeyId, int modifiers, int keycode)
{
    return false;
}

bool wxWindowPalm::UnregisterHotKey(int hotkeyId)
{
    return false;
}
#endif // # __WXUNIVERSAL__
#endif // wxUSE_HOTKEY
