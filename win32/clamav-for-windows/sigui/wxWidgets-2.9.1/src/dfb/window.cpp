/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/window.cpp
// Purpose:     wxWindow
// Author:      Vaclav Slavik
//              (based on GTK, MSW, MGL implementations)
// Created:     2006-80-10
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
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
    #include "wx/dcclient.h"
    #include "wx/nonownedwnd.h"
#endif

#include "wx/caret.h"
#include "wx/dynarray.h"

#include "wx/dfb/private.h"
#include "wx/private/overlay.h"

#define TRACE_EVENTS "events"
#define TRACE_PAINT  "paint"

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// global variables
// ---------------------------------------------------------------------------

// the window that has keyboard focus:
static wxWindowDFB *gs_focusedWindow = NULL;
// the window that is about to be focused after currently focused
// one looses focus:
static wxWindow *gs_toBeFocusedWindow = NULL;
// the window that has mouse capture
static wxWindowDFB *gs_mouseCapture = NULL;

// ---------------------------------------------------------------------------
// overlays support
// ---------------------------------------------------------------------------

WX_DEFINE_ARRAY_PTR(wxOverlayImpl*, wxDfbOverlaysList);

// ---------------------------------------------------------------------------
// event tables
// ---------------------------------------------------------------------------

// in wxUniv this class is abstract because it doesn't have DoPopupMenu()
IMPLEMENT_ABSTRACT_CLASS(wxWindowDFB, wxWindowBase)

BEGIN_EVENT_TABLE(wxWindowDFB, wxWindowBase)
END_EVENT_TABLE()

//-----------------------------------------------------------------------------
// global functions
//-----------------------------------------------------------------------------

wxWindow *wxGetActiveWindow()
{
    return wxWindow::FindFocus();
}

// ----------------------------------------------------------------------------
// constructors and such
// ----------------------------------------------------------------------------

void wxWindowDFB::Init()
{
    m_isShown = true;
    m_tlw = NULL;
    m_overlays = NULL;
}

// Destructor
wxWindowDFB::~wxWindowDFB()
{
    SendDestroyEvent();

    if ( gs_mouseCapture == this )
        ReleaseMouse();

    if ( gs_focusedWindow == this )
        DFBKillFocus();

    DestroyChildren();
}

// real construction (Init() must have been called before!)
bool wxWindowDFB::Create(wxWindow *parent,
                         wxWindowID id,
                         const wxPoint& pos,
                         const wxSize& size,
                         long style,
                         const wxString& name)
{
    if ( !m_tlw && parent )
        m_tlw = parent->GetTLW();

    if ( !CreateBase(parent, id, pos, size, style, wxDefaultValidator, name) )
        return false;

    if ( parent )
        parent->AddChild(this);

    // set the size to something bogus initially, in case some code tries to
    // create wxWindowDC before SetSize() is called below:
    m_rect.width = m_rect.height = 1;

    int x, y, w, h;
    x = pos.x, y = pos.y;
    if ( x == -1  ) x = 0;
    if ( y == -1 ) y = 0;
    w = WidthDefault(size.x);
    h = HeightDefault(size.y);
    SetSize(x, y, w, h);

    return true;
}

// ---------------------------------------------------------------------------
// surface access
// ---------------------------------------------------------------------------

wxIDirectFBSurfacePtr wxWindowDFB::ObtainDfbSurface() const
{
    wxCHECK_MSG( m_parent, NULL, "parentless window?" );

    wxIDirectFBSurfacePtr parentSurface(m_parent->GetDfbSurface());
    wxCHECK_MSG( parentSurface, NULL, "invalid parent surface" );

    wxRect r(GetRect());
    AdjustForParentClientOrigin(r.x, r.y, 0);
    DFBRectangle rect = { r.x, r.y, r.width, r.height };

    return parentSurface->GetSubSurface(&rect);
}

wxIDirectFBSurfacePtr wxWindowDFB::GetDfbSurface()
{
    if ( !m_surface )
    {
        m_surface = ObtainDfbSurface();
        wxASSERT_MSG( m_surface, "invalid DirectFB surface" );
    }

    return m_surface;
}

void wxWindowDFB::InvalidateDfbSurface()
{
    m_surface = NULL;

    // surfaces of the children are subsurfaces of this window's surface,
    // so they must be invalidated as well:
    wxWindowList& children = GetChildren();
    for ( wxWindowList::iterator i = children.begin(); i != children.end(); ++i )
    {
        (*i)->InvalidateDfbSurface();
    }
}

// ---------------------------------------------------------------------------
// basic operations
// ---------------------------------------------------------------------------

void wxWindowDFB::SetFocus()
{
    if ( gs_focusedWindow == this )
        return; // nothing to do, focused already

    wxWindowDFB *oldFocusedWindow = gs_focusedWindow;

    if ( gs_focusedWindow )
    {
        gs_toBeFocusedWindow = (wxWindow*)this;
        gs_focusedWindow->DFBKillFocus();
        gs_toBeFocusedWindow = NULL;
    }

    gs_focusedWindow = this;

    if ( IsShownOnScreen() &&
         (!oldFocusedWindow || oldFocusedWindow->GetTLW() != m_tlw) )
    {
        m_tlw->SetDfbFocus();
    }
    // else: do nothing, because DirectFB windows cannot have focus if they
    //       are hidden; when the TLW becomes visible, it will set the focus
    //       to use from wxTLW::Show()

    // notify the parent keeping track of focus for the kbd navigation
    // purposes that we got it
    wxChildFocusEvent eventFocus((wxWindow*)this);
    HandleWindowEvent(eventFocus);

    wxFocusEvent event(wxEVT_SET_FOCUS, GetId());
    event.SetEventObject(this);
    event.SetWindow((wxWindow*)oldFocusedWindow);
    HandleWindowEvent(event);

#if wxUSE_CARET
    // caret needs to be informed about focus change
    wxCaret *caret = GetCaret();
    if ( caret )
        caret->OnSetFocus();
#endif // wxUSE_CARET
}

void wxWindowDFB::DFBKillFocus()
{
    wxCHECK_RET( gs_focusedWindow == this,
                 "killing focus on window that doesn't have it" );

    gs_focusedWindow = NULL;

    if ( m_isBeingDeleted )
        return; // don't send any events from dtor

#if wxUSE_CARET
    // caret needs to be informed about focus change
    wxCaret *caret = GetCaret();
    if ( caret )
        caret->OnKillFocus();
#endif // wxUSE_CARET

    wxFocusEvent event(wxEVT_KILL_FOCUS, GetId());
    event.SetEventObject(this);
    event.SetWindow(gs_toBeFocusedWindow);
    HandleWindowEvent(event);
}

// ----------------------------------------------------------------------------
// this wxWindowBase function is implemented here (in platform-specific file)
// because it is static and so couldn't be made virtual
// ----------------------------------------------------------------------------
wxWindow *wxWindowBase::DoFindFocus()
{
    return (wxWindow*)gs_focusedWindow;
}

bool wxWindowDFB::Show(bool show)
{
    if ( !wxWindowBase::Show(show) )
        return false;

    // Unlike Refresh(), DoRefreshWindow() doesn't check visibility, so
    // call it to force refresh of either this window (if showing) or its
    // parent area at the place of this window (if hiding):
    DoRefreshWindow();

    return true;
}

// Raise the window to the top of the Z order
void wxWindowDFB::Raise()
{
    wxFAIL_MSG( "Raise() not implemented" );
}

// Lower the window to the bottom of the Z order
void wxWindowDFB::Lower()
{
    wxFAIL_MSG( "Lower() not implemented" );
}

void wxWindowDFB::DoCaptureMouse()
{
#warning "implement this"
#if 0
    if ( gs_mouseCapture )
        DFB_wmUncaptureEvents(gs_mouseCapture->m_wnd, wxDFB_CAPTURE_MOUSE);
#endif
    gs_mouseCapture = this;
#if 0
    DFB_wmCaptureEvents(m_wnd, EVT_MOUSEEVT, wxDFB_CAPTURE_MOUSE);
#endif
}

void wxWindowDFB::DoReleaseMouse()
{
    wxASSERT_MSG( gs_mouseCapture == this, wxT("attempt to release mouse, but this window hasn't captured it") );

#warning "implement this"
#if 0
    DFB_wmUncaptureEvents(m_wnd, wxDFB_CAPTURE_MOUSE);
#endif
    gs_mouseCapture = NULL;
}

/* static */ wxWindow *wxWindowBase::GetCapture()
{
    return (wxWindow*)gs_mouseCapture;
}

bool wxWindowDFB::SetCursor(const wxCursor& cursor)
{
    if ( !wxWindowBase::SetCursor(cursor) )
    {
        // no change
        return false;
    }

#warning "implement this"
#if 0
    if ( m_cursor.Ok() )
        DFB_wmSetWindowCursor(m_wnd, *m_cursor.GetDFBCursor());
    else
        DFB_wmSetWindowCursor(m_wnd, *wxSTANDARD_CURSOR->GetDFBCursor());
#endif

    return true;
}

void wxWindowDFB::WarpPointer(int x, int y)
{
    int w, h;
    wxDisplaySize(&w, &h);

    ClientToScreen(&x, &y);
    if ( x < 0 ) x = 0;
    if ( y < 0 ) y = 0;
    if ( x >= w ) x = w-1;
    if ( y >= h ) y = h-1;

    wxIDirectFBDisplayLayerPtr layer(wxIDirectFB::Get()->GetDisplayLayer());
    wxCHECK_RET( layer, "no display layer" );

    layer->WarpCursor(x, y);
}

// Set this window to be the child of 'parent'.
bool wxWindowDFB::Reparent(wxWindowBase *parent)
{
    if ( !wxWindowBase::Reparent(parent) )
        return false;

#warning "implement this"
    wxFAIL_MSG( "reparenting not yet implemented" );

    return true;
}

// ---------------------------------------------------------------------------
// moving and resizing
// ---------------------------------------------------------------------------

// Get total size
void wxWindowDFB::DoGetSize(int *x, int *y) const
{
    if (x) *x = m_rect.width;
    if (y) *y = m_rect.height;
}

void wxWindowDFB::DoGetPosition(int *x, int *y) const
{
    if (x) *x = m_rect.x;
    if (y) *y = m_rect.y;
}

static wxPoint GetScreenPosOfClientOrigin(const wxWindowDFB *win)
{
    wxCHECK_MSG( win, wxPoint(0, 0), "no window provided" );

    wxPoint pt(win->GetPosition() + win->GetClientAreaOrigin());

    if ( !win->IsTopLevel() )
        pt += GetScreenPosOfClientOrigin(win->GetParent());

    return pt;
}

void wxWindowDFB::DoScreenToClient(int *x, int *y) const
{
    wxPoint o = GetScreenPosOfClientOrigin(this);

    if (x) *x -= o.x;
    if (y) *y -= o.y;
}

void wxWindowDFB::DoClientToScreen(int *x, int *y) const
{
    wxPoint o = GetScreenPosOfClientOrigin(this);

    if (x) *x += o.x;
    if (y) *y += o.y;
}

// Get size *available for subwindows* i.e. excluding menu bar etc.
void wxWindowDFB::DoGetClientSize(int *x, int *y) const
{
    DoGetSize(x, y);
}

void wxWindowDFB::DoMoveWindow(int x, int y, int width, int height)
{
    // NB: [x,y] arguments are in (parent's) window coordinates, while
    //     m_rect.{x,y} are in (parent's) client coordinates. That's why we
    //     offset by parentOrigin in some places below

    wxPoint parentOrigin(0, 0);
    AdjustForParentClientOrigin(parentOrigin.x, parentOrigin.y);

    wxRect oldpos(m_rect);
    oldpos.Offset(parentOrigin);

    wxRect newpos(x, y, width, height);

    // input [x,y] is in window coords, but we store client coords in m_rect:
    m_rect = newpos;
    m_rect.Offset(-parentOrigin);

    // window's position+size changed and so did the subsurface that covers it
    InvalidateDfbSurface();

    if ( IsShown() )
    {
        // queue both former and new position of the window for repainting:
        wxWindow *parent = GetParent();

        // only refresh the visible parts:
        if ( !CanBeOutsideClientArea() )
        {
            wxRect parentClient(parent->GetClientSize());
            oldpos.Intersect(parentClient);
            newpos.Intersect(parentClient);
        }

        parent->RefreshRect(oldpos);
        parent->RefreshRect(newpos);
    }
}

// set the size of the window: if the dimensions are positive, just use them,
// but if any of them is equal to -1, it means that we must find the value for
// it ourselves (unless sizeFlags contains wxSIZE_ALLOW_MINUS_ONE flag, in
// which case -1 is a valid value for x and y)
//
// If sizeFlags contains wxSIZE_AUTO_WIDTH/HEIGHT flags (default), we calculate
// the width/height to best suit our contents, otherwise we reuse the current
// width/height
void wxWindowDFB::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
    // get the current size and position...
    int currentX, currentY;
    GetPosition(&currentX, &currentY);
    int currentW,currentH;
    GetSize(&currentW, &currentH);

    if ( x == -1 && !(sizeFlags & wxSIZE_ALLOW_MINUS_ONE) )
        x = currentX;
    if ( y == -1 && !(sizeFlags & wxSIZE_ALLOW_MINUS_ONE) )
        y = currentY;

    // ... and don't do anything (avoiding flicker) if it's already ok
    if ( x == currentX && y == currentY &&
         width == currentW && height == currentH )
    {
        return;
    }

    wxSize size(-1, -1);
    if ( width == -1 )
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

    if ( height == -1 )
    {
        if ( sizeFlags & wxSIZE_AUTO_HEIGHT )
        {
            if ( size.x == -1 )
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

    int maxWidth = GetMaxWidth(),
        minWidth = GetMinWidth(),
        maxHeight = GetMaxHeight(),
        minHeight = GetMinHeight();

    if ( minWidth != -1 && width < minWidth ) width = minWidth;
    if ( maxWidth != -1 && width > maxWidth ) width = maxWidth;
    if ( minHeight != -1 && height < minHeight ) height = minHeight;
    if ( maxHeight != -1 && height > maxHeight ) height = maxHeight;

    if ( m_rect.x != x || m_rect.y != y ||
         m_rect.width != width || m_rect.height != height )
    {
        AdjustForParentClientOrigin(x, y, sizeFlags);
        DoMoveWindow(x, y, width, height);

        wxSize newSize(width, height);
        wxSizeEvent event(newSize, GetId());
        event.SetEventObject(this);
        HandleWindowEvent(event);
    }
}

void wxWindowDFB::DoSetClientSize(int width, int height)
{
    SetSize(width, height);
}

// ---------------------------------------------------------------------------
// text metrics
// ---------------------------------------------------------------------------

int wxWindowDFB::GetCharHeight() const
{
    wxWindowDC dc((wxWindow*)this);
    return dc.GetCharHeight();
}

int wxWindowDFB::GetCharWidth() const
{
    wxWindowDC dc((wxWindow*)this);
    return dc.GetCharWidth();
}

void wxWindowDFB::DoGetTextExtent(const wxString& string,
                                  int *x, int *y,
                                  int *descent,
                                  int *externalLeading,
                                  const wxFont *theFont) const
{
    wxWindowDC dc((wxWindow*)this);
    dc.GetTextExtent(string, x, y, descent, externalLeading, (wxFont*)theFont);
}


// ---------------------------------------------------------------------------
// painting
// ---------------------------------------------------------------------------

void wxWindowDFB::Refresh(bool WXUNUSED(eraseBack), const wxRect *rect)
{
    if ( !IsShown() || IsFrozen() )
        return;

    // NB[1]: We intentionally ignore the eraseBack argument here. This is
    //        because of the way wxDFB's painting is implemented: the refresh
    //        request is propagated up to wxTLW, which is then painted in
    //        top-down order. This means that this window's area is first
    //        painted by its parent and this window is then painted over it, so
    //        it's not safe to not paint this window's background even if
    //        eraseBack=false.
    // NB[2]: wxWindow::Refresh() takes the rectangle in client coords, but
    //        wxUniv translates it to window coords before passing it to
    //        wxWindowDFB::Refresh(), so we can directly pass the rect to
    //        DoRefreshRect (which takes window, not client, coords) here.
    if ( rect )
        DoRefreshRect(*rect);
    else
        DoRefreshWindow();
}

void wxWindowDFB::RefreshWindowRect(const wxRect& rect)
{
    if ( !IsShown() || IsFrozen() )
        return;

    DoRefreshRect(rect);
}

void wxWindowDFB::DoRefreshWindow()
{
    // NB: DoRefreshRect() takes window coords, not client, so this is correct
    DoRefreshRect(wxRect(GetSize()));
}

void wxWindowDFB::DoRefreshRect(const wxRect& rect)
{
    wxWindow *parent = GetParent();
    wxCHECK_RET( parent, "no parent" );

    // don't overlap outside of the window (NB: 'rect' is in window coords):
    wxRect r(rect);
    r.Intersect(wxRect(GetSize()));
    if ( r.IsEmpty() )
        return;

    wxLogTrace(TRACE_PAINT,
               "%p ('%s'): refresh rect [%i,%i,%i,%i]",
               this, GetName().c_str(),
               rect.x, rect.y, rect.GetRight(), rect.GetBottom());

    // convert the refresh rectangle to parent's coordinates and
    // recursively refresh the parent:
    r.Offset(GetPosition());
    r.Offset(parent->GetClientAreaOrigin());

    // normal windows cannot extend out of its parent's client area, so don't
    // refresh any hidden parts:
    if ( !CanBeOutsideClientArea() )
        r.Intersect(parent->GetClientRect());

    parent->DoRefreshRect(r);
}

void wxWindowDFB::Update()
{
    if ( !IsShown() || IsFrozen() )
        return;

    GetParent()->Update();
}

void wxWindowDFB::DoThaw()
{
    if ( IsShown() )
        DoRefreshWindow();
}

void wxWindowDFB::PaintWindow(const wxRect& rect)
{
    wxCHECK_RET( !IsFrozen() && IsShown(), "shouldn't be called" );

    wxLogTrace(TRACE_PAINT,
               "%p ('%s'): painting region [%i,%i,%i,%i]",
               this, GetName().c_str(),
               rect.x, rect.y, rect.GetRight(), rect.GetBottom());

    m_updateRegion = rect;

    // FIXME_DFB: don't waste time rendering the area if it's fully covered
    //            by some children, go directly to rendering the children
    //            (unless some child has HasTransparentBackground()=true!)

    // NB: unconditionally send wxEraseEvent, because our implementation of
    //     wxWindow::Refresh() ignores the eraseBack argument
    wxWindowDC dc((wxWindow*)this);
    wxEraseEvent eventEr(m_windowId, &dc);
    eventEr.SetEventObject(this);
    HandleWindowEvent(eventEr);

    wxRect clientRect(GetClientRect());

    // only send wxNcPaintEvent if drawing at least part of nonclient area:
    if ( !clientRect.Contains(rect) )
    {
        wxNcPaintEvent eventNc(GetId());
        eventNc.SetEventObject(this);
        HandleWindowEvent(eventNc);
    }
    else
    {
        wxLogTrace(TRACE_PAINT, "%p ('%s'): not sending wxNcPaintEvent",
                   this, GetName().c_str());
    }

    // only send wxPaintEvent if drawing at least part of client area:
    if ( rect.Intersects(clientRect) )
    {
        wxPaintEvent eventPt(GetId());
        eventPt.SetEventObject(this);
        HandleWindowEvent(eventPt);
    }
    else
    {
        wxLogTrace(TRACE_PAINT, "%p ('%s'): not sending wxPaintEvent",
                   this, GetName().c_str());
    }

    // draw window's overlays on top of the painted window, if we have any:
    PaintOverlays(rect);

    m_updateRegion.Clear();

    // client area portion of 'rect':
    wxRect rectClientOnly(rect);
    rectClientOnly.Intersect(clientRect);

    // paint the children:
    wxPoint origin = GetClientAreaOrigin();
    wxWindowList& children = GetChildren();
    for ( wxWindowList::iterator i = children.begin();
          i != children.end(); ++i )
    {
        wxWindow *child = *i;

        if ( child->IsFrozen() || !child->IsShown() )
            continue; // don't paint anything if the window is frozen or hidden

        // compute child's area to repaint
        wxRect childrect(child->GetRect());
        childrect.Offset(origin);

        if ( child->CanBeOutsideClientArea() )
            childrect.Intersect(rect);
        else
            childrect.Intersect(rectClientOnly);

        if ( childrect.IsEmpty() )
            continue;

        // and repaint it:
        childrect.Offset(-child->GetPosition());
        childrect.Offset(-origin);
        child->PaintWindow(childrect);
    }
}

void wxWindowDFB::PaintOverlays(const wxRect& rect)
{
    if ( !m_overlays )
        return;

    for ( wxDfbOverlaysList::const_iterator i = m_overlays->begin();
          i != m_overlays->end(); ++i )
    {
        const wxOverlayImpl * const overlay = *i;

        wxRect orectOrig(overlay->GetRect());
        wxRect orect(orectOrig);
        orect.Intersect(rect);
        if ( orect.IsEmpty() )
            continue;

        if ( overlay->IsEmpty() )
            continue; // nothing to paint

        DFBRectangle dfbRect = { orect.x - orectOrig.x, orect.y - orectOrig.y,
                                 orect.width, orect.height };
        GetDfbSurface()->Blit
                         (
                           overlay->GetDirectFBSurface(),
                           &dfbRect,
                           orect.x, orect.y
                         );
    }
}

void wxWindowDFB::AddOverlay(wxOverlayImpl *overlay)
{
    if ( !m_overlays )
        m_overlays = new wxDfbOverlaysList;

    m_overlays->Add(overlay);
}

void wxWindowDFB::RemoveOverlay(wxOverlayImpl *overlay)
{
    wxCHECK_RET( m_overlays, "no overlays to remove" );

    m_overlays->Remove(overlay);

    if ( m_overlays->empty() )
    {
        wxDELETE(m_overlays);
    }

    if ( !m_isBeingDeleted )
        RefreshWindowRect(overlay->GetRect());
}


// ---------------------------------------------------------------------------
// events handling
// ---------------------------------------------------------------------------

#define KEY(dfb, wx)                                                \
    case dfb:                                                       \
          wxLogTrace(TRACE_EVENTS,                                  \
                     wxT("key " #dfb " mapped to " #wx));            \
          return wx

// returns translated keycode, i.e. the one for KEYUP/KEYDOWN where 'a'..'z' is
// translated to 'A'..'Z'
static long GetTranslatedKeyCode(DFBInputDeviceKeyIdentifier key_id)
{
    switch ( key_id )
    {
        KEY(DIKI_UNKNOWN,           0);

        KEY(DIKI_A,                 'A');
        KEY(DIKI_B,                 'B');
        KEY(DIKI_C,                 'C');
        KEY(DIKI_D,                 'D');
        KEY(DIKI_E,                 'E');
        KEY(DIKI_F,                 'F');
        KEY(DIKI_G,                 'G');
        KEY(DIKI_H,                 'H');
        KEY(DIKI_I,                 'I');
        KEY(DIKI_J,                 'J');
        KEY(DIKI_K,                 'K');
        KEY(DIKI_L,                 'L');
        KEY(DIKI_M,                 'M');
        KEY(DIKI_N,                 'N');
        KEY(DIKI_O,                 'O');
        KEY(DIKI_P,                 'P');
        KEY(DIKI_Q,                 'Q');
        KEY(DIKI_R,                 'R');
        KEY(DIKI_S,                 'S');
        KEY(DIKI_T,                 'T');
        KEY(DIKI_U,                 'U');
        KEY(DIKI_V,                 'V');
        KEY(DIKI_W,                 'W');
        KEY(DIKI_X,                 'X');
        KEY(DIKI_Y,                 'Y');
        KEY(DIKI_Z,                 'Z');

        KEY(DIKI_0,                 '0');
        KEY(DIKI_1,                 '1');
        KEY(DIKI_2,                 '2');
        KEY(DIKI_3,                 '3');
        KEY(DIKI_4,                 '4');
        KEY(DIKI_5,                 '5');
        KEY(DIKI_6,                 '6');
        KEY(DIKI_7,                 '7');
        KEY(DIKI_8,                 '8');
        KEY(DIKI_9,                 '9');

        KEY(DIKI_F1,                WXK_F1);
        KEY(DIKI_F2,                WXK_F2);
        KEY(DIKI_F3,                WXK_F3);
        KEY(DIKI_F4,                WXK_F4);
        KEY(DIKI_F5,                WXK_F5);
        KEY(DIKI_F6,                WXK_F6);
        KEY(DIKI_F7,                WXK_F7);
        KEY(DIKI_F8,                WXK_F8);
        KEY(DIKI_F9,                WXK_F9);
        KEY(DIKI_F10,               WXK_F10);
        KEY(DIKI_F11,               WXK_F11);
        KEY(DIKI_F12,               WXK_F12);

        KEY(DIKI_SHIFT_L,           WXK_SHIFT);
        KEY(DIKI_SHIFT_R,           WXK_SHIFT);
        KEY(DIKI_CONTROL_L,         WXK_CONTROL);
        KEY(DIKI_CONTROL_R,         WXK_CONTROL);
        KEY(DIKI_ALT_L,             WXK_ALT);
        KEY(DIKI_ALT_R,             WXK_ALT);
        // this key was removed in 0.9.25 but include it for previous versions
        // just to avoid gcc warnings about unhandled enum value in switch
#if !wxCHECK_DFB_VERSION(0, 9, 24)
        KEY(DIKI_ALTGR,             0);
#endif
        KEY(DIKI_META_L,            0);
        KEY(DIKI_META_R,            0);
        KEY(DIKI_SUPER_L,           0);
        KEY(DIKI_SUPER_R,           0);
        KEY(DIKI_HYPER_L,           0);
        KEY(DIKI_HYPER_R,           0);

        KEY(DIKI_CAPS_LOCK,         0);
        KEY(DIKI_NUM_LOCK,          WXK_NUMLOCK);
        KEY(DIKI_SCROLL_LOCK,       0);

        KEY(DIKI_ESCAPE,            WXK_ESCAPE);
        KEY(DIKI_LEFT,              WXK_LEFT);
        KEY(DIKI_RIGHT,             WXK_RIGHT);
        KEY(DIKI_UP,                WXK_UP);
        KEY(DIKI_DOWN,              WXK_DOWN);
        KEY(DIKI_TAB,               WXK_TAB);
        KEY(DIKI_ENTER,             WXK_RETURN);
        KEY(DIKI_SPACE,             WXK_SPACE);
        KEY(DIKI_BACKSPACE,         WXK_BACK);
        KEY(DIKI_INSERT,            WXK_INSERT);
        KEY(DIKI_DELETE,            WXK_DELETE);
        KEY(DIKI_HOME,              WXK_HOME);
        KEY(DIKI_END,               WXK_END);
        KEY(DIKI_PAGE_UP,           WXK_PAGEUP);
        KEY(DIKI_PAGE_DOWN,         WXK_PAGEDOWN);
        KEY(DIKI_PRINT,             WXK_PRINT);
        KEY(DIKI_PAUSE,             WXK_PAUSE);

        KEY(DIKI_QUOTE_LEFT,        '`');
        KEY(DIKI_MINUS_SIGN,        '-');
        KEY(DIKI_EQUALS_SIGN,       '=');
        KEY(DIKI_BRACKET_LEFT,      '[');
        KEY(DIKI_BRACKET_RIGHT,     ']');
        KEY(DIKI_BACKSLASH,         '\\');
        KEY(DIKI_SEMICOLON,         ';');
        KEY(DIKI_QUOTE_RIGHT,       '\'');
        KEY(DIKI_COMMA,             ',');
        KEY(DIKI_PERIOD,            '.');
        KEY(DIKI_SLASH,             '/');

        KEY(DIKI_LESS_SIGN,         '<');

        KEY(DIKI_KP_DIV,            WXK_NUMPAD_DIVIDE);
        KEY(DIKI_KP_MULT,           WXK_NUMPAD_MULTIPLY);
        KEY(DIKI_KP_MINUS,          WXK_NUMPAD_SUBTRACT);
        KEY(DIKI_KP_PLUS,           WXK_NUMPAD_ADD);
        KEY(DIKI_KP_ENTER,          WXK_NUMPAD_ENTER);
        KEY(DIKI_KP_SPACE,          WXK_NUMPAD_SPACE);
        KEY(DIKI_KP_TAB,            WXK_NUMPAD_TAB);
        KEY(DIKI_KP_F1,             WXK_NUMPAD_F1);
        KEY(DIKI_KP_F2,             WXK_NUMPAD_F2);
        KEY(DIKI_KP_F3,             WXK_NUMPAD_F3);
        KEY(DIKI_KP_F4,             WXK_NUMPAD_F4);
        KEY(DIKI_KP_EQUAL,          WXK_NUMPAD_EQUAL);
        KEY(DIKI_KP_SEPARATOR,      WXK_NUMPAD_SEPARATOR);

        KEY(DIKI_KP_DECIMAL,        WXK_NUMPAD_DECIMAL);
        KEY(DIKI_KP_0,              WXK_NUMPAD0);
        KEY(DIKI_KP_1,              WXK_NUMPAD1);
        KEY(DIKI_KP_2,              WXK_NUMPAD2);
        KEY(DIKI_KP_3,              WXK_NUMPAD3);
        KEY(DIKI_KP_4,              WXK_NUMPAD4);
        KEY(DIKI_KP_5,              WXK_NUMPAD5);
        KEY(DIKI_KP_6,              WXK_NUMPAD6);
        KEY(DIKI_KP_7,              WXK_NUMPAD7);
        KEY(DIKI_KP_8,              WXK_NUMPAD8);
        KEY(DIKI_KP_9,              WXK_NUMPAD9);

        case DIKI_KEYDEF_END:
        case DIKI_NUMBER_OF_KEYS:
            wxFAIL_MSG( "invalid key_id value" );
            return 0;
    }

    return 0; // silence compiler warnings
}

// returns untranslated keycode, i.e. for EVT_CHAR, where characters are left in
// the form they were entered (lowercase, diacritics etc.)
static long GetUntraslatedKeyCode(DFBInputDeviceKeyIdentifier key_id,
                                  DFBInputDeviceKeySymbol key_symbol)
{
    switch ( DFB_KEY_TYPE(key_symbol) )
    {
        case DIKT_UNICODE:
#if wxUSE_UNICODE
            return key_symbol;
#else
            if ( key_symbol < 128 )
                return key_symbol;
            else
            {
                wchar_t chr = key_symbol;
                wxCharBuffer buf(wxConvUI->cWC2MB(&chr, 1, NULL));
                if ( buf )
                    return *buf; // may be 0 if failed
                else
                    return 0;
            }
#endif

        default:
            return GetTranslatedKeyCode(key_id);
    }
}

#undef KEY

void wxWindowDFB::HandleKeyEvent(const wxDFBWindowEvent& event_)
{
    if ( !IsEnabled() )
        return;

    const DFBWindowEvent& e = event_;

    wxLogTrace(TRACE_EVENTS,
               "handling key %s event for window %p ('%s')",
               e.type == DWET_KEYUP ? "up" : "down",
               this, GetName().c_str());

    // fill in wxKeyEvent fields:
    wxKeyEvent event;
    event.SetEventObject(this);
    event.SetTimestamp(wxDFB_EVENT_TIMESTAMP(e));
    event.m_rawCode = e.key_code;
    event.m_keyCode = GetTranslatedKeyCode(e.key_id);
#if wxUSE_UNICODE
    event.m_uniChar = e.key_symbol;
#endif
    event.m_shiftDown = ( e.modifiers & DIMM_SHIFT ) != 0;
    event.m_controlDown = ( e.modifiers & DIMM_CONTROL ) != 0;
    event.m_altDown = ( e.modifiers & DIMM_ALT ) != 0;
    event.m_metaDown = ( e.modifiers & DIMM_META ) != 0;

    // translate coordinates from TLW-relative to this window-relative:
    event.m_x = e.x;
    event.m_y = e.y;
    GetTLW()->ClientToScreen(&event.m_x, &event.m_y);
    this->ScreenToClient(&event.m_x, &event.m_y);

    if ( e.type == DWET_KEYUP )
    {
        event.SetEventType(wxEVT_KEY_UP);
        HandleWindowEvent(event);
    }
    else
    {
        bool isTab = (event.m_keyCode == WXK_TAB);

        event.SetEventType(wxEVT_KEY_DOWN);

        if ( HandleWindowEvent(event) )
            return;

        // only send wxEVT_CHAR event if not processed yet:
        event.m_keyCode = GetUntraslatedKeyCode(e.key_id, e.key_symbol);
        if ( event.m_keyCode != 0 )
        {
            event.SetEventType(wxEVT_CHAR);
            if ( HandleWindowEvent(event) )
                return;
        }

        // Synthetize navigation key event, but do it only if the TAB key
        // wasn't handled yet:
        if ( isTab && GetParent() && GetParent()->HasFlag(wxTAB_TRAVERSAL) )
        {
            wxNavigationKeyEvent navEvent;
            navEvent.SetEventObject(GetParent());
            // Shift-TAB goes in reverse direction:
            navEvent.SetDirection(!event.m_shiftDown);
            // Ctrl-TAB changes the (parent) window, i.e. switch notebook page:
            navEvent.SetWindowChange(event.m_controlDown);
            navEvent.SetCurrentFocus(wxStaticCast(this, wxWindow));
            GetParent()->HandleWindowEvent(navEvent);
        }
    }
}

// ---------------------------------------------------------------------------
// idle events processing
// ---------------------------------------------------------------------------

void wxWindowDFB::OnInternalIdle()
{
    if (wxUpdateUIEvent::CanUpdate(this) && IsShown())
        UpdateWindowUI(wxUPDATE_UI_FROMIDLE);
}


// Find the wxWindow at the current mouse position, returning the mouse
// position.
wxWindow* wxFindWindowAtPointer(wxPoint& pt)
{
    return wxFindWindowAtPoint(pt = wxGetMousePosition());
}

wxWindow* wxFindWindowAtPoint(const wxPoint& WXUNUSED(pt))
{
    wxFAIL_MSG( "wxFindWindowAtPoint not implemented" );
    return NULL;
}
