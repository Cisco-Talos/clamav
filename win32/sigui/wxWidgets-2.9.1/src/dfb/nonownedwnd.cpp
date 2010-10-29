/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/nonownedwnd.cpp
// Purpose:     implementation of wxNonOwnedWindow
// Author:      Vaclav Slavik
// Created:     2006-12-24
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/toplevel.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif // WX_PRECOMP

#include "wx/hashmap.h"
#include "wx/evtloop.h"
#include "wx/dfb/private.h"

#define TRACE_EVENTS "events"
#define TRACE_PAINT  "paint"

// ============================================================================
// globals
// ============================================================================

// mapping of DirectFB windows to wxTLWs:
WX_DECLARE_HASH_MAP(DFBWindowID, wxNonOwnedWindow*,
                    wxIntegerHash, wxIntegerEqual,
                    wxDfbWindowsMap);
static wxDfbWindowsMap gs_dfbWindowsMap;

// ============================================================================
// helpers
// ============================================================================

// Queue of paint requests
class wxDfbQueuedPaintRequests
{
public:
    ~wxDfbQueuedPaintRequests() { Clear(); }

    // Adds paint request to the queue
    void Add(const wxRect& rect)
    {
        // We use a simple implementation here for now: all refresh requests
        // are merged together into single rectangle that is superset of
        // all the requested rectangles. This wastes some blitting and painting
        // time, but OTOH, EVT_PAINT handler is called only once per window.
        m_invalidated.Union(rect);
    }

    // Is the queue empty?
    bool IsEmpty() const { return m_invalidated.IsEmpty(); }

    // Empties the queue
    void Clear() { m_invalidated = wxRect(); }

    // Gets the next request in the queue, returns true if there was one,
    // false if the queue was empty
    bool GetNext(wxRect& rect)
    {
        if ( m_invalidated.IsEmpty() )
            return false;

        rect = m_invalidated;
        Clear(); // there's only one item in the queue
        return true;
    }

private:
    // currently invalidated region
    wxRect m_invalidated;
};

// ============================================================================
// wxNonOwnedWindow
// ============================================================================

// ----------------------------------------------------------------------------
// creation & destruction
// ----------------------------------------------------------------------------

void wxNonOwnedWindow::Init()
{
    m_isShown = false;
    m_sizeSet = false;
    m_opacity = 255;
    m_toPaint = new wxDfbQueuedPaintRequests;
    m_isPainting = false;
}

bool wxNonOwnedWindow::Create(wxWindow *parent,
                                 wxWindowID id,
                                 const wxPoint& pos,
                                 const wxSize& size,
                                 long style,
                                 const wxString &name)
{
    wxCHECK_MSG( pos.x >= 0 && pos.y >= 0, false, "invalid position" );
    wxCHECK_MSG( size.x > 0 && size.y > 0, false, "invalid size" );

    m_tlw = this;

    // create DirectFB window:
    wxIDirectFBDisplayLayerPtr layer(wxIDirectFB::Get()->GetDisplayLayer());
    wxCHECK_MSG( layer, false, "no display layer" );

    DFBWindowDescription desc;
    desc.flags = (DFBWindowDescriptionFlags)
                   (DWDESC_CAPS |
                    DWDESC_WIDTH | DWDESC_HEIGHT | DWDESC_POSX | DWDESC_POSY);
    desc.caps = DWCAPS_DOUBLEBUFFER;
    desc.posx = pos.x;
    desc.posy = pos.y;
    desc.width = size.x;
    desc.height = size.y;
    m_dfbwin = layer->CreateWindow(&desc);
    if ( !m_dfbwin )
        return false;

    // add the new TLW to DFBWindowID->wxTLW map:
    DFBWindowID winid;
    if ( !m_dfbwin->GetID(&winid) )
        return false;
    gs_dfbWindowsMap[winid] = this;

    // TLWs are created initially hidden:
    if ( !m_dfbwin->SetOpacity(wxALPHA_TRANSPARENT) )
        return false;

    if ( !wxWindow::Create(NULL, id, pos, size, style, name) )
        return false;

    SetParent(parent);
    if ( parent )
        parent->AddChild(this);

    if ( style & (wxSTAY_ON_TOP | wxPOPUP_WINDOW) )
    {
        m_dfbwin->SetStackingClass(DWSC_UPPER);
    }

    // direct events in this window to the global event buffer:
    m_dfbwin->AttachEventBuffer(wxEventLoop::GetDirectFBEventBuffer());

    return true;
}

wxNonOwnedWindow::~wxNonOwnedWindow()
{
    SendDestroyEvent();

    // destroy all children before we destroy the underlying DirectFB window,
    // so that if any of them does something with the TLW, it will still work:
    DestroyChildren();

    // it's safe to delete the underlying DirectFB window now:
    wxDELETE(m_toPaint);

    if ( !m_dfbwin )
        return;

    // remove the TLW from DFBWindowID->wxTLW map:
    DFBWindowID winid;
    if ( m_dfbwin->GetID(&winid) )
        gs_dfbWindowsMap.erase(winid);

    m_dfbwin->Destroy();
    m_dfbwin.Reset();
}

// ----------------------------------------------------------------------------
// window size & position
// ----------------------------------------------------------------------------

void wxNonOwnedWindow::DoGetPosition(int *x, int *y) const
{
    m_dfbwin->GetPosition(x, y);
}

void wxNonOwnedWindow::DoGetSize(int *width, int *height) const
{
    m_dfbwin->GetSize(width, height);
}

void wxNonOwnedWindow::DoMoveWindow(int x, int y, int width, int height)
{
    wxPoint curpos = GetPosition();
    if ( curpos.x != x || curpos.y != y )
    {
        m_dfbwin->MoveTo(x, y);
    }

    wxSize cursize = GetSize();
    if ( cursize.x != width || cursize.y != height )
    {
        // changing window's size changes its surface:
        InvalidateDfbSurface();

        m_dfbwin->Resize(width, height);

        // we must repaint the window after it changed size:
        if ( IsShown() )
            DoRefreshWindow();
    }
}

// ----------------------------------------------------------------------------
// showing and hiding
// ----------------------------------------------------------------------------

bool wxNonOwnedWindow::Show(bool show)
{
    // NB: this calls wxWindow::Show() and so ensures DoRefreshWindow() is
    //     called on the window -- we'll need that below
    if ( !wxWindow::Show(show) )
        return false;

    // If this is the first time Show was called, send size event,
    // so that the frame can adjust itself (think auto layout or single child)
    if ( !m_sizeSet )
    {
        m_sizeSet = true;
        wxSizeEvent event(GetSize(), GetId());
        event.SetEventObject(this);
        HandleWindowEvent(event);
    }

    // make sure the window is fully painted, with all pending updates, before
    // DFB WM shows it, otherwise it would attempt to show either empty (=
    // black) window surface (if shown for the first time) or it would show
    // window with outdated content; note that the window was already refreshed
    // in the wxWindow::Show() call above:
    if ( show )
        Update();

    // hide/show the window by setting its opacity to 0/full:
    m_dfbwin->SetOpacity(show ? m_opacity : 0);

    if ( show )
    {
        wxWindow *focused = FindFocus();
        if ( focused && focused->GetTLW() == this )
        {
            // focus is on this frame or its children, apply it to DirectFB
            SetDfbFocus();
        }
        // else: don't do anything, if this is wxFrame or wxDialog that should
        //       get focus when it's shown,
        //       wxTopLevelWindowDFB::HandleFocusEvent() will do it as soon as
        //       the event loop starts
    }

    return true;
}

void wxNonOwnedWindow::Raise()
{
    m_dfbwin->RaiseToTop();
}

void wxNonOwnedWindow::Lower()
{
    m_dfbwin->LowerToBottom();
}

// ----------------------------------------------------------------------------
// surfaces and painting
// ----------------------------------------------------------------------------

wxIDirectFBSurfacePtr wxNonOwnedWindow::ObtainDfbSurface() const
{
    return m_dfbwin->GetSurface();
}

void wxNonOwnedWindow::HandleQueuedPaintRequests()
{
    if ( m_toPaint->IsEmpty() )
        return; // nothing to do

    if ( IsFrozen() || !IsShown() )
    {
        // nothing to do if the window is frozen or hidden; clear the queue
        // and return (note that it's OK to clear the queue even if the window
        // is frozen, because Thaw() calls Refresh()):
        m_toPaint->Clear();
        return;
    }

    // process queued paint requests:
    wxRect winRect(wxPoint(0, 0), GetSize());
    wxRect paintedRect;

    // important note: all DCs created from now until m_isPainting is reset to
    // false will not update the front buffer as this flag indicates that we'll
    // blit the entire back buffer to front soon
    m_isPainting = true;

    int requestsCount = 0;

    wxRect request;
    while ( m_toPaint->GetNext(request) )
    {
        requestsCount++;
        wxRect clipped(request);
        clipped.Intersect(winRect);
        if ( clipped.IsEmpty() )
            continue; // nothing to refresh

        wxLogTrace(TRACE_PAINT,
                   "%p ('%s'): processing paint request [%i,%i,%i,%i]",
                   this, GetName().c_str(),
                   clipped.x, clipped.y, clipped.GetRight(), clipped.GetBottom());

        PaintWindow(clipped);

        // remember rectangle covering all repainted areas:
        if ( paintedRect.IsEmpty() )
            paintedRect = clipped;
        else
            paintedRect.Union(clipped);
    }

    m_isPainting = false;

    m_toPaint->Clear();

    if ( paintedRect.IsEmpty() )
        return; // no painting occurred, no need to flip

    // Flip the surface to make the changes visible. Note that the rectangle we
    // flip is *superset* of the union of repainted rectangles (created as
    // "rectangles union" by wxRect::Union) and so some parts of the back
    // buffer that we didn't touch in this HandleQueuedPaintRequests call will
    // be copied to the front buffer as well. This is safe/correct thing to do
    // *only* because wx always use wxIDirectFBSurface::FlipToFront() and so
    // the back and front buffers contain the same data.
    //
    // Note that we do _not_ split m_toPaint into disjoint rectangles and
    // do FlipToFront() for each of them, because that could result in visible
    // updating of the screen; instead, we prefer to flip everything at once.

    DFBRegion r = {paintedRect.GetLeft(), paintedRect.GetTop(),
                   paintedRect.GetRight(), paintedRect.GetBottom()};
    DFBRegion *rptr = (winRect == paintedRect) ? NULL : &r;

    GetDfbSurface()->FlipToFront(rptr);

    wxLogTrace(TRACE_PAINT,
               "%p ('%s'): processed %i paint requests, flipped surface: [%i,%i,%i,%i]",
               this, GetName().c_str(),
               requestsCount,
               paintedRect.x, paintedRect.y,
               paintedRect.GetRight(), paintedRect.GetBottom());
}

void wxNonOwnedWindow::DoRefreshRect(const wxRect& rect)
{
    // don't overlap outside of the window (NB: 'rect' is in window coords):
    wxRect r(rect);
    r.Intersect(wxRect(GetSize()));
    if ( r.IsEmpty() )
        return;

    wxLogTrace(TRACE_PAINT,
               "%p ('%s'): [TLW] refresh rect [%i,%i,%i,%i]",
               this, GetName().c_str(),
               rect.x, rect.y, rect.GetRight(), rect.GetBottom());

    // defer painting until idle time or until Update() is called:
    m_toPaint->Add(rect);
}

void wxNonOwnedWindow::Update()
{
    HandleQueuedPaintRequests();
}

// ---------------------------------------------------------------------------
// events handling
// ---------------------------------------------------------------------------

namespace
{

static wxNonOwnedWindow *gs_insideDFBFocusHandlerOf = NULL;

struct InsideDFBFocusHandlerSetter
{
    InsideDFBFocusHandlerSetter(wxNonOwnedWindow *win)
    {
        wxASSERT( gs_insideDFBFocusHandlerOf == NULL );
        gs_insideDFBFocusHandlerOf = win;
    }
    ~InsideDFBFocusHandlerSetter()
    {
        gs_insideDFBFocusHandlerOf = NULL;
    }
};

} // anonymous namespace


void wxNonOwnedWindow::SetDfbFocus()
{
    wxCHECK_RET( IsShown(), "cannot set focus to hidden window" );
    wxASSERT_MSG( FindFocus() && FindFocus()->GetTLW() == this,
                  "setting DirectFB focus to unexpected window" );

    // Don't set DirectFB focus if we're called from HandleFocusEvent() on
    // this window, because we already have the focus in that case. Not only
    // would it be unnecessary, it would be harmful: RequestFocus() adds
    // an event to DirectFB event queue and calling it when in
    // HandleFocusEvent() could result in a window being focused when it
    // should not be. Consider this example:
    //
    //     tlw1->SetFocus(); // (1)
    //     tlw2->SetFocus(); // (2)
    //
    // This results in adding these events to DFB queue:
    //
    //     DWET_GOTFOCUS(tlw1)
    //     DWET_LOSTFOCUS(tlw1)
    //     DWET_GOTFOCUS(tlw2)
    //
    // Note that the events are processed by event loop, i.e. not between
    // execution of lines (1) and (2) above. So by the time the first
    // DWET_GOTFOCUS event is handled, tlw2->SetFocus() was already executed.
    // If we onconditionally called RequestFocus() from here, handling the
    // first event would result in this change to the event queue:
    //
    //     DWET_LOSTFOCUS(tlw1)
    //     DWET_GOTFOCUS(tlw2) // (3)
    //     DWET_LOSTFOCUS(tlw2)
    //     DWET_GOTFOCUS(tlw1)
    //
    // And the focus would get back to tlw1 even though that's not what we
    // wanted.

    if ( gs_insideDFBFocusHandlerOf == this )
        return;

    GetDirectFBWindow()->RequestFocus();
}

/* static */
void wxNonOwnedWindow::HandleDFBWindowEvent(const wxDFBWindowEvent& event_)
{
    const DFBWindowEvent& event = event_;

    if ( gs_dfbWindowsMap.find(event.window_id) == gs_dfbWindowsMap.end() )
    {
        wxLogTrace(TRACE_EVENTS,
                   "received event for unknown DirectFB window, ignoring");
        return;
    }

    wxNonOwnedWindow *tlw = gs_dfbWindowsMap[event.window_id];

    switch ( event.type )
    {
        case DWET_KEYDOWN:
        case DWET_KEYUP:
        {
            wxWindow *recipient = wxWindow::FindFocus();
            if ( !recipient )
            {
                wxLogTrace(TRACE_EVENTS,
                           "ignoring event: no recipient window");
                return;
            }

            wxCHECK_RET( recipient && recipient->GetTLW() == tlw,
                         "event recipient not in TLW which received the event" );

            recipient->HandleKeyEvent(event_);
            break;
        }

        case DWET_GOTFOCUS:
        case DWET_LOSTFOCUS:
            {
                InsideDFBFocusHandlerSetter inside(tlw);
                tlw->HandleFocusEvent(event_);
            }
            break;

        case DWET_NONE:
        case DWET_ALL:
            wxFAIL_MSG( "invalid event type" );
            break;

        default:
            // we're not interested in them here
            break;
    }
}

// ---------------------------------------------------------------------------
// idle events processing
// ---------------------------------------------------------------------------

void wxNonOwnedWindow::OnInternalIdle()
{
    wxWindow::OnInternalIdle();
    HandleQueuedPaintRequests();
}
