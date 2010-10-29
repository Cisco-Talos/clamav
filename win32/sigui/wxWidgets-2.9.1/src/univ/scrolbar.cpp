/////////////////////////////////////////////////////////////////////////////
// Name:        src/univ/scrolbar.cpp
// Purpose:     wxScrollBar implementation
// Author:      Vadim Zeitlin
// Modified by:
// Created:     20.08.00
// RCS-ID:      $Id$
// Copyright:   (c) 2000 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_SCROLLBAR

#include "wx/scrolbar.h"

#ifndef WX_PRECOMP
    #include "wx/timer.h"
    #include "wx/dcclient.h"
    #include "wx/validate.h"
    #include "wx/log.h"
#endif

#include "wx/univ/scrtimer.h"

#include "wx/univ/renderer.h"
#include "wx/univ/inphand.h"
#include "wx/univ/theme.h"

#if wxDEBUG_LEVEL >= 2
    #define WXDEBUG_SCROLLBAR
#endif

#if defined(WXDEBUG_SCROLLBAR) && defined(__WXMSW__) && !defined(__WXMICROWIN__)
#include "wx/msw/private.h"
#endif

// ----------------------------------------------------------------------------
// wxScrollBarTimer: this class is used to repeatedly scroll the scrollbar
// when the mouse is help pressed on the arrow or on the bar. It generates the
// given scroll action command periodically.
// ----------------------------------------------------------------------------

class wxScrollBarTimer : public wxScrollTimer
{
public:
    wxScrollBarTimer(wxStdScrollBarInputHandler *handler,
                     const wxControlAction& action,
                     wxScrollBar *control);

protected:
    virtual bool DoNotify();

private:
    wxStdScrollBarInputHandler *m_handler;
    wxControlAction m_action;
    wxScrollBar    *m_control;
};

// ============================================================================
// implementation
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxScrollBar, wxControl)

BEGIN_EVENT_TABLE(wxScrollBar, wxScrollBarBase)
END_EVENT_TABLE()

// ----------------------------------------------------------------------------
// creation
// ----------------------------------------------------------------------------

#ifdef __VISUALC__
    // warning C4355: 'this' : used in base member initializer list
    #pragma warning(disable:4355)  // so what? disable it...
#endif

wxScrollBar::wxScrollBar()
           : m_arrows(this)
{
    Init();
}

wxScrollBar::wxScrollBar(wxWindow *parent,
                         wxWindowID id,
                         const wxPoint& pos,
                         const wxSize& size,
                         long style,
                         const wxValidator& validator,
                         const wxString& name)
           : m_arrows(this)
{
    Init();

    (void)Create(parent, id, pos, size, style, validator, name);
}

#ifdef __VISUALC__
    // warning C4355: 'this' : used in base member initializer list
    #pragma warning(default:4355)
#endif

void wxScrollBar::Init()
{
    m_range =
    m_thumbSize =
    m_thumbPos =
    m_pageSize = 0;

    m_thumbPosOld = -1;

    for ( size_t n = 0; n < WXSIZEOF(m_elementsState); n++ )
    {
        m_elementsState[n] = 0;
    }

    m_dirty = false;
}

bool wxScrollBar::Create(wxWindow *parent,
                         wxWindowID id,
                         const wxPoint &pos,
                         const wxSize &size,
                         long style,
                         const wxValidator& validator,
                         const wxString &name)
{
    // the scrollbars never have the border
    style &= ~wxBORDER_MASK;

    if ( !wxControl::Create(parent, id, pos, size, style, validator, name) )
        return false;

    SetInitialSize(size);

    // override the cursor of the target window (if any)
    SetCursor(wxCURSOR_ARROW);

    CreateInputHandler(wxINP_HANDLER_SCROLLBAR);

    return true;
}

wxScrollBar::~wxScrollBar()
{
}

// ----------------------------------------------------------------------------
// misc accessors
// ----------------------------------------------------------------------------

bool wxScrollBar::IsStandalone() const
{
    wxWindow *parent = GetParent();
    if ( !parent )
    {
        return true;
    }

    return (parent->GetScrollbar(wxHORIZONTAL) != this) &&
           (parent->GetScrollbar(wxVERTICAL) != this);
}

bool wxScrollBar::AcceptsFocus() const
{
    // the window scrollbars never accept focus
    return wxScrollBarBase::AcceptsFocus() && IsStandalone();
}

// ----------------------------------------------------------------------------
// scrollbar API
// ----------------------------------------------------------------------------

void wxScrollBar::DoSetThumb(int pos)
{
    // don't assert hecks here, we're a private function which is meant to be
    // called with any args at all
    if ( pos < 0 )
    {
        pos = 0;
    }
    else if ( pos > m_range - m_thumbSize )
    {
        pos = m_range - m_thumbSize;
    }

    if ( m_thumbPos == pos )
    {
        // nothing changed, avoid refreshes which would provoke flicker
        return;
    }

    if ( m_thumbPosOld == -1 )
    {
        // remember the old thumb position
        m_thumbPosOld = m_thumbPos;
    }

    m_thumbPos = pos;

    // we have to refresh the part of the bar which was under the thumb and the
    // thumb itself
    m_elementsState[Element_Thumb] |= wxCONTROL_DIRTY;
    m_elementsState[m_thumbPos > m_thumbPosOld
                        ? Element_Bar_1 : Element_Bar_2] |= wxCONTROL_DIRTY;
    m_dirty = true;
}

int wxScrollBar::GetThumbPosition() const
{
    return m_thumbPos;
}

int wxScrollBar::GetThumbSize() const
{
    return m_thumbSize;
}

int wxScrollBar::GetPageSize() const
{
    return m_pageSize;
}

int wxScrollBar::GetRange() const
{
    return m_range;
}

void wxScrollBar::SetThumbPosition(int pos)
{
    wxCHECK_RET( pos >= 0 && pos <= m_range, wxT("thumb position out of range") );

    DoSetThumb(pos);
}

void wxScrollBar::SetScrollbar(int position, int thumbSize,
                               int range, int pageSize,
                               bool refresh)
{
    // we only refresh everything when the range changes, thumb position
    // changes are handled in OnIdle
    bool needsRefresh = (range != m_range) ||
                        (thumbSize != m_thumbSize) ||
                        (pageSize != m_pageSize);

    // set all parameters
    m_range = range;
    m_thumbSize = thumbSize;
    SetThumbPosition(position);
    m_pageSize = pageSize;

    // ignore refresh parameter unless we really need to refresh everything -
    // there ir a lot of existing code which just calls SetScrollbar() without
    // specifying the last parameter even though it doesn't need at all to
    // refresh the window immediately
    if ( refresh && needsRefresh )
    {
        // and update the window
        Refresh();
        Update();
    }
}

// ----------------------------------------------------------------------------
// geometry
// ----------------------------------------------------------------------------

wxSize wxScrollBar::DoGetBestClientSize() const
{
    // this dimension is completely arbitrary
    static const wxCoord SIZE = 140;

    wxSize size = m_renderer->GetScrollbarArrowSize();
    if ( IsVertical() )
    {
        size.y = SIZE;
    }
    else // horizontal
    {
        size.x = SIZE;
    }

    return size;
}

wxScrollArrows::Arrow wxScrollBar::HitTestArrow(const wxPoint& pt) const
{
    switch ( HitTestBar(pt) )
    {
        case wxHT_SCROLLBAR_ARROW_LINE_1:
            return wxScrollArrows::Arrow_First;

        case wxHT_SCROLLBAR_ARROW_LINE_2:
            return wxScrollArrows::Arrow_Second;

        default:
            return wxScrollArrows::Arrow_None;
    }
}

wxHitTest wxScrollBar::HitTestBar(const wxPoint& pt) const
{
    // we only need to work with either x or y coord depending on the
    // orientation, choose one (but still check the other one to verify if the
    // mouse is in the window at all)
    const wxSize sizeArrowSB = m_renderer->GetScrollbarArrowSize();

    wxCoord coord, sizeArrow, sizeTotal;
    wxSize size = GetSize();
    if ( GetWindowStyle() & wxVERTICAL )
    {
        if ( pt.x < 0 || pt.x > size.x )
            return wxHT_NOWHERE;

        coord = pt.y;
        sizeArrow = sizeArrowSB.y;
        sizeTotal = size.y;
    }
    else // horizontal
    {
        if ( pt.y < 0 || pt.y > size.y )
            return wxHT_NOWHERE;

        coord = pt.x;
        sizeArrow = sizeArrowSB.x;
        sizeTotal = size.x;
    }

    // test for the arrows first as it's faster
    if ( coord < 0 || coord > sizeTotal )
    {
        return wxHT_NOWHERE;
    }
    else if ( coord < sizeArrow )
    {
        return wxHT_SCROLLBAR_ARROW_LINE_1;
    }
    else if ( coord > sizeTotal - sizeArrow )
    {
        return wxHT_SCROLLBAR_ARROW_LINE_2;
    }
    else
    {
        // calculate the thumb position in pixels
        sizeTotal -= 2*sizeArrow;
        wxCoord thumbStart, thumbEnd;
        int range = GetRange();
        if ( !range )
        {
            // clicking the scrollbar without range has no effect
            return wxHT_NOWHERE;
        }
        else
        {
            GetScrollBarThumbSize(sizeTotal,
                                  GetThumbPosition(),
                                  GetThumbSize(),
                                  range,
                                  &thumbStart,
                                  &thumbEnd);
        }

        // now compare with the thumb position
        coord -= sizeArrow;
        if ( coord < thumbStart )
            return wxHT_SCROLLBAR_BAR_1;
        else if ( coord > thumbEnd )
            return wxHT_SCROLLBAR_BAR_2;
        else
            return wxHT_SCROLLBAR_THUMB;
    }
}

/* static */
void wxScrollBar::GetScrollBarThumbSize(wxCoord length,
                                        int thumbPos,
                                        int thumbSize,
                                        int range,
                                        wxCoord *thumbStart,
                                        wxCoord *thumbEnd)
{
    // the thumb can't be made less than this number of pixels
    static const wxCoord thumbMinWidth = 8; // FIXME: should be configurable

    *thumbStart = (length*thumbPos) / range;
    *thumbEnd = (length*(thumbPos + thumbSize)) / range;

    if ( *thumbEnd - *thumbStart < thumbMinWidth )
    {
        // adjust the end if possible
        if ( *thumbStart <= length - thumbMinWidth )
        {
            // yes, just make it wider
            *thumbEnd = *thumbStart + thumbMinWidth;
        }
        else // it is at the bottom of the scrollbar
        {
            // so move it a bit up
            *thumbStart = length - thumbMinWidth;
            *thumbEnd = length;
        }
    }
}

wxRect wxScrollBar::GetScrollbarRect(wxScrollBar::Element elem,
                                     int thumbPos) const
{
    if ( thumbPos == -1 )
    {
        thumbPos = GetThumbPosition();
    }

    const wxSize sizeArrow = m_renderer->GetScrollbarArrowSize();

    wxSize sizeTotal = GetClientSize();
    wxCoord *start, *width;
    wxCoord length, arrow;
    wxRect rect;
    if ( IsVertical() )
    {
        rect.x = 0;
        rect.width = sizeTotal.x;
        length = sizeTotal.y;
        start = &rect.y;
        width = &rect.height;
        arrow = sizeArrow.y;
    }
    else // horizontal
    {
        rect.y = 0;
        rect.height = sizeTotal.y;
        length = sizeTotal.x;
        start = &rect.x;
        width = &rect.width;
        arrow = sizeArrow.x;
    }

    switch ( elem )
    {
        case wxScrollBar::Element_Arrow_Line_1:
            *start = 0;
            *width = arrow;
            break;

        case wxScrollBar::Element_Arrow_Line_2:
            *start = length - arrow;
            *width = arrow;
            break;

        case wxScrollBar::Element_Arrow_Page_1:
        case wxScrollBar::Element_Arrow_Page_2:
            // we don't have them at all
            break;

        case wxScrollBar::Element_Thumb:
        case wxScrollBar::Element_Bar_1:
        case wxScrollBar::Element_Bar_2:
            // we need to calculate the thumb position - do it
            {
                length -= 2*arrow;
                wxCoord thumbStart, thumbEnd;
                int range = GetRange();
                if ( !range )
                {
                    thumbStart =
                    thumbEnd = 0;
                }
                else
                {
                    GetScrollBarThumbSize(length,
                                          thumbPos,
                                          GetThumbSize(),
                                          range,
                                          &thumbStart,
                                          &thumbEnd);
                }

                if ( elem == wxScrollBar::Element_Thumb )
                {
                    *start = thumbStart;
                    *width = thumbEnd - thumbStart;
                }
                else if ( elem == wxScrollBar::Element_Bar_1 )
                {
                    *start = 0;
                    *width = thumbStart;
                }
                else // elem == wxScrollBar::Element_Bar_2
                {
                    *start = thumbEnd;
                    *width = length - thumbEnd;
                }

                // everything is relative to the start of the shaft so far
                *start += arrow;
            }
            break;

        case wxScrollBar::Element_Max:
        default:
            wxFAIL_MSG( wxT("unknown scrollbar element") );
    }

    return rect;
}

wxCoord wxScrollBar::GetScrollbarSize() const
{
    const wxSize sizeArrowSB = m_renderer->GetScrollbarArrowSize();

    wxCoord sizeArrow, sizeTotal;
    if ( GetWindowStyle() & wxVERTICAL )
    {
        sizeArrow = sizeArrowSB.y;
        sizeTotal = GetSize().y;
    }
    else // horizontal
    {
        sizeArrow = sizeArrowSB.x;
        sizeTotal = GetSize().x;
    }

    return sizeTotal - 2*sizeArrow;
}


wxCoord wxScrollBar::ScrollbarToPixel(int thumbPos)
{
    int range = GetRange();
    if ( !range )
    {
        // the only valid position anyhow
        return 0;
    }

    if ( thumbPos == -1 )
    {
        // by default use the current thumb position
        thumbPos = GetThumbPosition();
    }

    const wxSize sizeArrow = m_renderer->GetScrollbarArrowSize();
    return (thumbPos * GetScrollbarSize()) / range
             + (IsVertical() ? sizeArrow.y : sizeArrow.x);
}

int wxScrollBar::PixelToScrollbar(wxCoord coord)
{
    const wxSize sizeArrow = m_renderer->GetScrollbarArrowSize();
    return ((coord - (IsVertical() ? sizeArrow.y : sizeArrow.x)) *
               GetRange() ) / GetScrollbarSize();
}

// ----------------------------------------------------------------------------
// drawing
// ----------------------------------------------------------------------------

void wxScrollBar::OnInternalIdle()
{
    UpdateThumb();
    wxControl::OnInternalIdle();
}

void wxScrollBar::UpdateThumb()
{
    if ( m_dirty )
    {
        for ( size_t n = 0; n < WXSIZEOF(m_elementsState); n++ )
        {
            if ( m_elementsState[n] & wxCONTROL_DIRTY )
            {
                wxRect rect = GetScrollbarRect((Element)n);

                if ( rect.width && rect.height )
                {
                    // we try to avoid redrawing the entire shaft (which might
                    // be quite long) if possible by only redrawing the area
                    // wich really changed
                    if ( (n == Element_Bar_1 || n == Element_Bar_2) &&
                            (m_thumbPosOld != -1) )
                    {
                        // the less efficient but more reliable (i.e. this will
                        // probably work everywhere) version: refresh the
                        // distance covered by thumb since the last update
#if 0
                        wxRect rectOld =
                            GetRenderer()->GetScrollbarRect(this,
                                                            (Element)n,
                                                            m_thumbPosOld);
                        if ( IsVertical() )
                        {
                            if ( n == Element_Bar_1 )
                                rect.SetTop(rectOld.GetBottom());
                            else
                                rect.SetBottom(rectOld.GetBottom());
                        }
                        else // horizontal
                        {
                            if ( n == Element_Bar_1 )
                                rect.SetLeft(rectOld.GetRight());
                            else
                                rect.SetRight(rectOld.GetRight());
                        }
#else                   // efficient version: only repaint the area occupied by
                        // the thumb previously - we can't do better than this
                        rect = GetScrollbarRect(Element_Thumb, m_thumbPosOld);
#endif // 0/1
                    }

#ifdef WXDEBUG_SCROLLBAR
        static bool s_refreshDebug = false;
        if ( s_refreshDebug )
        {
            wxClientDC dc(this);
            dc.SetBrush(*wxCYAN_BRUSH);
            dc.SetPen(*wxTRANSPARENT_PEN);
            dc.DrawRectangle(rect);

            // under Unix we use "--sync" X option for this
            #if defined(__WXMSW__) && !defined(__WXMICROWIN__)
                ::GdiFlush();
                ::Sleep(200);
            #endif // __WXMSW__
        }
#endif // WXDEBUG_SCROLLBAR

                    Refresh(false, &rect);
                }

                m_elementsState[n] &= ~wxCONTROL_DIRTY;
            }
        }

        m_dirty = false;
    }
}

void wxScrollBar::DoDraw(wxControlRenderer *renderer)
{
    renderer->DrawScrollbar(this, m_thumbPosOld);

    // clear all dirty flags
    m_dirty = false;
    m_thumbPosOld = -1;
}

// ----------------------------------------------------------------------------
// state flags
// ----------------------------------------------------------------------------

static inline wxScrollBar::Element ElementForArrow(wxScrollArrows::Arrow arrow)
{
    return arrow == wxScrollArrows::Arrow_First
            ? wxScrollBar::Element_Arrow_Line_1
            : wxScrollBar::Element_Arrow_Line_2;
}

int wxScrollBar::GetArrowState(wxScrollArrows::Arrow arrow) const
{
    return GetState(ElementForArrow(arrow));
}

void wxScrollBar::SetArrowFlag(wxScrollArrows::Arrow arrow, int flag, bool set)
{
    Element which = ElementForArrow(arrow);
    int state = GetState(which);
    if ( set )
        state |= flag;
    else
        state &= ~flag;

    SetState(which, state);
}

int wxScrollBar::GetState(Element which) const
{
    // if the entire scrollbar is disabled, all of its elements are too
    int flags = m_elementsState[which];
    if ( !IsEnabled() )
        flags |= wxCONTROL_DISABLED;

    return flags;
}

void wxScrollBar::SetState(Element which, int flags)
{
    if ( (int)(m_elementsState[which] & ~wxCONTROL_DIRTY) != flags )
    {
        m_elementsState[which] = flags | wxCONTROL_DIRTY;

        m_dirty = true;
    }
}

// ----------------------------------------------------------------------------
// input processing
// ----------------------------------------------------------------------------

bool wxScrollBar::OnArrow(wxScrollArrows::Arrow arrow)
{
    int oldThumbPos = GetThumbPosition();
    PerformAction(arrow == wxScrollArrows::Arrow_First
                    ? wxACTION_SCROLL_LINE_UP
                    : wxACTION_SCROLL_LINE_DOWN);

    // did we scroll till the end?
    return GetThumbPosition() != oldThumbPos;
}

bool wxScrollBar::PerformAction(const wxControlAction& action,
                                long numArg,
                                const wxString& strArg)
{
    int thumbOld = m_thumbPos;

    bool notify = false; // send an event about the change?

    wxEventType scrollType;

    // test for thumb move first as these events happen in quick succession
    if ( action == wxACTION_SCROLL_THUMB_MOVE )
    {
        DoSetThumb(numArg);

        // VS: we have to force redraw here, otherwise the thumb will lack
        //     behind mouse cursor
        UpdateThumb();

        scrollType = wxEVT_SCROLLWIN_THUMBTRACK;
    }
    else if ( action == wxACTION_SCROLL_LINE_UP )
    {
        scrollType = wxEVT_SCROLLWIN_LINEUP;
        ScrollLines(-1);
    }
    else if ( action == wxACTION_SCROLL_LINE_DOWN )
    {
        scrollType = wxEVT_SCROLLWIN_LINEDOWN;
        ScrollLines(1);
    }
    else if ( action == wxACTION_SCROLL_PAGE_UP )
    {
        scrollType = wxEVT_SCROLLWIN_PAGEUP;
        ScrollPages(-1);
    }
    else if ( action == wxACTION_SCROLL_PAGE_DOWN )
    {
        scrollType = wxEVT_SCROLLWIN_PAGEDOWN;
        ScrollPages(1);
    }
    else if ( action == wxACTION_SCROLL_START )
    {
        scrollType = wxEVT_SCROLLWIN_THUMBRELEASE; // anything better?
        ScrollToStart();
    }
    else if ( action == wxACTION_SCROLL_END )
    {
        scrollType = wxEVT_SCROLLWIN_THUMBRELEASE; // anything better?
        ScrollToEnd();
    }
    else if ( action == wxACTION_SCROLL_THUMB_DRAG )
    {
        // we won't use it but this line suppresses the compiler
        // warning about "variable may be used without having been
        // initialized"
        scrollType = wxEVT_NULL;
    }
    else if ( action == wxACTION_SCROLL_THUMB_RELEASE )
    {
        // always notify about this
        notify = true;
        scrollType = wxEVT_SCROLLWIN_THUMBRELEASE;
    }
    else
        return wxControl::PerformAction(action, numArg, strArg);

    // has scrollbar position changed?
    bool changed = m_thumbPos != thumbOld;
    if ( notify || changed )
    {
        if ( IsStandalone() )
        {
            // we should generate EVT_SCROLL events for the standalone
            // scrollbars and not the EVT_SCROLLWIN ones
            //
            // NB: we assume that scrollbar events are sequentially numbered
            //     but this should be ok as other code relies on this as well
            scrollType += wxEVT_SCROLL_TOP - wxEVT_SCROLLWIN_TOP;
            wxScrollEvent event(scrollType, this->GetId(), m_thumbPos,
                                IsVertical() ? wxVERTICAL : wxHORIZONTAL);
            event.SetEventObject(this);
            GetEventHandler()->ProcessEvent(event);
        }
        else // part of the window
        {
            wxScrollWinEvent event(scrollType, m_thumbPos,
                                   IsVertical() ? wxVERTICAL : wxHORIZONTAL);
            event.SetEventObject(this);
            GetParent()->GetEventHandler()->ProcessEvent(event);
        }
    }

    return true;
}

void wxScrollBar::ScrollToStart()
{
    DoSetThumb(0);
}

void wxScrollBar::ScrollToEnd()
{
    DoSetThumb(m_range - m_thumbSize);
}

bool wxScrollBar::ScrollLines(int nLines)
{
    DoSetThumb(m_thumbPos + nLines);
    return true;
}

bool wxScrollBar::ScrollPages(int nPages)
{
    DoSetThumb(m_thumbPos + nPages*m_pageSize);
    return true;
}

/* static */
wxInputHandler *wxScrollBar::GetStdInputHandler(wxInputHandler *handlerDef)
{
    static wxStdScrollBarInputHandler
        s_handler(wxTheme::Get()->GetRenderer(), handlerDef);

    return &s_handler;
}

// ============================================================================
// scroll bar input handler
// ============================================================================

// ----------------------------------------------------------------------------
// wxScrollBarTimer
// ----------------------------------------------------------------------------

wxScrollBarTimer::wxScrollBarTimer(wxStdScrollBarInputHandler *handler,
                                   const wxControlAction& action,
                                   wxScrollBar *control)
{
    m_handler = handler;
    m_action = action;
    m_control = control;
}

bool wxScrollBarTimer::DoNotify()
{
    return m_handler->OnScrollTimer(m_control, m_action);
}

// ----------------------------------------------------------------------------
// wxStdScrollBarInputHandler
// ----------------------------------------------------------------------------

wxStdScrollBarInputHandler::wxStdScrollBarInputHandler(wxRenderer *renderer,
                                                       wxInputHandler *handler)
                          : wxStdInputHandler(handler)
{
    m_renderer = renderer;
    m_winCapture = NULL;
    m_htLast = wxHT_NOWHERE;
    m_timerScroll = NULL;
}

wxStdScrollBarInputHandler::~wxStdScrollBarInputHandler()
{
    // normally, it's NULL by now but just in case the user somehow managed to
    // keep the mouse captured until now...
    delete m_timerScroll;
}

void wxStdScrollBarInputHandler::SetElementState(wxScrollBar *control,
                                                 int flag,
                                                 bool doIt)
{
    if ( m_htLast > wxHT_SCROLLBAR_FIRST && m_htLast < wxHT_SCROLLBAR_LAST )
    {
        wxScrollBar::Element
            elem = (wxScrollBar::Element)(m_htLast - wxHT_SCROLLBAR_FIRST - 1);

        int flags = control->GetState(elem);
        if ( doIt )
            flags |= flag;
        else
            flags &= ~flag;
        control->SetState(elem, flags);
    }
}

bool wxStdScrollBarInputHandler::OnScrollTimer(wxScrollBar *scrollbar,
                                               const wxControlAction& action)
{
    int oldThumbPos = scrollbar->GetThumbPosition();
    scrollbar->PerformAction(action);
    if ( scrollbar->GetThumbPosition() != oldThumbPos )
        return true;

    // we scrolled till the end
    m_timerScroll->Stop();

    return false;
}

void wxStdScrollBarInputHandler::StopScrolling(wxScrollBar *control)
{
    // return everything to the normal state
    if ( m_winCapture )
    {
        m_winCapture->ReleaseMouse();
        m_winCapture = NULL;
    }

    m_btnCapture = -1;

    wxDELETE(m_timerScroll);

    // unpress the arrow and highlight the current element
    Press(control, false);
}

wxCoord
wxStdScrollBarInputHandler::GetMouseCoord(const wxScrollBar *scrollbar,
                                          const wxMouseEvent& event) const
{
    wxPoint pt = event.GetPosition();
    return scrollbar->GetWindowStyle() & wxVERTICAL ? pt.y : pt.x;
}

void wxStdScrollBarInputHandler::HandleThumbMove(wxScrollBar *scrollbar,
                                                 const wxMouseEvent& event)
{
    int thumbPos = GetMouseCoord(scrollbar, event) - m_ofsMouse;
    thumbPos = scrollbar->PixelToScrollbar(thumbPos);
    scrollbar->PerformAction(wxACTION_SCROLL_THUMB_MOVE, thumbPos);
}

bool wxStdScrollBarInputHandler::HandleKey(wxInputConsumer *consumer,
                                           const wxKeyEvent& event,
                                           bool pressed)
{
    // we only react to the key presses here
    if ( pressed )
    {
        wxControlAction action;
        switch ( event.GetKeyCode() )
        {
            case WXK_DOWN:
            case WXK_RIGHT:     action = wxACTION_SCROLL_LINE_DOWN; break;
            case WXK_UP:
            case WXK_LEFT:      action = wxACTION_SCROLL_LINE_UP;   break;
            case WXK_HOME:      action = wxACTION_SCROLL_START;     break;
            case WXK_END:       action = wxACTION_SCROLL_END;       break;
            case WXK_PAGEUP:    action = wxACTION_SCROLL_PAGE_UP;   break;
            case WXK_PAGEDOWN:  action = wxACTION_SCROLL_PAGE_DOWN; break;
        }

        if ( !action.IsEmpty() )
        {
            consumer->PerformAction(action);

            return true;
        }
    }

    return wxStdInputHandler::HandleKey(consumer, event, pressed);
}

bool wxStdScrollBarInputHandler::HandleMouse(wxInputConsumer *consumer,
                                             const wxMouseEvent& event)
{
    // is this a click event from an acceptable button?
    int btn = event.GetButton();
    if ( btn == wxMOUSE_BTN_LEFT )
    {
        // determine which part of the window mouse is in
        wxScrollBar *scrollbar = wxStaticCast(consumer->GetInputWindow(), wxScrollBar);
        wxHitTest ht = scrollbar->HitTestBar(event.GetPosition());

        // when the mouse is pressed on any scrollbar element, we capture it
        // and hold capture until the same mouse button is released
        if ( event.ButtonDown() || event.ButtonDClick() )
        {
            if ( !m_winCapture )
            {
                m_btnCapture = btn;
                m_winCapture = consumer->GetInputWindow();
                m_winCapture->CaptureMouse();

                // generate the command
                bool hasAction = true;
                wxControlAction action;
                switch ( ht )
                {
                    case wxHT_SCROLLBAR_ARROW_LINE_1:
                        action = wxACTION_SCROLL_LINE_UP;
                        break;

                    case wxHT_SCROLLBAR_ARROW_LINE_2:
                        action = wxACTION_SCROLL_LINE_DOWN;
                        break;

                    case wxHT_SCROLLBAR_BAR_1:
                        action = wxACTION_SCROLL_PAGE_UP;
                        m_ptStartScrolling = event.GetPosition();
                        break;

                    case wxHT_SCROLLBAR_BAR_2:
                        action = wxACTION_SCROLL_PAGE_DOWN;
                        m_ptStartScrolling = event.GetPosition();
                        break;

                    case wxHT_SCROLLBAR_THUMB:
                        consumer->PerformAction(wxACTION_SCROLL_THUMB_DRAG);
                        m_ofsMouse = GetMouseCoord(scrollbar, event) -
                                     scrollbar->ScrollbarToPixel();

                        // fall through: there is no immediate action

                    default:
                        hasAction = false;
                }

                // remove highlighting
                Highlight(scrollbar, false);
                m_htLast = ht;

                // and press the arrow or highlight thumb now instead
                if ( m_htLast == wxHT_SCROLLBAR_THUMB )
                    Highlight(scrollbar, true);
                else
                    Press(scrollbar, true);

                // start dragging
                if ( hasAction )
                {
                    m_timerScroll = new wxScrollBarTimer(this, action,
                                                         scrollbar);
                    m_timerScroll->StartAutoScroll();
                }
                //else: no (immediate) action

            }
            //else: mouse already captured, nothing to do
        }
        // release mouse if the *same* button went up
        else if ( btn == m_btnCapture )
        {
            if ( m_winCapture )
            {
                StopScrolling(scrollbar);

                // if we were dragging the thumb, send the last event
                if ( m_htLast == wxHT_SCROLLBAR_THUMB )
                {
                    scrollbar->PerformAction(wxACTION_SCROLL_THUMB_RELEASE);
                }

                m_htLast = ht;
                Highlight(scrollbar, true);
            }
            else
            {
                // this is not supposed to happen as the button can't go up
                // without going down previously and then we'd have
                // m_winCapture by now
                wxFAIL_MSG( wxT("logic error in mouse capturing code") );
            }
        }
    }

    return wxStdInputHandler::HandleMouse(consumer, event);
}

bool wxStdScrollBarInputHandler::HandleMouseMove(wxInputConsumer *consumer,
                                                 const wxMouseEvent& event)
{
    wxScrollBar *scrollbar = wxStaticCast(consumer->GetInputWindow(), wxScrollBar);

    if ( m_winCapture )
    {
        if ( (m_htLast == wxHT_SCROLLBAR_THUMB) && event.Dragging() )
        {
            // make the thumb follow the mouse by keeping the same offset
            // between the mouse position and the top/left of the thumb
            HandleThumbMove(scrollbar, event);

            return true;
        }

        // no other changes are possible while the mouse is captured
        return false;
    }

    bool isArrow = scrollbar->GetArrows().HandleMouseMove(event);

    if ( event.Dragging() )
    {
        wxHitTest ht = scrollbar->HitTestBar(event.GetPosition());
        if ( ht == m_htLast )
        {
            // nothing changed
            return false;
        }

#ifdef DEBUG_MOUSE
        wxLogDebug("Scrollbar::OnMouseMove: ht = %d", ht);
#endif // DEBUG_MOUSE

        Highlight(scrollbar, false);
        m_htLast = ht;

        if ( !isArrow )
            Highlight(scrollbar, true);
        //else: already done by wxScrollArrows::HandleMouseMove
    }
    else if ( event.Leaving() )
    {
        if ( !isArrow )
            Highlight(scrollbar, false);

        m_htLast = wxHT_NOWHERE;
    }
    else // event.Entering()
    {
        // we don't process this event
        return false;
    }

    // we did something
    return true;
}

#endif // wxUSE_SCROLLBAR

#if wxUSE_TIMER

// ----------------------------------------------------------------------------
// wxScrollTimer
// ----------------------------------------------------------------------------

wxScrollTimer::wxScrollTimer()
{
    m_skipNext = false;
}

void wxScrollTimer::StartAutoScroll()
{
    // start scrolling immediately
    if ( !DoNotify() )
    {
        // ... and end it too
        return;
    }

    // there is an initial delay before the scrollbar starts scrolling -
    // implement it by ignoring the first timer expiration and only start
    // scrolling from the second one
    m_skipNext = true;
    Start(200); // FIXME: hardcoded delay
}

void wxScrollTimer::Notify()
{
    if ( m_skipNext )
    {
        // scroll normally now - reduce the delay
        Stop();
        Start(50); // FIXME: hardcoded delay

        m_skipNext = false;
    }
    else
    {
        // if DoNotify() returns false, we're already deleted by the timer
        // event handler, so don't do anything else here
        (void)DoNotify();
    }
}

#endif // wxUSE_TIMER
