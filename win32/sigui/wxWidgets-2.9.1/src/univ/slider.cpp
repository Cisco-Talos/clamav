///////////////////////////////////////////////////////////////////////////////
// Name:        src/univ/slider.cpp
// Purpose:     implementation of the universal version of wxSlider
// Author:      Vadim Zeitlin
// Modified by:
// Created:     09.02.01
// RCS-ID:      $Id$
// Copyright:   (c) 2001 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

/*
   There is some discrepancy in wxSL_LABELS style handling between wxMSW and
   wxGTK: the latter handles it natively and shows only the current value of
   the slider on the side corresponding to wxSL_TOP/BOTTOM/LEFT/RIGHT style
   given (which can be combined with wxSL_HORIZONTAL/VERTICAL) while wxMSW
   emulates this somehow and shows the min and max values near the ends of the
   slider and the current value in a separate static box nearby.

   We currently follow wxGTK except that wxSL_HORIZONTAL slider can only have
   the label displayed on top or bottom of it and wxSL_VERTICAL - to the left
   or right.

   What we really need is probably a more fine grain control on labels, i.e. we
   should be able to select if we show nothing at all, the current value only
   or the value and the limits - the current approach is just that of the
   lowest common denominator.

   TODO:

  +0. add ticks support
   1. support for all orientations
   2. draw the slider thumb highlighted when it is dragged
  ?3. manual ticks support?
 */

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

#if wxUSE_SLIDER

#include "wx/slider.h"

#ifndef WX_PRECOMP
    #include "wx/dc.h"
#endif

#include "wx/univ/renderer.h"
#include "wx/univ/inphand.h"
#include "wx/univ/theme.h"

// ----------------------------------------------------------------------------
// wxStdSliderInputHandler: default slider input handling
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxStdSliderInputHandler : public wxStdInputHandler
{
public:
    // default ctor
    wxStdSliderInputHandler(wxInputHandler *inphand)
        : wxStdInputHandler(inphand)
    {
    }

    // base class methods
    virtual bool HandleKey(wxInputConsumer *consumer,
                           const wxKeyEvent& event,
                           bool pressed);
    virtual bool HandleMouse(wxInputConsumer *consumer,
                             const wxMouseEvent& event);
    virtual bool HandleMouseMove(wxInputConsumer *consumer,
                                 const wxMouseEvent& event);

    virtual bool HandleFocus(wxInputConsumer *consumer, const wxFocusEvent& event);
};

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// the margin between the slider and the label (FIXME: hardcoded)
static const wxCoord SLIDER_LABEL_MARGIN = 2;

// ============================================================================
// implementation of wxSlider
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxSlider, wxControl)

BEGIN_EVENT_TABLE(wxSlider, wxControl)
    EVT_SIZE(wxSlider::OnSize)
END_EVENT_TABLE()

// ----------------------------------------------------------------------------
// wxSlider creation
// ----------------------------------------------------------------------------

#ifdef __VISUALC__
    // warning C4355: 'this' : used in base member initializer list
    #pragma warning(disable:4355)
#endif

wxSlider::wxSlider()
        : m_thumb(this)
{
    Init();
}

wxSlider::wxSlider(wxWindow *parent,
                   wxWindowID id,
                   int value, int minValue, int maxValue,
                   const wxPoint& pos,
                   const wxSize& size,
                   long style,
                   const wxValidator& validator,
                   const wxString& name)
        : m_thumb(this)
{
    Init();

    (void)Create(parent, id, value, minValue, maxValue,
                 pos, size, style, validator, name);
}

#ifdef __VISUALC__
    // warning C4355: 'this' : used in base member initializer list
    #pragma warning(default:4355)
#endif

void wxSlider::Init()
{
    m_min =
    m_max =
    m_value = 0;

    m_tickFreq = 1;

    m_lineSize =
    m_pageSize = 0;

    m_thumbSize = 0;
    m_thumbFlags = 0;
}

bool wxSlider::Create(wxWindow *parent,
                      wxWindowID id,
                      int value, int minValue, int maxValue,
                      const wxPoint& pos,
                      const wxSize& size,
                      long style,
                      const wxValidator& validator,
                      const wxString& name)
{
    if ( !wxSliderBase::Create(parent, id, pos, size, style,
                               validator, name) )
        return false;

    SetRange(minValue, maxValue);
    SetValue(value);

    // call this after setting the range as the best size depends (at least if
    // we have wxSL_LABELS style) on the range
    SetInitialSize(size);

    CreateInputHandler(wxINP_HANDLER_SLIDER);

    return true;
}

// ----------------------------------------------------------------------------
// wxSlider range and value
// ----------------------------------------------------------------------------

int wxSlider::GetValue() const
{
    return m_value;
}

int wxSlider::NormalizeValue(int value) const
{
    if ( value < m_min )
        return m_min;
    else if ( value > m_max )
        return m_max;
    else
        return value;
}

bool wxSlider::ChangeValueBy(int inc)
{
    return ChangeValueTo(NormalizeValue(m_value + inc));
}

bool wxSlider::ChangeValueTo(int value)
{
    // check if the value is going to change at all
    if (value == m_value)
        return false;

    // this method is protected and we should only call it with normalized
    // value!
    wxCHECK_MSG( IsInRange(value), false, wxT("invalid slider value") );

    m_value = value;

    Refresh();

    // generate the events: both a specific scroll event and a command event
    wxScrollEvent eventScroll(wxEVT_SCROLL_CHANGED, GetId());
    eventScroll.SetPosition(m_value);
    eventScroll.SetEventObject( this );
    (void)GetEventHandler()->ProcessEvent(eventScroll);

    wxCommandEvent event(wxEVT_COMMAND_SLIDER_UPDATED, GetId());
    event.SetInt(m_value);
    event.SetEventObject(this);
    (void)GetEventHandler()->ProcessEvent(event);

    return true;
}

void wxSlider::SetValue(int value)
{
    value = NormalizeValue(value);

    if ( m_value != value )
    {
        m_value = value;

        Refresh();
    }
}

void wxSlider::SetRange(int minValue, int maxValue)
{
    if ( minValue > maxValue )
    {
        // swap them, we always want min to be less than max
        int tmp = minValue;
        minValue = maxValue;
        maxValue = tmp;
    }

    if ( m_min != minValue || m_max != maxValue )
    {
        m_min = minValue;
        m_max = maxValue;

        // reset the value to make sure it is in the new range
        SetValue(m_value);

        // the size of the label rect might have changed
        if ( HasLabels() )
        {
            CalcGeometry();
        }

        Refresh();
    }
    //else: nothing changed
}

int wxSlider::GetMin() const
{
    return m_min;
}

int wxSlider::GetMax() const
{
    return m_max;
}

// ----------------------------------------------------------------------------
// wxSlider line/page/thumb size
// ----------------------------------------------------------------------------

void wxSlider::SetLineSize(int lineSize)
{
    wxCHECK_RET( lineSize >= 0, wxT("invalid slider line size") );

    m_lineSize = lineSize;
}

void wxSlider::SetPageSize(int pageSize)
{
    wxCHECK_RET( pageSize >= 0, wxT("invalid slider page size") );

    m_pageSize = pageSize;
}

int wxSlider::GetLineSize() const
{
    if ( !m_lineSize )
    {
        // the default line increment is 1
        wxConstCast(this, wxSlider)->m_lineSize = 1;
    }

    return m_lineSize;
}

int wxSlider::GetPageSize() const
{
    if ( !m_pageSize )
    {
        // the default page increment is m_tickFreq
        wxConstCast(this, wxSlider)->m_pageSize = m_tickFreq;
    }

    return m_pageSize;
}

void wxSlider::SetThumbLength(int lenPixels)
{
    wxCHECK_RET( lenPixels >= 0, wxT("invalid slider thumb size") );

    // use m_thumbSize here directly and not GetThumbLength() to avoid setting
    // it to the default value as we don't need it
    if ( lenPixels != m_thumbSize )
    {
        m_thumbSize = lenPixels;

        Refresh();
    }
}

int wxSlider::GetThumbLength() const
{
    wxSize sz = GetDefaultThumbSize();
    int len = (IsVert() ? sz.x : sz.y);
    if (m_thumbSize > len)
    {
        return m_thumbSize;
    }
    else
    {
        return len;
    }

}

// ----------------------------------------------------------------------------
// wxSlider ticks
// ----------------------------------------------------------------------------

void wxSlider::SetTickFreq(int n, int WXUNUSED(dummy))
{
    wxCHECK_RET (n > 0, wxT("invalid slider tick frequency"));

    if ( n != m_tickFreq )
    {
        m_tickFreq = n;

        Refresh();
    }
}

// ----------------------------------------------------------------------------
// wxSlider geometry
// ----------------------------------------------------------------------------

wxSize wxSlider::CalcLabelSize() const
{
    wxSize size;

    // there is no sense in trying to calc the labels size if we haven't got
    // any, the caller must check for it
    wxCHECK_MSG( HasLabels(), size, wxT("shouldn't be called") );

    wxCoord w1, h1, w2, h2;
    GetTextExtent(FormatValue(m_min), &w1, &h1);
    GetTextExtent(FormatValue(m_max), &w2, &h2);

    size.x = wxMax(w1, w2);
    size.y = wxMax(h1, h2);

    return size;
}

wxSize wxSlider::DoGetBestClientSize() const
{
    // this dimension is completely arbitrary
    static const wxCoord SLIDER_WIDTH = 40;

    long style = GetWindowStyle();

    // first calculate the size of the slider itself: i.e. the shaft and the
    // thumb
    wxCoord height = GetRenderer()->GetSliderDim();

    wxSize size;
    if ( IsVert() )
    {
        size.x = height;
        size.y = SLIDER_WIDTH;
    }
    else // horizontal
    {
        size.x = SLIDER_WIDTH;
        size.y = height;
    }

    // add space for ticks
    if ( HasTicks() )
    {
        wxCoord lenTick = GetRenderer()->GetSliderTickLen();
        if (style & wxSL_BOTH)
        {
            lenTick = 2 * lenTick;
        }

        if ( IsVert() )
            size.x += lenTick;
        else
            size.y += lenTick;
    }

    // if we have the label, reserve enough space for it
    if ( HasLabels() )
    {
        wxSize sizeLabels = CalcLabelSize();

        if (style & (wxSL_LEFT|wxSL_RIGHT))
        {
            size.x += sizeLabels.x + SLIDER_LABEL_MARGIN;
        }
        else if (style & (wxSL_TOP|wxSL_BOTTOM))
        {
            size.y += sizeLabels.y + SLIDER_LABEL_MARGIN;
        }
    }

    return size;
}

void wxSlider::OnSize(wxSizeEvent& event)
{
    CalcGeometry();

    event.Skip();
}

const wxRect& wxSlider::GetSliderRect() const
{
    if ( m_rectSlider.width < 0 )
    {
        wxConstCast(this, wxSlider)->CalcGeometry();
    }

    return m_rectSlider;
}

void wxSlider::CalcGeometry()
{
    /*
       recalc the label and slider positions, this looks like this for
       wxSL_HORIZONTAL | wxSL_TOP slider:

       LLL             lll
       -------------------------
       |                T      |  <-- this is the slider rect
       | HHHHHHHHHHHHHHHTHHHHH |
       |                T      |
       | *  *  *  *  *  *  *  *|
       -------------------------

       LLL is m_rectLabel as calculated here and lll is the real rect used for
       label drawing in OnDraw() (TTT indicated the thumb position and *s are
       the ticks)

       in the wxSL_VERTICAL | wxSL_RIGHT case the picture is like this:

       ------ LLL
       | H  |
       | H *|
       | H  |
       | H *|
       | H  |
       | H *|
       | H  |
       |TTT*| lll
       | H  |
       | H *|
       ------
    */
    long style = GetWindowStyle();

    // initialize to the full client rect
    wxRect rectTotal = GetClientRect();
    m_rectSlider = rectTotal;
    wxSize sizeThumb = GetThumbSize();

    // Labels reduce the size of the slider rect
    if ( HasLabels() )
    {
       wxSize sizeLabels = CalcLabelSize();

        m_rectLabel = wxRect(rectTotal.GetPosition(), sizeLabels);

        if (style & wxSL_TOP)
        {
            // shrink and offset the slider to the bottom
            m_rectSlider.y += sizeLabels.y + SLIDER_LABEL_MARGIN;
            m_rectSlider.height -= sizeLabels.y + SLIDER_LABEL_MARGIN;
        }
        else if (style & wxSL_BOTTOM)
        {
            // shrink the slider and move the label to the bottom
            m_rectSlider.height -= sizeLabels.y + SLIDER_LABEL_MARGIN;
            m_rectLabel.y += m_rectSlider.height + SLIDER_LABEL_MARGIN;
        }
        else if (style & wxSL_LEFT)
        {
            // shrink and offset the slider to the right
            m_rectSlider.x += sizeLabels.x + SLIDER_LABEL_MARGIN;
            m_rectSlider.width -= sizeLabels.x + SLIDER_LABEL_MARGIN;
        }
        else if (style & wxSL_RIGHT)
        {
            // shrink the slider and move the label to the right
            m_rectSlider.width -= sizeLabels.x + SLIDER_LABEL_MARGIN;
            m_rectLabel.x += m_rectSlider.width + SLIDER_LABEL_MARGIN;
        }
    }

    // calculate ticks too
    if ( HasTicks() )
    {
        wxCoord lenTick = GetRenderer()->GetSliderTickLen();

        // it
        m_rectTicks = GetShaftRect();

        if ( IsVert() )
        {
            if (style & (wxSL_LEFT|wxSL_BOTH))
            {
                m_rectTicks.x = m_rectSlider.x;
            }
            else
            { // wxSL_RIGHT
                m_rectTicks.x = m_rectSlider.x + m_rectSlider.width - lenTick;
            }
            m_rectTicks.width = lenTick;
        }
        else // horizontal
        {
            if (style & (wxSL_TOP|wxSL_BOTH))
            {
                m_rectTicks.y = m_rectSlider.y;
            }
            else
            { // wxSL_BOTTOM
                m_rectTicks.y = m_rectSlider.y + m_rectSlider.height - lenTick;
            }
            m_rectTicks.height = lenTick;
        }
    }

    // slider is never smaller than thumb size unless rectTotal
    if ( IsVert() )
    {
        wxCoord width = wxMin ( rectTotal.width, sizeThumb.x );
        m_rectSlider.width = wxMax ( m_rectSlider.width, width );
    }
    else
    {
        wxCoord height = wxMin ( rectTotal.height, sizeThumb.y );
        m_rectSlider.height = wxMax ( m_rectSlider.height, height );
    }
}

wxSize wxSlider::GetDefaultThumbSize() const
{
    // Default size has no styles (arrows)
    return GetRenderer()->GetSliderThumbSize(GetSliderRect(), 0, GetOrientation());
}

wxSize wxSlider::GetThumbSize() const
{
    return GetRenderer()->GetSliderThumbSize(GetSliderRect(), m_thumbSize, GetOrientation());
}

// ----------------------------------------------------------------------------
// wxSlider thumb geometry
// ----------------------------------------------------------------------------

wxRect wxSlider::GetShaftRect() const
{
    return GetRenderer()->GetSliderShaftRect(m_rectSlider, m_thumbSize, GetOrientation(), GetWindowStyle());
}

void wxSlider::CalcThumbRect(const wxRect *rectShaftIn,
                             wxRect *rectThumbOut,
                             wxRect *rectLabelOut,
                             int value) const
{
    if ( value == INVALID_THUMB_VALUE )
    {
        // use the current if not specified
        value = m_value;
    }

    bool isVertical = IsVert();

    wxRect rectShaft;
    if ( rectShaftIn )
    {
        rectShaft = *rectShaftIn;
    }
    else // no shaft rect provided, calc it
    {
        rectShaft = GetShaftRect();
    }

    wxCoord lenShaft,
            lenThumb;
    wxCoord *p;

    wxRect rectThumb(rectShaft.GetPosition(), GetThumbSize());
    if ( isVertical )
    {
        rectThumb.x += (rectShaft.width - rectThumb.width) / 2;

        lenThumb = rectThumb.height;
        lenShaft = rectShaft.height;
        p = &rectThumb.y;
    }
    else // horz
    {
        rectThumb.y += (rectShaft.height - rectThumb.height) / 2;

        lenThumb = rectThumb.width;
        lenShaft = rectShaft.width;
        p = &rectThumb.x;
    }

    // the thumb must always be entirely inside the shaft limits, so the max
    // position is not at lenShaft but at lenShaft - thumbSize
    if ( m_max != m_min )
    {
        if ( isVertical )
        {
            *p += ((lenShaft - lenThumb)*(m_max - value))/(m_max - m_min);
        }
        else
        { // horz
            *p += ((lenShaft - lenThumb)*(value - m_min))/(m_max - m_min);
        }
    }

    // calc the label rect
    if ( HasLabels() && rectLabelOut )
    {
        long style = GetWindowStyle();
        wxRect rectLabel = m_rectLabel;

        // centre the label relatively to the thumb position
        if (style & (wxSL_TOP|wxSL_BOTTOM))
        {
            rectLabel.x = rectThumb.x + (rectThumb.width - m_rectLabel.width)/2;
        }
        else if (style & (wxSL_LEFT|wxSL_RIGHT))
        {
            rectLabel.y = rectThumb.y + (rectThumb.height - m_rectLabel.height)/2;
        }

        *rectLabelOut = rectLabel;
    }

    if ( rectThumbOut )

        *rectThumbOut = rectThumb;
}

// ----------------------------------------------------------------------------
// wxSlider drawing
// ----------------------------------------------------------------------------

wxString wxSlider::FormatValue(int value) const
{
    return wxString::Format(wxT("%d"), value);
}

void wxSlider::DoDraw(wxControlRenderer *renderer)
{
    wxRenderer *rend = GetRenderer();
    wxDC& dc = renderer->GetDC();
    wxRect rectUpdate = GetUpdateClientRect();

    wxOrientation orient = GetOrientation();
    int flags = GetStateFlags();
    long style = GetWindowStyle();

    wxSize sz = GetThumbSize();
    int len = IsVert() ? sz.x : sz.y;

    // first draw the shaft
    wxRect rectShaft = rend->GetSliderShaftRect(m_rectSlider, len, orient, style);
    if ( rectUpdate.Intersects(rectShaft) )
    {
        rend->DrawSliderShaft(dc, m_rectSlider, len, orient, flags, style);
    }

    // calculate the thumb position in pixels and draw it
    wxRect rectThumb, rectLabel;
    CalcThumbRect(&rectShaft, &rectThumb, &rectLabel);

    // then draw the ticks
    if ( HasTicks() && rectUpdate.Intersects(m_rectTicks) )
    {
        rend->DrawSliderTicks(dc, m_rectSlider, len, orient,
                              m_min, m_max, m_tickFreq, flags, style);
    }

    // then draw the thumb
    if ( rectUpdate.Intersects(rectThumb) )
    {
        rend->DrawSliderThumb(dc, rectThumb, orient, flags | m_thumbFlags, style);
    }

    // finally, draw the label near the thumb
    if ( HasLabels() && rectUpdate.Intersects(rectLabel) )
    {
        // align it to be close to the shaft
        int align = 0;
        if (style & wxSL_TOP)
        {
            align = wxALIGN_CENTRE_HORIZONTAL|wxALIGN_TOP;
        }
        else if (style & wxSL_BOTTOM)
        {
            align = wxALIGN_CENTRE_HORIZONTAL|wxALIGN_BOTTOM;
        }
        else if (style & wxSL_LEFT)
        {
            align = wxALIGN_CENTRE_VERTICAL|wxALIGN_LEFT;
        }
        else if (style & wxSL_RIGHT)
        {
            align = wxALIGN_CENTRE_VERTICAL|wxALIGN_RIGHT;
        }

        dc.SetFont(GetFont());
        dc.SetTextForeground(GetForegroundColour());

        // the slider label is never drawn focused
        rend->DrawLabel(dc, FormatValue(m_value), rectLabel,
                        flags & ~wxCONTROL_FOCUSED, align);
    }
}

// ----------------------------------------------------------------------------
// wxSlider input processing
// ----------------------------------------------------------------------------

bool wxSlider::PerformAction(const wxControlAction& action,
                             long numArg,
                             const wxString& strArg)
{
    wxEventType scrollEvent = wxEVT_NULL;
    int value;
    bool valueChanged = true;

    if ( action == wxACTION_SLIDER_START )
    {
        scrollEvent = wxEVT_SCROLL_TOP;
        value = m_min;
    }
    else if ( action == wxACTION_SLIDER_END )
    {
        scrollEvent = wxEVT_SCROLL_BOTTOM;
        value = m_max;
    }
    else if ( action == wxACTION_SLIDER_PAGE_CHANGE )
    {
        value = NormalizeValue(m_value + numArg * GetPageSize());
    }
    else if ( action == wxACTION_SLIDER_LINE_UP )
    {
        scrollEvent = wxEVT_SCROLL_LINEUP;
        value = NormalizeValue(m_value + +GetLineSize());
    }
    else if ( action == wxACTION_SLIDER_LINE_DOWN )
    {
        scrollEvent = wxEVT_SCROLL_LINEDOWN;
        value = NormalizeValue(m_value + -GetLineSize());
    }
    else if ( action == wxACTION_SLIDER_PAGE_UP )
    {
        scrollEvent = wxEVT_SCROLL_PAGEUP;
        value = NormalizeValue(m_value + +GetPageSize());
    }
    else if ( action == wxACTION_SLIDER_PAGE_DOWN )
    {
        scrollEvent = wxEVT_SCROLL_PAGEDOWN;
        value = NormalizeValue(m_value + -GetPageSize());
    }
    else if ( action == wxACTION_SLIDER_THUMB_DRAG ||
                action == wxACTION_SLIDER_THUMB_MOVE )
    {
        scrollEvent = wxEVT_SCROLL_THUMBTRACK;

        // we shouldn't generate a command event about this change but we still
        // should update our value and the slider appearance
        valueChanged = false;
        m_value =
        value = (int)numArg;
        Refresh();
    }
    else if ( action == wxACTION_SLIDER_THUMB_RELEASE )
    {
        scrollEvent = wxEVT_SCROLL_THUMBRELEASE;
        value = (int)numArg;
    }
    else
    {
        return wxControl::PerformAction(action, numArg, strArg);
    }

    // update wxSlider current value and generate wxCommandEvent, except while
    // dragging the thumb
    if ( valueChanged )
        ChangeValueTo(value);

    // also generate more precise wxScrollEvent if applicable
    if ( scrollEvent != wxEVT_NULL )
    {
        wxScrollEvent event(scrollEvent, GetId());
        event.SetPosition(value);
        event.SetEventObject( this );
        GetEventHandler()->ProcessEvent(event);
    }

    return true;
}

/* static */
wxInputHandler *wxSlider::GetStdInputHandler(wxInputHandler *handlerDef)
{
    static wxStdSliderInputHandler s_handler(handlerDef);

    return &s_handler;
}

// ----------------------------------------------------------------------------
// wxSlider implementation of wxControlWithThumb interface
// ----------------------------------------------------------------------------

wxScrollThumb::Shaft wxSlider::HitTest(const wxPoint& pt) const
{
    wxRect rectShaft = GetShaftRect();
    wxRect rectThumb;
    CalcThumbRect(&rectShaft, &rectThumb, NULL);

    // check for possible shaft or thumb hit
    if (!rectShaft.Contains(pt) && !rectThumb.Contains(pt))
    {
        return wxScrollThumb::Shaft_None;
    }

    // the position to test and the start and end of the thumb
    wxCoord x, x1, x2, x3, x4;
    if (IsVert())
    {
        x = pt.y;
        x1 = rectThumb.GetBottom();
        x2 = rectShaft.GetBottom();
        x3 = rectShaft.GetTop();
        x4 = rectThumb.GetTop();
    }
    else
    { // horz
        x = pt.x;
        x1 = rectShaft.GetLeft();
        x2 = rectThumb.GetLeft();
        x3 = rectThumb.GetRight();
        x4 = rectShaft.GetRight();
    }
    if ((x1 <= x) && (x < x2))
    {
        // or to the left
        return wxScrollThumb::Shaft_Above;
    }

    if ((x3 < x) && (x <= x4)) {
        // or to the right
        return wxScrollThumb::Shaft_Below;
    }

    // where else can it be?
    return wxScrollThumb::Shaft_Thumb;
}

wxCoord wxSlider::ThumbPosToPixel() const
{
    wxRect rectThumb;
    CalcThumbRect(NULL, &rectThumb, NULL);

    return IsVert() ? rectThumb.y : rectThumb.x;
}

int wxSlider::PixelToThumbPos(wxCoord x) const
{
    wxRect rectShaft = GetShaftRect();
    wxSize sizeThumb = GetThumbSize();

    wxCoord x0, len;
    if ( IsVert() )
    {
        x0 = rectShaft.y;
        len = rectShaft.height - sizeThumb.y;
    }
    else // horz
    {
        x0 = rectShaft.x;
        len = rectShaft.width - sizeThumb.x;
    }

    int pos = m_min;
    if ( len > 0 )
    {
        if ( x > x0 )
        {
            pos += ((x - x0) * (m_max - m_min)) / len;
            if ( pos > m_max )
                pos = m_max;
        }
        //else: x <= x0, leave pos = min
    }

    return pos;
}

void wxSlider::SetShaftPartState(wxScrollThumb::Shaft shaftPart,
                                 int flag,
                                 bool set)
{
    // for now we ignore the flags for the shaft as no renderer uses them
    // anyhow
    if ( shaftPart == wxScrollThumb::Shaft_Thumb )
    {
        if ( set )
            m_thumbFlags |= flag;
        else
            m_thumbFlags &= ~flag;

        Refresh();
    }
}

void wxSlider::OnThumbDragStart(int pos)
{
    if (IsVert())
    {
        PerformAction(wxACTION_SLIDER_THUMB_DRAG, m_max - pos);
    }
    else
    {
        PerformAction(wxACTION_SLIDER_THUMB_DRAG, pos);
    }
}

void wxSlider::OnThumbDrag(int pos)
{
    if (IsVert())
    {
        PerformAction(wxACTION_SLIDER_THUMB_MOVE, m_max - pos);
    }
    else
    {
        PerformAction(wxACTION_SLIDER_THUMB_MOVE, pos);
    }
}

void wxSlider::OnThumbDragEnd(int pos)
{
    if (IsVert())
    {
        PerformAction(wxACTION_SLIDER_THUMB_RELEASE, m_max - pos);
    }
    else
    {
        PerformAction(wxACTION_SLIDER_THUMB_RELEASE, pos);
    }
}

void wxSlider::OnPageScrollStart()
{
    // we do nothing here
}

bool wxSlider::OnPageScroll(int pageInc)
{
    int value = GetValue();
    PerformAction(wxACTION_SLIDER_PAGE_CHANGE, pageInc);

    return GetValue() != value;
}

// ----------------------------------------------------------------------------
// wxStdSliderInputHandler
// ----------------------------------------------------------------------------

bool wxStdSliderInputHandler::HandleKey(wxInputConsumer *consumer,
                                              const wxKeyEvent& event,
                                              bool pressed)
{
    if ( pressed )
    {
        int keycode = event.GetKeyCode();

        wxControlAction action;
        switch ( keycode )
        {
            case WXK_HOME:
                action = wxACTION_SLIDER_END;
                break;

            case WXK_END:
                action = wxACTION_SLIDER_START;
                break;

            case WXK_RIGHT:
            case WXK_UP:
                action = wxACTION_SLIDER_LINE_UP;
                break;

            case WXK_LEFT:
            case WXK_DOWN:
                action = wxACTION_SLIDER_LINE_DOWN;
                break;

            case WXK_PAGEUP:
                action = wxACTION_SLIDER_PAGE_UP;
                break;

            case WXK_PAGEDOWN:
                action = wxACTION_SLIDER_PAGE_DOWN;
                break;
        }

        if ( !action.IsEmpty() )
        {
            consumer->PerformAction(action);

            return true;
        }
    }

    return wxStdInputHandler::HandleKey(consumer, event, pressed);
}

bool wxStdSliderInputHandler::HandleMouse(wxInputConsumer *consumer,
                                                const wxMouseEvent& event)
{
    wxSlider *slider = wxStaticCast(consumer->GetInputWindow(), wxSlider);

    if ( slider->GetThumb().HandleMouse(event) )
    {
        // processed by the thumb
        return false;
    }

    return wxStdInputHandler::HandleMouse(consumer, event);
}

bool wxStdSliderInputHandler::HandleMouseMove(wxInputConsumer *consumer,
                                                    const wxMouseEvent& event)
{
    wxSlider *slider = wxStaticCast(consumer->GetInputWindow(), wxSlider);

    if ( slider->GetThumb().HandleMouseMove(event) )
    {
        // processed by the thumb
        return false;
    }

    return wxStdInputHandler::HandleMouseMove(consumer, event);
}

bool
wxStdSliderInputHandler::HandleFocus(wxInputConsumer * WXUNUSED(consumer),
                                           const wxFocusEvent& WXUNUSED(event))
{
    // slider appearance changes when it gets/loses focus
    return true;
}

#endif // wxUSE_SLIDER
