/////////////////////////////////////////////////////////////////////////////
// Name:        src/univ/scrthumb.cpp
// Purpose:     wxScrollThumb and related classes
// Author:      Vadim Zeitlin
// Modified by:
// Created:     13.02.01
// RCS-ID:      $Id$
// Copyright:   (c) 2001 SciTech Software, Inc. (www.scitechsoft.com)
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

#ifndef WX_PRECOMP
    #include "wx/window.h"
#endif // WX_PRECOMP

#include "wx/renderer.h"
#include "wx/univ/scrtimer.h"
#include "wx/univ/scrthumb.h"

// ----------------------------------------------------------------------------
// wxScrollThumbCaptureData: the struct used while dragging the scroll thumb
// ----------------------------------------------------------------------------

struct WXDLLEXPORT wxScrollThumbCaptureData
{
    // start mouse capture after the user clicked the mouse button btn on this
    // part of the control
    wxScrollThumbCaptureData(wxScrollThumb::Shaft part,
                             int btn,
                             wxControlWithThumb *control)
    {
        m_shaftPart = part;
        m_btnCapture = btn;
        m_timerScroll = NULL;

        m_window = control->GetWindow();
        m_window->CaptureMouse();
    }

    // release mouse
    ~wxScrollThumbCaptureData()
    {
        if ( m_window )
        {
            m_window->ReleaseMouse();
        }

#if wxUSE_TIMER
        delete m_timerScroll;
#endif // wxUSE_TIMER
    }

    // the thumb part being held pressed
    wxScrollThumb::Shaft m_shaftPart;

    // the mouse button which started the capture (-1 if none)
    int m_btnCapture;

    // the window which has captured the mouse
    wxWindow *m_window;

    // the offset between the mouse position and the start of the thumb which
    // is kept constant while dragging the thumb
    wxCoord m_ofsMouse;

    // the timer for generating the scroll events when scrolling by page
    wxScrollTimer *m_timerScroll;
};

// ----------------------------------------------------------------------------
// wxScrollTimer: the timer used when the arrow is kept pressed
// ----------------------------------------------------------------------------

#if wxUSE_TIMER

class wxScrollThumbTimer : public wxScrollTimer
{
public:
    wxScrollThumbTimer(wxControlWithThumb *control,
                       wxScrollThumb::Shaft shaftPart)
    {
        m_control = control;
        switch ( shaftPart )
        {
            case wxScrollThumb::Shaft_Above:
                m_inc = -1;
                break;

            default:
                wxFAIL_MSG(wxT("unexpected shaft part in wxScrollThumbTimer"));
                // fall through

            case wxScrollThumb::Shaft_Below:
                m_inc = 1;
                break;
        }

        m_control->OnPageScrollStart();

        StartAutoScroll();
    }

protected:
    virtual bool DoNotify()
    {
        return m_control->OnPageScroll(m_inc);
    }

    wxControlWithThumb *m_control;
    int m_inc;
};

#endif // wxUSE_TIMER

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxScrollThumb constructor and dtor
// ----------------------------------------------------------------------------

wxScrollThumb::wxScrollThumb(wxControlWithThumb *control)
{
    m_shaftPart = Shaft_None;
    m_control = control;
    m_captureData = NULL;
}

wxScrollThumb::~wxScrollThumb()
{
    // it should have been destroyed
    wxASSERT_MSG( !m_captureData, wxT("memory leak in wxScrollThumb") );
}

// ----------------------------------------------------------------------------
// wxScrollThumb mouse handling
// ----------------------------------------------------------------------------

bool wxScrollThumb::HandleMouse(const wxMouseEvent& event) const
{
    // is this a click event?
    int btn = event.GetButton();
    if ( btn == -1 )
    {
        // no...
        return false;
    }

    // when the mouse is pressed on any scrollbar element, we capture it
    // and hold capture until the same mouse button is released
    if ( event.ButtonDown() || event.ButtonDClick() )
    {
        if ( HasCapture() )
        {
            // mouse already captured, nothing to do
            return false;
        }

        // determine which part of the window the user clicked in
        Shaft shaftPart = m_control->HitTest(event.GetPosition());

        if ( shaftPart == Shaft_None )
        {
            // mouse pressed over something else
            return false;
        }

        // capture the mouse
        wxConstCast(this, wxScrollThumb)->m_captureData =
            new wxScrollThumbCaptureData(shaftPart, btn, m_control);

        // modify the visual appearance before sending the event which will
        // cause a redraw
        m_control->SetShaftPartState(shaftPart, wxCONTROL_PRESSED);

        if ( shaftPart == Shaft_Thumb )
        {
            // save the mouse offset from the thumb position - we will keep it
            // constant while dragging the thumb
            m_captureData->m_ofsMouse =
                GetMouseCoord(event) - m_control->ThumbPosToPixel();

            // generate an additional event if we start dragging the thumb
            m_control->OnThumbDragStart(GetThumbPos(event));
        }
#if wxUSE_TIMER
        else // not the thumb
        {
            // start timer for auto scrolling when the user presses the mouse
            // in the shaft above or below the thumb
            m_captureData->m_timerScroll =
                new wxScrollThumbTimer(m_control, shaftPart);
        }
#endif // wxUSE_TIMER
    }
    // release mouse if the *same* button went up
    else if ( HasCapture() && (btn == m_captureData->m_btnCapture) )
    {
        Shaft shaftPart = m_captureData->m_shaftPart;

        // if we were dragging the thumb, send the one last event
        if ( shaftPart == Shaft_Thumb )
        {
            m_control->OnThumbDragEnd(GetThumbPos(event));
        }

        // release the mouse and free capture data
        delete m_captureData;
        wxConstCast(this, wxScrollThumb)->m_captureData = NULL;

        m_control->SetShaftPartState(shaftPart, wxCONTROL_PRESSED, false);
    }
    else // another mouse button released
    {
        // we don't process this
        return false;
    }

    return true;
}

bool wxScrollThumb::HandleMouseMove(const wxMouseEvent& event) const
{
    if ( HasCapture() )
    {
        if ( (m_captureData->m_shaftPart == Shaft_Thumb) && event.Moving() )
        {
            // make the thumb follow the mouse by keeping the same offset
            // between the mouse position and the top/left of the thumb
            m_control->OnThumbDrag(GetThumbPos(event));
        }

        // we process all mouse events while the mouse is captured by us
        return true;
    }
    else // no capture
    {
        Shaft shaftPart;
        if ( event.Leaving() )
        {
            // no part of the shaft has mouse if it left the window completely
            shaftPart = Shaft_None;
        }
        else // Moving() or Entering(), treat them the same here
        {
            shaftPart = m_control->HitTest(event.GetPosition());
        }

        if ( shaftPart != m_shaftPart )
        {
            // update the highlighted state
            m_control->SetShaftPartState(m_shaftPart, wxCONTROL_CURRENT, false);
            wxConstCast(this, wxScrollThumb)->m_shaftPart = shaftPart;
            m_control->SetShaftPartState(m_shaftPart, wxCONTROL_CURRENT, true);
        }

        // if the event happened on the shaft, it was for us and we processed
        // it
        return shaftPart != Shaft_None;
    }
}

wxCoord wxScrollThumb::GetMouseCoord(const wxMouseEvent& event) const
{
    wxPoint pt = event.GetPosition();
    return m_control->IsVertical() ? pt.y : pt.x;
}

int wxScrollThumb::GetThumbPos(const wxMouseEvent& event) const
{
    wxCHECK_MSG( m_captureData && m_captureData->m_shaftPart == Shaft_Thumb, 0,
                 wxT("can't be called when thumb is not dragged") );

    int x = GetMouseCoord(event) - m_captureData->m_ofsMouse;
    return m_control->PixelToThumbPos(x);
}
