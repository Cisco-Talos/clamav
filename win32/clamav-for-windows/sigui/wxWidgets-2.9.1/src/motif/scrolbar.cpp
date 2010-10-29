/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/scrolbar.cpp
// Purpose:     wxScrollBar
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/scrolbar.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#include <Xm/ScrollBar.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

static void wxScrollBarCallback(Widget widget, XtPointer clientData,
                        XmScaleCallbackStruct *cbs);

IMPLEMENT_DYNAMIC_CLASS(wxScrollBar, wxControl)

// Scrollbar
bool wxScrollBar::Create(wxWindow *parent, wxWindowID id,
           const wxPoint& pos,
           const wxSize& size, long style,
           const wxValidator& validator,
           const wxString& name)
{
    if( !CreateControl( parent, id, pos, size, style, validator, name ) )
        return false;
    PreCreation();

    wxSize newSize =
        ( style & wxHORIZONTAL ) ? wxSize( 140, 16 ) : wxSize( 16, 140 );
    if( size.x != -1 ) newSize.x = size.x;
    if( size.y != -1 ) newSize.y = size.y;

    Widget parentWidget = (Widget) parent->GetClientWidget();

    m_mainWidget =
        DoCreateScrollBar( (WXWidget)parentWidget,
                           (wxOrientation)(style & (wxHORIZONTAL|wxVERTICAL)),
                           (void (*)())wxScrollBarCallback );

    PostCreation();
    AttachWidget (parent, m_mainWidget, (WXWidget) NULL,
                  pos.x, pos.y, newSize.x, newSize.y);

    return true;
}

wxScrollBar::~wxScrollBar()
{
}

void wxScrollBar::SetThumbPosition(int pos)
{
    XtVaSetValues ((Widget) m_mainWidget,
                   XmNvalue, pos,
                   NULL);
}

int wxScrollBar::GetThumbPosition() const
{
    int pos;
    XtVaGetValues((Widget) m_mainWidget,
                  XmNvalue, &pos, NULL);
    return pos;
}

void wxScrollBar::SetScrollbar(int position, int thumbSize, int range, int pageSize,
    bool WXUNUSED(refresh))
{
    m_viewSize = pageSize;
    m_pageSize = thumbSize;
    m_objectSize = range;

    if (range == 0)
      range = 1;
    if (thumbSize == 0)
      thumbSize = 1;

    XtVaSetValues((Widget) m_mainWidget,
         XmNvalue, position,
         XmNminimum, 0,
         XmNmaximum, range,
         XmNsliderSize, thumbSize,
         XmNpageIncrement, pageSize,
         NULL);
}

void wxScrollBar::Command(wxCommandEvent& event)
{
    SetThumbPosition(event.GetInt());
    ProcessCommand(event);
}

void wxScrollBar::ChangeFont(bool WXUNUSED(keepOriginalSize))
{
    // TODO
    // Do anything for a scrollbar? A font will never be seen.
}

void wxScrollBar::ChangeBackgroundColour()
{
    wxWindow::ChangeBackgroundColour();

    XtVaSetValues ((Widget) GetMainWidget(),
        XmNtroughColor, m_backgroundColour.AllocColour(XtDisplay((Widget) GetMainWidget())),
        NULL);
}

static void wxScrollBarCallback(Widget widget, XtPointer clientData,
                                XmScaleCallbackStruct *cbs)
{
    wxScrollBar *scrollBar = (wxScrollBar*)wxGetWindowFromTable(widget);
    wxCHECK_RET( scrollBar, wxT("invalid widget in scrollbar callback") );

    wxOrientation orientation = (wxOrientation)wxPtrToUInt(clientData);
    wxEventType eventType = wxEVT_NULL;

    switch (cbs->reason)
    {
        case XmCR_INCREMENT:
        {
            eventType = wxEVT_SCROLL_LINEDOWN;
            break;
        }
        case XmCR_DECREMENT:
        {
            eventType = wxEVT_SCROLL_LINEUP;
            break;
        }
        case XmCR_DRAG:
        {
            eventType = wxEVT_SCROLL_THUMBTRACK;
            break;
        }
        case XmCR_VALUE_CHANGED:
        {
            eventType = wxEVT_SCROLL_THUMBRELEASE;
            break;
        }
        case XmCR_PAGE_INCREMENT:
        {
            eventType = wxEVT_SCROLL_PAGEDOWN;
            break;
        }
        case XmCR_PAGE_DECREMENT:
        {
            eventType = wxEVT_SCROLL_PAGEUP;
            break;
        }
        case XmCR_TO_TOP:
        {
            eventType = wxEVT_SCROLL_TOP;
            break;
        }
        case XmCR_TO_BOTTOM:
        {
            eventType = wxEVT_SCROLL_BOTTOM;
            break;
        }
        default:
        {
            // Should never get here
            wxFAIL_MSG("Unknown scroll event.");
            break;
        }
    }

    wxScrollEvent event(eventType, scrollBar->GetId(),
                        cbs->value, orientation);
    event.SetEventObject(scrollBar);
    scrollBar->HandleWindowEvent(event);
}
