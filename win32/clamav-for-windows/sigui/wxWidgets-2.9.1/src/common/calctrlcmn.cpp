///////////////////////////////////////////////////////////////////////////////
// Name:        common/calctrlcmn.cpp
// Author:      Marcin Wojdyr
// Created:     2008-03-26
// RCS-ID:      $Id$
// Copyright:   (C) Marcin Wojdyr
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
#endif //WX_PRECOMP

#if wxUSE_CALENDARCTRL || wxUSE_DATEPICKCTRL

#include "wx/dateevt.h"
IMPLEMENT_DYNAMIC_CLASS(wxDateEvent, wxCommandEvent)
wxDEFINE_EVENT(wxEVT_DATE_CHANGED, wxDateEvent);

#endif // wxUSE_CALENDARCTRL || wxUSE_DATEPICKCTRL


#if wxUSE_CALENDARCTRL

#include "wx/calctrl.h"

// ----------------------------------------------------------------------------
// events
// ----------------------------------------------------------------------------
IMPLEMENT_DYNAMIC_CLASS(wxCalendarEvent, wxDateEvent)

wxDEFINE_EVENT( wxEVT_CALENDAR_SEL_CHANGED, wxCalendarEvent );
wxDEFINE_EVENT( wxEVT_CALENDAR_PAGE_CHANGED, wxCalendarEvent );
wxDEFINE_EVENT( wxEVT_CALENDAR_DOUBLECLICKED, wxCalendarEvent );
wxDEFINE_EVENT( wxEVT_CALENDAR_WEEKDAY_CLICKED, wxCalendarEvent );
wxDEFINE_EVENT( wxEVT_CALENDAR_WEEK_CLICKED, wxCalendarEvent );

// deprecated events
wxDEFINE_EVENT( wxEVT_CALENDAR_DAY_CHANGED, wxCalendarEvent );
wxDEFINE_EVENT( wxEVT_CALENDAR_MONTH_CHANGED, wxCalendarEvent );
wxDEFINE_EVENT( wxEVT_CALENDAR_YEAR_CHANGED, wxCalendarEvent );


wxCalendarDateAttr wxCalendarDateAttr::m_mark(wxCAL_BORDER_SQUARE);

bool wxCalendarCtrlBase::EnableMonthChange(bool enable)
{
    const long styleOrig = GetWindowStyle();
    long style = enable ? styleOrig & ~wxCAL_NO_MONTH_CHANGE
                        : styleOrig | wxCAL_NO_MONTH_CHANGE;
    if ( style == styleOrig )
        return false;

    SetWindowStyle(style);

    return true;
}

bool wxCalendarCtrlBase::GenerateAllChangeEvents(const wxDateTime& dateOld)
{
    const wxDateTime::Tm tm1 = dateOld.GetTm(),
                         tm2 = GetDate().GetTm();

    bool pageChanged = false;

    GenerateEvent(wxEVT_CALENDAR_SEL_CHANGED);
    if ( tm1.year != tm2.year || tm1.mon != tm2.mon )
    {
        GenerateEvent(wxEVT_CALENDAR_PAGE_CHANGED);

        pageChanged = true;
    }

    // send also one of the deprecated events
    if ( tm1.year != tm2.year )
        GenerateEvent(wxEVT_CALENDAR_YEAR_CHANGED);
    else if ( tm1.mon != tm2.mon )
        GenerateEvent(wxEVT_CALENDAR_MONTH_CHANGED);
    else
        GenerateEvent(wxEVT_CALENDAR_DAY_CHANGED);

    return pageChanged;
}

void wxCalendarCtrlBase::EnableHolidayDisplay(bool display)
{
    long style = GetWindowStyle();
    if ( display )
        style |= wxCAL_SHOW_HOLIDAYS;
    else
        style &= ~wxCAL_SHOW_HOLIDAYS;

    if ( style == GetWindowStyle() )
        return;

    SetWindowStyle(style);

    if ( display )
        SetHolidayAttrs();
    else
        ResetHolidayAttrs();

    RefreshHolidays();
}

bool wxCalendarCtrlBase::SetHolidayAttrs()
{
    if ( !HasFlag(wxCAL_SHOW_HOLIDAYS) )
        return false;

    ResetHolidayAttrs();

    wxDateTime::Tm tm = GetDate().GetTm();
    wxDateTime dtStart(1, tm.mon, tm.year),
               dtEnd = dtStart.GetLastMonthDay();

    wxDateTimeArray hol;
    wxDateTimeHolidayAuthority::GetHolidaysInRange(dtStart, dtEnd, hol);

    const size_t count = hol.GetCount();
    for ( size_t n = 0; n < count; n++ )
    {
        SetHoliday(hol[n].GetDay());
    }

    return true;
}

#endif // wxUSE_CALENDARCTRL

