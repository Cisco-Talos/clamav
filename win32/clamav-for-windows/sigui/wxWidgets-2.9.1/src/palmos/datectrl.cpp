/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/datectrl.cpp
// Purpose:     wxDatePickerCtrl implementation
// Author:      Wlodzimierz ABX Skiba
// Modified by:
// Created:     02/14/05
// RCS-ID:      $Id$
// Copyright:   (c) Wlodzimierz Skiba
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

#if wxUSE_DATEPICKCTRL

#include "wx/datectrl.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/app.h"
#endif

#include "wx/dynlib.h"

#include "wx/dateevt.h"

#include <Control.h>
#include <SelDay.h>

IMPLEMENT_DYNAMIC_CLASS(wxDatePickerCtrl, wxControl)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxDatePickerCtrl creation
// ----------------------------------------------------------------------------

bool wxDatePickerCtrl::Create(wxWindow *parent,
                              wxWindowID id,
                              const wxDateTime& dt,
                              const wxPoint& pos,
                              const wxSize& size,
                              long style,
                              const wxValidator& validator,
                              const wxString& name)
{
    if(!wxControl::Create(parent, id, pos, size, style, validator, name))
        return false;

    wxString label;

    if ( dt.IsValid() )
    {
        label = dt.FormatDate();
        m_dt = dt;
    }

    if(!wxControl::PalmCreateControl(selectorTriggerCtl, label, pos, size))
        return false;

    return true;
}

// ----------------------------------------------------------------------------
// wxDatePickerCtrl geometry
// ----------------------------------------------------------------------------

wxSize wxDatePickerCtrl::DoGetBestSize() const
{
    return wxSize(16,16);
}

// ----------------------------------------------------------------------------
// wxDatePickerCtrl operations
// ----------------------------------------------------------------------------

void wxDatePickerCtrl::SetValue(const wxDateTime& dt)
{
    if ( dt.IsValid() )
        m_dt = dt;

    SetLabel(m_dt.FormatDate());
}

wxDateTime wxDatePickerCtrl::GetValue() const
{
    return m_dt;
}

void wxDatePickerCtrl::SetRange(const wxDateTime& dt1, const wxDateTime& dt2)
{
    // TODO
}

bool wxDatePickerCtrl::GetRange(wxDateTime *dt1, wxDateTime *dt2) const
{
    // TODO
    return false;
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

bool wxDatePickerCtrl::SendClickEvent()
{
    int16_t month = (int16_t)m_dt.GetMonth() + 1;
    int16_t day = m_dt.GetDay();
    int16_t year = m_dt.GetYear();

    //if(!SelectDay(selectDayByDay,&month,&day,&year,wxT("Pick date")))
    if(!SelectDay(selectDayByDay,&month,&day,&year, "Pick date"))
        return false;
    wxDateTime dt(m_dt);
    dt.Set((wxDateTime::wxDateTime_t)day,
           (wxDateTime::Month)(month-1),
           (int)year);
    SetValue(dt);
    return true;
}

#endif // wxUSE_DATEPICKCTRL
