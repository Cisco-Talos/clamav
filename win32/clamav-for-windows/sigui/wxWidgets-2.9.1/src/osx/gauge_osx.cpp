/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/gauge_osx.cpp
// Purpose:     wxGauge class
// Author:      Stefan Csomor
// Modified by:
// Created:     1998-01-01
// RCS-ID:      $Id: gauge.cpp 54820 2008-07-29 20:04:11Z SC $
// Copyright:   (c) Stefan Csomor
// Licence:       wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_GAUGE

#include "wx/gauge.h"

IMPLEMENT_DYNAMIC_CLASS(wxGauge, wxControl)

#include "wx/osx/private.h"

bool wxGauge::Create( wxWindow *parent,
    wxWindowID id,
    int range,
    const wxPoint& pos,
    const wxSize& s,
    long style,
    const wxValidator& validator,
    const wxString& name )
{
    m_macIsUserPane = false;

    if ( !wxGaugeBase::Create( parent, id, range, pos, s, style & 0xE0FFFFFF, validator, name ) )
        return false;

    wxSize size = s;

    m_peer = wxWidgetImpl::CreateGauge( this, parent, id, GetValue() , 0, GetRange(), pos, size, style, GetExtraStyle() );

    MacPostControlCreate( pos, size );

    return true;
}

void wxGauge::SetRange(int r)
{
    // we are going via the base class in case there is
    // some change behind the values by it
    wxGaugeBase::SetRange( r ) ;
    if ( m_peer )
        m_peer->SetMaximum( GetRange() ) ;
}

void wxGauge::SetValue(int pos)
{
    // we are going via the base class in case there is
    // some change behind the values by it
    wxGaugeBase::SetValue( pos ) ;

    if ( m_peer )
        m_peer->SetValue( GetValue() ) ;
}

int wxGauge::GetValue() const
{
    return m_gaugePos ;
}

void wxGauge::Pulse()
{
    m_peer->PulseGauge();
}

#endif // wxUSE_GAUGE

