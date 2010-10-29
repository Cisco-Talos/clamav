/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/pen.cpp
// Purpose:     wxPen
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/pen.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/bitmap.h"
    #include "wx/colour.h"
#endif

//-----------------------------------------------------------------------------
// wxPen
//-----------------------------------------------------------------------------

class wxPenRefData : public wxGDIRefData
{
public:
    wxPenRefData()
    {
        m_width = 1;
        m_style = wxPENSTYLE_SOLID;
        m_joinStyle = wxJOIN_ROUND;
        m_capStyle = wxCAP_ROUND;
        m_dash = NULL;
        m_countDashes = 0;
    }

    wxPenRefData( const wxPenRefData& data )
    {
        m_style = data.m_style;
        m_width = data.m_width;
        m_joinStyle = data.m_joinStyle;
        m_capStyle = data.m_capStyle;
        m_colour = data.m_colour;
        m_countDashes = data.m_countDashes;
/*
        if (data.m_dash)  TODO
            m_dash = new
*/
        m_dash = data.m_dash;
        m_stipple = data.m_stipple;
    }

    bool operator == (const wxPenRefData& data) const
    {
        return (m_style == data.m_style &&
                m_width == data.m_width &&
                m_joinStyle == data.m_joinStyle &&
                m_capStyle == data.m_capStyle &&
                m_colour == data.m_colour);
    }

    int        m_width;
    wxPenStyle m_style;
    wxPenJoin  m_joinStyle;
    wxPenCap   m_capStyle;
    wxColour   m_colour;
    int        m_countDashes;
    wxBitmap   m_stipple;
    wxX11Dash *m_dash;
};

//-----------------------------------------------------------------------------

#define M_PENDATA ((wxPenRefData *)m_refData)

IMPLEMENT_DYNAMIC_CLASS(wxPen,wxGDIObject)

wxPen::wxPen( const wxColour &colour, int width, wxPenStyle style )
{
    m_refData = new wxPenRefData();
    M_PENDATA->m_width = width;
    M_PENDATA->m_style = style;
    M_PENDATA->m_colour = colour;
}

#if FUTURE_WXWIN_COMPATIBILITY_3_0
wxPen::wxPen(const wxColour& colour, int width, int style)
{
    m_refData = new wxPenRefData();
    M_PENDATA->m_width = width;
    M_PENDATA->m_style = (wxPenStyle)style;
    M_PENDATA->m_colour = colour;
}
#endif

wxPen::~wxPen()
{
    // m_refData unrefed in ~wxObject
}

wxGDIRefData *wxPen::CreateGDIRefData() const
{
    return new wxPenRefData;
}

wxGDIRefData *wxPen::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxPenRefData(*(wxPenRefData *)data);
}

bool wxPen::operator == ( const wxPen& pen ) const
{
    if (m_refData == pen.m_refData) return true;

    if (!m_refData || !pen.m_refData) return false;

    return ( *(wxPenRefData*)m_refData == *(wxPenRefData*)pen.m_refData );
}

void wxPen::SetColour( const wxColour &colour )
{
    AllocExclusive();

    M_PENDATA->m_colour = colour;
}

void wxPen::SetDashes( int number_of_dashes, const wxDash *dash )
{
    AllocExclusive();

    M_PENDATA->m_countDashes = number_of_dashes;
    M_PENDATA->m_dash = (wxX11Dash *)dash; // TODO
}

void wxPen::SetColour( unsigned char red, unsigned char green, unsigned char blue )
{
    AllocExclusive();

    M_PENDATA->m_colour.Set( red, green, blue );
}

void wxPen::SetCap( wxPenCap capStyle )
{
    AllocExclusive();

    M_PENDATA->m_capStyle = capStyle;
}

void wxPen::SetJoin( wxPenJoin joinStyle )
{
    AllocExclusive();

    M_PENDATA->m_joinStyle = joinStyle;
}

void wxPen::SetStipple( const wxBitmap& stipple )
{
    AllocExclusive();

    M_PENDATA->m_stipple = stipple;
}

void wxPen::SetStyle( wxPenStyle style )
{
    AllocExclusive();

    M_PENDATA->m_style = style;
}

void wxPen::SetWidth( int width )
{
    AllocExclusive();

    M_PENDATA->m_width = width;
}

int wxPen::GetDashes( wxDash **ptr ) const
{
    wxCHECK_MSG( Ok(), -1, wxT("invalid pen") );

    *ptr = (wxDash*)M_PENDATA->m_dash;
    return M_PENDATA->m_countDashes;
}

int wxPen::GetDashCount() const
{
    return (M_PENDATA->m_countDashes);
}

wxDash* wxPen::GetDash() const
{
    return (wxDash*)M_PENDATA->m_dash;
}

wxPenCap wxPen::GetCap() const
{
    wxCHECK_MSG( Ok(), wxCAP_INVALID, wxT("invalid pen") );

    return M_PENDATA->m_capStyle;
}

wxPenJoin wxPen::GetJoin() const
{
    wxCHECK_MSG( Ok(), wxJOIN_INVALID, wxT("invalid pen") );

    return M_PENDATA->m_joinStyle;
}

wxPenStyle wxPen::GetStyle() const
{
    wxCHECK_MSG( Ok(), wxPENSTYLE_INVALID, wxT("invalid pen") );

    return M_PENDATA->m_style;
}

int wxPen::GetWidth() const
{
    wxCHECK_MSG( Ok(), -1, wxT("invalid pen") );

    return M_PENDATA->m_width;
}

wxColour wxPen::GetColour() const
{
    wxCHECK_MSG( Ok(), wxNullColour, wxT("invalid pen") );

    return M_PENDATA->m_colour;
}

wxBitmap *wxPen::GetStipple() const
{
    wxCHECK_MSG( Ok(), &wxNullBitmap, wxT("invalid pen") );

    return &M_PENDATA->m_stipple;
}
