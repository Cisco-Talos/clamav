/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/pen.cpp
// Purpose:     wxPen class implementation
// Author:      Vaclav Slavik
// Created:     2006-08-04
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/pen.h"

#ifndef WX_PRECOMP
    #include "wx/bitmap.h"
    #include "wx/colour.h"
#endif

//-----------------------------------------------------------------------------
// wxPen
//-----------------------------------------------------------------------------

class wxPenRefData : public wxGDIRefData
{
public:
    wxPenRefData(const wxColour& clr = wxNullColour, wxPenStyle style = wxPENSTYLE_SOLID)
    {
        m_colour = clr;
        SetStyle(style);
    }

    wxPenRefData(const wxPenRefData& data)
        : m_style(data.m_style), m_colour(data.m_colour) {}

    virtual bool IsOk() const { return m_colour.IsOk(); }

    void SetStyle(wxPenStyle style)
    {
        if ( style != wxPENSTYLE_SOLID && style != wxPENSTYLE_TRANSPARENT )
        {
            wxFAIL_MSG( "only wxSOLID and wxTRANSPARENT styles are supported" );
            style = wxPENSTYLE_SOLID;
        }

        m_style = style;
    }

    wxPenStyle     m_style;
    wxColour       m_colour;
};

//-----------------------------------------------------------------------------

#define M_PENDATA ((wxPenRefData *)m_refData)

IMPLEMENT_DYNAMIC_CLASS(wxPen, wxGDIObject)

wxPen::wxPen(const wxColour &colour, int width, wxPenStyle style)
{
    wxASSERT_MSG( width <= 1, "only width=0,1 are supported" );

    m_refData = new wxPenRefData(colour, style);
}

#if FUTURE_WXWIN_COMPATIBILITY_3_0
wxPen::wxPen(const wxColour& col, int width, int style)
{
    m_refData = new wxPenRefData(col, (wxPenStyle)style);
}
#endif

wxPen::wxPen(const wxBitmap& WXUNUSED(stipple), int WXUNUSED(width))
{
    wxFAIL_MSG( "stipple pens not supported" );

    m_refData = new wxPenRefData();
}

bool wxPen::operator==(const wxPen& pen) const
{
#warning "this is incorrect (MGL too)"
    return m_refData == pen.m_refData;
}

void wxPen::SetColour(const wxColour &colour)
{
    AllocExclusive();
    M_PENDATA->m_colour = colour;
}

void wxPen::SetDashes(int WXUNUSED(number_of_dashes), const wxDash *WXUNUSED(dash))
{
    wxFAIL_MSG( "SetDashes not implemented" );
}

void wxPen::SetColour(unsigned char red, unsigned char green, unsigned char blue)
{
    AllocExclusive();
    M_PENDATA->m_colour.Set(red, green, blue);
}

void wxPen::SetCap(wxPenCap WXUNUSED(capStyle))
{
    wxFAIL_MSG( "SetCap not implemented" );
}

void wxPen::SetJoin(wxPenJoin WXUNUSED(joinStyle))
{
    wxFAIL_MSG( "SetJoin not implemented" );
}

void wxPen::SetStyle(wxPenStyle style)
{
    AllocExclusive();
    M_PENDATA->SetStyle(style);
}

void wxPen::SetStipple(const wxBitmap& WXUNUSED(stipple))
{
    wxFAIL_MSG( "SetStipple not implemented" );
}

void wxPen::SetWidth(int width)
{
    wxASSERT_MSG( width <= 1, "only width=0,1 are implemented" );
}

int wxPen::GetDashes(wxDash **ptr) const
{
    wxFAIL_MSG( "GetDashes not implemented" );

    *ptr = NULL;
    return 0;
}

int wxPen::GetDashCount() const
{
    wxFAIL_MSG( "GetDashCount not implemented" );

    return 0;
}

wxDash* wxPen::GetDash() const
{
    wxFAIL_MSG( "GetDash not implemented" );

    return NULL;
}

wxPenCap wxPen::GetCap() const
{
    wxCHECK_MSG( Ok(), wxCAP_INVALID, wxT("invalid pen") );

    wxFAIL_MSG( "GetCap not implemented" );
    return wxCAP_INVALID;
}

wxPenJoin wxPen::GetJoin() const
{
    wxCHECK_MSG( Ok(), wxJOIN_INVALID, wxT("invalid pen") );

    wxFAIL_MSG( "GetJoin not implemented" );
    return wxJOIN_INVALID;
}

wxPenStyle wxPen::GetStyle() const
{
    wxCHECK_MSG( Ok(), wxPENSTYLE_INVALID, wxT("invalid pen") );

    return M_PENDATA->m_style;
}

int wxPen::GetWidth() const
{
    wxCHECK_MSG( Ok(), -1, wxT("invalid pen") );

    return 1;
}

wxColour wxPen::GetColour() const
{
    wxCHECK_MSG( Ok(), wxNullColour, wxT("invalid pen") );

    return M_PENDATA->m_colour;
}

wxBitmap *wxPen::GetStipple() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid pen") );

    wxFAIL_MSG( "GetStipple not implemented" );
    return NULL;
}

wxGDIRefData *wxPen::CreateGDIRefData() const
{
    return new wxPenRefData;
}

wxGDIRefData *wxPen::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxPenRefData(*(wxPenRefData *)data);
}
