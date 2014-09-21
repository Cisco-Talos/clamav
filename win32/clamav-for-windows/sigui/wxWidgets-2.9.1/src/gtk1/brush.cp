/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/brush.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/brush.h"

#ifndef WX_PRECOMP
    #include "wx/colour.h"
#endif

#include <gdk/gdk.h>

//-----------------------------------------------------------------------------
// wxBrush
//-----------------------------------------------------------------------------

class wxBrushRefData: public wxGDIRefData
{
public:
    wxBrushRefData()
    {
        m_style = wxBRUSHSTYLE_INVALID;
    }

    wxBrushRefData( const wxBrushRefData& data )
        : wxGDIRefData()
    {
        m_style = data.m_style;
        m_stipple = data.m_stipple;
        m_colour = data.m_colour;
    }

    bool operator == (const wxBrushRefData& data) const
    {
        return (m_style == data.m_style &&
                m_stipple.IsSameAs(data.m_stipple) &&
                m_colour == data.m_colour);
    }

    wxBrushStyle m_style;
    wxColour     m_colour;
    wxBitmap     m_stipple;
};

//-----------------------------------------------------------------------------

#define M_BRUSHDATA ((wxBrushRefData *)m_refData)

IMPLEMENT_DYNAMIC_CLASS(wxBrush,wxGDIObject)

wxBrush::wxBrush( const wxColour &colour, wxBrushStyle style )
{
    m_refData = new wxBrushRefData();
    M_BRUSHDATA->m_style = style;
    M_BRUSHDATA->m_colour = colour;
}

#if FUTURE_WXWIN_COMPATIBILITY_3_0
wxBrush::wxBrush(const wxColour& col, int style)
{
    m_refData = new wxBrushRefData;
    M_BRUSHDATA->m_style = (wxBrushStyle)style;
    M_BRUSHDATA->m_colour = col;
}
#endif

wxBrush::wxBrush( const wxBitmap &stippleBitmap )
{
    m_refData = new wxBrushRefData();
    M_BRUSHDATA->m_colour = *wxBLACK;

    M_BRUSHDATA->m_stipple = stippleBitmap;

    if (M_BRUSHDATA->m_stipple.GetMask())
        M_BRUSHDATA->m_style = wxBRUSHSTYLE_STIPPLE_MASK_OPAQUE;
    else
        M_BRUSHDATA->m_style = wxBRUSHSTYLE_STIPPLE_MASK;
}

wxBrush::~wxBrush()
{
    // m_refData unrefed in ~wxObject
}

wxGDIRefData *wxBrush::CreateGDIRefData() const
{
    return new wxBrushRefData;
}

wxGDIRefData *wxBrush::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxBrushRefData(*(wxBrushRefData *)data);
}

bool wxBrush::operator == ( const wxBrush& brush ) const
{
    if (m_refData == brush.m_refData) return true;

    if (!m_refData || !brush.m_refData) return false;

    return ( *(wxBrushRefData*)m_refData == *(wxBrushRefData*)brush.m_refData );
}

wxBrushStyle wxBrush::GetStyle() const
{
    wxCHECK_MSG( Ok(), wxBRUSHSTYLE_INVALID, wxT("invalid brush") );

    return M_BRUSHDATA->m_style;
}

wxColour wxBrush::GetColour() const
{
    wxCHECK_MSG( Ok(), wxNullColour, wxT("invalid brush") );

    return M_BRUSHDATA->m_colour;
}

wxBitmap *wxBrush::GetStipple() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid brush") );

    return &M_BRUSHDATA->m_stipple;
}

void wxBrush::SetColour( const wxColour& col )
{
    AllocExclusive();

    M_BRUSHDATA->m_colour = col;
}

void wxBrush::SetColour( unsigned char r, unsigned char g, unsigned char b )
{
    AllocExclusive();

    M_BRUSHDATA->m_colour.Set( r, g, b );
}

void wxBrush::SetStyle( wxBrushStyle style )
{
    AllocExclusive();

    M_BRUSHDATA->m_style = style;
}

void wxBrush::SetStipple( const wxBitmap& stipple )
{
    AllocExclusive();

    M_BRUSHDATA->m_stipple = stipple;
    if (M_BRUSHDATA->m_stipple.GetMask())
        M_BRUSHDATA->m_style = wxBRUSHSTYLE_STIPPLE_MASK_OPAQUE;
    else
        M_BRUSHDATA->m_style = wxBRUSHSTYLE_STIPPLE_MASK;
}
