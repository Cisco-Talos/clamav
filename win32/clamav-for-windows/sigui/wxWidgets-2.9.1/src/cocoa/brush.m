/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/brush.mm
// Purpose:     wxBrush
// Author:      David Elliott <dfe@cox.net>
// Modified by:
// Created:     2003/07/03
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/brush.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/colour.h"
#endif //WX_PRECOMP

#import <AppKit/NSColor.h>

class WXDLLEXPORT wxBrushRefData: public wxGDIRefData
{
public:
    wxBrushRefData(const wxColour& colour = wxNullColour,
                   wxBrushStyle style = wxBRUSHSTYLE_SOLID);
    wxBrushRefData(const wxBitmap& stipple);
    wxBrushRefData(const wxBrushRefData& data);
    virtual ~wxBrushRefData();

    WX_NSColor GetNSColor();
    void Free();

    bool operator==(const wxBrushRefData& data) const;

    // accessors
    const wxColour& GetColour() const { return m_colour; }
    wxBrushStyle GetStyle() const { return m_style; }
    wxBitmap *GetStipple() { return &m_stipple; }

    void SetColour(const wxColour& colour) { Free(); m_colour = colour; }
    void SetStyle(wxBrushStyle style) { Free(); m_style = style; }
    void SetStipple(const wxBitmap& stipple) { Free(); DoSetStipple(stipple); }

private:
    void DoSetStipple(const wxBitmap& stipple);

    WX_NSColor    m_cocoaNSColor;
    wxBrushStyle  m_style;
    wxBitmap      m_stipple;
    wxColour      m_colour;

    // no assignment operator, the objects of this class are shared and never
    // assigned after being created once
    wxBrushRefData& operator=(const wxBrushRefData&);
};

#define M_BRUSHDATA ((wxBrushRefData *)m_refData)
IMPLEMENT_DYNAMIC_CLASS(wxBrush, wxGDIObject)

wxBrushRefData::wxBrushRefData(const wxColour& colour, wxBrushStyle style)
{
    m_cocoaNSColor = NULL;
    m_style = style;
    m_colour = colour;
}

wxBrushRefData::wxBrushRefData(const wxBitmap& stipple)
{
    m_cocoaNSColor = NULL;
    DoSetStipple(stipple);
}

wxBrushRefData::wxBrushRefData(const wxBrushRefData& data)
{
    m_cocoaNSColor = data.m_cocoaNSColor;
    [m_cocoaNSColor retain];
    m_style = data.m_style;
    m_stipple = data.m_stipple;
    m_colour = data.m_colour;
}

wxBrushRefData::~wxBrushRefData()
{
    Free();
}

void wxBrushRefData::Free()
{
    [m_cocoaNSColor release];
    m_cocoaNSColor = NULL;
}

bool wxBrushRefData::operator==(const wxBrushRefData& data) const
{
    // don't compare our NSColor
    return m_style == data.m_style &&
           m_colour == data.m_colour &&
           m_stipple.IsSameAs(data.m_stipple);
}

void wxBrushRefData::DoSetStipple(const wxBitmap& stipple)
{
    m_stipple = stipple;
    m_style = stipple.GetMask() ? wxBRUSHSTYLE_STIPPLE_MASK_OPAQUE
                                : wxBRUSHSTYLE_STIPPLE;
}

WX_NSColor wxBrushRefData::GetNSColor()
{
    if(!m_cocoaNSColor)
    {
        switch( m_style )
        {
        case wxTRANSPARENT:
            m_cocoaNSColor = [[NSColor clearColor] retain];
            break;
        case wxSTIPPLE:
//  wxBitmap isn't implemented yet
//            m_cocoaNSColor = [[NSColor colorWithPatternImage: m_stipple.GetNSImage()] retain];
//            break;
        case wxSTIPPLE_MASK_OPAQUE:
            // This should be easy when wxBitmap works.
//            break;
        // The hatch brushes are going to be tricky
        case wxBDIAGONAL_HATCH:
        case wxCROSSDIAG_HATCH:
        case wxFDIAGONAL_HATCH:
        case wxCROSS_HATCH:
        case wxHORIZONTAL_HATCH:
        case wxVERTICAL_HATCH:
        default:
        case wxSOLID:
            NSColor *colour_NSColor = m_colour.GetNSColor();
            if(!colour_NSColor)
                colour_NSColor = [NSColor clearColor];
            m_cocoaNSColor = [colour_NSColor copyWithZone:nil];
            break;
        }
    }
    return m_cocoaNSColor;
}

// Brushes
wxBrush::wxBrush()
{
}

wxBrush::~wxBrush()
{
}

wxBrush::wxBrush(const wxColour& col, wxBrushStyle style)
{
    m_refData = new wxBrushRefData(col, style);
}

wxBrush::wxBrush(const wxColour& col, int style)
{
    m_refData = new wxBrushRefData(col, (wxBrushStyle)style);
}

wxBrush::wxBrush(const wxBitmap& stipple)
{
    m_refData = new wxBrushRefData(stipple);
}

wxGDIRefData *wxBrush::CreateGDIRefData() const
{
    return new wxBrushRefData;
}

wxGDIRefData *wxBrush::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxBrushRefData(*(wxBrushRefData *)data);
}

void wxBrush::SetColour(const wxColour& col)
{
    AllocExclusive();
    M_BRUSHDATA->SetColour(col);
}

void wxBrush::SetColour(unsigned char r, unsigned char g, unsigned char b)
{
    AllocExclusive();
    M_BRUSHDATA->SetColour(wxColour(r,g,b));
}

void wxBrush::SetStyle(wxBrushStyle style)
{
    AllocExclusive();
    M_BRUSHDATA->SetStyle(style);
}

void wxBrush::SetStipple(const wxBitmap& stipple)
{
    AllocExclusive();
    M_BRUSHDATA->SetStipple(stipple);
}

wxColour wxBrush::GetColour() const
{
    wxCHECK_MSG( Ok(), wxNullColour, wxT("invalid brush") );
    return M_BRUSHDATA->GetColour();
}

wxBrushStyle wxBrush::GetStyle() const
{
    wxCHECK_MSG( Ok(), wxBRUSHSTYLE_INVALID, wxT("invalid brush") );
    return M_BRUSHDATA->GetStyle();
}

wxBitmap *wxBrush::GetStipple() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid brush") );
    return M_BRUSHDATA->GetStipple();
}

WX_NSColor wxBrush::GetNSColor()
{
    if(!m_refData)
        return [NSColor clearColor];
    return M_BRUSHDATA->GetNSColor();
}
