/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/pen.mm
// Purpose:     wxPen
// Author:      David Elliott
// Modified by:
// Created:     2003/08/02
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/pen.h"
    #include "wx/bitmap.h"
    #include "wx/colour.h"
#endif //WX_PRECOMP

#include "wx/cocoa/ObjcRef.h"

#import <AppKit/NSColor.h>

// ========================================================================
// wxPenRefData
// ========================================================================
class WXDLLEXPORT wxPenRefData: public wxGDIRefData
{
public:
    wxPenRefData(const wxColour& colour = wxNullColour,
        int width = 1, int style = wxSOLID,
        const wxBitmap& stipple = wxNullBitmap);
    wxPenRefData(const wxPenRefData& data);
    ~wxPenRefData() { FreeCocoaNSColor(); FreeCocoaDash(); }

    void SetWidth(int Width) { m_width = Width; }
    void SetStyle(int Style)
    {   FreeCocoaNSColor();
        FreeCocoaDash();
        m_style = Style;
    }
    void SetJoin(int Join) { m_join = Join; }
    void SetCap(int Cap) { m_cap = Cap; }
    void SetColour(const wxColour& col) { FreeCocoaNSColor(); m_colour = col; }
    void SetDashes(int nb_dashes, const wxDash *Dash)
    {
        FreeCocoaDash();
        m_nbDash = nb_dashes;
        m_dash = (wxDash *)Dash;
    }
    void SetStipple(const wxBitmap& Stipple)
    {
        FreeCocoaNSColor();
        m_stipple = Stipple;
        m_style = wxSTIPPLE;
    }
    WX_NSColor GetNSColor();
    int GetCocoaLineDash(const CGFloat **pattern);
protected:
    void FreeCocoaNSColor();
    void FreeCocoaDash();

    int             m_width;
    int             m_style;
    int             m_join;
    int             m_cap;
    wxColour        m_colour;
    int             m_nbDash;
    wxDash         *m_dash;
    wxBitmap        m_stipple;
    WX_NSColor      m_cocoaNSColor;
    CGFloat        *m_cocoaDash;

    // Predefined dash patterns
    static const int scm_countDot;
    static const CGFloat scm_patternDot[];
    static const int scm_countLongDash;
    static const CGFloat scm_patternLongDash[];
    static const int scm_countShortDash;
    static const CGFloat scm_patternShortDash[];
    static const int scm_countDotDash;
    static const CGFloat scm_patternDotDash[];

    friend class WXDLLIMPEXP_FWD_CORE wxPen;

private:
    // Don't allow assignment
    wxPenRefData& operator=(const wxPenRefData& data);
};

const int wxPenRefData::scm_countDot = 1;
const CGFloat wxPenRefData::scm_patternDot[] = {
    1.0
};
const int wxPenRefData::scm_countLongDash = 1;
const CGFloat wxPenRefData::scm_patternLongDash[] = {
    10.0
};
const int wxPenRefData::scm_countShortDash = 1;
const CGFloat wxPenRefData::scm_patternShortDash[] = {
    5.0
};
const int wxPenRefData::scm_countDotDash = 4;
const CGFloat wxPenRefData::scm_patternDotDash[] = {
    1.0
,   1.0
,   5.0
,   1.0
};

#define M_PENDATA ((wxPenRefData *)m_refData)

inline wxPenRefData::wxPenRefData(const wxColour& colour,
        int width, int style, const wxBitmap& stipple)
{
    m_width = width;
    m_style = style;
    m_join = wxJOIN_ROUND;
    m_cap = wxCAP_ROUND;
    m_colour = colour;
    m_nbDash = 0;
    m_dash = 0;
    m_stipple = stipple;
    m_cocoaNSColor = nil;
    m_cocoaDash = NULL;
}

inline wxPenRefData::wxPenRefData(const wxPenRefData& data)
{
    m_width = data.m_width;
    m_style = data.m_style;
    m_join = data.m_join;
    m_cap = data.m_cap;
    m_colour = data.m_colour;
    m_nbDash = data.m_nbDash;
    m_dash = data.m_dash;
    m_stipple = data.m_stipple;
    m_cocoaNSColor = wxGCSafeRetain(data.m_cocoaNSColor);
    m_cocoaDash = NULL;
}

inline void wxPenRefData::FreeCocoaNSColor()
{
    wxGCSafeRelease(m_cocoaNSColor);
    m_cocoaNSColor = nil;
}

inline void wxPenRefData::FreeCocoaDash()
{
    delete m_cocoaDash;
    m_cocoaDash = NULL;
}

inline WX_NSColor wxPenRefData::GetNSColor()
{
    if(!m_cocoaNSColor)
    {
        switch( m_style )
        {
        case wxTRANSPARENT:
            m_cocoaNSColor = wxGCSafeRetain([NSColor clearColor]);
            break;
        case wxSTIPPLE:
//  wxBitmap isn't implemented yet
//            m_cocoaNSColor = [[NSColor colorWithPatternImage: m_stipple.GetNSImage()] retain];
//            break;
        // The hatch brushes are going to be tricky
        case wxBDIAGONAL_HATCH:
        case wxCROSSDIAG_HATCH:
        case wxFDIAGONAL_HATCH:
        case wxCROSS_HATCH:
        case wxHORIZONTAL_HATCH:
        case wxVERTICAL_HATCH:
        default:
        // Dot/dashed pens use solid colors
        case wxDOT:
        case wxLONG_DASH:
        case wxSHORT_DASH:
        case wxDOT_DASH:
        case wxUSER_DASH:
        case wxSOLID:
            NSColor *colour_NSColor = m_colour.GetNSColor();
            if(!colour_NSColor)
                colour_NSColor = [NSColor clearColor];
            m_cocoaNSColor = [colour_NSColor copyWithZone:nil];
            [wxGCSafeRetain(m_cocoaNSColor) release]; // retain in GC. no change in RR.
            break;
        }
    }
    return m_cocoaNSColor;
}

int wxPenRefData::GetCocoaLineDash(const CGFloat **pattern)
{
    int count;
    switch( m_style )
    {
    case wxDOT:
        count = scm_countDot;
        if(pattern)
            *pattern = scm_patternDot;
        break;
    case wxLONG_DASH:
        count = scm_countLongDash;
        if(pattern)
            *pattern = scm_patternLongDash;
        break;
    case wxSHORT_DASH:
        count = scm_countShortDash;
        if(pattern)
            *pattern = scm_patternShortDash;
        break;
    case wxDOT_DASH:
        count = scm_countDotDash;
        if(pattern)
            *pattern = scm_patternDotDash;
        break;
    case wxUSER_DASH:
        count = m_nbDash;
        if(pattern)
        {
            if(!m_cocoaDash)
            {
                m_cocoaDash = new CGFloat[count];
                for(int i=0; i<count; i++)
                    m_cocoaDash[i] = m_dash[i];
            }
            *pattern = m_cocoaDash;
        }
        break;
    case wxTRANSPARENT:
    case wxSTIPPLE:
    case wxBDIAGONAL_HATCH:
    case wxCROSSDIAG_HATCH:
    case wxFDIAGONAL_HATCH:
    case wxCROSS_HATCH:
    case wxHORIZONTAL_HATCH:
    case wxVERTICAL_HATCH:
    case wxSOLID:
    default:
        count = 0;
        if(pattern)
            *pattern = NULL;
    }
    return count;
}

// ========================================================================
// wxPen
// ========================================================================
IMPLEMENT_DYNAMIC_CLASS(wxPen, wxGDIObject)

wxPen::wxPen()
{
}

wxPen::~wxPen()
{
}

// Should implement Create
wxPen::wxPen(const wxColour& colour, int width, int style)
{
    m_refData = new wxPenRefData(colour,width,style);
}

wxPen::wxPen(const wxBitmap& stipple, int width)
{
    m_refData = new wxPenRefData(wxNullColour,width,wxSTIPPLE,stipple);
}

wxGDIRefData *wxPen::CreateGDIRefData() const
{
    return new wxPenRefData;
}

wxGDIRefData *wxPen::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxPenRefData(*(wxPenRefData *)data);
}

void wxPen::SetWidth(int Width)
{
    AllocExclusive();
    M_PENDATA->SetWidth(Width);
}

void wxPen::SetStyle(int Style)
{
    AllocExclusive();
    M_PENDATA->SetStyle(Style);
}

void wxPen::SetJoin(int Join)
{
    AllocExclusive();
    M_PENDATA->SetJoin(Join);
}

void wxPen::SetCap(int Cap)
{
    AllocExclusive();
    M_PENDATA->SetCap(Cap);
}

void wxPen::SetColour(const wxColour& col)
{
    AllocExclusive();
    M_PENDATA->SetColour(col);
}

void wxPen::SetColour(unsigned char r, unsigned char g, unsigned char b)
{
    AllocExclusive();
    M_PENDATA->SetColour(wxColour(r, g, b));
}

void wxPen::SetDashes(int nb_dashes, const wxDash *Dash)
{
    AllocExclusive();
    M_PENDATA->SetDashes(nb_dashes, Dash);
}

void wxPen::SetStipple(const wxBitmap& Stipple)
{
    AllocExclusive();
    M_PENDATA->SetStipple(Stipple);
}

wxColour wxPen::GetColour() const
{
    return (M_PENDATA ? M_PENDATA->m_colour : wxNullColour);
}

int wxPen::GetWidth() const
{
    return (M_PENDATA ? M_PENDATA->m_width : 0);
}

int wxPen::GetStyle() const
{
    return (M_PENDATA ? M_PENDATA->m_style : 0);
}

int wxPen::GetJoin() const
{
    return (M_PENDATA ? M_PENDATA->m_join : 0);
}

int wxPen::GetCap() const
{
    return (M_PENDATA ? M_PENDATA->m_cap : 0);
}

int wxPen::GetDashes(wxDash **ptr) const
{
    *ptr = (M_PENDATA ? M_PENDATA->m_dash : (wxDash*) NULL); return (M_PENDATA ? M_PENDATA->m_nbDash : 0);
}

wxBitmap *wxPen::GetStipple() const
{
    return (M_PENDATA ? (& M_PENDATA->m_stipple) : (wxBitmap*) NULL);
}

WX_NSColor wxPen::GetNSColor()
{
    return (M_PENDATA ? M_PENDATA->GetNSColor() : nil);
}

int wxPen::GetCocoaLineDash(const CGFloat **pattern)
{
    if(M_PENDATA)
        return M_PENDATA->GetCocoaLineDash(pattern);
    if(pattern)
        *pattern = NULL;
    return 0;
}
