/////////////////////////////////////////////////////////////////////////////
// Name:        wx/brush.h
// Purpose:     Includes platform-specific wxBrush file
// Author:      Julian Smart
// Modified by:
// Created:
// RCS-ID:      $Id$
// Copyright:   Julian Smart
// Licence:     wxWindows Licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_BRUSH_H_BASE_
#define _WX_BRUSH_H_BASE_

#include "wx/defs.h"
#include "wx/object.h"
#include "wx/gdiobj.h"
#include "wx/gdicmn.h"      // for wxGDIObjListBase

// NOTE: these values cannot be combined together!
enum wxBrushStyle
{
    wxBRUSHSTYLE_INVALID = -1,

    wxBRUSHSTYLE_SOLID = wxSOLID,
    wxBRUSHSTYLE_TRANSPARENT = wxTRANSPARENT,
    wxBRUSHSTYLE_STIPPLE_MASK_OPAQUE = wxSTIPPLE_MASK_OPAQUE,
    wxBRUSHSTYLE_STIPPLE_MASK = wxSTIPPLE_MASK,
    wxBRUSHSTYLE_STIPPLE = wxSTIPPLE,
    wxBRUSHSTYLE_BDIAGONAL_HATCH = wxBDIAGONAL_HATCH,
    wxBRUSHSTYLE_CROSSDIAG_HATCH = wxCROSSDIAG_HATCH,
    wxBRUSHSTYLE_FDIAGONAL_HATCH = wxFDIAGONAL_HATCH,
    wxBRUSHSTYLE_CROSS_HATCH = wxCROSS_HATCH,
    wxBRUSHSTYLE_HORIZONTAL_HATCH = wxHORIZONTAL_HATCH,
    wxBRUSHSTYLE_VERTICAL_HATCH = wxVERTICAL_HATCH,
    wxBRUSHSTYLE_FIRST_HATCH = wxFIRST_HATCH,
    wxBRUSHSTYLE_LAST_HATCH = wxLAST_HATCH
};


// wxBrushBase
class WXDLLIMPEXP_CORE wxBrushBase: public wxGDIObject
{
public:
    virtual ~wxBrushBase() { }

    virtual void SetColour(const wxColour& col) = 0;
    virtual void SetColour(unsigned char r, unsigned char g, unsigned char b) = 0;
    virtual void SetStyle(wxBrushStyle style) = 0;
    virtual void SetStipple(const wxBitmap& stipple) = 0;

    virtual wxColour GetColour() const = 0;
    virtual wxBrushStyle GetStyle() const = 0;
    virtual wxBitmap *GetStipple() const = 0;

    virtual bool IsHatch() const
        { return (GetStyle()>=wxBRUSHSTYLE_FIRST_HATCH) && (GetStyle()<=wxBRUSHSTYLE_LAST_HATCH); }
};

#if defined(__WXPALMOS__)
    #include "wx/palmos/brush.h"
#elif defined(__WXMSW__)
    #include "wx/msw/brush.h"
#elif defined(__WXMOTIF__) || defined(__WXX11__)
    #include "wx/x11/brush.h"
#elif defined(__WXGTK20__)
    #include "wx/gtk/brush.h"
#elif defined(__WXGTK__)
    #include "wx/gtk1/brush.h"
#elif defined(__WXMGL__)
    #include "wx/mgl/brush.h"
#elif defined(__WXDFB__)
    #include "wx/dfb/brush.h"
#elif defined(__WXMAC__)
    #include "wx/osx/brush.h"
#elif defined(__WXCOCOA__)
    #include "wx/cocoa/brush.h"
#elif defined(__WXPM__)
    #include "wx/os2/brush.h"
#endif

class WXDLLIMPEXP_CORE wxBrushList: public wxGDIObjListBase
{
public:
    wxBrush *FindOrCreateBrush(const wxColour& colour,
                               wxBrushStyle style = wxBRUSHSTYLE_SOLID);

#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxBrush *FindOrCreateBrush(const wxColour& colour, int style)
        { return FindOrCreateBrush(colour, (wxBrushStyle)style); }
#endif

#if WXWIN_COMPATIBILITY_2_6
    wxDEPRECATED( void AddBrush(wxBrush*) );
    wxDEPRECATED( void RemoveBrush(wxBrush*) );
#endif
};

extern WXDLLIMPEXP_DATA_CORE(wxBrushList*)   wxTheBrushList;

// provide comparison operators to allow code such as
//
//      if ( brush.GetStyle() == wxTRANSPARENT )
//
// to compile without warnings which it would otherwise provoke from some
// compilers as it compares elements of different enums
#if FUTURE_WXWIN_COMPATIBILITY_3_0

inline bool operator==(wxBrushStyle s, wxDeprecatedGUIConstants t)
{
    return static_cast<int>(s) == static_cast<int>(t);
}

inline bool operator!=(wxBrushStyle s, wxDeprecatedGUIConstants t)
{
    return !(s == t);
}

#endif // FUTURE_WXWIN_COMPATIBILITY_3_0

#endif // _WX_BRUSH_H_BASE_
