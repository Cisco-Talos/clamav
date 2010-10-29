/////////////////////////////////////////////////////////////////////////////
// Name:        wx/pen.h
// Purpose:     Base header for wxPen
// Author:      Julian Smart
// Modified by:
// Created:
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows Licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PEN_H_BASE_
#define _WX_PEN_H_BASE_

#include "wx/gdiobj.h"
#include "wx/gdicmn.h"

enum wxPenStyle
{
    wxPENSTYLE_INVALID = -1,

    wxPENSTYLE_SOLID = wxSOLID,
    wxPENSTYLE_DOT = wxDOT,
    wxPENSTYLE_LONG_DASH = wxLONG_DASH,
    wxPENSTYLE_SHORT_DASH = wxSHORT_DASH,
    wxPENSTYLE_DOT_DASH = wxDOT_DASH,
    wxPENSTYLE_USER_DASH = wxUSER_DASH,

    wxPENSTYLE_TRANSPARENT = wxTRANSPARENT,

    wxPENSTYLE_STIPPLE_MASK_OPAQUE = wxSTIPPLE_MASK_OPAQUE,
    wxPENSTYLE_STIPPLE_MASK = wxSTIPPLE_MASK,
    wxPENSTYLE_STIPPLE = wxSTIPPLE,

    wxPENSTYLE_BDIAGONAL_HATCH = wxBDIAGONAL_HATCH,
    wxPENSTYLE_CROSSDIAG_HATCH = wxCROSSDIAG_HATCH,
    wxPENSTYLE_FDIAGONAL_HATCH = wxFDIAGONAL_HATCH,
    wxPENSTYLE_CROSS_HATCH = wxCROSS_HATCH,
    wxPENSTYLE_HORIZONTAL_HATCH = wxHORIZONTAL_HATCH,
    wxPENSTYLE_VERTICAL_HATCH = wxVERTICAL_HATCH,

    wxPENSTYLE_FIRST_HATCH = wxFIRST_HATCH,
    wxPENSTYLE_LAST_HATCH = wxLAST_HATCH
};

enum wxPenJoin
{
    wxJOIN_INVALID = -1,

    wxJOIN_BEVEL = 120,
    wxJOIN_MITER,
    wxJOIN_ROUND
};

enum wxPenCap
{
    wxCAP_INVALID = -1,

    wxCAP_ROUND = 130,
    wxCAP_PROJECTING,
    wxCAP_BUTT
};


class WXDLLIMPEXP_CORE wxPenBase : public wxGDIObject
{
public:
    virtual ~wxPenBase() { }

    virtual void SetColour(const wxColour& col) = 0;
    virtual void SetColour(unsigned char r, unsigned char g, unsigned char b) = 0;

    virtual void SetWidth(int width) = 0;
    virtual void SetStyle(wxPenStyle style) = 0;
    virtual void SetStipple(const wxBitmap& stipple) = 0;
    virtual void SetDashes(int nb_dashes, const wxDash *dash) = 0;
    virtual void SetJoin(wxPenJoin join) = 0;
    virtual void SetCap(wxPenCap cap) = 0;

    virtual wxColour GetColour() const = 0;
    virtual wxBitmap *GetStipple() const = 0;
    virtual wxPenStyle GetStyle() const = 0;
    virtual wxPenJoin GetJoin() const = 0;
    virtual wxPenCap GetCap() const = 0;
    virtual int GetWidth() const = 0;
    virtual int GetDashes(wxDash **ptr) const = 0;
};

#if defined(__WXPALMOS__)
    #include "wx/palmos/pen.h"
#elif defined(__WXMSW__)
    #include "wx/msw/pen.h"
#elif defined(__WXMOTIF__) || defined(__WXX11__)
    #include "wx/x11/pen.h"
#elif defined(__WXGTK20__)
    #include "wx/gtk/pen.h"
#elif defined(__WXGTK__)
    #include "wx/gtk1/pen.h"
#elif defined(__WXMGL__)
    #include "wx/mgl/pen.h"
#elif defined(__WXDFB__)
    #include "wx/dfb/pen.h"
#elif defined(__WXMAC__)
    #include "wx/osx/pen.h"
#elif defined(__WXCOCOA__)
    #include "wx/cocoa/pen.h"
#elif defined(__WXPM__)
    #include "wx/os2/pen.h"
#endif

class WXDLLIMPEXP_CORE wxPenList: public wxGDIObjListBase
{
public:
    wxPen *FindOrCreatePen(const wxColour& colour,
                           int width = 1,
                           wxPenStyle style = wxPENSTYLE_SOLID);

#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxPen *FindOrCreatePen(const wxColour& colour, int width, int style)
        { return FindOrCreatePen(colour, width, (wxPenStyle)style); }
#endif
#if WXWIN_COMPATIBILITY_2_6
    wxDEPRECATED( void AddPen(wxPen*) );
    wxDEPRECATED( void RemovePen(wxPen*) );
#endif
};

extern WXDLLIMPEXP_DATA_CORE(wxPenList*)   wxThePenList;

// provide comparison operators to allow code such as
//
//      if ( pen.GetStyle() == wxTRANSPARENT )
//
// to compile without warnings which it would otherwise provoke from some
// compilers as it compares elements of different enums
#if FUTURE_WXWIN_COMPATIBILITY_3_0

inline bool operator==(wxPenStyle s, wxDeprecatedGUIConstants t)
{
    return static_cast<int>(s) == static_cast<int>(t);
}

inline bool operator!=(wxPenStyle s, wxDeprecatedGUIConstants t)
{
    return !(s == t);
}

#endif // FUTURE_WXWIN_COMPATIBILITY_3_0

#endif // _WX_PEN_H_BASE_
