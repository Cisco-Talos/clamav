/////////////////////////////////////////////////////////////////////////////
// Name:        wx/mgl/pen.h
// Purpose:
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __WX_PEN_H__
#define __WX_PEN_H__

#include "wx/defs.h"
#include "wx/object.h"
#include "wx/string.h"
#include "wx/gdiobj.h"
#include "wx/gdicmn.h"

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxBitmap;
class WXDLLIMPEXP_FWD_CORE wxPen;

//-----------------------------------------------------------------------------
// wxPen
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxPen : public wxPenBase
{
public:
    wxPen() {}
    wxPen(const wxColour &colour, int width = 1, wxPenStyle style = wxPENSTYLE_SOLID);
#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxDEPRECATED_FUTURE( wxPen(const wxColour& col, int width, int style) );
#endif

    wxPen(const wxBitmap& stipple, int width);
    virtual ~wxPen() {}
    bool operator == (const wxPen& pen) const;
    bool operator != (const wxPen& pen) const;

    void SetColour(const wxColour &colour);
    void SetColour(unsigned char red, unsigned char green, unsigned char blue);
    void SetCap(wxPenCap capStyle);
    void SetJoin(wxPenJoin joinStyle);
    void SetStyle(wxPenStyle style);
    void SetWidth(int width);
    void SetDashes(int number_of_dashes, const wxDash *dash);
    void SetStipple(const wxBitmap& stipple);

    wxColour GetColour() const;
    wxPenCap GetCap() const;
    wxPenJoin GetJoin() const;
    wxPenStyle GetStyle() const;
    int GetWidth() const;
    int GetDashes(wxDash **ptr) const;
    int GetDashCount() const;
    wxDash* GetDash() const;
    wxBitmap *GetStipple() const;

#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxDEPRECATED_FUTURE( void SetStyle(int style) )
        { SetStyle((wxPenStyle)style); }
#endif

    // implementation:
    void* GetPixPattern() const;

protected:
    virtual wxGDIRefData *CreateGDIRefData() const;
    virtual wxGDIRefData *CloneGDIRefData(const wxGDIRefData *data) const;

private:
    DECLARE_DYNAMIC_CLASS(wxPen)
};

#endif // __WX_PEN_H__
