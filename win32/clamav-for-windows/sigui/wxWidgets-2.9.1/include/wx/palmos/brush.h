/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/brush.h
// Purpose:     wxBrush class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_BRUSH_H_
#define _WX_BRUSH_H_

#include "wx/gdicmn.h"
#include "wx/gdiobj.h"
#include "wx/bitmap.h"

class WXDLLIMPEXP_FWD_CORE wxBrush;

// ----------------------------------------------------------------------------
// wxBrush
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxBrush : public wxBrushBase
{
public:
    wxBrush();
    wxBrush(const wxColour& col, wxBrushStyle style = wxBRUSHSTYLE_SOLID);
#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxDEPRECATED_FUTURE( wxBrush(const wxColour& col, int style) );
#endif
    wxBrush(const wxBitmap& stipple);
    virtual ~wxBrush();

    virtual void SetColour(const wxColour& col);
    virtual void SetColour(unsigned char r, unsigned char g, unsigned char b);
    virtual void SetStyle(wxBrushStyle style);
    virtual void SetStipple(const wxBitmap& stipple);

    bool operator==(const wxBrush& brush) const;
    bool operator!=(const wxBrush& brush) const { return !(*this == brush); }

    wxColour GetColour() const;
    wxBrushStyle GetStyle() const;
    wxBitmap *GetStipple() const;

#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxDEPRECATED_FUTURE( void SetStyle(int style) )
        { SetStyle((wxBrushStyle)style); }
#endif

    // return the HBRUSH for this brush
    virtual WXHANDLE GetResourceHandle() const;

protected:
    virtual wxGDIRefData *CreateGDIRefData() const;
    virtual wxGDIRefData *CloneGDIRefData(const wxGDIRefData *data) const;

private:
    DECLARE_DYNAMIC_CLASS(wxBrush)
};

#endif // _WX_BRUSH_H_
