/////////////////////////////////////////////////////////////////////////////
// Name:        wx/mgl/brush.h
// Purpose:
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __WX_BRUSH_H__
#define __WX_BRUSH_H__

#include "wx/defs.h"
#include "wx/object.h"
#include "wx/string.h"
#include "wx/gdiobj.h"
#include "wx/bitmap.h"

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxBitmap;
class WXDLLIMPEXP_FWD_CORE wxBrush;

//-----------------------------------------------------------------------------
// wxBrush
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxBrush : public wxBrushBase
{
public:
    wxBrush() {}
    wxBrush(const wxColour &colour, wxBrushStyle style = wxBRUSHSTYLE_SOLID);
#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxDEPRECATED_FUTURE( wxBrush(const wxColour& col, int style) );
#endif
    wxBrush(const wxBitmap &stippleBitmap);

    bool operator==(const wxBrush& brush) const;
    bool operator!=(const wxBrush& brush) const;

    wxBrushStyle GetStyle() const;
    wxColour GetColour() const;
    wxBitmap *GetStipple() const;

    void SetColour(const wxColour& col);
    void SetColour(unsigned char r, unsigned char g, unsigned char b);
    void SetStyle(wxBrushStyle style);
    void SetStipple(const wxBitmap& stipple);

#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxDEPRECATED_FUTURE( void SetStyle(int style) )
        { SetStyle((wxBrushStyle)style); }
#endif

    // implementation:

    void* GetMaskPattern() const;
    void* GetPixPattern() const;

protected:
    virtual wxGDIRefData *CreateGDIRefData() const;
    virtual wxGDIRefData *CloneGDIRefData(const wxGDIRefData *data) const;

private:
    DECLARE_DYNAMIC_CLASS(wxBrush)
};

#endif // __WX_BRUSH_H__
