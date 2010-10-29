/////////////////////////////////////////////////////////////////////////////
// Name:        cursor.h
// Purpose:
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __WX_CURSOR_H__
#define __WX_CURSOR_H__

#include "wx/gdiobj.h"
#include "wx/gdicmn.h"

class MGLCursor;

//-----------------------------------------------------------------------------
// wxCursor
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxCursor : public wxGDIObject
{
public:

    wxCursor();
    wxCursor(wxStockCursor id) { InitFromStock(id); }
#if WXWIN_COMPATIBILITY_2_8
    wxCursor(int id) { InitFromStock((wxStockCursor)id); }
#endif
    wxCursor(const wxString& name,
             wxBitmapType type = wxCURSOR_DEFAULT_TYPE,
             int hotSpotX = 0, int hotSpotY = 0);
    virtual ~wxCursor();

    // implementation
    MGLCursor *GetMGLCursor() const;

private:
    void InitFromStock(wxStockCursor);

    DECLARE_DYNAMIC_CLASS(wxCursor)
};

#endif // __WX_CURSOR_H__
