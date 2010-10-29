/////////////////////////////////////////////////////////////////////////////
// Name:        dcscreen.h
// Purpose:
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __WX_DCSCREEN_H__
#define __WX_DCSCREEN_H__

#include "wx/dcclient.h"

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxScreenDC;

//-----------------------------------------------------------------------------
// wxScreenDC
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxScreenDC: public wxDC
{
public:
    wxScreenDC();
    virtual ~wxScreenDC();

    static bool StartDrawingOnTop(wxWindow *WXUNUSED(window)) { return TRUE; }
    static bool StartDrawingOnTop(wxRect *WXUNUSED(rect) = NULL) { return TRUE; }
    static bool EndDrawingOnTop() { return TRUE; }

private:
    DECLARE_DYNAMIC_CLASS(wxScreenDC)
};

#endif

    // __WX_DCSCREEN_H__

