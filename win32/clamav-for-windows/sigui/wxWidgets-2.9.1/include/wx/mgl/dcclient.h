/////////////////////////////////////////////////////////////////////////////
// Name:        dcclient.h
// Purpose:
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __WX_DCCLIENT_H__
#define __WX_DCCLIENT_H__

#include "wx/dc.h"

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxWindowDC;
class WXDLLIMPEXP_FWD_CORE wxPaintDC;
class WXDLLIMPEXP_FWD_CORE wxClientDC;
class WXDLLIMPEXP_FWD_CORE wxWindowMGL;

//-----------------------------------------------------------------------------
// wxWindowDC
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxWindowDC : public wxDC
{
public:
    wxWindowDC() {}
    virtual ~wxWindowDC();
    wxWindowDC(wxWindow *win);

protected:
    wxWindow *m_wnd;
    bool      m_inPaintHandler;

private:
    DECLARE_DYNAMIC_CLASS(wxWindowDC)
};

//-----------------------------------------------------------------------------
// wxClientDC
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxClientDC : public wxWindowDC
{
public:
    wxClientDC() : wxWindowDC() {}
    wxClientDC(wxWindow *win);

private:
    DECLARE_DYNAMIC_CLASS(wxClientDC)
};

//-----------------------------------------------------------------------------
// wxPaintDC
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxPaintDC : public wxClientDC
{
public:
    wxPaintDC() : wxClientDC() {}
    wxPaintDC(wxWindow *win) : wxClientDC(win) {}

private:
    DECLARE_DYNAMIC_CLASS(wxPaintDC)
};

#endif // __WX_DCCLIENT_H__
