/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/dcclient.cpp
// Purpose:
// Author:      Vaclav Slavik
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/dcclient.h"

#ifndef WX_PRECOMP
    #include "wx/window.h"
#endif

#include <mgraph.hpp>

IMPLEMENT_DYNAMIC_CLASS(wxWindowDC, wxDC)
IMPLEMENT_DYNAMIC_CLASS(wxClientDC,wxWindowDC)
IMPLEMENT_DYNAMIC_CLASS(wxPaintDC, wxClientDC)

wxWindowDC::wxWindowDC(wxWindow *win) : m_wnd(win)
{
    MGLDevCtx *dc = win->GetPaintMGLDC();

    if ( dc )
    {
        m_inPaintHandler = TRUE;

        m_globalClippingRegion = win->GetUpdateRegion();
        SetMGLDC(dc, FALSE);
    }
    else
    {
        m_inPaintHandler = FALSE;

        dc = new MGLDevCtx(MGL_wmBeginPaint(win->GetHandle()));

        MGLRegion clip;
        dc->getClipRegion(clip);
        m_globalClippingRegion = wxRegion(clip);
        SetMGLDC(dc, TRUE);
        // TRUE means that dtor will delete MGLDevCtx object
        // but it won't destroy MGLDC returned by MGL_wmBeginPaint because
        // ~MGLDevCtx() doesn't call destroy()
    }
}

wxWindowDC::~wxWindowDC()
{
    if ( !m_inPaintHandler )
    {
        GetMGLDC()->setDC(NULL);
        MGL_wmEndPaint(m_wnd->GetHandle());
    }
}

wxClientDC::wxClientDC(wxWindow *win) : wxWindowDC(win)
{
    wxRect r = m_wnd->GetClientRect();
    m_globalClippingRegion.Intersect(r);
    SetClippingRegion(m_globalClippingRegion);
    SetDeviceOrigin(r.x, r.y);
}
