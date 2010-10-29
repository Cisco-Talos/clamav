/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/dcscreen.cpp
// Purpose:     wxScreenDC class
// Author:      Julian Smart, Robert Roebling
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart, Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/dcscreen.h"
#include "wx/x11/dcscreen.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/window.h"
    #include "wx/frame.h"
#endif

#include "wx/fontutil.h"

#include "wx/x11/private.h"

//-----------------------------------------------------------------------------
// wxScreenDC
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxScreenDCImpl,wxPaintDCImpl)

wxScreenDCImpl::wxScreenDCImpl( wxDC* owner )
              : wxPaintDCImpl( owner )
{
    m_ok = false;

    m_display = (WXDisplay *) wxGlobalDisplay();

    int screen = DefaultScreen( (Display*) m_display );
    m_cmap = (WXColormap) DefaultColormap( (Display*) m_display, screen );

    m_x11window = (WXWindow) RootWindow( (Display*) m_display, screen );

    m_isScreenDC = true;

#if wxUSE_UNICODE
    m_context = wxTheApp->GetPangoContext();
    m_fontdesc = wxNORMAL_FONT->GetNativeFontInfo()->description;
#endif

    SetUpDC();

    XSetSubwindowMode( (Display*) m_display, (GC) m_penGC, IncludeInferiors );
    XSetSubwindowMode( (Display*) m_display, (GC) m_brushGC, IncludeInferiors );
    XSetSubwindowMode( (Display*) m_display, (GC) m_textGC, IncludeInferiors );
    XSetSubwindowMode( (Display*) m_display, (GC) m_bgGC, IncludeInferiors );
}

wxScreenDCImpl::~wxScreenDCImpl()
{
    XSetSubwindowMode( (Display*) m_display, (GC) m_penGC, ClipByChildren );
    XSetSubwindowMode( (Display*) m_display, (GC) m_brushGC, ClipByChildren );
    XSetSubwindowMode( (Display*) m_display, (GC) m_textGC, ClipByChildren );
    XSetSubwindowMode( (Display*) m_display, (GC) m_bgGC, ClipByChildren );
}

void wxScreenDCImpl::DoGetSize(int *width, int *height) const
{
    wxDisplaySize(width, height);
}
