/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/dcmemory.cpp
// Purpose:     wxMemoryDCImpl class
// Author:      Julian Smart
// Modified by:
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/settings.h"
    #include "wx/dcmemory.h"
    #include "wx/dcclient.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"
#include "wx/motif/dcmemory.h"

//-----------------------------------------------------------------------------
// wxMemoryDCImpl
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxMemoryDCImpl, wxWindowDCImpl)

void wxMemoryDCImpl::Init()
{
    m_ok = true;
    m_display = wxGetDisplay();

    Display* display = (Display*) m_display;

    XGCValues gcvalues;
    gcvalues.foreground = BlackPixel (display, DefaultScreen (display));
    gcvalues.background = WhitePixel (display, DefaultScreen (display));
    gcvalues.graphics_exposures = False;
    gcvalues.subwindow_mode = IncludeInferiors;
    gcvalues.line_width = 1;
    m_gc = (WXGC) XCreateGC (display, RootWindow (display, DefaultScreen (display)),
        GCForeground | GCBackground | GCGraphicsExposures | GCLineWidth | GCSubwindowMode,
        &gcvalues);

    m_backgroundPixel = gcvalues.background;

    SetBrush (* wxWHITE_BRUSH);
    SetPen (* wxBLACK_PEN);
    SetFont(wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT));
}

wxMemoryDCImpl::wxMemoryDCImpl(wxMemoryDC *owner, wxDC* dc)
              : wxWindowDCImpl(owner)
{
    m_ok = true;
    if (dc && dc->IsKindOf(CLASSINFO(wxWindowDC)))
        m_display = ((wxWindowDCImpl *)dc->GetImpl())->GetDisplay();
    else
        m_display = wxGetDisplay();

    Display* display = (Display*) m_display;

    XGCValues gcvalues;
    gcvalues.foreground = BlackPixel (display, DefaultScreen (display));
    gcvalues.background = WhitePixel (display, DefaultScreen (display));
    gcvalues.graphics_exposures = False;
    gcvalues.subwindow_mode = IncludeInferiors;
    gcvalues.line_width = 1;
    m_gc = (WXGC) XCreateGC (display, RootWindow (display, DefaultScreen (display)),
        GCForeground | GCBackground | GCGraphicsExposures | GCLineWidth | GCSubwindowMode,
        &gcvalues);

    m_backgroundPixel = gcvalues.background;

    SetBrush (* wxWHITE_BRUSH);
    SetPen (* wxBLACK_PEN);
}

wxMemoryDCImpl::~wxMemoryDCImpl(void)
{
}

void wxMemoryDCImpl::DoSelect( const wxBitmap& bitmap )
{
    m_bitmap = bitmap;

    if (m_gc)
        XFreeGC((Display*) m_display, (GC) m_gc);
    m_gc = (WXGC) NULL;

    if (m_bitmap.Ok() && (bitmap.GetDisplay() == m_display))
    {
        m_pixmap = m_bitmap.GetDrawable();
        Display* display = (Display*) m_display;

        XGCValues gcvalues;
        gcvalues.foreground = BlackPixel (display, DefaultScreen (display));
        gcvalues.background = WhitePixel (display, DefaultScreen (display));
        gcvalues.graphics_exposures = False;
        gcvalues.subwindow_mode = IncludeInferiors;
        gcvalues.line_width = 1;
        m_gc = (WXGC) XCreateGC (display, (Drawable)m_pixmap/* RootWindow (display, DefaultScreen (display)) */,
            GCForeground | GCBackground | GCGraphicsExposures | GCLineWidth | GCSubwindowMode,
            &gcvalues);

        m_backgroundPixel = gcvalues.background;
        m_ok = true;

        SetBrush (* wxWHITE_BRUSH);
        SetPen (* wxBLACK_PEN);
    }
    else
    {
        m_ok = false;
        m_pixmap = (WXPixmap) 0;
    };
}

void wxMemoryDCImpl::DoGetSize( int *width, int *height ) const
{
    if (m_bitmap.Ok())
    {
        if (width) (*width) = m_bitmap.GetWidth();
        if (height) (*height) = m_bitmap.GetHeight();
    }
    else
    {
        if (width) (*width) = 0;
        if (height) (*height) = 0;
    };
}
