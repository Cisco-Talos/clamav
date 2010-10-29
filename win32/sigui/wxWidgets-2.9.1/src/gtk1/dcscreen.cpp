/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/dcscreen.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/window.h"
#endif

#include <gdk/gdk.h>
#include <gdk/gdkx.h>
#include <gtk/gtk.h>

#include "wx/dcscreen.h"
#include "wx/gtk1/dcscreen.h"

//-----------------------------------------------------------------------------
// global data initialization
//-----------------------------------------------------------------------------

GdkWindow *wxScreenDCImpl::sm_overlayWindow  = NULL;
int wxScreenDCImpl::sm_overlayWindowX = 0;
int wxScreenDCImpl::sm_overlayWindowY = 0;

//-----------------------------------------------------------------------------
// wxScreenDCImpl
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxScreenDCImpl, wxPaintDCImpl)

wxScreenDCImpl::wxScreenDCImpl(wxScreenDC *owner)
              : wxPaintDCImpl(owner)
{
    m_ok = false;
    m_cmap = gdk_colormap_get_system();
    m_window = GDK_ROOT_PARENT();

    m_isScreenDC = true;

    SetUpDC();

    gdk_gc_set_subwindow( m_penGC, GDK_INCLUDE_INFERIORS );
    gdk_gc_set_subwindow( m_brushGC, GDK_INCLUDE_INFERIORS );
    gdk_gc_set_subwindow( m_textGC, GDK_INCLUDE_INFERIORS );
    gdk_gc_set_subwindow( m_bgGC, GDK_INCLUDE_INFERIORS );
}

wxScreenDCImpl::~wxScreenDCImpl()
{
    gdk_gc_set_subwindow( m_penGC, GDK_CLIP_BY_CHILDREN );
    gdk_gc_set_subwindow( m_brushGC, GDK_CLIP_BY_CHILDREN );
    gdk_gc_set_subwindow( m_textGC, GDK_CLIP_BY_CHILDREN );
    gdk_gc_set_subwindow( m_bgGC, GDK_CLIP_BY_CHILDREN );
}

void wxScreenDCImpl::DoGetSize(int *width, int *height) const
{
    wxDisplaySize(width, height);
}
