/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/dcmemory.cpp
// Purpose:
// Author:      Robert Roebling
// RCS-ID:      $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/gtk1/dcmemory.h"

#include <gdk/gdk.h>
#include <gtk/gtk.h>

//-----------------------------------------------------------------------------
// wxMemoryDCImpl
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxMemoryDCImpl, wxWindowDCImpl)

void wxMemoryDCImpl::Init()
{
    m_ok = false;

    m_cmap = gtk_widget_get_default_colormap();
}

wxMemoryDCImpl::wxMemoryDCImpl(wxMemoryDC *owner, wxDC *WXUNUSED(dc))
              : wxWindowDCImpl(owner)
{
    Init();
}

wxMemoryDCImpl::~wxMemoryDCImpl()
{
}

void wxMemoryDCImpl::DoSelect( const wxBitmap& bitmap )
{
    Destroy();

    m_selected = bitmap;
    if (m_selected.Ok())
    {
        if (m_selected.GetPixmap())
        {
            m_window = m_selected.GetPixmap();
        }
        else
        {
            m_window = m_selected.GetBitmap();
        }

        m_isMemDC = true;

        SetUpDC();
    }
    else
    {
        m_ok = false;
        m_window = NULL;
    }
}

void wxMemoryDCImpl::SetPen( const wxPen& penOrig )
{
    wxPen pen( penOrig );
    if ( m_selected.Ok() &&
            m_selected.GetBitmap() &&
                (pen != *wxTRANSPARENT_PEN) )
    {
        pen.SetColour( pen.GetColour() == *wxWHITE ? *wxBLACK : *wxWHITE );
    }

    wxWindowDCImpl::SetPen( pen );
}

void wxMemoryDCImpl::SetBrush( const wxBrush& brushOrig )
{
    wxBrush brush( brushOrig );
    if ( m_selected.Ok() &&
            m_selected.GetBitmap() &&
                (brush != *wxTRANSPARENT_BRUSH) )
    {
        brush.SetColour( brush.GetColour() == *wxWHITE ? *wxBLACK : *wxWHITE);
    }

    wxWindowDCImpl::SetBrush( brush );
}

void wxMemoryDCImpl::SetBackground( const wxBrush& brushOrig )
{
    wxBrush brush(brushOrig);

    if ( m_selected.Ok() &&
            m_selected.GetBitmap() &&
                (brush != *wxTRANSPARENT_BRUSH) )
    {
        brush.SetColour( brush.GetColour() == *wxWHITE ? *wxBLACK : *wxWHITE );
    }

    wxWindowDCImpl::SetBackground( brush );
}

void wxMemoryDCImpl::SetTextForeground( const wxColour& col )
{
    if ( m_selected.Ok() && m_selected.GetBitmap() )
    {
        wxWindowDCImpl::SetTextForeground( col == *wxWHITE ? *wxBLACK : *wxWHITE);
    }
    else
    {
        wxWindowDCImpl::SetTextForeground( col );
    }
}

void wxMemoryDCImpl::SetTextBackground( const wxColour &col )
{
    if (m_selected.Ok() && m_selected.GetBitmap())
    {
        wxWindowDCImpl::SetTextBackground( col == *wxWHITE ? *wxBLACK : *wxWHITE );
    }
    else
    {
        wxWindowDCImpl::SetTextBackground( col );
    }
}

void wxMemoryDCImpl::DoGetSize( int *width, int *height ) const
{
    if (m_selected.Ok())
    {
        if (width) (*width) = m_selected.GetWidth();
        if (height) (*height) = m_selected.GetHeight();
    }
    else
    {
        if (width) (*width) = 0;
        if (height) (*height) = 0;
    }
}
