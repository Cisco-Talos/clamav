/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/dc.cpp
// Purpose:     wxDC class
// Author:      Julian Smart
// Modified by:
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/dc.h"
#include "wx/x11/dc.h"

#ifndef WX_PRECOMP
    #include "wx/dcmemory.h"
#endif

IMPLEMENT_ABSTRACT_CLASS(wxX11DCImpl, wxDCImpl)

//-----------------------------------------------------------------------------
// wxDC
//-----------------------------------------------------------------------------

wxX11DCImpl::wxX11DCImpl( wxDC *owner ) :
   wxDCImpl( owner )
{
    m_ok = false;

    m_pen = *wxBLACK_PEN;
    m_font = *wxNORMAL_FONT;
    m_brush = *wxWHITE_BRUSH;

    m_backgroundMode = wxTRANSPARENT;
}

void wxX11DCImpl::DoSetClippingRegion( wxCoord x, wxCoord y, wxCoord width, wxCoord height )
{
    m_clipping = true;
    m_clipX1 = x;
    m_clipY1 = y;
    m_clipX2 = x + width;
    m_clipY2 = y + height;
}

void wxX11DCImpl::DoGetSizeMM( int* width, int* height ) const
{
    int w, h;
    DoGetSize( &w, &h );

    if ( width )
        *width = int( double(w) / (m_scaleX*m_mm_to_pix_x) );
    if ( height )
        *height = int( double(h) / (m_scaleY*m_mm_to_pix_y) );
}

// Resolution in pixels per logical inch
wxSize wxX11DCImpl::GetPPI() const
{
    // TODO (should probably be pure virtual)
    return wxSize(0, 0);
}
