/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/dcmemory.cpp
// Purpose:     wxMemoryDC class
// Author:      Julian Smart
// Modified by:
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/dcmemory.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/settings.h"
#endif

#include "wx/x11/private.h"
#include "wx/x11/dcmemory.h"

IMPLEMENT_ABSTRACT_CLASS(wxMemoryDCImpl,wxWindowDCImpl)

wxMemoryDCImpl::wxMemoryDCImpl( wxDC *owner )
  : wxWindowDCImpl( owner )
{
    Init();
}

wxMemoryDCImpl::wxMemoryDCImpl(  wxDC *owner, wxBitmap& bitmap )
  : wxWindowDCImpl( owner )
{
    Init();
    DoSelect(bitmap);
}

wxMemoryDCImpl::wxMemoryDCImpl( wxDC* owner, wxDC *WXUNUSED(dc) )
  : wxWindowDCImpl( owner )
{
    Init();
}

void wxMemoryDCImpl::Init()
{
    m_ok = false;

    m_display = (WXDisplay *) wxGlobalDisplay();

    int screen = DefaultScreen( wxGlobalDisplay() );
    m_cmap = (WXColormap) DefaultColormap( wxGlobalDisplay(), screen );
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
            m_x11window = (WXWindow) m_selected.GetPixmap();
        }
        else
        {
            m_x11window = m_selected.GetBitmap();
        }

        m_isMemDC = true;

        SetUpDC();
    }
    else
    {
        m_ok = false;
        m_x11window = NULL;
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

const wxBitmap& wxMemoryDCImpl::GetSelectedBitmap() const
{
    return m_selected;
}

wxBitmap& wxMemoryDCImpl::GetSelectedBitmap()
{
    return m_selected;
}
