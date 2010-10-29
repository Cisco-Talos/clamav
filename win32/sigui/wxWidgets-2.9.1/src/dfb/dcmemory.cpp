/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/dcmemory.cpp
// Purpose:     wxMemoryDCImpl implementation
// Author:      Vaclav Slavik
// Created:     2006-08-16
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/bitmap.h"
#endif

#include "wx/dcmemory.h"
#include "wx/dfb/dcmemory.h"
#include "wx/dfb/private.h"

// ===========================================================================
// implementation
// ===========================================================================

//-----------------------------------------------------------------------------
// wxMemoryDCImpl
//-----------------------------------------------------------------------------

#warning "FIXME: verify/fix that wxMemoryDCImpl works correctly with mono bitmaps"

IMPLEMENT_ABSTRACT_CLASS(wxMemoryDCImpl, wxDFBDCImpl)

void wxMemoryDCImpl::Init()
{
}

wxMemoryDCImpl::wxMemoryDCImpl(wxMemoryDC *owner)
              : wxDFBDCImpl(owner)
{
    Init();
}

wxMemoryDCImpl::wxMemoryDCImpl(wxMemoryDC *owner, wxBitmap& bitmap)
              : wxDFBDCImpl(owner)
{
    Init();
    DoSelect(bitmap);
}

wxMemoryDCImpl::wxMemoryDCImpl(wxMemoryDC *owner, wxDC *WXUNUSED(dc))
              : wxDFBDCImpl(owner)
{
}

void wxMemoryDCImpl::DoSelect(const wxBitmap& bitmap)
{
    m_bmp = bitmap;

    if ( !bitmap.Ok() )
    {
        // select the bitmap out of the DC
        m_surface = NULL;
        return;
    }

    // init the DC for drawing to this bitmap
    DFBInit(bitmap.GetDirectFBSurface());
}
