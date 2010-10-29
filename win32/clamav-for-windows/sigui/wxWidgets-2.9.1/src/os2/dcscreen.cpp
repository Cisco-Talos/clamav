/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/dcscreen.cpp
// Purpose:     wxScreenDC class
// Author:      David Webster
// Modified by:
// Created:     10/14/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/os2/dcscreen.h"

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/window.h"
#endif

#include "wx/os2/private.h"

IMPLEMENT_ABSTRACT_CLASS(wxScreenDCImpl, wxPMDCImpl)

// Create a DC representing the whole screen
wxScreenDCImpl::wxScreenDCImpl( wxScreenDC *owner ) :
    wxPMDCImpl( owner )
{
    m_hDC = ::WinOpenWindowDC(HWND_DESKTOP);
    m_hPS = ::WinGetScreenPS(HWND_DESKTOP);
    ::GpiSetBackMix(m_hPS, BM_LEAVEALONE);
} // end of wxScreenDC::wxScreenDC()

void wxScreenDCImpl::DoGetSize( int* pnWidth,
                                int* pnHeight ) const
{
    //
    // Skip wxWindowDC version because it doesn't work without a valid m_canvas
    // (which we don't have)
    //
    wxPMDCImpl::DoGetSize( pnWidth, pnHeight );

} // end of wxScreenDC::DoGetSize
