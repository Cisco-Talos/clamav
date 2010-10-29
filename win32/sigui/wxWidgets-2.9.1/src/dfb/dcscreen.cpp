/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/dcscreen.cpp
// Purpose:     wxScreenDC implementation
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

#include "wx/dcscreen.h"
#include "wx/dfb/dcscreen.h"
#include "wx/dfb/private.h"

// ===========================================================================
// implementation
// ===========================================================================

//-----------------------------------------------------------------------------
// wxScreenDC
//-----------------------------------------------------------------------------

// FIXME: Currently, wxScreenDC doesn't work at all in non-exclusive mode
//        (DFSCL_NORMAL). In this mode, requesting primary surface results
//        in one of the following actions, depending on directfbrc
//        configuration:
//
//        (1) if force-desktop, a surface is created and used as *background*
//            for the windows managed by DFB WM
//
//        (2) otherwise, a dummy surface of the right size and format is
//            created, but isn't shown on the screen
//
//        (3) furthermore, if autoflip-window option is not used and primary
//            surface is requested as single-buffered (which is needed to
//            implement wxScreenDC semantics), a warning is issued in addition
//            to 2); if autoflip-window is used, then a helper thread is
//            created and does periodic flipping, which is even worse
//
//        2) and 3) are obviously unsatisfactory. 1) isn't suitable either,
//        because wxScreenDC has to render *on top* of windows.
//
//        In conclusion, wxScreenDC as currently implemented is only usable
//        for measuring things (e.g. font sizes). For this task, however, it
//        is quite expensive to create in DFSCL_NORMAL mode, because it
//        involves creation of a new surface as big as the screen.
//
//        The surface, as obtained from GetPrimarySurface(), is double-buffered
//        for the sole purpose of silencing the warning from 3) above.

IMPLEMENT_ABSTRACT_CLASS(wxScreenDCImpl, wxDFBDCImpl)

wxScreenDCImpl::wxScreenDCImpl(wxScreenDC *owner)
              : wxDFBDCImpl(owner)
{
    DFBInit(wxIDirectFB::Get()->GetPrimarySurface());
}
