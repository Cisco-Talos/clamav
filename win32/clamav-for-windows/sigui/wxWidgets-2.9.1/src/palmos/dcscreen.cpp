/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/dcscreen.cpp
// Purpose:     wxScreenDC class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/palmos/dcscreen.h"

#ifndef WX_PRECOMP
   #include "wx/string.h"
   #include "wx/window.h"
#endif

IMPLEMENT_ABSTRACT_CLASS(wxScreenDCImpl, wxPalmDCImpl)

// Create a DC representing the whole screen
wxScreenDCImpl::wxScreenDCImpl( wxScreenDC *owner ) :
    wxPalmDCImpl( owner )
{
}

void wxScreenDCImpl::DoGetSize (int *w, int *h) const
{
}
