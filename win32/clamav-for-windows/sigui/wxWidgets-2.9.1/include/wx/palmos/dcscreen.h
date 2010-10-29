/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/dcscreen.h
// Purpose:     wxScreenDC class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_DCSCREEN_H_
#define _WX_DCSCREEN_H_

#include "wx/dcscreen.h"
#include "wx/palmos/dc.h"

class WXDLLIMPEXP_CORE wxScreenDCImpl : public wxPalmDCImpl
{
public:
    // Create a DC representing the whole screen
    wxScreenDCImpl( wxScreenDC *owner );

    virtual void DoGetSize(int *w, int *h) const;

    DECLARE_CLASS(wxScreenDCImpl)
    wxDECLARE_NO_COPY_CLASS(wxScreenDCImpl);
};

#endif
    // _WX_DCSCREEN_H_

