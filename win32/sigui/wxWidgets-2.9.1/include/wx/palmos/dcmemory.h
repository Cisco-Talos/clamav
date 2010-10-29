/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/dcmemory.h
// Purpose:     wxMemoryDC class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_DCMEMORY_H_
#define _WX_DCMEMORY_H_

#include "wx/dcmemory.h"
#include "wx/palmos/dc.h"

class WXDLLIMPEXP_CORE wxMemoryDCImpl: public wxPalmDCImpl
{
public:
    wxMemoryDCImpl( wxMemoryDC *owner );
    wxMemoryDCImpl( wxMemoryDC *owner, wxBitmap& bitmap );
    wxMemoryDCImpl( wxMemoryDC *owner, wxDC *dc ); // Create compatible DC

    // override some base class virtuals
    virtual void DoGetSize(int* width, int* height) const;
    virtual void DoSelect(const wxBitmap& bitmap);

    virtual wxBitmap DoGetAsBitmap(const wxRect* subrect) const;

protected:
    // create DC compatible with the given one or screen if dc == NULL
    bool CreateCompatible(wxDC *dc);

    // initialize the newly created DC
    void Init();

    DECLARE_CLASS(wxMemoryDCImpl)
    wxDECLARE_NO_COPY_CLASS(wxMemoryDCImpl);
};

#endif
    // _WX_DCMEMORY_H_
