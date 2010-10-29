/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/colordlg.h
// Purpose:     wxColourDialog class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - real native implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_COLORDLG_H_
#define _WX_COLORDLG_H_

#include "wx/defs.h"
#include "wx/dialog.h"
#include "wx/cmndata.h"

// ----------------------------------------------------------------------------
// wxColourDialog: dialog for choosing a colours
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxColourDialog : public wxDialog
{
public:
    wxColourDialog();
    wxColourDialog(wxWindow *parent, wxColourData *data = NULL);

    bool Create(wxWindow *parent, wxColourData *data = NULL);

    wxColourData& GetColourData() { return m_colourData; }

    virtual int ShowModal();

protected:
    wxColourData        m_colourData;

    DECLARE_DYNAMIC_CLASS_NO_COPY(wxColourDialog)
};

#endif
    // _WX_COLORDLG_H_
