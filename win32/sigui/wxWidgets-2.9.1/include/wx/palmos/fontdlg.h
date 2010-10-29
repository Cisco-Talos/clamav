/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/fontdlg.h
// Purpose:     wxFontDialog class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PALMOS_FONTDLG_H_
#define _WX_PALMOS_FONTDLG_H_

// ----------------------------------------------------------------------------
// wxFontDialog
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxFontDialog : public wxFontDialogBase
{
public:
    wxFontDialog() : wxFontDialogBase() { /* must be Create()d later */ }
    wxFontDialog(wxWindow *parent)
        : wxFontDialogBase(parent) { Create(parent); }
    wxFontDialog(wxWindow *parent, const wxFontData& data)
        : wxFontDialogBase(parent, data) { Create(parent, data); }

    virtual int ShowModal();

protected:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxFontDialog)
};

#endif
    // _WX_PALMOS_FONTDLG_H_
