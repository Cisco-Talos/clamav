/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/dirdlg.h
// Purpose:     wxDirDialog class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_DIRDLG_H_
#define _WX_DIRDLG_H_

class WXDLLIMPEXP_CORE wxDirDialog : public wxDirDialogBase
{
public:
    wxDirDialog(wxWindow *parent,
                const wxString& message = wxDirSelectorPromptStr,
                const wxString& defaultPath = wxEmptyString,
                long style = 0,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                const wxString& name = wxDirDialogNameStr);

    void SetPath(const wxString& path);

    virtual int ShowModal();

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxDirDialog)
};

#endif
    // _WX_DIRDLG_H_
