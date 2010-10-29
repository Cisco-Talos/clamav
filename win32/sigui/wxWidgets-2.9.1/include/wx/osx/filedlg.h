/////////////////////////////////////////////////////////////////////////////
// Name:        filedlg.h
// Purpose:     wxFileDialog class
// Author:      Stefan Csomor
// Modified by:
// Created:     1998-01-01
// RCS-ID:      $Id$
// Copyright:   (c) Stefan Csomor
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_FILEDLG_H_
#define _WX_FILEDLG_H_

//-------------------------------------------------------------------------
// wxFileDialog
//-------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxFileDialog: public wxFileDialogBase
{
DECLARE_DYNAMIC_CLASS(wxFileDialog)
protected:
    wxArrayString m_fileNames;
    wxArrayString m_paths;

public:
    wxFileDialog(wxWindow *parent,
                 const wxString& message = wxFileSelectorPromptStr,
                 const wxString& defaultDir = wxEmptyString,
                 const wxString& defaultFile = wxEmptyString,
                 const wxString& wildCard = wxFileSelectorDefaultWildcardStr,
                 long style = wxFD_DEFAULT_STYLE,
                 const wxPoint& pos = wxDefaultPosition,
                 const wxSize& sz = wxDefaultSize,
                 const wxString& name = wxFileDialogNameStr);

    virtual void GetPaths(wxArrayString& paths) const { paths = m_paths; }
    virtual void GetFilenames(wxArrayString& files) const { files = m_fileNames ; }

    virtual int ShowModal();
    
#if wxOSX_USE_COCOA
    virtual void ShowWindowModal();
    virtual void ModalFinishedCallback(void* panel, int resultCode);
#endif

    virtual bool SupportsExtraControl() const;
    
protected:
    // not supported for file dialog, RR
    virtual void DoSetSize(int WXUNUSED(x), int WXUNUSED(y),
                           int WXUNUSED(width), int WXUNUSED(height),
                           int WXUNUSED(sizeFlags) = wxSIZE_AUTO) {}
    
    void SetupExtraControls(WXWindow nativeWindow);
};

#endif // _WX_FILEDLG_H_
