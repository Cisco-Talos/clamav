/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/combobox.h
// Purpose:     wxComboBox class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_COMBOBOX_H_
#define _WX_COMBOBOX_H_

#include "wx/choice.h"

#if wxUSE_COMBOBOX

// ----------------------------------------------------------------------------
// Combobox control
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxComboBox: public wxChoice
{
public:
    wxComboBox() { }

    wxComboBox(wxWindow *parent, wxWindowID id,
            const wxString& value = wxEmptyString,
            const wxPoint& pos = wxDefaultPosition,
            const wxSize& size = wxDefaultSize,
            int n = 0, const wxString choices[] = NULL,
            long style = 0,
            const wxValidator& validator = wxDefaultValidator,
            const wxString& name = wxComboBoxNameStr)
    {
        Create(parent, id, value, pos, size, n, choices, style, validator, name);
    }
    wxComboBox(wxWindow *parent, wxWindowID id,
            const wxString& value,
            const wxPoint& pos,
            const wxSize& size,
            const wxArrayString& choices,
            long style = 0,
            const wxValidator& validator = wxDefaultValidator,
            const wxString& name = wxComboBoxNameStr)
    {
        Create(parent, id, value, pos, size, choices, style, validator, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& value = wxEmptyString,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                int n = 0,
                const wxString choices[] = NULL,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxComboBoxNameStr);
    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& value,
                const wxPoint& pos,
                const wxSize& size,
                const wxArrayString& choices,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxComboBoxNameStr);

    // List functions: see wxChoice

    // Text field functions
    wxString GetValue() const { return GetLabel(); }
    virtual void SetValue(const wxString& value);

    // Clipboard operations
    virtual void Copy();
    virtual void Cut();
    virtual void Paste();
    virtual void SetInsertionPoint(long pos);
    virtual void SetInsertionPointEnd();
    virtual long GetInsertionPoint() const;
    virtual wxTextPos GetLastPosition() const;
    virtual void Replace(long from, long to, const wxString& value);
    virtual void Remove(long from, long to);
    virtual void SetSelection(int n) { wxChoice::SetSelection(n); }
    virtual void SetSelection(long from, long to);
    virtual void SetEditable(bool editable);
    virtual bool IsEditable() const;

    virtual void Undo();
    virtual void Redo();
    virtual void SelectAll();

    virtual bool CanCopy() const;
    virtual bool CanCut() const;
    virtual bool CanPaste() const;
    virtual bool CanUndo() const;
    virtual bool CanRedo() const;

    // implementation only from now on
    virtual bool MSWCommand(WXUINT param, WXWORD id);
    bool MSWProcessEditMsg(WXUINT msg, WXWPARAM wParam, WXLPARAM lParam);
    virtual WXLRESULT MSWWindowProc(WXUINT nMsg, WXWPARAM wParam, WXLPARAM lParam);

    WXHWND GetEditHWND() const;

protected:
    virtual WXDWORD MSWGetStyle(long style, WXDWORD *exstyle) const;

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxComboBox)
};

#endif // wxUSE_COMBOBOX
#endif
    // _WX_COMBOBOX_H_
