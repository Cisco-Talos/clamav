/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/control.h
// Purpose:     wxControl class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_CONTROL_H_
#define _WX_CONTROL_H_

#include "wx/dynarray.h"

// General item class
class WXDLLIMPEXP_CORE wxControl : public wxControlBase
{
public:
    wxControl() { Init(); }

    wxControl(wxWindow *parent, wxWindowID id,
              const wxPoint& pos = wxDefaultPosition,
              const wxSize& size = wxDefaultSize, long style = 0,
              const wxValidator& validator = wxDefaultValidator,
              const wxString& name = wxControlNameStr)
    {
        Init();
        Create(parent, id, pos, size, style, validator, name);
    }

    bool Create(wxWindow *parent, wxWindowID id,
            const wxPoint& pos = wxDefaultPosition,
            const wxSize& size = wxDefaultSize, long style = 0,
            const wxValidator& validator = wxDefaultValidator,
            const wxString& name = wxControlNameStr);

    virtual ~wxControl();

    // Simulates an event
    virtual void Command(wxCommandEvent& event) { ProcessCommand(event); }

    virtual bool Enable( bool enable = true );
    virtual bool IsEnabled() const;

    virtual bool Show( bool show = true );
    virtual bool IsShown() const;

    virtual void SetLabel(const wxString& label);
    //virtual wxString GetLabel();

    // implementation from now on
    // --------------------------

    virtual wxVisualAttributes GetDefaultAttributes() const
    {
        return GetClassDefaultAttributes(GetWindowVariant());
    }

    static wxVisualAttributes
    GetClassDefaultAttributes(wxWindowVariant variant = wxWINDOW_VARIANT_NORMAL);

    // Calls the callback and appropriate event handlers
    bool ProcessCommand(wxCommandEvent& event);

    const wxArrayLong& GetSubcontrols() const { return m_subControls; }

    void OnEraseBackground(wxEraseEvent& event);

protected:
    // regardless how deeply we are in wxWidgets hierarchy always get correct form
    WXFORMPTR GetParentForm() const;
    WXFORMPTR GetObjectFormIndex(uint16_t& index) const;
    void* GetObjectPtr() const;

    // choose the default border for this window
    virtual wxBorder GetDefaultBorder() const;

    // on/off-like controls
    void SetBoolValue(bool value);
    bool GetBoolValue() const;
    void SetIntValue(int val);

    // native labels access
    void SetFieldLabel(const wxString& label);
    void SetControlLabel(const wxString& label);
    wxString GetFieldLabel();
    wxString GetControlLabel();

    // return default best size (doesn't really make any sense, override this)
    virtual wxSize DoGetBestSize() const;

    // getting and setting sizes
    virtual void DoGetPosition( int *x, int *y ) const;
    virtual void DoGetSize( int *width, int *height ) const;
    virtual void DoMoveWindow(int x, int y, int width, int height);

    // create the control of the given ControlStyleType: this is typically called
    // from Create() method of the derived class passing its label, pos and
    // size parameter (style parameter is not needed because m_windowStyle is
    // supposed to had been already set and so is used instead when this
    // function is called)
    bool PalmCreateControl(int palmStyle,
                           const wxString& label,
                           const wxPoint& pos,
                           const wxSize& size,
                           uint8_t groupID = 0);
    inline bool IsPalmControl() const { return m_palmControl; }

    bool PalmCreateField(const wxString& label,
                         const wxPoint& pos,
                         const wxSize& size,
                         bool editable,
                         bool underlined,
                         int justification);
    inline bool IsPalmField() const { return m_palmField; }

    // this is a helper for the derived class GetClassDefaultAttributes()
    // implementation: it returns the right colours for the classes which
    // contain something else (e.g. wxListBox, wxTextCtrl, ...) instead of
    // being simple controls (such as wxButton, wxCheckBox, ...)
    static wxVisualAttributes
        GetCompositeControlsDefaultAttributes(wxWindowVariant variant);


    // for controls like radiobuttons which are really composite this array
    // holds the ids (not HWNDs!) of the sub controls
    wxArrayLong m_subControls;

    // m_label stores label in case of wxButton, wxCheckBox, wxToggleButton etc.
    // We must ensure that it persists for as long as it is being displayed
    // (that is, for as long as the control is displayed or until we call
    // CtlSetLabel() with a new string), and we must free the string after
    // it is no longer in use (typically after the form containing the
    // control is freed).
    wxString m_label;

private:

    bool m_palmControl:1;
    bool m_palmField:1;

    // common part of all ctors
    void Init();

    virtual void DoGetBounds( WXRECTANGLEPTR rect ) const;
    virtual void DoSetBounds( WXRECTANGLEPTR rect );

    DECLARE_DYNAMIC_CLASS_NO_COPY(wxControl)
    DECLARE_EVENT_TABLE()
};

#endif
    // _WX_CONTROL_H_
