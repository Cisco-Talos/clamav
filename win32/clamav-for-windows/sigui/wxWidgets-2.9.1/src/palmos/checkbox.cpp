/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/checkbox.cpp
// Purpose:     wxCheckBox
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_CHECKBOX

#include "wx/checkbox.h"

#ifndef WX_PRECOMP
    #include "wx/brush.h"
    #include "wx/dcscreen.h"
    #include "wx/settings.h"
#endif

#include <Control.h>

// ============================================================================
// implementation
// ============================================================================

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxCheckBoxStyle )

wxBEGIN_FLAGS( wxCheckBoxStyle )
    // new style border flags, we put them first to
    // use them for streaming out
    wxFLAGS_MEMBER(wxBORDER_SIMPLE)
    wxFLAGS_MEMBER(wxBORDER_SUNKEN)
    wxFLAGS_MEMBER(wxBORDER_DOUBLE)
    wxFLAGS_MEMBER(wxBORDER_RAISED)
    wxFLAGS_MEMBER(wxBORDER_STATIC)
    wxFLAGS_MEMBER(wxBORDER_NONE)

    // old style border flags
    wxFLAGS_MEMBER(wxSIMPLE_BORDER)
    wxFLAGS_MEMBER(wxSUNKEN_BORDER)
    wxFLAGS_MEMBER(wxDOUBLE_BORDER)
    wxFLAGS_MEMBER(wxRAISED_BORDER)
    wxFLAGS_MEMBER(wxSTATIC_BORDER)
    wxFLAGS_MEMBER(wxNO_BORDER)

    // standard window styles
    wxFLAGS_MEMBER(wxTAB_TRAVERSAL)
    wxFLAGS_MEMBER(wxCLIP_CHILDREN)
    wxFLAGS_MEMBER(wxTRANSPARENT_WINDOW)
    wxFLAGS_MEMBER(wxWANTS_CHARS)
    wxFLAGS_MEMBER(wxNO_FULL_REPAINT_ON_RESIZE)
    wxFLAGS_MEMBER(wxALWAYS_SHOW_SB )
    wxFLAGS_MEMBER(wxVSCROLL)
    wxFLAGS_MEMBER(wxHSCROLL)

wxEND_FLAGS( wxCheckBoxStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxCheckBox, wxControl,"wx/checkbox.h")

wxBEGIN_PROPERTIES_TABLE(wxCheckBox)
    wxEVENT_PROPERTY( Click , wxEVT_COMMAND_CHECKBOX_CLICKED , wxCommandEvent )

    wxPROPERTY( Font , wxFont , SetFont , GetFont , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Label,wxString, SetLabel, GetLabel, wxString() , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Value ,bool, SetValue, GetValue, EMPTY_MACROVALUE, 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxCheckBoxStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE, 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxCheckBox)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_6( wxCheckBox , wxWindow* , Parent , wxWindowID , Id , wxString , Label , wxPoint , Position , wxSize , Size , long , WindowStyle )
#else
IMPLEMENT_DYNAMIC_CLASS(wxCheckBox, wxControl)
#endif


// ----------------------------------------------------------------------------
// wxCheckBox
// ----------------------------------------------------------------------------

bool wxCheckBox::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxString& label,
                        const wxPoint& pos,
                        const wxSize& size, long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    if(!wxControl::Create(parent, id, pos, size, style, validator, name))
        return false;

    m_state = wxCHK_UNCHECKED;
    return wxControl::PalmCreateControl(checkboxCtl, label, pos, size);
}

wxSize wxCheckBox::DoGetBestSize() const
{
    return wxSize(0,0);
}

void wxCheckBox::SetValue(bool val)
{
    SetBoolValue(val);
}

bool wxCheckBox::GetValue() const
{
    return GetBoolValue();
}

bool wxCheckBox::SendClickEvent()
{
    wxCommandEvent event(wxEVT_COMMAND_CHECKBOX_CLICKED, GetId());
    event.SetInt(GetValue());
    event.SetEventObject(this);
    return ProcessCommand(event);
}

void wxCheckBox::Command(wxCommandEvent& event)
{
    int state = event.GetInt();
    wxCHECK_RET( (state == wxCHK_UNCHECKED) || (state == wxCHK_CHECKED)
        || (state == wxCHK_UNDETERMINED),
        wxT("event.GetInt() returned an invalid checkbox state") );

    Set3StateValue((wxCheckBoxState) state);
    ProcessCommand(event);
}

void wxCheckBox::DoSet3StateValue(wxCheckBoxState state)
{
    Int16 newValue;
    ControlType *control = (ControlType *)GetObjectPtr();
    if(NULL == control) {
        return;
    }
    m_state = state;
    switch (state) {
    case wxCHK_UNCHECKED:
        newValue = 0;
        break;
    case wxCHK_CHECKED:
        newValue = 1;
        break;
    case wxCHK_UNDETERMINED:
    default:
        return;
        break;
    }
    CtlSetValue (control, newValue);
}

wxCheckBoxState wxCheckBox::DoGet3StateValue() const
{
    return m_state;
}

#endif // wxUSE_CHECKBOX
