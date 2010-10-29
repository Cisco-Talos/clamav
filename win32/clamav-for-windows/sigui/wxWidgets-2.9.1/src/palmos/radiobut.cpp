/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/radiobut.cpp
// Purpose:     wxRadioButton
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native wxRadioButton implementation
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

#if wxUSE_RADIOBTN

#include "wx/radiobut.h"

#ifndef WX_PRECOMP
    #include "wx/settings.h"
    #include "wx/dcscreen.h"
#endif

#include <Control.h>

// ============================================================================
// wxRadioButton implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxRadioButton creation
// ----------------------------------------------------------------------------


#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxRadioButtonStyle )

wxBEGIN_FLAGS( wxRadioButtonStyle )
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
    wxFLAGS_MEMBER(wxBORDER)

    // standard window styles
    wxFLAGS_MEMBER(wxTAB_TRAVERSAL)
    wxFLAGS_MEMBER(wxCLIP_CHILDREN)
    wxFLAGS_MEMBER(wxTRANSPARENT_WINDOW)
    wxFLAGS_MEMBER(wxWANTS_CHARS)
    wxFLAGS_MEMBER(wxFULL_REPAINT_ON_RESIZE)
    wxFLAGS_MEMBER(wxALWAYS_SHOW_SB )
    wxFLAGS_MEMBER(wxVSCROLL)
    wxFLAGS_MEMBER(wxHSCROLL)

    wxFLAGS_MEMBER(wxRB_GROUP)

wxEND_FLAGS( wxRadioButtonStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxRadioButton, wxControl,"wx/radiobut.h")

wxBEGIN_PROPERTIES_TABLE(wxRadioButton)
    wxEVENT_PROPERTY( Click , wxEVT_COMMAND_RADIOBUTTON_SELECTED , wxCommandEvent )
    wxPROPERTY( Font , wxFont , SetFont , GetFont  , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Label,wxString, SetLabel, GetLabel, wxString(), 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxPROPERTY( Value ,bool, SetValue, GetValue, EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxPROPERTY_FLAGS( WindowStyle , wxRadioButtonStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxRadioButton)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_6( wxRadioButton , wxWindow* , Parent , wxWindowID , Id , wxString , Label , wxPoint , Position , wxSize , Size , long , WindowStyle )

#else
IMPLEMENT_DYNAMIC_CLASS(wxRadioButton, wxControl)
#endif


void wxRadioButton::Init()
{
    m_radioStyle = pushButtonCtl;
    m_groupID = 0;
}

bool wxRadioButton::Create(wxWindow *parent,
                           wxWindowID id,
                           const wxString& label,
                           const wxPoint& pos,
                           const wxSize& size,
                           long style,
                           const wxValidator& validator,
                           const wxString& name)
{
    // replace native push button with native checkbox
    if ( style & wxRB_USE_CHECKBOX )
        m_radioStyle = checkboxCtl;

    if(!wxControl::Create(parent, id, pos, size, style, validator, name))
        return false;

    return wxControl::PalmCreateControl(
                          // be sure only one of two possibilities was taken
                          m_radioStyle == checkboxCtl ? checkboxCtl : pushButtonCtl,
                          label,
                          pos,
                          size,
                          m_groupID
                      );
}

void wxRadioButton::SetGroup(uint8_t group)
{
    m_groupID = group;
}

// ----------------------------------------------------------------------------
// wxRadioButton functions
// ----------------------------------------------------------------------------

void wxRadioButton::SetValue(bool value)
{
    SetBoolValue(value);
}

bool wxRadioButton::GetValue() const
{
    return GetBoolValue();
}

// ----------------------------------------------------------------------------
// wxRadioButton event processing
// ----------------------------------------------------------------------------

bool wxRadioButton::SendClickEvent()
{
    wxCommandEvent event(wxEVT_COMMAND_RADIOBUTTON_SELECTED, GetId());
    event.SetInt(GetValue());
    event.SetEventObject(this);
    return ProcessCommand(event);
}

void wxRadioButton::Command (wxCommandEvent& event)
{
}

// ----------------------------------------------------------------------------
// wxRadioButton geometry
// ----------------------------------------------------------------------------

wxSize wxRadioButton::DoGetBestSize() const
{
    return wxSize(0,0);
}

#endif // wxUSE_RADIOBTN

