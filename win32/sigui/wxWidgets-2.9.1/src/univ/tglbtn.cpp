/////////////////////////////////////////////////////////////////////////////
// Name:        univ/tglbtn.cpp
// Purpose:     wxToggleButton
// Author:      Vadim Zeitlin
// Modified by: David Bjorkevik
// Created:     16.05.06
// RCS-ID:      $Id$
// Copyright:   (c) 2000 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_TOGGLEBTN

#include "wx/tglbtn.h"

wxDEFINE_EVENT( wxEVT_COMMAND_TOGGLEBUTTON_CLICKED, wxCommandEvent );

IMPLEMENT_DYNAMIC_CLASS(wxToggleButton, wxButton)

wxToggleButton::wxToggleButton()
{
    Init();
}

wxToggleButton::wxToggleButton(wxWindow *parent,
                               wxWindowID id,
                               const wxBitmap& bitmap,
                               const wxString& label,
                               const wxPoint& pos,
                               const wxSize& size,
                               long style,
                               const wxValidator& validator,
                               const wxString& name)
{
    Init();
    Create(parent, id, bitmap, label, pos, size, style, validator, name);
}

wxToggleButton::wxToggleButton(wxWindow *parent,
                               wxWindowID id,
                               const wxString& label,
                               const wxPoint& pos,
                               const wxSize& size,
                               long style,
                               const wxValidator& validator,
                               const wxString& name)
{
    Init();
    Create(parent, id, label, pos, size, style, validator, name);
}

wxToggleButton::~wxToggleButton()
{
}

void wxToggleButton::Init()
{
    m_isPressed = false;
    m_value = false;
}

void wxToggleButton::Toggle()
{
    if ( m_isPressed )
        Release();
    else
        Press();

    if ( !m_isPressed )
    {
        // releasing button after it had been pressed generates a click event
        // and toggles value
        m_value = !m_value;
        Click();
    }
}

void wxToggleButton::Click()
{
    wxCommandEvent event(wxEVT_COMMAND_TOGGLEBUTTON_CLICKED, GetId());
    InitCommandEvent(event);
    event.SetInt(GetValue());
    Command(event);
}

void wxToggleButton::SetValue(bool state)
{
    m_value = state;
    Refresh();
}

#endif // wxUSE_TOGGLEBTN
