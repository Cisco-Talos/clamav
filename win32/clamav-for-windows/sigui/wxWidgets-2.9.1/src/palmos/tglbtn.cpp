/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/tglbtn.cpp
// Purpose:     Definition of the wxToggleButton class, which implements a
//              toggle button.
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declatations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_TOGGLEBTN

#include "wx/tglbtn.h"

#ifndef WX_PRECOMP
    #include "wx/button.h"
    #include "wx/brush.h"
    #include "wx/dcscreen.h"
    #include "wx/settings.h"

    #include "wx/log.h"
#endif // WX_PRECOMP

#include <Control.h>

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxToggleButton, wxControl)
wxDEFINE_EVENT( wxEVT_COMMAND_TOGGLEBUTTON_CLICKED, wxCommandEvent );

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxToggleButton
// ----------------------------------------------------------------------------

// Single check box item
bool wxToggleButton::Create(wxWindow *parent, wxWindowID id,
                            const wxString& label,
                            const wxPoint& pos,
                            const wxSize& size, long style,
                            const wxValidator& validator,
                            const wxString& name)
{
    if(!wxControl::Create(parent, id, pos, size, style, validator, name))
        return false;

    return wxControl::PalmCreateControl(pushButtonCtl, label, pos, size);
}

wxBorder wxToggleButton::GetDefaultBorder() const
{
    return wxBORDER_NONE;
}

wxSize wxToggleButton::DoGetBestSize() const
{
   return wxSize(0,0);
}

void wxToggleButton::SetValue(bool val)
{
    SetBoolValue(val);
}

bool wxToggleButton::GetValue() const
{
    return GetBoolValue();
}

bool wxToggleButton::SendClickEvent()
{
    wxCommandEvent event(wxEVT_COMMAND_TOGGLEBUTTON_CLICKED, GetId());
    event.SetInt(GetValue());
    event.SetEventObject(this);
    return ProcessCommand(event);
}

void wxToggleButton::Command(wxCommandEvent & event)
{
}

#endif // wxUSE_TOGGLEBTN
