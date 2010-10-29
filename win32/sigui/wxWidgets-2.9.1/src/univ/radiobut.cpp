/////////////////////////////////////////////////////////////////////////////
// Name:        src/univ/radiobut.cpp
// Purpose:     wxRadioButton implementation
// Author:      Vadim Zeitlin
// Modified by:
// Created:     10.09.00
// RCS-ID:      $Id$
// Copyright:   (c) 2000 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_RADIOBTN

#include "wx/radiobut.h"

#ifndef WX_PRECOMP
    #include "wx/dcclient.h"
    #include "wx/validate.h"
#endif

#include "wx/univ/theme.h"
#include "wx/univ/renderer.h"
#include "wx/univ/inphand.h"
#include "wx/univ/colschem.h"

// ============================================================================
// implementation
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxRadioButton, wxControl)

// ----------------------------------------------------------------------------
// wxRadioButton
// ----------------------------------------------------------------------------

bool wxRadioButton::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxString &label,
                        const wxPoint &pos,
                        const wxSize &size,
                        long style,
                        const wxValidator& validator,
                        const wxString &name)
{
    if ( !wxCheckBox::Create(parent, id, label, pos, size, style,
                             validator, name) )
    {
        return false;
    }

    return true;
}

// ----------------------------------------------------------------------------
// radio button methods
// ----------------------------------------------------------------------------

void wxRadioButton::OnCheck()
{
    // clear all others radio buttons in our group: for this we need to
    // find the radio button which is the first in the group, i.e. the one
    // with wxRB_GROUP style
    const wxWindowList& siblings = GetParent()->GetChildren();
    wxWindowList::compatibility_iterator nodeStart = siblings.Find(this);
    while ( nodeStart )
    {
        // stop if we found a radio button with wxRB_GROUP style or it we
        // are at the first control
        if ( !nodeStart->GetPrevious() ||
             (nodeStart->GetData()->GetWindowStyle() & wxRB_GROUP) )
            break;

        nodeStart = nodeStart->GetPrevious();
    }

    // now clear all radio buttons from the starting one until the next
    // one with wxRB_GROUP style
    while ( nodeStart )
    {
        wxWindow *win = nodeStart->GetData();
        if ( win != this )
        {
            wxRadioButton *btn = wxDynamicCast(win, wxRadioButton);
            if ( btn )
            {
                btn->ClearValue();
            }
        }

        nodeStart = nodeStart->GetNext();
        if ( !nodeStart ||
             (nodeStart->GetData()->GetWindowStyle() & wxRB_GROUP) )
        {
            // we reached the next group
            break;
        }
    }
}

void wxRadioButton::ChangeValue(bool value)
{
    if ( value == IsChecked() )
        return;

    if ( !IsChecked() )
    {
        wxCheckBox::ChangeValue(value);
    }
    else // attempt to clear a radio button - this can't be done
    {
        // but still refresh as our PRESSED flag changed
        Refresh();
    }
}

void wxRadioButton::ClearValue()
{
    if ( IsChecked() )
    {
        SetValue(false);
    }
}

void wxRadioButton::SendEvent()
{
    wxCommandEvent event(wxEVT_COMMAND_RADIOBUTTON_SELECTED, GetId());
    InitCommandEvent(event);
    event.SetInt(IsChecked());
    Command(event);
}

// ----------------------------------------------------------------------------
// overridden wxCheckBox methods
// ----------------------------------------------------------------------------

wxSize wxRadioButton::GetBitmapSize() const
{
    wxBitmap bmp = GetBitmap(State_Normal, Status_Checked);
    return bmp.Ok() ? wxSize(bmp.GetWidth(), bmp.GetHeight())
                    : GetRenderer()->GetRadioBitmapSize();
}

void wxRadioButton::DoDraw(wxControlRenderer *renderer)
{
    wxDC& dc = renderer->GetDC();
    dc.SetFont(GetFont());
    dc.SetTextForeground(GetForegroundColour());

    int flags = GetStateFlags();
    Status status = GetStatus();
    if ( status == Status_Checked )
        flags |= wxCONTROL_CHECKED;

    renderer->GetRenderer()->
        DrawRadioButton(dc,
                        GetLabel(),
                        GetBitmap(GetState(flags), status),
                        renderer->GetRect(),
                        flags,
                        GetWindowStyle() & wxALIGN_RIGHT ? wxALIGN_RIGHT
                                                         : wxALIGN_LEFT,
                        GetAccelIndex());
}

#endif // wxUSE_RADIOBTN
