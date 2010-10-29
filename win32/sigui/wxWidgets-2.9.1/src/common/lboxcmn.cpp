///////////////////////////////////////////////////////////////////////////////
// Name:        src/common/lboxcmn.cpp
// Purpose:     wxListBox class methods common to all platforms
// Author:      Vadim Zeitlin
// Modified by:
// Created:     22.10.99
// RCS-ID:      $Id$
// Copyright:   (c) wxWidgets team
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

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

#if wxUSE_LISTBOX

#include "wx/listbox.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/arrstr.h"
#endif

#include "wx/log.h"

// ============================================================================
// implementation
// ============================================================================

wxListBoxBase::~wxListBoxBase()
{
    // this destructor is required for Darwin
}

// ----------------------------------------------------------------------------
// selection
// ----------------------------------------------------------------------------

bool wxListBoxBase::SetStringSelection(const wxString& s, bool select)
{
    const int sel = FindString(s);
    if ( sel == wxNOT_FOUND )
        return false;

    SetSelection(sel, select);

    return true;
}

void wxListBoxBase::DeselectAll(int itemToLeaveSelected)
{
    if ( HasMultipleSelection() )
    {
        wxArrayInt selections;
        GetSelections(selections);

        size_t count = selections.GetCount();
        for ( size_t n = 0; n < count; n++ )
        {
            int item = selections[n];
            if ( item != itemToLeaveSelected )
                Deselect(item);
        }
    }
    else // single selection
    {
        int sel = GetSelection();
        if ( sel != wxNOT_FOUND && sel != itemToLeaveSelected )
        {
            Deselect(sel);
        }
    }
}

void wxListBoxBase::UpdateOldSelections()
{
    if (HasFlag(wxLB_MULTIPLE) || HasFlag(wxLB_EXTENDED))
        GetSelections( m_oldSelections );
}

bool wxListBoxBase::SendEvent(wxEventType evtType, int item, bool selected)
{
    wxCommandEvent event(evtType, GetId());
    event.SetEventObject(this);

    event.SetInt(item);
    event.SetString(GetString(item));
    event.SetExtraLong(selected);

    if ( HasClientObjectData() )
        event.SetClientObject(GetClientObject(item));
    else if ( HasClientUntypedData() )
        event.SetClientData(GetClientData(item));

    return HandleWindowEvent(event);
}

bool wxListBoxBase::CalcAndSendEvent()
{
    wxArrayInt selections;
    GetSelections(selections);
    bool selected = true;

    if ( selections.empty() && m_oldSelections.empty() )
    {
        // nothing changed, just leave
        return false;
    }

    const size_t countSel = selections.size(),
                 countSelOld = m_oldSelections.size();
    if ( countSel == countSelOld )
    {
        bool changed = false;
        for ( size_t idx = 0; idx < countSel; idx++ )
        {
            if (selections[idx] != m_oldSelections[idx])
            {
                changed = true;
                break;
            }
        }

        // nothing changed, just leave
        if ( !changed )
           return false;
    }

    int item = wxNOT_FOUND;
    if ( selections.empty() )
    {
        selected = false;
        item = m_oldSelections[0];
    }
    else // we [still] have some selections
    {
        // Now test if any new item is selected
        bool any_new_selected = false;
        for ( size_t idx = 0; idx < countSel; idx++ )
        {
            item = selections[idx];
            if ( m_oldSelections.Index(item) == wxNOT_FOUND )
            {
                any_new_selected = true;
                break;
            }
        }

        if ( !any_new_selected )
        {
            // No new items selected, now test if any new item is deselected
            bool any_new_deselected = false;
            for ( size_t idx = 0; idx < countSelOld; idx++ )
            {
                item = m_oldSelections[idx];
                if ( selections.Index(item) == wxNOT_FOUND )
                {
                    any_new_deselected = true;
                    break;
                }
            }

            if ( any_new_deselected )
            {
                // indicate that this is a selection
                selected = false;
            }
            else
            {
                item = wxNOT_FOUND; // this should be impossible
            }
        }
    }

    wxASSERT_MSG( item != wxNOT_FOUND,
                  "Logic error in wxListBox selection event generation code" );

    m_oldSelections = selections;

    return SendEvent(wxEVT_COMMAND_LISTBOX_SELECTED, item, selected);
}

// ----------------------------------------------------------------------------
// misc
// ----------------------------------------------------------------------------

void wxListBoxBase::Command(wxCommandEvent& event)
{
    SetSelection(event.GetInt(), event.GetExtraLong() != 0);
    (void)GetEventHandler()->ProcessEvent(event);
}

// ----------------------------------------------------------------------------
// SetFirstItem() and such
// ----------------------------------------------------------------------------

void wxListBoxBase::SetFirstItem(const wxString& s)
{
    int n = FindString(s);

    wxCHECK_RET( n != wxNOT_FOUND, wxT("invalid string in wxListBox::SetFirstItem") );

    DoSetFirstItem(n);
}

void wxListBoxBase::AppendAndEnsureVisible(const wxString& s)
{
    Append(s);
    EnsureVisible(GetCount() - 1);
}

void wxListBoxBase::EnsureVisible(int WXUNUSED(n))
{
    // the base class version does nothing (the only alternative would be to
    // call SetFirstItem() but this is probably even more stupid)
}

#endif // wxUSE_LISTBOX
