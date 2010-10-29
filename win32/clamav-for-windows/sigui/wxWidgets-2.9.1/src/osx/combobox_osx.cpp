/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/combobox_osx.cpp
// Purpose:     wxComboBox class using HIView ComboBox
// Author:      Stefan Csomor
// Modified by:
// Created:     1998-01-01
// RCS-ID:      $Id: combobox_osx.cpp 58318 2009-01-23 08:36:16Z RR $
// Copyright:   (c) Stefan Csomor
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_COMBOBOX && wxOSX_USE_COCOA

#include "wx/combobox.h"
#include "wx/osx/private.h"

#ifndef WX_PRECOMP
#endif

// work in progress

IMPLEMENT_DYNAMIC_CLASS(wxComboBox, wxControl)

wxComboBox::~wxComboBox()
{
}

void wxComboBox::Init()
{
}

bool wxComboBox::Create(wxWindow *parent, wxWindowID id,
           const wxString& value,
           const wxPoint& pos,
           const wxSize& size,
           const wxArrayString& choices,
           long style,
           const wxValidator& validator,
           const wxString& name)
{
    wxCArrayString chs( choices );

    return Create( parent, id, value, pos, size, chs.GetCount(),
                   chs.GetStrings(), style, validator, name );
}

bool wxComboBox::Create(wxWindow *parent, wxWindowID id,
           const wxString& value,
           const wxPoint& pos,
           const wxSize& size,
           int n, const wxString choices[],
           long style,
           const wxValidator& validator,
           const wxString& name)
{
    m_text = NULL;
    m_choice = NULL;

    m_macIsUserPane = false;

    if ( !wxControl::Create( parent, id, pos, size, style, validator, name ) )
        return false;

    wxASSERT_MSG( !(style & wxCB_SORT),
                  "wxCB_SORT not currently supported by wxOSX/Cocoa");

    m_peer = wxWidgetImpl::CreateComboBox( this, parent, id, NULL, pos, size, style, GetExtraStyle() );

    MacPostControlCreate( pos, size );

    Append(n, choices);

    // Set up the initial value, by default the first item is selected.
    if ( !value.empty() )
        SetValue(value);
    else if (n > 0)
        SetSelection( 0 );

    // Needed because it is a wxControlWithItems
    SetInitialSize( size );

    return true;
}

void wxComboBox::DelegateTextChanged( const wxString& value )
{
    SetStringSelection( value );
}

void wxComboBox::DelegateChoice( const wxString& value )
{
    SetStringSelection( value );
}

int wxComboBox::DoInsertItems(const wxArrayStringsAdapter& items,
                              unsigned int pos,
                              void **clientData, wxClientDataType type)
{
    const unsigned int numItems = items.GetCount();
    for( unsigned int i = 0; i < numItems; ++i, ++pos )
    {
        unsigned int idx;

        idx = pos;
        GetComboPeer()->InsertItem( idx, items[i] );

        if (idx > m_datas.GetCount())
            m_datas.SetCount(idx);
        m_datas.Insert( NULL, idx );
        AssignNewItemClientData(idx, clientData, i, type);
    }

    m_peer->SetMaximum( GetCount() );

    return pos - 1;
}

// ----------------------------------------------------------------------------
// client data
// ----------------------------------------------------------------------------
void wxComboBox::DoSetItemClientData(unsigned int n, void* clientData)
{
    wxCHECK_RET( IsValid(n), "invalid index" );

    m_datas[n] = (char*)clientData ;
}

void * wxComboBox::DoGetItemClientData(unsigned int n) const
{
    wxCHECK_MSG( IsValid(n), NULL, "invalid index" );

    return (void *)m_datas[n];
}

unsigned int wxComboBox::GetCount() const
{
    return GetComboPeer()->GetNumberOfItems();
}

void wxComboBox::DoDeleteOneItem(unsigned int n)
{
    GetComboPeer()->RemoveItem(n);
}

void wxComboBox::DoClear()
{
    GetComboPeer()->Clear();
}

void wxComboBox::GetSelection(long *from, long *to) const
{
    wxTextEntry::GetSelection(from, to);
}

int wxComboBox::GetSelection() const
{
    return GetComboPeer()->GetSelectedItem();
}

void wxComboBox::SetSelection(int n)
{
    GetComboPeer()->SetSelectedItem(n);
}

void wxComboBox::SetSelection(long from, long to)
{
    wxTextEntry::SetSelection(from, to);
}

int wxComboBox::FindString(const wxString& s, bool bCase) const
{
    if (!bCase)
    {
        for (unsigned i = 0; i < GetCount(); i++)
        {
            if (s.IsSameAs(GetString(i), false))
                return i;
        }
        return wxNOT_FOUND;
    }

    return GetComboPeer()->FindString(s);
}

wxString wxComboBox::GetString(unsigned int n) const
{
    return GetComboPeer()->GetStringAtIndex(n);
}

wxString wxComboBox::GetStringSelection() const
{
    return GetString(GetSelection());
}

void wxComboBox::SetString(unsigned int n, const wxString& s)
{
    Delete(n);
    Insert(s, n);
    SetValue(s); // changing the item in the list won't update the display item
}

void wxComboBox::EnableTextChangedEvents(bool WXUNUSED(enable))
{
    // nothing to do here, events are never generated when we change the
    // control value programmatically anyhow by Cocoa
}

bool wxComboBox::OSXHandleClicked( double WXUNUSED(timestampsec) )
{
    wxCommandEvent event(wxEVT_COMMAND_COMBOBOX_SELECTED, m_windowId );
    event.SetInt(GetSelection());
    event.SetEventObject(this);
    event.SetString(GetStringSelection());
    ProcessCommand(event);
    return true;
}

wxComboWidgetImpl* wxComboBox::GetComboPeer() const
{
    return dynamic_cast<wxComboWidgetImpl*> (m_peer);
}

#endif // wxUSE_COMBOBOX && wxOSX_USE_COCOA
