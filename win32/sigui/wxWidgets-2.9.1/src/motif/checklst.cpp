///////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/checklst.cpp
// Purpose:     implementation of wxCheckListBox class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// headers & declarations
// ============================================================================

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_CHECKLISTBOX

#include "wx/checklst.h"

#ifndef WX_PRECOMP
    #include "wx/arrstr.h"
#endif

// ============================================================================
// implementation
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxCheckListBox, wxListBox)

// ----------------------------------------------------------------------------
// implementation of wxCheckListBox class
// ----------------------------------------------------------------------------

// define event table
// ------------------
BEGIN_EVENT_TABLE(wxCheckListBox, wxListBox)
END_EVENT_TABLE()

// control creation
// ----------------

static const wxString prefixChecked = "[x] ";
static const wxString prefixUnchecked = "[ ] ";
static const char checkChar = 'x', uncheckChar = ' ';

static inline const wxString& Prefix(bool checked)
    { return checked ? prefixChecked : prefixUnchecked; }
static inline bool IsChecked(const wxString& s)
    { wxASSERT(s.length() >=4); return s[1] == checkChar; }

// def ctor: use Create() to really create the control
wxCheckListBox::wxCheckListBox() : wxCheckListBoxBase()
{
}

// ctor which creates the associated control
wxCheckListBox::wxCheckListBox(wxWindow *parent, wxWindowID id,
                               const wxPoint& pos, const wxSize& size,
                               int nStrings, const wxString choices[],
                               long style, const wxValidator& val,
                               const wxString& name)
                               : wxCheckListBoxBase()
{
    Create(parent, id, pos, size, nStrings, choices,
           style, val, name);
}

wxCheckListBox::wxCheckListBox(wxWindow *parent, wxWindowID id,
                               const wxPoint& pos, const wxSize& size,
                               const wxArrayString& choices,
                               long style, const wxValidator& val,
                               const wxString& name)
                               : wxCheckListBoxBase()
{
    Create(parent, id, pos, size, choices,
           style, val, name);
}

bool wxCheckListBox::Create(wxWindow *parent, wxWindowID id,
                            const wxPoint& pos,
                            const wxSize& size,
                            int n, const wxString choices[],
                            long style,
                            const wxValidator& validator,
                            const wxString& name)
{
    // wxListBox::Create calls set, which adds the prefixes
    bool retVal = wxListBox::Create(parent, id, pos, size, n, choices,
                                    style, validator, name);
    return retVal;
}

bool wxCheckListBox::Create(wxWindow *parent, wxWindowID id,
                            const wxPoint& pos,
                            const wxSize& size,
                            const wxArrayString& choices,
                            long style,
                            const wxValidator& validator,
                            const wxString& name)
{
    // wxListBox::Create calls set, which adds the prefixes
    bool retVal = wxListBox::Create(parent, id, pos, size, choices,
                                    style, validator, name);
    return retVal;
}

// check items
// -----------

bool wxCheckListBox::IsChecked(unsigned int uiIndex) const
{
    return ::IsChecked(wxListBox::GetString(uiIndex));
}

void wxCheckListBox::Check(unsigned int uiIndex, bool bCheck)
{
    wxString label = wxListBox::GetString(uiIndex);
    if(::IsChecked(label) == bCheck) return;
    label[1u] = bCheck ? checkChar : uncheckChar;
    wxListBox::SetString(uiIndex, label);
}

void wxCheckListBox::DoToggleItem( int n, int x )
{
    if( x > 0 && x < 23 )
    {
        wxString label = wxListBox::GetString(n);
        label[1u] = (!::IsChecked(label)) ? checkChar : uncheckChar;
        wxListBox::SetString(n, label);

        wxCommandEvent event(wxEVT_COMMAND_CHECKLISTBOX_TOGGLED, GetId());
        if( HasClientObjectData() )
            event.SetClientObject( GetClientObject(n) );
        else if( HasClientUntypedData() )
            event.SetClientData( GetClientData(n) );
        event.SetInt(n);
        event.SetExtraLong(true);
        event.SetEventObject(this);
        event.SetString(GetString(n));

        HandleWindowEvent(event);
    }
}

int wxCheckListBox::FindString(const wxString& s, bool bCase) const
{
    int n1 = wxListBox::FindString(Prefix(false) + s, bCase);
    int n2 = wxListBox::FindString(Prefix(true) + s, bCase);
    int min = wxMin(n1, n2), max = wxMax(n1, n2);

    // why this works:
    // n1 == -1, n2 == -1 => return -1 OK
    // n1 != -1 || n2 != -1 => min == -1 => return the other one
    // both != -1 => return the first one.
    if( min == -1 ) return max;
    return min;
}

void wxCheckListBox::SetString(unsigned int n, const wxString& s)
{
    wxListBox::SetString(n, Prefix(IsChecked(n)) + s);
}

wxString wxCheckListBox::GetString(unsigned int n) const
{
    return wxListBox::GetString(n).substr(4);
}

int wxCheckListBox::DoInsertItems(const wxArrayStringsAdapter& items,
                                  unsigned int pos,
                                  void **clientData, wxClientDataType type)
{
    wxArrayString copy;
    copy.reserve(pos);
    for ( size_t i = 0; i < items.GetCount(); ++i )
        copy.push_back( Prefix(false) + items[i] );

    return wxListBox::DoInsertItems(copy, pos, clientData, type);
}

#endif // wxUSE_CHECKLISTBOX
