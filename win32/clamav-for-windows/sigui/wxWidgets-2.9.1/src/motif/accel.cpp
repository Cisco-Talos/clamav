/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/accel.cpp
// Purpose:     wxAcceleratorTable
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/accel.h"

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/utils.h"
#endif

#include <ctype.h>

IMPLEMENT_DYNAMIC_CLASS(wxAcceleratorTable, wxObject)

class WXDLLEXPORT wxAcceleratorRefData: public wxObjectRefData
{
    friend class wxAcceleratorTable;
public:
    wxAcceleratorRefData();
    virtual ~wxAcceleratorRefData();

public:
    int m_count;
    wxAcceleratorEntry* m_entries;
};

#define M_ACCELDATA ((wxAcceleratorRefData *)m_refData)

wxAcceleratorRefData::wxAcceleratorRefData()
{
    m_count = 0;
    m_entries = NULL;
}

wxAcceleratorRefData::~wxAcceleratorRefData()
{
    wxDELETEA(m_entries);
    m_count = 0;
}

wxAcceleratorTable::wxAcceleratorTable()
{
    m_refData = NULL;
}

wxAcceleratorTable::~wxAcceleratorTable()
{
    // Data deleted in ~wxObject
}

// Load from .rc resource
wxAcceleratorTable::wxAcceleratorTable(const wxString& WXUNUSED(resource))
{
    m_refData = new wxAcceleratorRefData;
}

// Create from an array
wxAcceleratorTable::wxAcceleratorTable(int n, const wxAcceleratorEntry entries[])
{
    wxAcceleratorRefData* data = new wxAcceleratorRefData;
    m_refData = data;

    data->m_count = n;
    data->m_entries = new wxAcceleratorEntry[n];
    int i;
    for (i = 0; i < n; i++)
        data->m_entries[i] = entries[i];

}

bool wxAcceleratorTable::IsOk() const
{
    return (m_refData != NULL);
}

int wxAcceleratorTable::GetCount() const
{
    return M_ACCELDATA->m_count;
}

wxAcceleratorEntry* wxAcceleratorTable::GetEntries() const
{
    return M_ACCELDATA->m_entries;
}

// Implementation use only
bool wxAcceleratorEntry::MatchesEvent(const wxKeyEvent& event) const
{
    bool eventAltDown = event.AltDown();
    bool eventCtrlDown = event.ControlDown();
    bool eventShiftDown = event.ShiftDown();
    int  eventKeyCode = event.GetKeyCode();

    bool accAltDown = ((GetFlags() & wxACCEL_ALT) == wxACCEL_ALT);
    bool accCtrlDown = ((GetFlags() & wxACCEL_CTRL) == wxACCEL_CTRL);
    bool accShiftDown = ((GetFlags() & wxACCEL_SHIFT) == wxACCEL_SHIFT);
    int  accKeyCode = GetKeyCode();
    int  accKeyCode2 = GetKeyCode();
    if (wxIsascii(accKeyCode2))
        accKeyCode2 = wxTolower(accKeyCode2);

    return ((eventAltDown == accAltDown) && (eventCtrlDown == accCtrlDown) &&
        (eventShiftDown == accShiftDown) &&
        ((eventKeyCode == accKeyCode || eventKeyCode == accKeyCode2))) ;
}
