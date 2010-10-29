/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/accel.cpp
// Purpose:     wxAcceleratorTable
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/window.h"
#endif

#include "wx/accel.h"

#if wxUSE_ACCEL

#include "wx/palmos/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxAcceleratorTable, wxObject)

class WXDLLEXPORT wxAcceleratorRefData: public wxObjectRefData
{
    friend class WXDLLEXPORT wxAcceleratorTable;
public:
    wxAcceleratorRefData();
    virtual ~wxAcceleratorRefData();

    inline HACCEL GetHACCEL() const { return m_hAccel; }
protected:
    HACCEL      m_hAccel;
    bool        m_ok;

    wxDECLARE_NO_COPY_CLASS(wxAcceleratorRefData);
};

#define M_ACCELDATA ((wxAcceleratorRefData *)m_refData)

wxAcceleratorRefData::wxAcceleratorRefData()
{
}

wxAcceleratorRefData::~wxAcceleratorRefData()
{
}

wxAcceleratorTable::wxAcceleratorTable()
{
}

wxAcceleratorTable::~wxAcceleratorTable()
{
}

wxAcceleratorTable::wxAcceleratorTable(const wxString& resource)
{
}

extern int wxCharCodeWXToMSW(int id, bool *isVirtual);

wxAcceleratorTable::wxAcceleratorTable(int n, const wxAcceleratorEntry entries[])
{
}

bool wxAcceleratorTable::IsOk() const
{
    return false;
}

void wxAcceleratorTable::SetHACCEL(WXHACCEL hAccel)
{
}

WXHACCEL wxAcceleratorTable::GetHACCEL() const
{
    return 0;
}

bool wxAcceleratorTable::Translate(wxWindow *window, WXMSG *wxmsg) const
{
    return false;
}

#endif
