/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/statbox_osx.cpp
// Purpose:     wxStaticBox
// Author:      Stefan Csomor
// Modified by:
// Created:     1998-01-01
// RCS-ID:      $Id: statbox.cpp 54129 2008-06-11 19:30:52Z SC $
// Copyright:   (c) Stefan Csomor
// Licence:       wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_STATBOX

#include "wx/statbox.h"
#include "wx/osx/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxStaticBox, wxControl)

bool wxStaticBox::Create( wxWindow *parent,
    wxWindowID id,
    const wxString& label,
    const wxPoint& pos,
    const wxSize& size,
    long style,
    const wxString& name )
{
    m_macIsUserPane = false;

    if ( !wxControl::Create( parent, id, pos, size, style, wxDefaultValidator, name ) )
        return false;

    m_labelOrig = m_label = label;

    m_peer = wxWidgetImpl::CreateGroupBox( this, parent, id, label, pos, size, style, GetExtraStyle() );

    MacPostControlCreate( pos, size );

    return true;
}

void wxStaticBox::GetBordersForSizer(int *borderTop, int *borderOther) const
{
    static int extraTop = -1; // Uninitted
    static int other = 5;

    if ( extraTop == -1 )
    {
        // The minimal border used for the top.
        // Later on, the staticbox's font height is added to this.
        extraTop = 0;

        // As indicated by the HIG, Panther needs an extra border of 11
        // pixels (otherwise overlapping occurs at the top). The "other"
        // border has to be 11.
        extraTop = 11;
        other = 11;
    }

    *borderTop = extraTop;
    if ( !m_label.empty() )
        *borderTop += GetCharHeight();

    *borderOther = other;
}

bool wxStaticBox::SetFont(const wxFont& font)
{
    bool retval = wxWindowBase::SetFont( font );

    // dont' update the native control, it has its own small font

    return retval;
}

#endif // wxUSE_STATBOX

