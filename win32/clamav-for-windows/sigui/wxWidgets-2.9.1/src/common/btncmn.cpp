///////////////////////////////////////////////////////////////////////////////
// Name:        src/common/btncmn.cpp
// Purpose:     implementation of wxButtonBase
// Author:      Vadim Zeitlin
// Created:     2007-04-08
// RCS-ID:      $Id$
// Copyright:   (c) 2007 Vadim Zeitlin <vadim@wxwindows.org>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_BUTTON

#ifndef WX_PRECOMP
    #include "wx/button.h"
    #include "wx/toplevel.h"
#endif //WX_PRECOMP

// ============================================================================
// implementation
// ============================================================================

wxWindow *wxButtonBase::SetDefault()
{
    wxTopLevelWindow * const
        tlw = wxDynamicCast(wxGetTopLevelParent(this), wxTopLevelWindow);

    wxCHECK_MSG( tlw, NULL, wxT("button without top level window?") );

    return tlw->SetDefaultItem(this);
}

void wxButtonBase::SetBitmapPosition(wxDirection dir)
{
    wxASSERT_MSG( !(dir & ~wxDIRECTION_MASK), "non-direction flag used" );
    wxASSERT_MSG( !!(dir & wxLEFT) +
                    !!(dir & wxRIGHT) +
                      !!(dir & wxTOP) +
                       !!(dir & wxBOTTOM) == 1,
                   "exactly one direction flag must be set" );

    DoSetBitmapPosition(dir);

}
#endif // wxUSE_BUTTON
