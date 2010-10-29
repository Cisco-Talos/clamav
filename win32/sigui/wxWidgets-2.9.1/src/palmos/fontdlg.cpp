/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/fontdlg.cpp
// Purpose:     wxFontDialog class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

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

#if wxUSE_FONTDLG

#include "wx/fontdlg.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/math.h"
    #include "wx/log.h"
    #include "wx/cmndata.h"
#endif

#include "wx/palmos/private.h"

#include <stdlib.h>
#include <string.h>

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxFontDialog, wxDialog)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxFontDialog
// ----------------------------------------------------------------------------

int wxFontDialog::ShowModal()
{
    return wxID_CANCEL;
}

#endif // wxUSE_FONTDLG
