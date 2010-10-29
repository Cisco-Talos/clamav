/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/helpwin.cpp
// Purpose:     Help system: WinHelp implementation
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

#if wxUSE_HELP

#ifndef WX_PRECOMP
#endif

#include "wx/filefn.h"


IMPLEMENT_DYNAMIC_CLASS(wxWinHelpController, wxHelpControllerBase)

bool wxWinHelpController::Initialize(const wxString& filename)
{
    return false;
}

bool wxWinHelpController::LoadFile(const wxString& file)
{
    return false;
}

bool wxWinHelpController::DisplayContents(void)
{
    return false;
}

bool wxWinHelpController::DisplaySection(int section)
{
    return false;
}

bool wxWinHelpController::DisplayContextPopup(int contextId)
{
    return false;
}

bool wxWinHelpController::DisplayBlock(long block)
{
    return false;
}

bool wxWinHelpController::KeywordSearch(const wxString& k,
                                        wxHelpSearchMode WXUNUSED(mode))
{
    return false;
}

bool wxWinHelpController::Quit(void)
{
    return false;
}

wxString wxWinHelpController::GetValidFilename(const wxString& file) const
{
    wxString ret;

    return ret;
}

#endif // wxUSE_HELP
