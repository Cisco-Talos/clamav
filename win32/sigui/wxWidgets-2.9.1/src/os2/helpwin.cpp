/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/helpwin.cpp
// Purpose:     Help system: native implementation
// Author:      David Webster
// Modified by:
// Created:     10/09/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_HELP

#ifndef WX_PRECOMP
#endif

#include "wx/os2/helpwin.h"

#include <time.h>

#include "wx/os2/private.h"

#include <string.h>

// MAX path length
#define _MAXPATHLEN 500

// MAX length of Help descriptor
#define _MAX_HELP_LEN 500

IMPLEMENT_DYNAMIC_CLASS(wxWinHelpController, wxHelpControllerBase)

wxWinHelpController::wxWinHelpController()
{
    m_helpFile = wxEmptyString;
}

wxWinHelpController::~wxWinHelpController()
{
}

bool wxWinHelpController::Initialize(const wxString& filename)
{
    m_helpFile = filename;
    // TODO any other inits
    return true;
}

bool wxWinHelpController::LoadFile(const wxString& file)
{
    m_helpFile = file;
    // TODO
    return true;
}

bool wxWinHelpController::DisplayContents()
{
    if (m_helpFile.empty())
        return false;

    wxString str = m_helpFile;
    size_t len = str.length();
    if (!(str[(size_t)(len-1)] == wxT('p') && str[(size_t)(len-2)] == wxT('l') && str[(size_t)(len-3)] == wxT('h') && str[(size_t)(len-4)] == wxT('.')))
        str += wxT(".hlp");

    if (wxTheApp->GetTopWindow())
    {
        // TODO : display the help
        return true;
    }
    return false;
}

bool wxWinHelpController::DisplaySection(int WXUNUSED(section))
{
    // Use context number
    if (m_helpFile.empty())
        return false;

    wxString str = m_helpFile;
    size_t len = str.length();
    if (!(str[(size_t)(len-1)] == wxT('p') && str[(size_t)(len-2)] == wxT('l') && str[(size_t)(len-3)] == wxT('h') && str[(size_t)(len-4)] == wxT('.')))
      str += wxT(".hlp");

    if (wxTheApp->GetTopWindow())
    {
        // TODO ::
        //  WinHelp((HWND) wxTheApp->GetTopWindow()->GetHWND(), (const wxChar*) str, HELP_CONTEXT, (DWORD)section);
        return true;
    }

    return false;
}

bool wxWinHelpController::DisplayBlock(long WXUNUSED(block))
{
    // Use context number -- a very rough equivalent to block id!
    if (m_helpFile.empty())
        return false;

    wxString str = m_helpFile;
    size_t len = str.length();
    if (!(str[(size_t)(len-1)] == wxT('p') && str[(size_t)(len-2)] == wxT('l') && str[(size_t)(len-3)] == wxT('h') && str[(size_t)(len-4)] == wxT('.')))
      str += wxT(".hlp");

    if (wxTheApp->GetTopWindow())
    {
        // TODO:
        //  WinHelp((HWND) wxTheApp->GetTopWindow()->GetHWND(), (const wxChar*) str, HELP_CONTEXT, (DWORD)block);
        return true;
    }
    return false;
}

bool wxWinHelpController::KeywordSearch(const wxString& WXUNUSED(k),
                                        wxHelpSearchMode WXUNUSED(mode))
{
    if (m_helpFile == wxEmptyString) return false;

    wxString str = m_helpFile;
    size_t len = str.length();
    if (!(str[(size_t)(len-1)] == wxT('p') && str[(size_t)(len-2)] == wxT('l') && str[(size_t)(len-3)] == wxT('h') && str[(size_t)(len-4)] == wxT('.')))
      str += wxT(".hlp");

    if (wxTheApp->GetTopWindow())
    {
      // TODO:
      // WinHelp((HWND) wxTheApp->GetTopWindow()->GetHWND(), (const wxChar*) str, HELP_PARTIALKEY, (DWORD)(const wxChar*) k);
      return true;
    }
    return false;
}

// Can't close the help window explicitly in WinHelp
bool wxWinHelpController::Quit()
{
    if (wxTheApp->GetTopWindow())
    {
      // TODO:
      // WinHelp((HWND) wxTheApp->GetTopWindow()->GetHWND(), 0, HELP_QUIT, 0L);
      return true;
    }

    return false;
}

void wxWinHelpController::OnQuit()
{
}

#endif // wxUSE_HELP
