/////////////////////////////////////////////////////////////////////////////
// Name:        src/common/hyperlnkcmn.cpp
// Purpose:     Hyperlink control
// Author:      David Norris <danorris@gmail.com>, Otto Wyss
// Modified by: Ryan Norton, Francesco Montorsi
// Created:     04/02/2005
// RCS-ID:      $Id$
// Copyright:   (c) 2005 David Norris
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

//---------------------------------------------------------------------------
// Pre-compiled header stuff
//---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_HYPERLINKCTRL

//---------------------------------------------------------------------------
// Includes
//---------------------------------------------------------------------------

#include "wx/hyperlink.h"

#ifndef WX_PRECOMP
    #include "wx/menu.h"
    #include "wx/log.h"
    #include "wx/dataobj.h"
#endif

// ============================================================================
// implementation
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxHyperlinkEvent, wxCommandEvent)
wxDEFINE_EVENT( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEvent );

const char wxHyperlinkCtrlNameStr[] = "hyperlink";

// ----------------------------------------------------------------------------
// wxHyperlinkCtrlBase
// ----------------------------------------------------------------------------

void
wxHyperlinkCtrlBase::CheckParams(const wxString& label,
                                 const wxString& url,
                                 long style)
{
#if wxDEBUG_LEVEL
    wxASSERT_MSG(!url.empty() || !label.empty(),
                 wxT("Both URL and label are empty ?"));

    int alignment = (int)((style & wxHL_ALIGN_LEFT) != 0) +
                    (int)((style & wxHL_ALIGN_CENTRE) != 0) +
                    (int)((style & wxHL_ALIGN_RIGHT) != 0);
    wxASSERT_MSG(alignment == 1,
        wxT("Specify exactly one align flag!"));
#else // !wxDEBUG_LEVEL
    wxUnusedVar(label);
    wxUnusedVar(url);
    wxUnusedVar(style);
#endif // wxDEBUG_LEVEL/!wxDEBUG_LEVEL
}

void wxHyperlinkCtrlBase::SendEvent()
{
    wxString url = GetURL();
    wxHyperlinkEvent linkEvent(this, GetId(), url);
    if (!GetEventHandler()->ProcessEvent(linkEvent))     // was the event skipped ?
    {
        if (!wxLaunchDefaultBrowser(url))
        {
            wxLogWarning(wxT("Could not launch the default browser with url '%s' !"), url.c_str());
        }
    }
}

#endif // wxUSE_HYPERLINKCTRL
