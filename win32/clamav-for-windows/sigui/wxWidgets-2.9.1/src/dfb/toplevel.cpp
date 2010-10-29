/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/toplevel.cpp
// Purpose:     Top level window, abstraction of wxFrame and wxDialog
// Author:      Vaclav Slavik
// Created:     2006-08-10
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/toplevel.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif // WX_PRECOMP

#include "wx/dfb/private.h"

#define TRACE_EVENTS "events"

// ============================================================================
// wxTopLevelWindowDFB
// ============================================================================

// ----------------------------------------------------------------------------
// creation & destruction
// ----------------------------------------------------------------------------

void wxTopLevelWindowDFB::Init()
{
    m_isMaximized = false;
    m_fsIsShowing = false;
}

bool wxTopLevelWindowDFB::Create(wxWindow *parent,
                                 wxWindowID id,
                                 const wxString& title,
                                 const wxPoint& posOrig,
                                 const wxSize& sizeOrig,
                                 long style,
                                 const wxString &name)
{
    // always create a frame of some reasonable, even if arbitrary, size (at
    // least for MSW compatibility)
    wxSize size(sizeOrig);
    if ( size.x == wxDefaultCoord || size.y == wxDefaultCoord )
    {
        wxSize sizeDefault = GetDefaultSize();
        if ( size.x == wxDefaultCoord )
            size.x = sizeDefault.x;
        if ( size.y == wxDefaultCoord )
            size.y = sizeDefault.y;
    }

    wxPoint pos(posOrig);
    if ( pos.x == wxDefaultCoord )
        pos.x = 0;
    if ( pos.y == wxDefaultCoord )
        pos.y = 0;

    if ( !wxNonOwnedWindow::Create(parent, id, pos, size, style, name) )
        return false;

    wxTopLevelWindows.Append(this);
    m_title = title;

    return true;
}

// ----------------------------------------------------------------------------
// showing and hiding
// ----------------------------------------------------------------------------

#warning "FIXME: the rest of this file is almost same as for MGL, merge it"
bool wxTopLevelWindowDFB::ShowFullScreen(bool show, long style)
{
    if ( show == m_fsIsShowing )
        return true;

    m_fsIsShowing = show;

    if (show)
    {
        m_fsSaveStyle = m_windowStyle;
        m_fsSaveFlag = style;
        GetPosition(&m_fsSaveFrame.x, &m_fsSaveFrame.y);
        GetSize(&m_fsSaveFrame.width, &m_fsSaveFrame.height);

        if ( style & wxFULLSCREEN_NOCAPTION )
            m_windowStyle &= ~wxCAPTION;
        if ( style & wxFULLSCREEN_NOBORDER )
            m_windowStyle = wxSIMPLE_BORDER;

        int x, y;
        wxDisplaySize(&x, &y);
        SetSize(0, 0, x, y);
    }
    else
    {
        m_windowStyle = m_fsSaveStyle;
        SetSize(m_fsSaveFrame.x, m_fsSaveFrame.y,
                m_fsSaveFrame.width, m_fsSaveFrame.height);
    }

    return true;
}

bool wxTopLevelWindowDFB::SetTransparent(wxByte alpha)
{
    if ( IsShown() )
    {
        if ( !m_dfbwin->SetOpacity(alpha) )
            return false;
    }

    m_opacity = alpha;
    return true;
}

// ----------------------------------------------------------------------------
// maximize, minimize etc.
// ----------------------------------------------------------------------------

void wxTopLevelWindowDFB::Maximize(bool maximize)
{
    int x, y, w, h;
    wxClientDisplayRect(&x, &y, &w, &h);

    if ( maximize && !m_isMaximized )
    {
        m_isMaximized = true;

        GetPosition(&m_savedFrame.x, &m_savedFrame.y);
        GetSize(&m_savedFrame.width, &m_savedFrame.height);

        SetSize(x, y, w, h);
    }
    else if ( !maximize && m_isMaximized )
    {
        m_isMaximized = false;
        SetSize(m_savedFrame.x, m_savedFrame.y,
                m_savedFrame.width, m_savedFrame.height);
    }
}

bool wxTopLevelWindowDFB::IsMaximized() const
{
    return m_isMaximized;
}

void wxTopLevelWindowDFB::Restore()
{
    if ( IsMaximized() )
    {
        Maximize(false);
    }
}

void wxTopLevelWindowDFB::Iconize(bool WXUNUSED(iconize))
{
    wxFAIL_MSG(wxT("Iconize not supported under wxDFB"));
}

bool wxTopLevelWindowDFB::IsIconized() const
{
    return false;
}

// ----------------------------------------------------------------------------
// focus handling
// ----------------------------------------------------------------------------

void wxTopLevelWindowDFB::HandleFocusEvent(const wxDFBWindowEvent& event_)
{
    const DFBWindowEvent& dfbevent = event_;
    const bool activate = (dfbevent.type == DWET_GOTFOCUS);

    wxLogTrace(TRACE_EVENTS,
               "toplevel window %p ('%s') %s focus",
               this, GetName(),
               activate ? "got" : "lost");

    wxActivateEvent event(wxEVT_ACTIVATE, activate, GetId());
    event.SetEventObject(this);
    HandleWindowEvent(event);

    // if a frame that doesn't have wx focus inside it just got focus, we
    // need to set focus to it (or its child):
    if ( activate )
    {
        wxWindow *focused = wxWindow::FindFocus();
        if ( !focused || focused->GetTLW() != this )
        {
            wxLogTrace(TRACE_EVENTS,
                       "setting wx focus to toplevel window %p ('%s')",
                       this, GetName());

            if ( CanAcceptFocus() )
                SetFocus();
            else
                wxLogTrace(TRACE_EVENTS, "...which doesn't accept it");
        }
    }
}
