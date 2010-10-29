/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/toplevel.cpp
// Purpose:
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/toplevel.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif // WX_PRECOMP

#include "wx/mgl/private.h"

// ----------------------------------------------------------------------------
// idle system
// ----------------------------------------------------------------------------

extern int g_openDialogs;

// ----------------------------------------------------------------------------
// event tables
// ----------------------------------------------------------------------------

#ifndef __WXUNIVERSAL__
    IMPLEMENT_DYNAMIC_CLASS(wxTopLevelWindow, wxWindow)
#endif


// ============================================================================
// implementation
// ============================================================================

void wxTopLevelWindowMGL::Init()
{
    m_isShown = false;
    m_isIconized = false;
    m_isMaximized = false;
    m_fsIsShowing = false;
    m_sizeSet = false;
}

bool wxTopLevelWindowMGL::Create(wxWindow *parent,
                                 wxWindowID id,
                                 const wxString& title,
                                 const wxPoint& posOrig,
                                 const wxSize& sizeOrig,
                                 long style,
                                 const wxString &name)
{
    // always create a frame of some reasonable, even if arbitrary, size (at
    // least for MSW compatibility)
    wxSize size = sizeOrig;
    if ( size.x == wxDefaultCoord || size.y == wxDefaultCoord )
    {
        wxSize sizeDefault = GetDefaultSize();
        if ( size.x == wxDefaultCoord )
            size.x = sizeDefault.x;
        if ( size.y == wxDefaultCoord )
            size.y = sizeDefault.y;
    }

    // for default positioning, centre the first top level window and
    // cascade any addtional ones from there.
    wxPoint pos = posOrig;
    if ( pos.x == wxDefaultCoord || pos.y == wxDefaultCoord )
    {
        wxSize sizeDisplay = wxGetDisplaySize();
        static wxPoint nextPos((sizeDisplay.x - size.x) / 2,
                               (sizeDisplay.y - size.y) / 2);

        if ( pos.x == wxDefaultCoord )
            pos.x = nextPos.x;
        if ( pos.y == wxDefaultCoord )
            pos.y = nextPos.y;
        if ( pos.x + size.x > sizeDisplay.x || pos.y + size.y > sizeDisplay.y )
            pos = wxPoint();

        const wxSize cascadeOffset(16, 20);
        nextPos = pos + cascadeOffset;
    }

    wxWindow::Create(NULL, id, pos, size, style, name);
    SetParent(parent);
    if ( parent )
        parent->AddChild(this);

    wxTopLevelWindows.Append(this);
    m_title = title;

    return true;
}

bool wxTopLevelWindowMGL::ShowFullScreen(bool show, long style)
{
    if (show == m_fsIsShowing) return false; // return what?

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

bool wxTopLevelWindowMGL::Show(bool show)
{
    bool ret = wxTopLevelWindowBase::Show(show);

    // If this is the first time Show was called, send size event,
    // so that the frame can adjust itself (think auto layout or single child)
    if ( !m_sizeSet )
    {
        m_sizeSet = true;
        wxSizeEvent event(GetSize(), GetId());
        event.SetEventObject(this);
        HandleWindowEvent(event);
    }

    if ( ret && show && CanAcceptFocus() )
        SetFocus();
        // FIXME_MGL -- don't do this for popup windows?
    return ret;
}

void wxTopLevelWindowMGL::Maximize(bool maximize)
{
    int x, y, w, h;
    wxClientDisplayRect(&x, &y, &w, &h);

    rect_t screenRect = MGL_defRect(x, y, w, h);
    MGL_wmInvalidateRect(g_winMng, &screenRect);

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

bool wxTopLevelWindowMGL::IsMaximized() const
{
    return m_isMaximized;
}

void wxTopLevelWindowMGL::Restore()
{
    if ( IsIconized() )
    {
        Iconize(false);
    }
    if ( IsMaximized() )
    {
        Maximize(false);
    }
}

void wxTopLevelWindowMGL::Iconize(bool WXUNUSED(iconize))
{
    wxFAIL_MSG(wxT("Iconize not supported under wxMGL"));
    // FIXME_MGL - Iconize is not supported in fullscreen mode.
    //             It will be supported in windowed mode (if ever implemented in MGL...)
}

bool wxTopLevelWindowMGL::IsIconized() const
{
    return m_isIconized;
}
