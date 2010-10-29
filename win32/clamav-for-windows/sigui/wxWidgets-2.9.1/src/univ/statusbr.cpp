/////////////////////////////////////////////////////////////////////////////
// Name:        src/univ/statusbr.cpp
// Purpose:     wxStatusBar implementation
// Author:      Vadim Zeitlin
// Modified by:
// Created:     14.10.01
// RCS-ID:      $Id$
// Copyright:   (c) 2000 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_STATUSBAR

#include "wx/statusbr.h"

#ifndef WX_PRECOMP
    #include "wx/settings.h"
    #include "wx/dcclient.h"
    #include "wx/toplevel.h"
#endif

#include "wx/univ/renderer.h"

// ============================================================================
// implementation
// ============================================================================

BEGIN_EVENT_TABLE(wxStatusBarUniv, wxStatusBarBase)
    EVT_SIZE(wxStatusBarUniv::OnSize)

    WX_EVENT_TABLE_INPUT_CONSUMER(wxStatusBarUniv)
END_EVENT_TABLE()

WX_FORWARD_TO_INPUT_CONSUMER(wxStatusBarUniv)

// ----------------------------------------------------------------------------
// creation
// ----------------------------------------------------------------------------

void wxStatusBarUniv::Init()
{
}

bool wxStatusBarUniv::Create(wxWindow *parent,
                             wxWindowID id,
                             long style,
                             const wxString& name)
{
    if ( !wxWindow::Create(parent, id,
                           wxDefaultPosition, wxDefaultSize,
                           style, name) )
    {
        return false;
    }

    SetFieldsCount(1);

    CreateInputHandler(wxINP_HANDLER_STATUSBAR);

    SetSize(DoGetBestSize());

    return true;
}

// ----------------------------------------------------------------------------
// drawing
// ----------------------------------------------------------------------------

wxRect wxStatusBarUniv::GetTotalFieldRect(wxCoord *borderBetweenFields)
{
    wxRect rect = GetClientRect();

    // no, don't do this - the borders are meant to be inside this rect
    // wxSize sizeBorders =
    if ( borderBetweenFields )
        *borderBetweenFields = m_renderer->GetStatusBarBorderBetweenFields();
    //rect.Deflate(sizeBorders.x, sizeBorders.y);

    // recalc the field widths if needed
    if ( m_widthsAbs.IsEmpty() )
    {
        // the total width for the fields doesn't include the borders between
        // them
        m_widthsAbs = CalculateAbsWidths(rect.width -
                                         *borderBetweenFields*(m_panes.GetCount() - 1));
    }

    return rect;
}

void wxStatusBarUniv::DoDraw(wxControlRenderer *renderer)
{
    // get the fields rect
    wxCoord borderBetweenFields;
    wxRect rect = GetTotalFieldRect(&borderBetweenFields);

    // prepare the DC
    wxDC& dc = renderer->GetDC();
    dc.SetFont(GetFont());
    dc.SetTextForeground(GetForegroundColour());

    // do draw the fields
    int flags = IsEnabled() ? 0 : (int)wxCONTROL_DISABLED;
    for ( int n = 0; n < (int)m_panes.GetCount(); n++ )
    {
        rect.width = m_widthsAbs[n];

        if ( IsExposed(rect) )
        {
            wxTopLevelWindow *parentTLW = wxDynamicCast(GetParent(), wxTopLevelWindow);

            // the size grip may be drawn only on the last field and only if we
            // have the corresponding style and even then only if we really can
            // resize this frame
            if ( n == (int)m_panes.GetCount() - 1 &&
                 HasFlag(wxSTB_SIZEGRIP) &&
                 GetParent()->HasFlag(wxRESIZE_BORDER) &&
                 parentTLW && !parentTLW->IsMaximized() )
            {
                flags |= wxCONTROL_SIZEGRIP;
            }

            m_renderer->DrawStatusField(dc, rect, GetStatusText(n), flags, m_panes[n].GetStyle());
        }

        rect.x += rect.width + borderBetweenFields;
    }
}

void wxStatusBarUniv::DoUpdateStatusText(int i)
{
    wxRect rect;
    if ( GetFieldRect(i, rect) )
    {
        RefreshRect(rect);
    }
}

// ----------------------------------------------------------------------------
// fields count/widths
// ----------------------------------------------------------------------------

void wxStatusBarUniv::SetFieldsCount(int number, const int *widths)
{
    wxStatusBarBase::SetFieldsCount(number, widths);

    m_widthsAbs.Empty();
}

void wxStatusBarUniv::SetStatusWidths(int n, const int widths[])
{
    wxStatusBarBase::SetStatusWidths(n, widths);

    m_widthsAbs.Empty();
}

// ----------------------------------------------------------------------------
// geometry
// ----------------------------------------------------------------------------

void wxStatusBarUniv::OnSize(wxSizeEvent& event)
{
    // we don't need to refresh the fields whose width didn't change, so find
    // the first field whose width did change and refresh starting from it
    size_t field;
    if ( m_bSameWidthForAllPanes )
    {
        // hence all fields widths have changed
        field = 0;
    }
    else
    {
        for ( field = 0; field < m_panes.GetCount(); field++ )
        {
            if ( m_panes[field].GetWidth() < 0 )
            {
                // var width field
                break;
            }
        }
    }

    if ( field < m_panes.GetCount() )
    {
        // call this before invalidating the old widths as we want to use them,
        // not the new ones
        wxRect rect = DoGetFieldRect(field);

        // invalidate the widths, we'll have to recalc them
        m_widthsAbs.Empty();

        // refresh everything after the first invalid field
        rect.y = 0;
        rect.SetRight(event.GetSize().x);
        rect.height = event.GetSize().y;
        RefreshRect(rect);
    }

    event.Skip();
}

bool wxStatusBarUniv::GetFieldRect(int n, wxRect& rect) const
{
    wxCHECK_MSG( n >= 0 && (size_t)n < m_panes.GetCount(), false,
                 wxT("invalid field index in GetFieldRect()") );

    // this is a fix for a bug exhibited by the statbar sample: if
    // GetFieldRect() is called from the derived class OnSize() handler, then
    // our geometry info is wrong as our OnSize() didn't invalidate m_widthsAbs
    // yet - so recalc it just in case
    wxConstCast(this, wxStatusBarUniv)->m_widthsAbs.Empty();

    rect = DoGetFieldRect(n);

    return true;
}

wxRect wxStatusBarUniv::DoGetFieldRect(int n) const
{
    wxStatusBarUniv *self = wxConstCast(this, wxStatusBarUniv);

    wxCoord borderBetweenFields;
    wxRect rect = self->GetTotalFieldRect(&borderBetweenFields);

    // it's the caller responsability to check this, if unsure - call
    // GetFieldRect() instead
    wxCHECK_MSG( !m_widthsAbs.IsEmpty(), rect,
                 wxT("can't be called if we don't have the widths") );

    for ( int i = 0; i <= n; i++ )
    {
        rect.width = m_widthsAbs[i];

        if ( i < n )
            rect.x += rect.width + borderBetweenFields;
    }

    return rect;
}

wxCoord wxStatusBarUniv::GetHeight() const
{
    return GetCharHeight() + 2*GetBorderY();
}

wxSize wxStatusBarUniv::DoGetBestSize() const
{
    return wxSize(100, GetHeight());
}

void wxStatusBarUniv::DoSetSize(int x, int y,
                                int width, int WXUNUSED(height),
                                int sizeFlags)
{
    wxStatusBarBase::DoSetSize(x, y, width, GetHeight(), sizeFlags);
}

// ----------------------------------------------------------------------------
// misc
// ----------------------------------------------------------------------------

void wxStatusBarUniv::SetMinHeight(int WXUNUSED(height))
{
    // nothing to do here, we don't support it - and why would we?
}

int wxStatusBarUniv::GetBorderX() const
{
    return m_renderer->GetStatusBarBorders().x +
           m_renderer->GetStatusBarFieldMargins().x;
}

int wxStatusBarUniv::GetBorderY() const
{
    return m_renderer->GetStatusBarBorders().y +
           m_renderer->GetStatusBarFieldMargins().y;
}

#endif // wxUSE_STATUSBAR
