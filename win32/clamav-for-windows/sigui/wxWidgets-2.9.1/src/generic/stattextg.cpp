/////////////////////////////////////////////////////////////////////////////
// Name:        src/generic/stattextg.cpp
// Purpose:     wxGenericStaticText
// Author:      Marcin Wojdyr
// Created:     2008-06-26
// RCS-ID:      $Id$
// Copyright:   Marcin Wojdyr
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_STATTEXT

#ifndef WX_PRECOMP
    #include "wx/dcclient.h"
    #include "wx/settings.h"
    #include "wx/validate.h"
#endif

#include "wx/generic/stattextg.h"


IMPLEMENT_DYNAMIC_CLASS(wxGenericStaticText, wxStaticTextBase)


bool wxGenericStaticText::Create(wxWindow *parent,
                                 wxWindowID id,
                                 const wxString &label,
                                 const wxPoint &pos,
                                 const wxSize &size,
                                 long style,
                                 const wxString &name)
{
    if ( !wxControl::Create(parent, id, pos, size, style,
                            wxDefaultValidator, name) )
        return false;

    SetLabel(label);
    SetInitialSize(size);
    Connect(wxEVT_PAINT, wxPaintEventHandler(wxGenericStaticText::OnPaint));
    return true;
}

void wxGenericStaticText::OnPaint(wxPaintEvent& WXUNUSED(event))
{
    if ( m_label.empty() )
        return;
    wxPaintDC dc(this);
    PrepareDC(dc);

    wxRect rect = GetClientRect();
    if ( IsEnabled() )
    {
        dc.SetTextForeground(
                       wxSystemSettings::GetColour(wxSYS_COLOUR_BTNTEXT));
    }
    else // paint disabled text
    {
        // draw shadow of the text
        dc.SetTextForeground(
                       wxSystemSettings::GetColour(wxSYS_COLOUR_BTNHIGHLIGHT));
        wxRect rectShadow = rect;
        rectShadow.Offset(1, 1);
        dc.DrawLabel(m_label, rectShadow, GetAlignment(), m_mnemonic);
        dc.SetTextForeground(
                       wxSystemSettings::GetColour(wxSYS_COLOUR_BTNSHADOW));
    }
    dc.DrawLabel(m_label, wxNullBitmap, rect, GetAlignment(), m_mnemonic);
}


wxSize wxGenericStaticText::DoGetBestClientSize() const
{
    wxClientDC dc(wxConstCast(this, wxGenericStaticText));
    wxCoord width, height;
    dc.GetMultiLineTextExtent(GetLabel(), &width, &height);
    return wxSize(width, height);
}

void wxGenericStaticText::SetLabel(const wxString& label)
{
    wxControl::SetLabel(label);
    DoSetLabel(GetEllipsizedLabelWithoutMarkup());
    if ( !HasFlag(wxST_NO_AUTORESIZE) && !IsEllipsized() )
        InvalidateBestSize();
    Refresh();
}

void wxGenericStaticText::DoSetLabel(const wxString& label)
{
    m_mnemonic = FindAccelIndex(label, &m_label);
}

bool wxGenericStaticText::SetFont(const wxFont &font)
{
    if ( !wxControl::SetFont(font) )
        return false;
    if ( !HasFlag(wxST_NO_AUTORESIZE) )
        InvalidateBestSize();
    Refresh();
    return true;
}

void wxGenericStaticText::DoSetSize(int x, int y, int width, int height,
                                    int sizeFlags)
{
    wxStaticTextBase::DoSetSize(x, y, width, height, sizeFlags);
    UpdateLabel();
}


#endif // wxUSE_STATTEXT
