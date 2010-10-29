/////////////////////////////////////////////////////////////////////////////
// Name:        src/generic/msgdlgg.cpp
// Purpose:     wxGenericMessageDialog
// Author:      Julian Smart, Robert Roebling
// Modified by:
// Created:     04/01/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart and Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#if wxUSE_MSGDLG && (!defined(__WXGTK20__) || defined(__WXUNIVERSAL__) || defined(__WXGPE__))

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/button.h"
    #include "wx/stattext.h"
    #include "wx/statbmp.h"
    #include "wx/layout.h"
    #include "wx/intl.h"
    #include "wx/icon.h"
    #include "wx/sizer.h"
    #include "wx/app.h"
    #include "wx/settings.h"
#endif

#include <stdio.h>
#include <string.h>

#define __WX_COMPILING_MSGDLGG_CPP__ 1
#include "wx/msgdlg.h"
#include "wx/artprov.h"

#if wxUSE_STATLINE
    #include "wx/statline.h"
#endif

// ----------------------------------------------------------------------------
// icons
// ----------------------------------------------------------------------------

BEGIN_EVENT_TABLE(wxGenericMessageDialog, wxDialog)
        EVT_BUTTON(wxID_YES, wxGenericMessageDialog::OnYes)
        EVT_BUTTON(wxID_NO, wxGenericMessageDialog::OnNo)
        EVT_BUTTON(wxID_CANCEL, wxGenericMessageDialog::OnCancel)
END_EVENT_TABLE()

IMPLEMENT_CLASS(wxGenericMessageDialog, wxDialog)

wxGenericMessageDialog::wxGenericMessageDialog( wxWindow *parent,
                                                const wxString& message,
                                                const wxString& caption,
                                                long style,
                                                const wxPoint& pos)
                      : wxMessageDialogBase(GetParentForModalDialog(parent, style),
                                            message,
                                            caption,
                                            style),
                        m_pos(pos)
{
    m_created = false;
}

void wxGenericMessageDialog::DoCreateMsgdialog()
{
    wxDialog::Create(m_parent, wxID_ANY, m_caption, m_pos, wxDefaultSize, wxDEFAULT_DIALOG_STYLE);

    bool is_pda = (wxSystemSettings::GetScreenType() <= wxSYS_SCREEN_PDA);

    wxBoxSizer *topsizer = new wxBoxSizer( wxVERTICAL );

    wxBoxSizer *icon_text = new wxBoxSizer( wxHORIZONTAL );

#if wxUSE_STATBMP
    // 1) icon
    if (m_dialogStyle & wxICON_MASK)
    {
        wxStaticBitmap *icon = new wxStaticBitmap
                                   (
                                    this,
                                    wxID_ANY,
                                    wxArtProvider::GetMessageBoxIcon(m_dialogStyle)
                                   );
        if (is_pda)
            topsizer->Add( icon, 0, wxTOP|wxLEFT|wxRIGHT | wxALIGN_LEFT, 10 );
        else
            icon_text->Add( icon, 0, wxCENTER );
    }
#endif // wxUSE_STATBMP

#if wxUSE_STATTEXT
    // 2) text
    icon_text->Add( CreateTextSizer( GetFullMessage() ), 0, wxALIGN_CENTER | wxLEFT, 10 );

    topsizer->Add( icon_text, 1, wxCENTER | wxLEFT|wxRIGHT|wxTOP, 10 );
#endif // wxUSE_STATTEXT

    // 3) buttons
    int center_flag = wxEXPAND;
    if (m_dialogStyle & wxYES_NO)
        center_flag = wxALIGN_CENTRE;
    wxSizer *sizerBtn = CreateSeparatedButtonSizer
                        (
                            m_dialogStyle & (wxOK | wxCANCEL | wxYES_NO |
                                             wxNO_DEFAULT | wxCANCEL_DEFAULT)
                        );
    if ( sizerBtn )
        topsizer->Add(sizerBtn, 0, center_flag | wxALL, 10 );

    SetAutoLayout( true );
    SetSizer( topsizer );

    topsizer->SetSizeHints( this );
    topsizer->Fit( this );
    wxSize size( GetSize() );
    if (size.x < size.y*3/2)
    {
        size.x = size.y*3/2;
        SetSize( size );
    }

    Centre( wxBOTH | wxCENTER_FRAME);
}

void wxGenericMessageDialog::OnYes(wxCommandEvent& WXUNUSED(event))
{
    EndModal( wxID_YES );
}

void wxGenericMessageDialog::OnNo(wxCommandEvent& WXUNUSED(event))
{
    EndModal( wxID_NO );
}

void wxGenericMessageDialog::OnCancel(wxCommandEvent& WXUNUSED(event))
{
    // Allow cancellation via ESC/Close button except if
    // only YES and NO are specified.
    const long style = GetMessageDialogStyle();
    if ( (style & wxYES_NO) != wxYES_NO || (style & wxCANCEL) )
    {
        EndModal( wxID_CANCEL );
    }
}

int wxGenericMessageDialog::ShowModal()
{
    if ( !m_created )
    {
        m_created = true;
        DoCreateMsgdialog();
    }

    return wxMessageDialogBase::ShowModal();
}

#endif // wxUSE_MSGDLG && !defined(__WXGTK20__)
