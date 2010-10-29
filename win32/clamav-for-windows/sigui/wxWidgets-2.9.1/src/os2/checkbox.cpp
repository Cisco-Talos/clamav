/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/checkbox.cpp
// Purpose:     wxCheckBox
// Author:      David Webster
// Modified by:
// Created:     10/13/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/checkbox.h"

#ifndef WX_PRECOMP
    #include "wx/brush.h"
    #include "wx/scrolwin.h"
    #include "wx/dcscreen.h"
    #include "wx/settings.h"
#endif

#include "wx/os2/private.h"

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxCheckBox, wxControl)
IMPLEMENT_DYNAMIC_CLASS(wxBitmapCheckBox, wxCheckBox)

extern void  wxAssociateWinWithHandle( HWND         hWnd
                                      ,wxWindowOS2* pWin
                                     );

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxCheckBox
// ----------------------------------------------------------------------------

bool wxCheckBox::OS2Command( WXUINT WXUNUSED(uParam),
                             WXWORD WXUNUSED(wId) )
{
    wxCommandEvent rEvent( wxEVT_COMMAND_CHECKBOX_CLICKED, m_windowId );
    rEvent.SetInt(GetValue());
    rEvent.SetEventObject(this);
    ProcessCommand(rEvent);
    return true;
} // end of wxCheckBox::OS2Command

bool wxCheckBox::Create(wxWindow* pParent,
                        wxWindowID vId,
                        const wxString& rsLabel,
                        const wxPoint& rPos,
                        const wxSize& rSize,
                        long lStyle,
                        const wxValidator& rValidator,
                        const wxString& rsName )
{
    if (!CreateControl( pParent
                       ,vId
                       ,rPos
                       ,rSize
                       ,lStyle
                       ,rValidator
                       ,rsName
                      ))
        return false;


    long osStyle = BS_AUTOCHECKBOX | WS_TABSTOP | WS_VISIBLE;

    bool bOk = OS2CreateControl( wxT("BUTTON")
                           ,osStyle
                           ,rPos
                           ,rSize
                           ,rsLabel
                           ,0
                          );
    m_backgroundColour = pParent->GetBackgroundColour();

    LONG lColor = (LONG)m_backgroundColour.GetPixel();
    ::WinSetPresParam( m_hWnd
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    wxAssociateWinWithHandle(m_hWnd, this);
    return bOk;
} // end of wxCheckBox::Create

void wxCheckBox::SetLabel( const wxString& rsLabel )
{
    wxString  sLabel=::wxPMTextToLabel(rsLabel);
    ::WinSetWindowText(GetHwnd(), sLabel.c_str());
} // end of wxCheckBox::SetLabel

wxSize wxCheckBox::DoGetBestSize() const
{
    // We should probably compute nCheckSize but it seems to be a constant
    // independent of its label's font size and not made available by OS/2.
    int      nCheckSize = RADIO_SIZE;
    int      nWidthCheckbox;
    int      nHeightCheckbox;
    wxString sStr = wxGetWindowText(GetHWND());

    if (!sStr.empty())
    {
        GetTextExtent( sStr
                      ,&nWidthCheckbox
                      ,&nHeightCheckbox
                     );
        nWidthCheckbox += nCheckSize;

        if (nHeightCheckbox < nCheckSize)
            nHeightCheckbox = nCheckSize;
    }
    else
    {
        nWidthCheckbox  = nCheckSize;
        nHeightCheckbox = nCheckSize;
    }

    return wxSize( nWidthCheckbox, nHeightCheckbox );
} // end of wxCheckBox::DoGetBestSize

void wxCheckBox::SetValue( bool bValue )
{
    ::WinSendMsg(GetHwnd(), BM_SETCHECK, (MPARAM)bValue, 0);
} // end of wxCheckBox::SetValue

#ifndef BST_CHECKED
#define BST_CHECKED 0x0001
#endif

bool wxCheckBox::GetValue() const
{
    return((LONGFROMMR(::WinSendMsg(GetHwnd(), BM_QUERYCHECK, (MPARAM)0, (MPARAM)0)) == 1L));
} // end of wxCheckBox::GetValue

void wxCheckBox::Command ( wxCommandEvent& rEvent )
{
    SetValue((rEvent.GetInt() != 0));
    ProcessCommand(rEvent);
} // end of wxCheckBox:: Command

// ----------------------------------------------------------------------------
// wxBitmapCheckBox
// ----------------------------------------------------------------------------

bool wxBitmapCheckBox::Create( wxWindow*          pParent,
                               wxWindowID         vId,
                               const wxBitmap*    WXUNUSED(pLabel),
                               const wxPoint&     rPos,
                               const wxSize&      rSize,
                               long               lStyle,
                               const wxValidator& rValidator,
                               const wxString&    rsName)
{
    SetName(rsName);
#if wxUSE_VALIDATORS
    SetValidator(rValidator);
#endif
    if (pParent)
        pParent->AddChild(this);

    SetBackgroundColour(pParent->GetBackgroundColour()) ;
    SetForegroundColour(pParent->GetForegroundColour()) ;
    m_windowStyle = lStyle;

    if (vId == -1)
        m_windowId = NewControlId();
    else
        m_windowId = vId;

    int                             nX      = rPos.x;
    int                             nY      = rPos.y;
    int                             nWidth  = rSize.x;
    int                             nHeight = rSize.y;

    m_nCheckWidth = -1 ;
    m_nCheckHeight = -1 ;
//    long msStyle = CHECK_FLAGS;

    HWND hButton = 0; // TODO: Create the bitmap checkbox

    m_hWnd = (WXHWND)hButton;

    //
    // Subclass again for purposes of dialog editing mode
    //
    SubclassWin((WXHWND)hButton);

    SetSize( nX
            ,nY
            ,nWidth
            ,nHeight
           );

    ::WinShowWindow(hButton, TRUE);
    return true;
} // end of wxBitmapCheckBox::Create

void wxBitmapCheckBox::SetLabel( const wxBitmap& WXUNUSED(rBitmap) )
{
    wxFAIL_MSG(wxT("not implemented"));
}  // end of wxBitmapCheckBox::SetLabel
