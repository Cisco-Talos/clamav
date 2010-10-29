/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/stattext.cpp
// Purpose:     wxStaticText
// Author:      David Webster
// Modified by:
// Created:     10/17/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/stattext.h"

#ifndef WX_PRECOMP
    #include "wx/event.h"
    #include "wx/app.h"
    #include "wx/brush.h"
    #include "wx/scrolwin.h"
#endif

#include "wx/os2/private.h"
#include <stdio.h>

IMPLEMENT_DYNAMIC_CLASS(wxStaticText, wxControl)

bool wxStaticText::Create( wxWindow*        pParent,
                           wxWindowID       vId,
                           const wxString&  rsLabel,
                           const wxPoint&   rPos,
                           const wxSize&    rSize,
                           long             lStyle,
                           const wxString&  rsName )
{
    SetName(rsName);
    if (pParent)
        pParent->AddChild(this);

    SetBackgroundColour(pParent->GetBackgroundColour()) ;
    SetForegroundColour(pParent->GetForegroundColour()) ;

    if ( vId == wxID_ANY )
        m_windowId = (int)NewControlId();
    else
        m_windowId = vId;

    int nX      = rPos.x;
    int nY      = rPos.y;
    int nWidth  = rSize.x;
    int nHeight = rSize.y;

    m_windowStyle = lStyle;

    long lSstyle = 0L;

    // Used to have DT_VCENTER but that doesn't work correctly with
    // multiline strings and DT_WORDBREAK. Accept a reasonable
    // compromise for now
    lSstyle = WS_VISIBLE | SS_TEXT | DT_WORDBREAK | DT_MNEMONIC;
    if (m_windowStyle & wxALIGN_CENTRE)
        lSstyle |= DT_CENTER;
    else if (m_windowStyle & wxALIGN_RIGHT)
        lSstyle |= DT_RIGHT;
    else
        lSstyle |= DT_LEFT;

    m_hWnd = (WXHWND)::WinCreateWindow( (HWND)GetHwndOf(pParent) // Parent window handle
                                       ,WC_STATIC                // Window class
                                       ,NULL                     // Initial Text
                                       ,(ULONG)lSstyle           // Style flags
                                       ,0L, 0L, 0L, 0L           // Origin -- 0 size
                                       ,(HWND)GetHwndOf(pParent) // owner window handle (same as parent
                                       ,HWND_TOP                 // initial z position
                                       ,(ULONG)m_windowId        // Window identifier
                                       ,NULL                     // no control data
                                       ,NULL                     // no Presentation parameters
                                      );

    wxCHECK_MSG(m_hWnd, false, wxT("Failed to create static ctrl"));

    LONG lColor = (LONG)wxBLACK->GetPixel();

    ::WinSetPresParam( m_hWnd
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    lColor = (LONG)m_backgroundColour.GetPixel();

    ::WinSetPresParam( m_hWnd
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );

    SubclassWin(m_hWnd);
    SetFont(*wxSMALL_FONT);
    SetXComp(0);
    SetYComp(0);
    SetSize( nX, nY, nWidth, nHeight );

    SetLabel(rsLabel);

    return true;
} // end of wxStaticText::Create

wxSize wxStaticText::DoGetBestSize() const
{
    wxString sText(GetLabel());
    int      nWidthTextMax = 0;
    int      nWidthLine = 0;
    int      nHeightTextTotal = 0;
    int      nHeightLineDefault = 0;
    int      nHeightLine = 0;
    wxString sCurLine;
    bool     bLastWasTilde = false;

    for (const wxChar *pc = sText; ; pc++)
    {
        if ( *pc == wxT('\n') || *pc == wxT('\0') )
        {
            if (!sCurLine )
            {
                //
                // We can't use GetTextExtent - it will return 0 for both width
                // and height and an empty line should count in height
                // calculation
                //
                if (!nHeightLineDefault)
                    nHeightLineDefault = nHeightLine;
                if (!nHeightLineDefault)
                    GetTextExtent(wxT("W"), NULL, &nHeightLineDefault);
                nHeightTextTotal += nHeightLineDefault;
            }
            else
            {
                GetTextExtent( sCurLine
                              ,&nWidthLine
                              ,&nHeightLine
                             );
                if (nWidthLine > nWidthTextMax)
                    nWidthTextMax = nWidthLine;
                nHeightTextTotal += nHeightLine;
            }

            if ( *pc == wxT('\n') )
            {
                sCurLine.Empty();
            }
            else
            {
               break;
            }
        }
        else
        {
            //
            // We shouldn't take into account the '~' which just introduces the
            // mnemonic characters and so are not shown on the screen -- except
            // when it is preceded by another '~' in which case it stands for a
            // literal tilde
            //
            if (*pc == wxT('~'))
            {
                if (!bLastWasTilde)
                {
                    bLastWasTilde = true;

                    //
                    // Skip the statement adding pc to curLine below
                    //
                    continue;
                }

                //
                // It is a literal tilde
                //
                bLastWasTilde = false;
            }
            sCurLine += *pc;
        }
    }
    return wxSize( nWidthTextMax
                  ,nHeightTextTotal
                 );
} // end of wxStaticText::DoGetBestSize

void wxStaticText::DoSetSize(
  int                               nX
, int                               nY
, int                               nWidth
, int                               nHeight
, int                               nSizeFlags
)
{
    //
    // We need to refresh the window after changing its size as the standard
    // control doesn't always update itself properly.
    //
    wxStaticTextBase::DoSetSize( nX
                                ,nY
                                ,nWidth
                                ,nHeight
                                ,nSizeFlags
                               );

    // eventually update label (if ellipsizing is on):
    UpdateLabel();

    Refresh();
} // end of wxStaticText::DoSetSize

bool wxStaticText::SetFont(
  const wxFont&                     rFont
)
{
    bool                            bRet = wxControl::SetFont(rFont);

    //
    // Adjust the size of the window to fit to the label unless autoresizing is
    // disabled
    //
    if ( !(GetWindowStyle() & wxST_NO_AUTORESIZE) )
    {
        DoSetSize(-1, -1, -1, -1, wxSIZE_AUTO_WIDTH | wxSIZE_AUTO_HEIGHT);
    }
    return bRet;
} // end of wxStaticText::SetFont

void wxStaticText::SetLabel(
  const wxString&                   rsLabel
)
{
    m_labelOrig = rsLabel;       // save original label

    // OS/2 does not support neither ellipsize nor markup in static text:
    DoSetLabel(rsLabel);
    DoSetLabel(GetEllipsizedLabelWithoutMarkup());

    //
    // Adjust the size of the window to fit to the label unless autoresizing is
    // disabled
    //
    if (!(GetWindowStyle() & wxST_NO_AUTORESIZE) &&
        !IsEllipsized())
    {
        wxCoord                     vX;
        wxCoord                     vY;
        wxCoord                     vWidth;
        wxCoord                     vHeight;

        GetPosition(&vX, &vY);
        GetSize(&vWidth, &vHeight);
        if (!(vX == -1 && vY == -1 && vWidth == -1 && vHeight == -1))
            DoSetSize(vX, vY, vWidth, vHeight, wxSIZE_AUTO_WIDTH | wxSIZE_AUTO_HEIGHT);
        else
            DoSetSize(-1, -1, -1, -1, wxSIZE_AUTO_WIDTH | wxSIZE_AUTO_HEIGHT);
    }
} // end of wxStaticText::SetLabel

MRESULT wxStaticText::OS2WindowProc(
  WXUINT                            uMsg
, WXWPARAM                          wParam
, WXLPARAM                          lParam
)
{
    return wxWindow::OS2WindowProc( uMsg
                                   ,wParam
                                   ,lParam
                                  );
} // end of wxStaticText::OS2WindowProc


// for wxST_ELLIPSIZE_* support:

void wxStaticText::DoSetLabel(const wxString& str)
{
    wxString sLabel = ::wxPMTextToLabel(str);
    ::WinSetWindowText(GetHwnd(), sLabel.c_str());
}

wxString wxStaticText::DoGetLabel() const
{
    return wxGetWindowText(GetHwnd());
}

