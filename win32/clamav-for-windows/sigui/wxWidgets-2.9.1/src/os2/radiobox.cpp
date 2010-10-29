/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/radiobox.cpp
// Purpose:     wxRadioBox
// Author:      David Webster
// Modified by:
// Created:     10/12/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_RADIOBOX

#include "wx/radiobox.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/crt.h"
    #include "wx/string.h"
    #include "wx/bitmap.h"
    #include "wx/brush.h"
#endif

#include "wx/os2/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxRadioBox, wxControl)

// ---------------------------------------------------------------------------
// private functions
// ---------------------------------------------------------------------------

// wnd proc for radio buttons
MRESULT EXPENTRY wxRadioBtnWndProc( HWND hWnd
                                   ,UINT uMessage
                                   ,MPARAM wParam
                                   ,MPARAM lParam
                                  );
MRESULT EXPENTRY wxRadioBoxWndProc( HWND   hWnd
                                   ,UINT   uMessage
                                   ,MPARAM wParam
                                   ,MPARAM lParam
                                  );

// ---------------------------------------------------------------------------
// global vars
// ---------------------------------------------------------------------------

extern void  wxAssociateWinWithHandle( HWND         hWnd
                                      ,wxWindowOS2* pWin
                                     );
extern void wxRemoveHandleAssociation( wxWindowOS2 *pWin );
// the pointer to standard radio button & box wnd procs
static WXFARPROC                    fnWndProcRadioBtn = NULL;
static WXFARPROC                    fnWndProcRadioBox = NULL;

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// wxRadioBox
// ---------------------------------------------------------------------------

// Radio box item
wxRadioBox::wxRadioBox()
{
    m_nSelectedButton = -1;
    m_nNoItems = 0;
    m_ahRadioButtons = NULL;
    m_pnRadioWidth = NULL;
    m_pnRadioHeight = NULL;
} // end of wxRadioBox::wxRadioBox

wxRadioBox::~wxRadioBox()
{
    SendDestroyEvent();

    if (m_hWnd)
        wxRemoveHandleAssociation(this);
    if (m_ahRadioButtons)
    {
        for (unsigned int i = 0; i < m_nNoItems; i++)
        {
            wxWindow* pWin = wxFindWinFromHandle((WXHWND)m_ahRadioButtons[i]);
            wxRemoveHandleAssociation(pWin);

            ::WinDestroyWindow((HWND)m_ahRadioButtons[i]);
    }
        delete[] m_ahRadioButtons;
    }
    if (m_pnRadioWidth)
        delete[] m_pnRadioWidth;
    if (m_pnRadioHeight)
        delete[] m_pnRadioHeight;
} // end of wxRadioBox::~wxRadioBox

void wxRadioBox::Command ( wxCommandEvent& rEvent )
{
    SetSelection (rEvent.GetInt());
    ProcessCommand(rEvent);
} // end of wxRadioBox::Command

bool wxRadioBox::ContainsHWND( WXHWND hWnd ) const
{
    unsigned int nCount = GetCount();
    unsigned int i;

    for (i = 0; i < nCount; i++)
    {
        if (GetRadioButtons()[i] == hWnd)
            return true;
    }
    return false;
} // end of wxRadioBox::ContainsHWND

bool wxRadioBox::Create( wxWindow* pParent,
                         wxWindowID vId,
                         const wxString& rsTitle,
                         const wxPoint& rPos,
                         const wxSize& rSize,
                         const wxArrayString& asChoices,
                         int nMajorDim,
                         long lStyle,
                         const wxValidator& rVal,
                         const wxString& rsName )
{
    wxCArrayString chs(asChoices);

    return Create(pParent, vId, rsTitle, rPos, rSize, chs.GetCount(),
                  chs.GetStrings(), nMajorDim, lStyle, rVal, rsName);
}

bool wxRadioBox::Create( wxWindow* pParent,
                         wxWindowID vId,
                         const wxString& rsTitle,
                         const wxPoint& rPos,
                         const wxSize& rSize,
                         int nNum,
                         const wxString asChoices[],
                         int nMajorDim,
                         long lStyle,
                         const wxValidator& rVal,
                         const wxString& rsName )
{
    wxColour vColour(*wxBLACK);
    LONG     lColor;
    HWND     hWndParent = GetHwndOf(pParent);

    m_backgroundColour = pParent->GetBackgroundColour();
    m_nSelectedButton = -1;
    m_nNoItems = 0;

    //
    // Common initialization
    //
    if (!CreateControl( pParent
                       ,vId
                       ,rPos
                       ,rSize
                       ,lStyle
                       ,rVal
                       ,rsName
                      ))
        return false;
    if (!OS2CreateControl( wxT("STATIC")
                          ,SS_GROUPBOX
                          ,rPos
                          ,rSize
                          ,rsTitle
                         ))
        return false;

    wxAssociateWinWithHandle(m_hWnd, this);

    //
    // Now we can set m_nNoItems and let SetMajorDim set m_numCols/m_numRows
    //
    m_nNoItems = (unsigned int)nNum;
    SetMajorDim(nMajorDim == 0 ? nNum : nMajorDim, lStyle);

    m_ahRadioButtons = new WXHWND[nNum];
    m_pnRadioWidth   = new int[nNum];
    m_pnRadioHeight  = new int[nNum];

    for (int i = 0; i < nNum; i++)
    {
        m_pnRadioWidth[i] = m_pnRadioHeight[i] = -1;
        long                        lStyleBtn = BS_AUTORADIOBUTTON | WS_VISIBLE;
        int                         nNewId = NewControlId();

        if (i == 0)
            lStyleBtn |= WS_GROUP | WS_TABSTOP;

        wxString                    sLabel = ::wxPMTextToLabel(asChoices[i]);

        HWND                        hWndBtn = (WXHWND)::WinCreateWindow ( hWndParent,
                                                                          WC_BUTTON,
                                                                          sLabel.c_str(),
                                                                          lStyleBtn,
                                                                          0, 0, 0, 0,
                                                                          hWndParent,
                                                                          HWND_BOTTOM,
                                                                          (HMENU)nNewId,
                                                                          NULL,
                                                                          NULL
                                                                        );
        if (!hWndBtn)
        {
            return false;
        }
        lColor = (LONG)vColour.GetPixel();
        ::WinSetPresParam( hWndBtn
                          ,PP_FOREGROUNDCOLOR
                          ,sizeof(LONG)
                          ,(PVOID)&lColor
                         );

        lColor = (LONG)m_backgroundColour.GetPixel();
        ::WinSetPresParam( hWndBtn
                          ,PP_BACKGROUNDCOLOR
                          ,sizeof(LONG)
                          ,(PVOID)&lColor
                         );
        m_ahRadioButtons[i] = (WXHWND)hWndBtn;
        SubclassRadioButton((WXHWND)hWndBtn);
        wxAssociateWinWithHandle(hWndBtn, this);
        wxOS2SetFont( hWndBtn
                     ,*wxSMALL_FONT
                    );
        ::WinSetWindowULong(hWndBtn, QWL_USER, (ULONG)this);
        m_aSubControls.Add(nNewId);
    }

    //
    // Create a dummy control to end the group.
    //
    (void)::WinCreateWindow ( hWndParent,
                              WC_BUTTON,
                              "",
                              WS_GROUP,
                              0, 0, 0, 0,
                              hWndParent,
                              HWND_TOP,
                              (HMENU)NewControlId(),
                              NULL,
                              NULL
                            );
    fnWndProcRadioBox = (WXFARPROC)::WinSubclassWindow( GetHwnd()
                                                       ,(PFNWP)wxRadioBoxWndProc
                                                      );
    ::WinSetWindowULong(GetHwnd(), QWL_USER, (ULONG)this);
    lColor = (LONG)vColour.GetPixel();
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
    SetXComp(0);
    SetYComp(0);
    SetSelection(0);
    SetSize( rPos.x
            ,rPos.y
            ,rSize.x
            ,rSize.y
           );
    return true;
} // end of wxRadioBox::Create

wxSize wxRadioBox::DoGetBestSize() const
{
    return (GetTotalButtonSize(GetMaxButtonSize()));
} // end of wxRadioBox::DoGetBestSize

void wxRadioBox::DoSetSize(
  int                               nX
, int                               nY
, int                               nWidth
, int                               nHeight
, int                               nSizeFlags
)
{
    //
    // Input parameters assume wxWidgets coordinate system
    //
    int                             nCurrentX;
    int                             nCurrentY;
    int                             nWidthOld;
    int                             nHeightOld;
    int                             nXx = nX;
    int                             nYy = nY;
    int                             nXOffset = nXx;
    int                             nYOffset = nYy;
    int                             nCx1;
    int                             nCy1;
    wxSize                          vMaxSize = GetMaxButtonSize();
    int                             nMaxWidth;
    int                             nMaxHeight;
    wxSize                          vTotSize;
    int                             nTotWidth;
    int                             nTotHeight;
    int                             nStartX;
    int                             nStartY;
    wxFont                          vFont = GetFont();

    m_nSizeFlags = nSizeFlags;
    GetPosition( &nCurrentX
                ,&nCurrentY
               );
    GetSize( &nWidthOld
            ,&nHeightOld
           );

    if (nX == wxDefaultCoord && !(nSizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        nXx = nCurrentX;
    if (nY == wxDefaultCoord && !(nSizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        nYy = nCurrentY;
    if (nYy < 0)
        nYy = 0;
    if (nXx < 0)
        nXx = 0;

    wxGetCharSize( m_hWnd
                  ,&nCx1
                  ,&nCy1
                  ,&vFont
                 );

    //
    // Attempt to have a look coherent with other platforms: We compute the
    // biggest toggle dim, then we align all items according this value.
    //
    vMaxSize   = GetMaxButtonSize();
    nMaxWidth  = vMaxSize.x;
    nMaxHeight = vMaxSize.y;

    vTotSize   = GetTotalButtonSize(vMaxSize);
    nTotWidth  = vTotSize.x;
    nTotHeight = vTotSize.y;

    //
    // Only change our width/height if asked for
    //
    if (nWidth == -1)
    {
        if (nSizeFlags & wxSIZE_AUTO_WIDTH )
            nWidth = nTotWidth;
        else
            nWidth = nWidthOld;
    }

    if (nHeight == -1)
    {
        if (nSizeFlags & wxSIZE_AUTO_HEIGHT)
            nHeight = nTotHeight;
        else
            nHeight = nHeightOld;
    }

    //
    // Now convert to OS/2 coordinate system
    //
    wxWindowOS2*                    pParent = (wxWindowOS2*)GetParent();
    if (pParent)
        nYy = GetOS2ParentHeight(pParent) - nYy - nHeight;
    else
    {
        RECTL                       vRect;
        ::WinQueryWindowRect(HWND_DESKTOP, &vRect);
        nYy = vRect.yTop - nYy - nHeight;
    }
    nYOffset = nYy + nHeight;
    ::WinSetWindowPos( GetHwnd()
                      ,HWND_TOP
                      ,(LONG)nXx
                      ,(LONG)nYy
                      ,(LONG)nWidth
                      ,(LONG)nHeight
                      ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                     );

    //
    // Now position all the buttons: the current button will be put at
    // wxPoint(x_offset, y_offset) and the new row/column will start at
    // startX/startY. The size of all buttons will be the same wxSize(maxWidth,
    // maxHeight) except for the buttons in the last column which should extend
    // to the right border of radiobox and thus can be wider than this.
    //
    // Also, remember that wxRA_SPECIFY_COLS means that we arrange buttons in
    // left to right order and m_majorDim is the number of columns while
    // wxRA_SPECIFY_ROWS means that the buttons are arranged top to bottom and
    // m_majorDim is the number of rows.
    //
    nXOffset += nCx1;
    nYOffset -= (nMaxHeight + ((3*nCy1)/2));

    nStartX = nXOffset;
    nStartY = nYOffset;

    for (unsigned int i = 0; i < m_nNoItems; i++)
    {
        //
        // The last button in the row may be wider than the other ones as the
        // radiobox may be wider than the sum of the button widths (as it
        // happens, for example, when the radiobox label is very long)
        //
        bool bIsLastInTheRow;

        if (m_windowStyle & wxRA_SPECIFY_COLS)
        {
            //
            // Item is the last in its row if it is a multiple of the number of
            // columns or if it is just the last item
            //
            int                  n = i + 1;

            bIsLastInTheRow = ((n % GetMajorDim()) == 0) || (n == (int)m_nNoItems);
        }
        else // winRA_SPECIFY_ROWS
        {
            //
            // Item is the last in the row if it is in the last columns
            //
            bIsLastInTheRow = i >= (m_nNoItems/GetMajorDim()) * GetMajorDim();
        }

        //
        // Is this the start of new row/column?
        //
        if (i && (i % GetMajorDim() == 0))
        {
            if (m_windowStyle & wxRA_SPECIFY_ROWS)
            {
                //
                // Start of new column
                //
                nYOffset = nStartY;
                nXOffset += nMaxWidth + nCx1;
            }
            else // start of new row
            {
                nXOffset = nStartX;
                nYOffset -= nMaxHeight;
                if (m_pnRadioWidth[0] > 0L)
                    nYOffset -= nCy1/2;
            }
        }

        int                      nWidthBtn;

        if (bIsLastInTheRow)
        {
            //
            // Make the button go to the end of radio box
            //
            nWidthBtn = nStartX + nWidth - nXOffset - (2 * nCx1);
            if (nWidthBtn < nMaxWidth)
                nWidthBtn = nMaxWidth;
        }
        else
        {
            //
            // Normal button, always of the same size
            //
            nWidthBtn = nMaxWidth;
        }

        //
        // Make all buttons of the same, maximal size - like this they
        // cover the radiobox entirely and the radiobox tooltips are always
        // shown (otherwise they are not when the mouse pointer is in the
        // radiobox part not belonging to any radiobutton)
        //
        ::WinSetWindowPos( (HWND)m_ahRadioButtons[i]
                          ,HWND_BOTTOM
                          ,(LONG)nXOffset
                          ,(LONG)nYOffset
                          ,(LONG)nWidthBtn
                          ,(LONG)nMaxHeight
                          ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                         );
        //
        // Where do we put the next button?
        //
        if (m_windowStyle & wxRA_SPECIFY_ROWS)
        {
            //
            // Below this one
            //
            nYOffset -= nMaxHeight;
            if (m_pnRadioWidth[0] > 0)
                nYOffset -= nCy1/2;
        }
        else
        {
            //
            // To the right of this one
            //
            nXOffset += nWidthBtn + nCx1;
        }
    }
} // end of wxRadioBox::DoSetSize

bool wxRadioBox::Enable(unsigned int nItem, bool bEnable)
{
    wxCHECK_MSG( IsValid(nItem), false,
                 wxT("invalid item in wxRadioBox::Enable()") );

    ::WinEnableWindow((HWND) m_ahRadioButtons[nItem], bEnable);
    return true;
} // end of wxRadioBox::Enable

bool wxRadioBox::Enable(bool bEnable)
{
    if ( !wxControl::Enable(bEnable) )
        return false;
    for (unsigned int i = 0; i < m_nNoItems; i++)
        ::WinEnableWindow((HWND)m_ahRadioButtons[i], bEnable);
    return true;
} // end of wxRadioBox::Enable

unsigned int wxRadioBox::GetCount() const
{
    return m_nNoItems;
} // end of wxRadioBox::GetCount

wxString wxRadioBox::GetLabel(int nItem) const
{
    wxCHECK_MSG( IsValid(nItem), wxEmptyString, wxT("invalid radiobox index") );

    return wxGetWindowText(m_ahRadioButtons[nItem]);
} // end of wxRadioBox::GetLabel

wxSize wxRadioBox::GetMaxButtonSize() const
{
    int nWidthMax = 0;
    int nHeightMax = 0;

    for (unsigned int i = 0 ; i < m_nNoItems; i++)
    {
        int nWidth;
        int nHeight;

        if (m_pnRadioWidth[i] < 0L)
        {
            GetTextExtent( wxGetWindowText(m_ahRadioButtons[i])
                          ,&nWidth
                          ,&nHeight
                         );

            //
            // Adjust the size to take into account the radio box itself
            // FIXME this is totally bogus!
            //
            nWidth  += RADIO_SIZE;
            nHeight *= 3;
            nHeight /= 2;
        }
        else
        {
            nWidth  = m_pnRadioWidth[i];
            nHeight = m_pnRadioHeight[i];
        }
        if (nWidthMax < nWidth )
            nWidthMax = nWidth;
        if (nHeightMax < nHeight )
            nHeightMax = nHeight;
    }
    wxSize maxsize( nWidthMax, nHeightMax);
    return maxsize;
} // end of wxRadioBox::GetMaxButtonSize

// Get single selection, for single choice list items
int wxRadioBox::GetSelection() const
{
    return m_nSelectedButton;
} // end of wxRadioBox::GetSelection

void wxRadioBox::GetSize( int* pnWidth, int* pnHeight ) const
{
    RECT vRect;

    vRect.xLeft   = -1;
    vRect.xRight  = -1;
    vRect.yTop    = -1;
    vRect.yBottom = -1;

    if (m_hWnd)
        wxFindMaxSize( m_hWnd, &vRect );

    for (unsigned int i = 0; i < m_nNoItems; i++)
        wxFindMaxSize( m_ahRadioButtons[i], &vRect );

    if (pnWidth)
        *pnWidth  = vRect.xRight - vRect.xLeft;
    if (pnHeight)
        *pnHeight = vRect.yTop - vRect.yBottom;
} // end of wxRadioBox::GetSize

// Find string for position
wxString wxRadioBox::GetString(unsigned int nNum) const
{
    wxCHECK_MSG( IsValid(nNum), wxEmptyString, wxT("invalid radiobox index") );
    return wxGetWindowText(m_ahRadioButtons[nNum]);
} // end of wxRadioBox::GetString

// For single selection items only
wxString wxRadioBox::GetStringSelection() const
{
    wxString sResult;
    int nSel = GetSelection();

    if (nSel != wxNOT_FOUND)
        sResult = GetString(nSel);

    return sResult;
} // end of wxRadioBox::GetStringSelection

wxSize wxRadioBox::GetTotalButtonSize( const wxSize& rSizeBtn ) const
{
    int    nCx1;
    int    nCy1;
    int    nHeight;
    int    nWidth;
    int    nWidthLabel = 0;

    nCx1 = GetCharWidth();
    nCy1 = GetCharHeight();
    nHeight = GetRowCount() * rSizeBtn.y + (2 * nCy1);
    nWidth  = GetColumnCount() * (rSizeBtn.x + nCx1) + nCx1;

    //
    // And also wide enough for its label
    //
    wxString sStr = wxGetWindowText(GetHwnd());
    if (!sStr.empty())
    {
        GetTextExtent( sStr
                      ,&nWidthLabel
                      ,NULL
                     );
        nWidthLabel += 2*nCx1;
    }
    if (nWidthLabel > nWidth)
        nWidth = nWidthLabel;

    wxSize total( nWidth, nHeight );
    return total;
} // end of wxRadioBox::GetTotalButtonSize

WXHBRUSH wxRadioBox::OnCtlColor( WXHDC    hwinDC,
                                 WXHWND   WXUNUSED(hWnd),
                                 WXUINT   WXUNUSED(uCtlColor),
                                 WXUINT   WXUNUSED(uMessage),
                                 WXWPARAM WXUNUSED(wParam),
                                 WXLPARAM WXUNUSED(lParam) )
{
    HPS hPS = (HPS)hwinDC; // pass in a PS handle in OS/2

    if (GetParent()->GetTransparentBackground())
        ::GpiSetBackMix(hPS, BM_LEAVEALONE);
    else
        ::GpiSetBackMix(hPS, BM_OVERPAINT);

    wxColour vColBack = GetBackgroundColour();

    ::GpiSetBackColor(hPS, vColBack.GetPixel());
    ::GpiSetColor(hPS, vColBack.GetPixel());

    wxBrush* pBrush = wxTheBrushList->FindOrCreateBrush( vColBack, wxSOLID );
    return ((WXHBRUSH)pBrush->GetResourceHandle());
} // end of wxRadioBox::OnCtlColor

bool wxRadioBox::OS2Command( WXUINT uCmd,
                             WXWORD wId)
{
    int nSelectedButton = -1;

    if (uCmd == BN_CLICKED)
    {
        if (wId == GetId())
            return true;

        for (unsigned int i = 0; i < m_nNoItems; i++)
        {
            if (wId == wxGetWindowId(m_ahRadioButtons[i]))
            {
                nSelectedButton = i;
                break;
            }
        }
        if (nSelectedButton == -1)
        {
            //
            // Just ignore it
            //
            return false;
        }
        if (nSelectedButton != m_nSelectedButton)
        {
            m_nSelectedButton = nSelectedButton;
            SendNotificationEvent();
        }
        return true;
    }
    else
        return false;
} // end of wxRadioBox::OS2Command

void wxRadioBox::SendNotificationEvent()
{
    wxCommandEvent vEvent(
                       wxEVT_COMMAND_RADIOBOX_SELECTED,
                       m_windowId
                   );

    vEvent.SetInt( m_nSelectedButton );
    vEvent.SetString( GetString(m_nSelectedButton) );
    vEvent.SetEventObject(this);
    ProcessCommand(vEvent);
} // end of wxRadioBox::SendNotificationEvent

void wxRadioBox::SetFocus()
{
    if (m_nNoItems > 0)
    {
        if (m_nSelectedButton == -1)
            ::WinSetFocus(HWND_DESKTOP, (HWND)m_ahRadioButtons[0]);
        else
            ::WinSetFocus(HWND_DESKTOP, (HWND)m_ahRadioButtons[m_nSelectedButton]);
    }
} // end of wxRadioBox::SetFocus

bool wxRadioBox::SetFont(const wxFont& rFont)
{
    if (!wxControl::SetFont(rFont))
    {
        //
        // Nothing to do
        //
        return false;
    }
    //
    // Also set the font of our radio buttons
    //
    for (unsigned int n = 0; n < m_nNoItems; n++)
    {
        HWND hWndBtn = (HWND)m_ahRadioButtons[n];

        wxOS2SetFont( hWndBtn, rFont );
        ::WinInvalidateRect(hWndBtn, NULL, FALSE);
    }
    return true;
} // end of wxRadioBox::SetFont

void wxRadioBox::SetSelection(
  int                               nNum
)
{
    wxCHECK_RET( IsValid(nNum), wxT("invalid radiobox index") );

    if ( IsValid(m_nSelectedButton) )
        ::WinSendMsg((HWND)m_ahRadioButtons[m_nSelectedButton], BM_SETCHECK, (MPARAM)0, (MPARAM)0);

    ::WinSendMsg((HWND)m_ahRadioButtons[nNum], BM_SETCHECK, (MPARAM)1, (MPARAM)0);
    ::WinSetFocus(HWND_DESKTOP, (HWND)m_ahRadioButtons[nNum]);
    m_nSelectedButton = nNum;
} // end of wxRadioBox::SetSelection

void wxRadioBox::SetString(unsigned int nItem, const wxString& rsLabel)
{
    wxCHECK_RET( IsValid(nItem), wxT("invalid radiobox index") );

    m_pnRadioWidth[nItem] = m_pnRadioHeight[nItem] = -1;
    ::WinSetWindowText((HWND)m_ahRadioButtons[nItem], rsLabel.c_str());
} // end of wxRadioBox::SetString

bool wxRadioBox::SetStringSelection(const wxString& rsStr)
{
    int nSel = FindString(rsStr);

    if (nSel > -1)
    {
        SetSelection(nSel);
        return true;
    }
    else
        return false;
} // end of wxRadioBox::SetStringSelection

bool wxRadioBox::Show(bool bShow)
{
    if (!wxControl::Show(bShow))
        return false;

    for (unsigned int i = 0; i < m_nNoItems; i++)
    {
        ::WinShowWindow((HWND)m_ahRadioButtons[i], (BOOL)bShow);
    }
    return true;
} // end of wxRadioBox::Show

// Show a specific button
bool wxRadioBox::Show(unsigned int nItem, bool bShow)
{
    wxCHECK_MSG( IsValid(nItem), false,
                 wxT("invalid item in wxRadioBox::Show()") );

    ::WinShowWindow((HWND)m_ahRadioButtons[nItem], bShow);

    return true;
} // end of wxRadioBox::Show

void wxRadioBox::SubclassRadioButton(
  WXHWND                            hWndBtn
)
{
    fnWndProcRadioBtn = (WXFARPROC)::WinSubclassWindow(hWndBtn, (PFNWP)wxRadioBtnWndProc);
} // end of wxRadioBox::SubclassRadioButton

MRESULT wxRadioBox::WindowProc(
  WXUINT                            uMsg
, WXWPARAM                          wParam
, WXLPARAM                          lParam
)
{
    return (wxControl::OS2WindowProc( uMsg
                                     ,wParam
                                     ,lParam
                                    ));
} // end of wxRadioBox::WindowProc

// ---------------------------------------------------------------------------
// window proc for radio buttons
// ---------------------------------------------------------------------------

MRESULT wxRadioBtnWndProc(
  HWND                              hWnd
, UINT                              uMessage
, MPARAM                            wParam
, MPARAM                            lParam
)
{
    switch (uMessage)
    {
        case WM_CHAR:
            {
                USHORT                  uKeyFlags = SHORT1FROMMP((MPARAM)wParam);

                if (!(uKeyFlags & KC_KEYUP)) // Key Down event
                {
                    if (uKeyFlags & KC_VIRTUALKEY)
                    {
                        wxRadioBox*             pRadiobox = (wxRadioBox *)::WinQueryWindowULong( hWnd
                                                                                                ,QWL_USER
                                                                                               );
                        USHORT                  uVk = SHORT2FROMMP((MPARAM)lParam);
                        bool                    bProcessed = true;
                        wxDirection             eDir;

                        switch(uVk)
                        {
                            case VK_LEFT:
                                eDir = wxLEFT;
                                break;

                            case VK_RIGHT:
                                eDir = wxRIGHT;
                                break;

                            case VK_DOWN:
                                eDir = wxDOWN;
                                break;

                            case VK_UP:
                                eDir = wxUP;
                                break;

                            default:
                                bProcessed = false;

                                //
                                // Just to suppress the compiler warning
                                //
                                eDir = wxALL;
                        }

                        if (bProcessed)
                        {
                            int             nSelOld = pRadiobox->GetSelection();
                            int             nSelNew = pRadiobox->GetNextItem( nSelOld
                                                                             ,eDir
                                                                             ,pRadiobox->GetWindowStyleFlag()
                                                                            );

                            if (nSelNew != nSelOld)
                            {
                                pRadiobox->SetSelection(nSelNew);

                                //
                                // Emulate the button click
                                //
                                pRadiobox->SendNotificationEvent();
                                return 0;
                            }
                        }
                    }
                }
            }
            break;
    }

    return fnWndProcRadioBtn( hWnd
                             ,(ULONG)uMessage
                             ,(MPARAM)wParam
                             ,(MPARAM)lParam
                            );
} // end of wxRadioBtnWndProc

MRESULT EXPENTRY wxRadioBoxWndProc( HWND hWnd,
                                    UINT uMessage,
                                    MPARAM wParam,
                                    MPARAM lParam )
{
    return (fnWndProcRadioBox( hWnd,
                               (ULONG)uMessage,
                               (MPARAM)wParam,
                               (MPARAM)lParam )
           );
} // end of wxRadioBoxWndProc

#endif // wxUSE_RADIOBOX
