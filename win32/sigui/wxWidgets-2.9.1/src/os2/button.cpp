/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/button.cpp
// Purpose:     wxButton
// Author:      David Webster
// Modified by:
// Created:     10/13/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/button.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/brush.h"
    #include "wx/panel.h"
    #include "wx/bmpbuttn.h"
    #include "wx/settings.h"
    #include "wx/dcscreen.h"
    #include "wx/scrolwin.h"
    #include "wx/toplevel.h"
#endif

#include "wx/stockitem.h"
#include "wx/os2/private.h"

#define BUTTON_HEIGHT_FROM_CHAR_HEIGHT(cy) (11*EDIT_HEIGHT_FROM_CHAR_HEIGHT(cy)/10)

//
// Should be at the very least less than winDEFAULT_BUTTON_MARGIN
//
#define FOCUS_MARGIN 3

#ifndef BST_CHECKED
#define BST_CHECKED 0x0001
#endif

IMPLEMENT_DYNAMIC_CLASS(wxButton, wxControl)

// Button

bool wxButton::Create( wxWindow*          pParent,
                       wxWindowID         vId,
                       const wxString&    rsLbl,
                       const wxPoint&     rPos,
                       const wxSize&      rSize,
                       long               lStyle,
                       const wxValidator& rValidator,
                       const wxString&    rsName)
{
    wxString rsLabel(rsLbl);
    if (rsLabel.empty() && wxIsStockID(vId))
        rsLabel = wxGetStockLabel(vId);

    wxString                        sLabel = ::wxPMTextToLabel(rsLabel);

    SetName(rsName);
#if wxUSE_VALIDATORS
    SetValidator(rValidator);
#endif
    m_windowStyle = lStyle;
    pParent->AddChild((wxButton *)this);
    if (vId == -1)
        m_windowId = NewControlId();
    else
        m_windowId = vId;
    lStyle = WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON;

    //
    // OS/2 PM does not have Right/Left/Top/Bottom styles.
    // We will have to define an additional style when we implement notebooks
    // for a notebook page button
    //
    if (m_windowStyle & wxCLIP_SIBLINGS )
        lStyle |= WS_CLIPSIBLINGS;

    m_hWnd = (WXHWND)::WinCreateWindow( GetHwndOf(pParent)   // Parent handle
                                       ,WC_BUTTON            // A Button class window
                                       ,sLabel.c_str()  // Button text
                                       ,lStyle               // Button style
                                       ,0, 0, 0, 0           // Location and size
                                       ,GetHwndOf(pParent)   // Owner handle
                                       ,HWND_TOP             // Top of Z-Order
                                       ,vId                  // Identifier
                                       ,NULL                 // No control data
                                       ,NULL                 // No Presentation parameters
                                      );
    if (m_hWnd == 0)
    {
        return false;
    }

    //
    // Subclass again for purposes of dialog editing mode
    //
    SubclassWin(m_hWnd);
    wxFont*                          pButtonFont = new wxFont( 8
                                                              ,wxSWISS
                                                              ,wxNORMAL
                                                              ,wxNORMAL
                                                             );
    SetFont(*pButtonFont);
    SetXComp(0);
    SetYComp(0);
    SetSize( rPos.x
            ,rPos.y
            ,rSize.x
            ,rSize.y
           );
    delete pButtonFont;
    return true;
} // end of wxButton::Create

wxButton::~wxButton()
{
    wxTopLevelWindow *tlw = wxDynamicCast(wxGetTopLevelParent(this), wxTopLevelWindow);

    if (tlw)
    {
        if (tlw->GetDefaultItem() == this)
        {
            //
            // Don't leave the panel with invalid default item
            //
            tlw->SetDefaultItem(NULL);
        }
    }
} // end of wxButton::~wxButton

// ----------------------------------------------------------------------------
// size management including autosizing
// ----------------------------------------------------------------------------

wxSize wxButton::DoGetBestSize() const
{
    wxString                        rsLabel = wxGetWindowText(GetHWND());
    int                             nWidthButton;
    int                             nWidthChar;
    int                             nHeightChar;
    wxFont                          vFont = (wxFont)GetFont();

    GetTextExtent( rsLabel
                  ,&nWidthButton
                  ,NULL
                 );

    wxGetCharSize( GetHWND()
                  ,&nWidthChar
                  ,&nHeightChar
                  ,&vFont
                 );

    //
    // Add a margin - the button is wider than just its label
    //
    nWidthButton += 3 * nWidthChar;

    //
    // The button height is proportional to the height of the font used
    //
    int                             nHeightButton = BUTTON_HEIGHT_FROM_CHAR_HEIGHT(nHeightChar);

    //
    // Need a little extra to make it look right
    //
    nHeightButton += (int)(nHeightChar/1.5);

    if (!HasFlag(wxBU_EXACTFIT))
    {
        wxSize                      vSize = GetDefaultSize();

        if (nWidthButton > vSize.x)
            vSize.x = nWidthButton;
        if (nHeightButton > vSize.y)
            vSize.y = nHeightButton;
        return vSize;
    }
    return wxSize( nWidthButton
                  ,nHeightButton
                 );
} // end of wxButton::DoGetBestSize

/* static */
wxSize wxButton::GetDefaultSize()
{
    static wxSize                   vSizeBtn;

    if (vSizeBtn.x == 0)
    {
        wxScreenDC                  vDc;

        vDc.SetFont(wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT));

        //
        // The size of a standard button in the dialog units is 50x14,
        // translate this to pixels
        // NB1: the multipliers come from the Windows convention
        // NB2: the extra +1/+2 were needed to get the size be the same as the
        //      size of the buttons in the standard dialog - I don't know how
        //      this happens, but on my system this size is 75x23 in pixels and
        //      23*8 isn't even divisible by 14... Would be nice to understand
        //      why these constants are needed though!
        vSizeBtn.x = (50 * (vDc.GetCharWidth() + 1))/4;
        vSizeBtn.y = ((14 * vDc.GetCharHeight()) + 2)/8;
    }
    return vSizeBtn;
} // end of wxButton::GetDefaultSize

void wxButton::Command (
  wxCommandEvent&                   rEvent
)
{
    ProcessCommand (rEvent);
} // end of wxButton::Command

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

bool wxButton::SendClickEvent()
{
    wxCommandEvent                  vEvent( wxEVT_COMMAND_BUTTON_CLICKED
                                           ,GetId()
                                          );

    vEvent.SetEventObject(this);
    return ProcessCommand(vEvent);
} // end of wxButton::SendClickEvent

wxWindow *wxButton::SetDefault()
{
    //
    // Set this one as the default button both for wxWidgets and Windows
    //
    wxWindow* pWinOldDefault = wxButtonBase::SetDefault();

    SetDefaultStyle( wxDynamicCast(pWinOldDefault, wxButton), false);
    SetDefaultStyle( this, true );

    return pWinOldDefault;
} // end of wxButton::SetDefault

void wxButton::SetTmpDefault()
{
    wxTopLevelWindow *tlw = wxDynamicCast(wxGetTopLevelParent(this), wxTopLevelWindow);

    wxCHECK_RET( tlw, wxT("button without top level window?") );

    wxWindow*                       pWinOldDefault = tlw->GetDefaultItem();

    tlw->SetTmpDefaultItem(this);
    SetDefaultStyle( wxDynamicCast(pWinOldDefault, wxButton), false);
    SetDefaultStyle( this, true );
} // end of wxButton::SetTmpDefault

void wxButton::UnsetTmpDefault()
{
    wxTopLevelWindow *tlw = wxDynamicCast(wxGetTopLevelParent(this), wxTopLevelWindow);

    wxCHECK_RET( tlw, wxT("button without top level window?") );

    tlw->SetTmpDefaultItem(NULL);

    wxWindow*                       pWinOldDefault = tlw->GetDefaultItem();

    SetDefaultStyle( this, false );
    SetDefaultStyle( wxDynamicCast(pWinOldDefault, wxButton), true );
} // end of wxButton::UnsetTmpDefault

void wxButton::SetDefaultStyle(
  wxButton*                         pBtn
, bool                              bOn
)
{
    long                            lStyle;
    //
    // We may be called with NULL pointer -- simpler to do the check here than
    // in the caller which does wxDynamicCast()
    //
    if (!pBtn)
        return;

    //
    // First, let DefDlgProc() know about the new default button
    //
    if (bOn)
    {
        if (!wxTheApp->IsActive())
            return;

        //
        // In OS/2 the dialog/panel doesn't really know it has a default
        // button, the default button simply has that style.  We'll just
        // simulate by setting focus to it
        //
        pBtn->SetFocus();
    }
    lStyle = ::WinQueryWindowULong(GetHwndOf(pBtn), QWL_STYLE);
    if (!(lStyle & BS_DEFAULT) == bOn)
    {
        if ((lStyle & BS_USERBUTTON) != BS_USERBUTTON)
        {
            if (bOn)
                lStyle |= BS_DEFAULT;
            else
                lStyle &= ~BS_DEFAULT;
            ::WinSetWindowULong(GetHwndOf(pBtn), QWL_STYLE, lStyle);
        }
        else
        {
            //
            // Redraw the button - it will notice itself that it's not the
            // default one any longer
            //
            pBtn->Refresh();
        }
    }
} // end of wxButton::UpdateDefaultStyle

// ----------------------------------------------------------------------------
// event/message handlers
// ----------------------------------------------------------------------------

bool wxButton::OS2Command(WXUINT uParam, WXWORD WXUNUSED(wId))
{
    bool bProcessed = false;

    switch (uParam)
    {
        case BN_CLICKED:            // normal buttons send this
        case BN_DBLCLICKED:         // owner-drawn ones also send this
            bProcessed = SendClickEvent();
            break;
    }

    return bProcessed;
} // end of wxButton::OS2Command

WXHBRUSH wxButton::OnCtlColor( WXHDC    WXUNUSED(pDC),
                               WXHWND   WXUNUSED(pWnd),
                               WXUINT   WXUNUSED(nCtlColor),
                               WXUINT   WXUNUSED(uMessage),
                               WXWPARAM WXUNUSED(wParam),
                               WXLPARAM WXUNUSED(lParam) )
{
    wxBrush* pBackgroundBrush = wxTheBrushList->FindOrCreateBrush( GetBackgroundColour()
                                                                  ,wxSOLID
                                                                  );

    return (WXHBRUSH)pBackgroundBrush->GetResourceHandle();
} // end of wxButton::OnCtlColor

void wxButton::MakeOwnerDrawn()
{
    long                            lStyle = 0L;

    lStyle = ::WinQueryWindowULong(GetHwnd(), QWL_STYLE);
    if ((lStyle & BS_USERBUTTON) != BS_USERBUTTON)
    {
        //
        // Make it so
        //
        lStyle |= BS_USERBUTTON;
        ::WinSetWindowULong(GetHwnd(), QWL_STYLE, lStyle);
    }
} // end of wxButton::MakeOwnerDrawn

WXDWORD wxButton::OS2GetStyle(
  long                              lStyle
, WXDWORD*                          pdwExstyle
) const
{
    //
    // Buttons never have an external border, they draw their own one
    //
    WXDWORD                         dwStyle = wxControl::OS2GetStyle( (lStyle & ~wxBORDER_MASK) | wxBORDER_NONE
                                                                     ,pdwExstyle
                                                                    );

    //
    // We must use WS_CLIPSIBLINGS with the buttons or they would draw over
    // each other in any resizeable dialog which has more than one button in
    // the bottom
    //
    dwStyle |= WS_CLIPSIBLINGS;
    return dwStyle;
} // end of wxButton::OS2GetStyle

MRESULT wxButton::WindowProc( WXUINT   uMsg,
                              WXWPARAM wParam,
                              WXLPARAM lParam )
{
    //
    // When we receive focus, we want to temporary become the default button in
    // our parent panel so that pressing "Enter" would activate us -- and when
    // losing it we should restore the previous default button as well
    //
    if (uMsg == WM_SETFOCUS)
    {
        if (SHORT1FROMMP(lParam) == TRUE)
            SetTmpDefault();
        else
            UnsetTmpDefault();

        //
        // Let the default processign take place too
        //
    }

    else if (uMsg == WM_BUTTON1DBLCLK)
    {
        //
        // Emulate a click event to force an owner-drawn button to change its
        // appearance - without this, it won't do it
        //
        (void)wxControl::OS2WindowProc( WM_BUTTON1DOWN
                                       ,wParam
                                       ,lParam
                                      );

        //
        // And conitnue with processing the message normally as well
        //
    }

    //
    // Let the base class do all real processing
    //
    return (wxControl::OS2WindowProc( uMsg
                                     ,wParam
                                     ,lParam
                                    ));
} // end of wxWindowProc
