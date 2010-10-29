/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/textctrl.cpp
// Purpose:     wxTextCtrl
// Author:      David Webster
// Modified by:
// Created:     10/17/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/textctrl.h"

#ifndef WX_PRECOMP
    #include "wx/scrolwin.h"
    #include "wx/settings.h"
    #include "wx/brush.h"
    #include "wx/utils.h"
    #include "wx/log.h"
    #include "wx/app.h"
#endif

#if wxUSE_CLIPBOARD
    #include "wx/clipbrd.h"
#endif

#include "wx/textfile.h"

#include "wx/os2/private.h"

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#if wxUSE_IOSTREAMH
#   include <fstream.h>
#else
#   include <fstream>
#endif

#if !defined(MLE_INDEX)
#define MLE_INDEX  0
#define MLE_RGB    1
#endif


// ----------------------------------------------------------------------------
// event tables and other macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxTextCtrl, wxTextCtrlBase)

BEGIN_EVENT_TABLE(wxTextCtrl, wxTextCtrlBase)
    EVT_CHAR(wxTextCtrl::OnChar)
    EVT_DROP_FILES(wxTextCtrl::OnDropFiles)

    EVT_MENU(wxID_CUT, wxTextCtrl::OnCut)
    EVT_MENU(wxID_COPY, wxTextCtrl::OnCopy)
    EVT_MENU(wxID_PASTE, wxTextCtrl::OnPaste)
    EVT_MENU(wxID_UNDO, wxTextCtrl::OnUndo)
    EVT_MENU(wxID_REDO, wxTextCtrl::OnRedo)

    EVT_UPDATE_UI(wxID_CUT, wxTextCtrl::OnUpdateCut)
    EVT_UPDATE_UI(wxID_COPY, wxTextCtrl::OnUpdateCopy)
    EVT_UPDATE_UI(wxID_PASTE, wxTextCtrl::OnUpdatePaste)
    EVT_UPDATE_UI(wxID_UNDO, wxTextCtrl::OnUpdateUndo)
    EVT_UPDATE_UI(wxID_REDO, wxTextCtrl::OnUpdateRedo)
END_EVENT_TABLE()


// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// creation
// ----------------------------------------------------------------------------

wxTextCtrl::wxTextCtrl()
{
}

wxTextCtrl::~wxTextCtrl()
{
}

bool wxTextCtrl::Create(
  wxWindow*                         pParent
, wxWindowID                        vId
, const wxString&                   rsValue
, const wxPoint&                    rPos
, const wxSize&                     rSize
, long                              lStyle
, const wxValidator&                rValidator
, const wxString&                   rsName
)
{
    //
    // Base initialization
    //
    if ( !CreateBase( pParent
                     ,vId
                     ,rPos
                     ,rSize
                     ,lStyle
                     ,rValidator
                     ,rsName
                    ))
        return false;

    wxPoint                         vPos = rPos; // The OS/2 position
    SWP                             vSwp;

    if (pParent )
    {
        pParent->AddChild(this);
    }

    m_windowStyle = lStyle;
    m_bIsMLE = false;
    m_bSkipUpdate = false;

    long                            lSstyle = WS_VISIBLE | WS_TABSTOP;

    //
    // Single and multiline edit fields are two different controls in PM
    //
    if ( m_windowStyle & wxTE_MULTILINE )
    {
        lSstyle |= MLS_BORDER | MLS_WORDWRAP;
        m_bIsMLE = true;

        if ((m_windowStyle & wxTE_NO_VSCROLL) == 0)
            lSstyle |= MLS_VSCROLL;
        if (m_windowStyle & wxHSCROLL)
            lSstyle |= MLS_HSCROLL;
        if (m_windowStyle & wxTE_READONLY)
            lSstyle |= MLS_READONLY;
    }
    else
    {
        lSstyle |= ES_LEFT | ES_AUTOSCROLL | ES_MARGIN;

        if (m_windowStyle & wxHSCROLL)
            lSstyle |=  ES_AUTOSCROLL;
        if (m_windowStyle & wxTE_READONLY)
            lSstyle |= ES_READONLY;
        if (m_windowStyle & wxTE_PASSWORD) // hidden input
            lSstyle |= ES_UNREADABLE;
    }

    if (m_bIsMLE)
    {
        m_hWnd = (WXHWND)::WinCreateWindow( (HWND)GetHwndOf(pParent) // Parent window handle
                                           ,WC_MLE                   // Window class
                                           ,rsValue.c_str()     // Initial Text
                                           ,(ULONG)lSstyle           // Style flags
                                           ,(LONG)0                  // X pos of origin
                                           ,(LONG)0                  // Y pos of origin
                                           ,(LONG)0                  // field width
                                           ,(LONG)0                  // field height
                                           ,(HWND)GetHwndOf(pParent) // owner window handle (same as parent
                                           ,HWND_TOP                 // initial z position
                                           ,(ULONG)vId               // Window identifier
                                           ,NULL                     // no control data
                                           ,NULL                     // no Presentation parameters
                                          );
    }
    else
    {
        m_hWnd = (WXHWND)::WinCreateWindow( (HWND)GetHwndOf(pParent) // Parent window handle
                                           ,WC_ENTRYFIELD            // Window class
                                           ,rsValue.c_str()     // Initial Text
                                           ,(ULONG)lSstyle           // Style flags
                                           ,(LONG)0                  // X pos of origin
                                           ,(LONG)0                  // Y pos of origin
                                           ,(LONG)0                  // field width
                                           ,(LONG)0                  // field height
                                           ,(HWND)GetHwndOf(pParent) // owner window handle (same as parent
                                           ,HWND_TOP                 // initial z position
                                           ,(ULONG)vId               // Window identifier
                                           ,NULL                     // no control data
                                           ,NULL                     // no Presentation parameters
                                          );
    }

    if (m_hWnd == 0)
    {
        return false;
    }

    SubclassWin(GetHWND());

    //
    // Set font, position, size and initial value
    //
    wxFont*                          pTextFont = new wxFont( 8
                                                            ,wxMODERN
                                                            ,wxNORMAL
                                                            ,wxNORMAL
                                                           );
    SetFont(*pTextFont);
    if (!rsValue.empty())
    {
        SetValue(rsValue);
    }
    SetupColours();
    //
    // If X and/or Y are not zero the difference is the compensation value
    // for margins for OS/2 controls.
    //
    ::WinQueryWindowPos(m_hWnd, &vSwp);
    SetXComp(vSwp.x);
    SetYComp(vSwp.y);
    SetSize( vPos.x - GetXComp()
            ,vPos.y - GetYComp()
            ,rSize.x
            ,rSize.y
           );
    delete pTextFont;
    return true;
} // end of wxTextCtrl::Create

//
// Make sure the window style (etc.) reflects the HWND style (roughly)
//
void wxTextCtrl::AdoptAttributesFromHWND()
{
    HWND                            hWnd = GetHwnd();
    LONG                            lStyle = ::WinQueryWindowULong(hWnd, QWL_STYLE);

    wxWindow::AdoptAttributesFromHWND();

    if (m_bIsMLE)
    {
        m_windowStyle |= wxTE_MULTILINE;
        if (lStyle & MLS_READONLY)
            m_windowStyle |= wxTE_READONLY;
    }
    else
    {
        if (lStyle & ES_UNREADABLE)
            m_windowStyle |= wxTE_PASSWORD;
        if (lStyle & ES_READONLY)
            m_windowStyle |= wxTE_READONLY;
    }
} // end of wxTextCtrl::AdoptAttributesFromHWND

WXDWORD wxTextCtrl::OS2GetStyle(
  long                              lStyle
, WXDWORD*                          pdwExstyle
) const
{
    //
    // Default border for the text controls is the sunken one
    //
    if ((lStyle & wxBORDER_MASK) == wxBORDER_DEFAULT )
    {
        lStyle |= wxBORDER_SUNKEN;
    }

    long                            dwStyle = wxControl::OS2GetStyle( lStyle
                                                                     ,pdwExstyle
                                                                    );

    dwStyle = WS_VISIBLE | WS_TABSTOP;

    //
    // Single and multiline edit fields are two different controls in PM
    //
    if ( m_windowStyle & wxTE_MULTILINE )
    {
        dwStyle |= MLS_BORDER | MLS_WORDWRAP;
        if ((m_windowStyle & wxTE_NO_VSCROLL) == 0)
            dwStyle |= MLS_VSCROLL;
        if (m_windowStyle & wxHSCROLL)
            dwStyle |= MLS_HSCROLL;
        if (m_windowStyle & wxTE_READONLY)
            dwStyle |= MLS_READONLY;
    }
    else
    {
        dwStyle |= ES_LEFT | ES_AUTOSCROLL | ES_MARGIN;
        if (m_windowStyle & wxHSCROLL)
            dwStyle |=  ES_AUTOSCROLL;
        if (m_windowStyle & wxTE_READONLY)
            dwStyle |= ES_READONLY;
        if (m_windowStyle & wxTE_PASSWORD) // hidden input
            dwStyle |= ES_UNREADABLE;
    }
    return dwStyle;
} // end of wxTextCtrl::OS2GetStyle

void wxTextCtrl::SetWindowStyleFlag(
  long                              lStyle
)
{
    wxControl::SetWindowStyleFlag(lStyle);
} // end of wxTextCtrl::SetWindowStyleFlag

void wxTextCtrl::SetupColours()
{
    wxColour                        vBkgndColour;

    vBkgndColour = wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW);
    SetBackgroundColour(vBkgndColour);
    SetForegroundColour(GetParent()->GetForegroundColour());
    if (m_bIsMLE)
    {
        ::WinSendMsg( GetHwnd()
                     ,MLM_SETTEXTCOLOR
                     ,(MPARAM)GetParent()->GetForegroundColour().GetPixel()
                     ,(MPARAM)MLE_RGB
                    );
    }
} // end of wxTextCtrl::SetupColours

// ----------------------------------------------------------------------------
// set/get the controls text
// ----------------------------------------------------------------------------

wxString wxTextCtrl::GetValue() const
{
    wxString                        sStr = wxGetWindowText(GetHWND());
    wxCharBuffer                    buf(sStr.char_str());
    char*                           zStr = buf.data();

    for ( ; *zStr; zStr++ )
    {
        //
        // this will replace \r\n with just \n
        //
        if (*zStr == '\n')
            *zStr = '\0';
        if (*zStr == '\r')
            *zStr = '\n';
    }
    return zStr;
} // end of wxTextCtrl::GetValue

void wxTextCtrl::DoSetValue(
  const wxString&                   rsValue,
  int flags
)
{
    //
    // If the text is long enough, it's faster to just set it instead of first
    // comparing it with the old one (chances are that it will be different
    // anyhow, this comparison is there to avoid flicker for small single-line
    // edit controls mostly)
    //
    if ((rsValue.length() > 0x400) || (rsValue != GetValue()))
    {
        if ( flags & SetValue_SendEvent )
            m_bSkipUpdate = true;

        ::WinSetWindowText(GetHwnd(), rsValue.c_str());
        AdjustSpaceLimit();
    }
} // end of wxTextCtrl::SetValue

void wxTextCtrl::WriteText(
  const wxString&                   rsValue
)
{
    if (m_bIsMLE)
        ::WinSendMsg(GetHwnd(), MLM_INSERT, MPARAM(rsValue.wx_str()), MPARAM(0));
    else
        ::WinSetWindowText(GetHwnd(), rsValue.c_str());
    AdjustSpaceLimit();
} // end of wxTextCtrl::WriteText

void wxTextCtrl::AppendText(
  const wxString&                   rsText
)
{
    SetInsertionPointEnd();
    WriteText(rsText);
} // end of wxTextCtrl::AppendText

void wxTextCtrl::Clear()
{
    ::WinSetWindowText(GetHwnd(), "");
} // end of wxTextCtrl::Clear

bool wxTextCtrl::EmulateKeyPress(
  const wxKeyEvent&                 rEvent
)
{
    SetFocus();
    return(wxTextCtrlBase::EmulateKeyPress(rEvent));
} // end of wxTextCtrl::EmulateKeyPress

// ----------------------------------------------------------------------------
// Clipboard operations
// ----------------------------------------------------------------------------

void wxTextCtrl::Copy()
{
    if (CanCopy())
    {
        HWND hWnd = GetHwnd();
        if (m_bIsMLE)
            ::WinSendMsg(hWnd, MLM_COPY, 0, 0);
        else
            ::WinSendMsg(hWnd, EM_COPY, 0, 0);
    }
} // end of wxTextCtrl::Copy

void wxTextCtrl::Cut()
{
    if (CanCut())
    {
        HWND hWnd = GetHwnd();

        if (m_bIsMLE)
            ::WinSendMsg(hWnd, MLM_CUT, 0, 0);
        else
            ::WinSendMsg(hWnd, EM_CUT, 0, 0);
    }
} // end of wxTextCtrl::Cut

void wxTextCtrl::Paste()
{
    if (CanPaste())
    {
        HWND                        hWnd = GetHwnd();

        ::WinSendMsg(hWnd, EM_PASTE, 0, 0);
    }
} // end of wxTextCtrl::Paste

bool wxTextCtrl::CanCopy() const
{
    //
    // Can copy if there's a selection
    //
    long                            lFrom = 0L;
    long                            lTo = 0L;

    GetSelection(&lFrom, &lTo);
    return (lFrom != lTo);
} // end of wxTextCtrl::CanCopy

bool wxTextCtrl::CanCut() const
{
    //
    // Can cut if there's a selection
    //
    long                            lFrom = 0L;
    long                            lTo = 0L;

    GetSelection(&lFrom, &lTo);
    return (lFrom != lTo);
} // end of wxTextCtrl::CanCut

bool wxTextCtrl::CanPaste() const
{
    bool                            bIsTextAvailable = false;

    if (!IsEditable())
        return false;

    //
    // Check for straight text on clipboard
    //
    if (::WinOpenClipbrd(vHabmain))
    {
        bIsTextAvailable = (::WinQueryClipbrdData(vHabmain, CF_TEXT) != 0);
        ::WinCloseClipbrd(vHabmain);
    }
    return bIsTextAvailable;
} // end of wxTextCtrl::CanPaste

// ----------------------------------------------------------------------------
// Accessors
// ----------------------------------------------------------------------------

void wxTextCtrl::SetEditable(
  bool                              bEditable
)
{
    HWND                            hWnd = GetHwnd();

    if (m_bIsMLE)
        ::WinSendMsg(hWnd, MLM_SETREADONLY, MPFROMLONG(!bEditable), (MPARAM)0);
    else
        ::WinSendMsg(hWnd, EM_SETREADONLY, MPFROMLONG(!bEditable), (MPARAM)0);
} // end of wxTextCtrl::SetEditable

void wxTextCtrl::SetInsertionPoint(
  long                              lPos
)
{
    HWND                            hWnd = GetHwnd();

    if (m_bIsMLE)
        ::WinSendMsg(hWnd, MLM_SETSEL, (MPARAM)lPos, (MPARAM)lPos);
    else
        ::WinSendMsg(hWnd, EM_SETSEL, MPFROM2SHORT((USHORT)lPos, (USHORT)lPos), (MPARAM)0);
} // end of wxTextCtrl::SetInsertionPoint

void wxTextCtrl::SetInsertionPointEnd()
{
    wxTextPos                       lPos = GetLastPosition();

    //
    // We must not do anything if the caret is already there because calling
    // SetInsertionPoint() thaws the controls if Freeze() had been called even
    // if it doesn't actually move the caret anywhere and so the simple fact of
    // doing it results in horrible flicker when appending big amounts of text
    // to the control in a few chunks (see DoAddText() test in the text sample)
    //
    if (GetInsertionPoint() == GetLastPosition())
        return;
    SetInsertionPoint(lPos);
} // end of wxTextCtrl::SetInsertionPointEnd

long wxTextCtrl::GetInsertionPoint() const
{
    WXDWORD                         dwPos = 0L;

    if (m_bIsMLE)
        dwPos = (WXDWORD)::WinSendMsg(GetHwnd(), MLM_QUERYSEL, (MPARAM)MLFQS_MINSEL, 0);
    else
    {
        dwPos = (WXDWORD)::WinSendMsg(GetHwnd(), EM_QUERYSEL, 0, 0);
        dwPos = SHORT1FROMMP((MPARAM)dwPos);  // the first 16 bit value is the min pos
    }
    return (dwPos & 0xFFFF);
} // end of wxTextCtrl::GetInsertionPoint

wxTextPos wxTextCtrl::GetLastPosition() const
{
    HWND                            hWnd = GetHwnd();
    long                            lCharIndex;
    long                            lLineLength;

    if (m_bIsMLE)
    {
        lCharIndex = 0;

        //
        // This just gets the total text length.  The last will be this value
        //
        lLineLength = (long)::WinSendMsg(hWnd, MLM_QUERYTEXTLENGTH, 0, 0);
    }
    else
    {
        WNDPARAMS                   vParams;

        lCharIndex = 0;
        vParams.fsStatus = WPM_CCHTEXT;
        if (::WinSendMsg( GetHwnd()
                         ,WM_QUERYWINDOWPARAMS
                         ,&vParams
                         ,0
                        ))
        {
            lLineLength = (long)vParams.cchText;
        }
        else
            lLineLength = 0;
    }
    return(lCharIndex + lLineLength);
} // end of wxTextCtrl::GetLastPosition

// If the return values from and to are the same, there is no
// selection.
void wxTextCtrl::GetSelection(
  long*                             plFrom
, long*                             plTo
) const
{
    WXDWORD                         dwPos;

    if (m_bIsMLE)
        dwPos = (WXDWORD)::WinSendMsg(GetHwnd(), MLM_QUERYSEL, (MPARAM)MLFQS_MINSEL, 0);
    else
    {
        dwPos = (WXDWORD)::WinSendMsg(GetHwnd(), EM_QUERYSEL, 0, 0);
    }
    *plFrom = SHORT1FROMMP((MPARAM)dwPos);  // the first 16 bit value is the min pos
    *plTo = SHORT2FROMMP((MPARAM)dwPos);  // the first 16 bit value is the min pos
} // end of wxTextCtrl::GetSelection

bool wxTextCtrl::IsEditable() const
{
    if (m_bIsMLE)
        return((bool)LONGFROMMR(::WinSendMsg(GetHwnd(), MLM_QUERYREADONLY, 0, 0)));
    else
        return((bool)LONGFROMMR(::WinSendMsg(GetHwnd(), EM_QUERYREADONLY, 0, 0)));
} // end of wxTextCtrl::IsEditable

// ----------------------------------------------------------------------------
// Editing
// ----------------------------------------------------------------------------

void wxTextCtrl::Replace( long lFrom,
                          long lTo,
                          const wxString& rsValue )
{
#if wxUSE_CLIPBOARD
    HWND hWnd = GetHwnd();

    //
    // Set selection and remove it
    //
    if (m_bIsMLE)
    {
        ::WinSendMsg(hWnd, MLM_SETSEL, MPFROM2SHORT((USHORT)lFrom, (USHORT)lTo), 0);
        ::WinSendMsg(hWnd, MLM_CUT, 0, 0);
    }
    else
    {
        ::WinSendMsg(hWnd, EM_SETSEL, MPFROM2SHORT((USHORT)lFrom, (USHORT)lTo), 0);
        ::WinSendMsg(hWnd, EM_CUT, 0, 0);
    }

    //
    // Now replace with 'value', by pasting.
    //
    wxSetClipboardData(wxDF_TEXT, (wxObject *) (const wxChar *)rsValue, 0, 0);

    // Paste into edit control
    if (m_bIsMLE)
        ::WinSendMsg(hWnd, MLM_PASTE, (MPARAM)0, (MPARAM)0);
    else
        ::WinSendMsg(hWnd, EM_PASTE, (MPARAM)0, (MPARAM)0);
#else
    wxUnusedVar(lFrom);
    wxUnusedVar(lTo);
    wxUnusedVar(rsValue);
    wxFAIL_MSG("wxTextCtrl::Replace not implemented if wxUSE_CLIPBOARD is 0.");
#endif
}  // end of wxTextCtrl::Replace

void wxTextCtrl::Remove(
  long                              lFrom
, long                              lTo
)
{
    HWND                            hWnd      = GetHwnd();

    if (m_bIsMLE)
    {
        ::WinSendMsg(hWnd, MLM_SETSEL, MPFROM2SHORT((USHORT)lFrom, (USHORT)lTo), 0);
        ::WinSendMsg(hWnd, MLM_CUT, 0, 0);
    }
    else
    {
        ::WinSendMsg(hWnd, EM_SETSEL, MPFROM2SHORT((USHORT)lFrom, (USHORT)lTo), 0);
        ::WinSendMsg(hWnd, EM_CUT, 0, 0);
    }
} // end of wxTextCtrl::Remove

void wxTextCtrl::SetSelection(
  long                              lFrom
, long                              lTo
)
{
    HWND                            hWnd = GetHwnd();
    long                            lFromChar = lFrom;
    long                            lToChar = lTo;

    //
    // If from and to are both -1, it means (in wxWidgets) that all text should
    // be selected. Translate into Windows convention
    //
    if ((lFrom == -1L) && (lTo == -1L))
    {
        lFromChar = 0L;
        lToChar   = -1L;
    }
    if (m_bIsMLE)
        ::WinSendMsg(hWnd, MLM_SETSEL, (MPARAM)lFromChar, (MPARAM)lToChar);
    else
        ::WinSendMsg(hWnd, EM_SETSEL, MPFROM2SHORT((USHORT)lFromChar, (USHORT)lToChar), (MPARAM)0);
} // end of wxTextCtrl::SetSelection

bool wxTextCtrl::DoLoadFile(
  const wxString&                   rsFile,
  int                               fileType
)
{
    if ( wxTextCtrlBase::DoLoadFile(rsFile, fileType) )
    {
        //
        // Update the size limit if needed
        //
        AdjustSpaceLimit();
        return true;
    }
    return false;
} // end of wxTextCtrl::DoLoadFile

bool wxTextCtrl::IsModified() const
{
    bool                            bRc;

    if (m_bIsMLE)
        bRc = (bool)LONGFROMMR(::WinSendMsg(GetHwnd(), MLM_QUERYCHANGED, 0, 0));
    else
        bRc = (bool)LONGFROMMR(::WinSendMsg(GetHwnd(), EM_QUERYCHANGED, 0, 0));
    return bRc;
} // end of wxTextCtrl::IsModified

void wxTextCtrl::MarkDirty()
{
    if (m_bIsMLE)
        ::WinSendMsg(GetHwnd(), MLM_SETCHANGED, MPFROMLONG(TRUE), 0);
    else
        // EM controls do not have a SETCHANGED, what can we do??
        wxFAIL_MSG( wxT("not implemented") );
}

//
// Makes 'unmodified'
//
void wxTextCtrl::DiscardEdits()
{
    if (m_bIsMLE)
        ::WinSendMsg(GetHwnd(), MLM_SETCHANGED, MPFROMLONG(FALSE), 0);
    else
        //
        // EM controls do not have a SETCHANGED but issuing a query should reset it
        //
        ::WinSendMsg(GetHwnd(), EM_QUERYCHANGED, 0, 0);
} // end of wxTextCtrl::DiscardEdits

int wxTextCtrl::GetNumberOfLines() const
{
    int                             nNumLines;

    if (m_bIsMLE)
        nNumLines = (int)::WinSendMsg(GetHwnd(), MLM_QUERYLINECOUNT, 0, 0);
    else
        nNumLines = 1;
    return nNumLines;
} // end of wxTextCtrl::GetNumberOfLines

long wxTextCtrl::XYToPosition(
  long                              lX
, long                              lY
) const
{
    long                            lCharIndex = 0L;
    long                            lLen;

    if (m_bIsMLE)
    {
        lLen = (long)::WinSendMsg(GetHwnd(), MLM_QUERYLINELENGTH, 0, 0);
        lCharIndex = ((lLen * lY) + lX);
    }
    else
        lCharIndex = lX;
    return lCharIndex;
} // end of wxTextCtrl::XYToPosition

bool wxTextCtrl::PositionToXY(
  long                              lPos
, long*                             plX
, long*                             plY
) const
{
    HWND                            hWnd = GetHwnd();
    long                            nLineNo = -1;
    long                            lCharIndex = 0;

    if (m_bIsMLE)
        nLineNo = (long)::WinSendMsg(hWnd, MLM_LINEFROMCHAR, (MPARAM)lPos, 0);
    else
        nLineNo = 0;

    if (nLineNo == -1)
    {
        // no such line
        return false;
    }

    //
    // This gets the char index for the _beginning_ of this line
    //
    long                            lLineWidth;

    if (m_bIsMLE)
    {
        lLineWidth = (long)::WinSendMsg(hWnd, MLM_QUERYLINELENGTH, (MPARAM)0, (MPARAM)0);
        lCharIndex = (nLineNo + 1) * lLineWidth;
    }
    else
    {
        WNDPARAMS                   vParams;

        vParams.fsStatus = WPM_CCHTEXT;
        if (::WinSendMsg( hWnd
                         ,WM_QUERYWINDOWPARAMS
                         ,&vParams
                         ,0
                        ))
        {
            lCharIndex = vParams.cchText;
        }
        else
            lCharIndex = 32;
    }

    if (lCharIndex == -1)
    {
        return false;
    }

    //
    // The X position must therefore be the difference between pos and charIndex
    //
    if (plX)
        *plX = lPos - lCharIndex;
    if (plY)
        *plY = nLineNo;

    return true;
} // end of wxTextCtrl::PositionToXY

void wxTextCtrl::ShowPosition( long WXUNUSED(lPos) )
{
    HWND hWnd = GetHwnd();
    long lCurrentLineLineNo = 0L;

    // To scroll to a position, we pass the number of lines and characters
    // to scroll *by*. This means that we need to:
    // (1) Find the line position of the current line.
    // (2) Find the line position of pos.
    // (3) Scroll by (pos - current).
    // For now, ignore the horizontal scrolling.

    //
    // Is this where scrolling is relative to - the line containing the caret?
    // Or is the first visible line??? Try first visible line.
    //
    if (m_bIsMLE)
    {
        //
        // In PM this is the actual char position
        //
        lCurrentLineLineNo = (long)::WinSendMsg(hWnd, MLM_QUERYFIRSTCHAR, (MPARAM)0, (MPARAM)0);

        //
        // This will cause a scroll to the selected position
        //
        ::WinSendMsg(hWnd, MLM_SETSEL, (MPARAM)lCurrentLineLineNo, (MPARAM)lCurrentLineLineNo);
    }
} // end of wxTextCtrl::ShowPosition

int wxTextCtrl::GetLineLength( long WXUNUSED(lLineNo) ) const
{
    long lLen = 0L;

    if (m_bIsMLE)
    {
        lLen = (long)::WinSendMsg(GetHwnd(), MLM_QUERYLINELENGTH, 0, 0);
    }
    else
    {
        WNDPARAMS vParams;

        vParams.fsStatus = WPM_CCHTEXT;
        if (::WinSendMsg( GetHwnd()
                         ,WM_QUERYWINDOWPARAMS
                         ,&vParams
                         ,0
                        ))
        {
            lLen = vParams.cchText;
        }
        else
            lLen = 32;
    }
    return lLen;
} // end ofwxTextCtrl::GetLineLength

wxString wxTextCtrl::GetLineText(
  long                              lLineNo
) const
{
    long                            lLen = (long)GetLineLength((long)lLineNo) + 1;
    wxString                        sStr;
    wxChar*                         zBuf;

    //
    // There must be at least enough place for the length WORD in the
    // buffer
    //
    lLen += sizeof(WORD);
    zBuf = new wxChar[lLen];
    if (m_bIsMLE)
    {
        long                        lIndex;
        long                        lBuflen;
        long                        lCopied;

        lLen = (long)::WinSendMsg(GetHwnd(), MLM_QUERYLINELENGTH, 0, 0);
        lIndex = lLen * lLineNo;

        ::WinSendMsg(GetHwnd(), MLM_SETSEL, (MPARAM)lIndex, (MPARAM)lIndex);
        ::WinSendMsg(GetHwnd(), MLM_SETIMPORTEXPORT, MPFROMP(zBuf), MPFROMSHORT((USHORT)WXSIZEOF(zBuf)));
        lBuflen = (long)::WinSendMsg(GetHwnd(), MLM_QUERYFORMATTEXTLENGTH, MPFROMLONG(lIndex), MPFROMLONG(-1));
        lCopied = (long)::WinSendMsg(GetHwnd(), MLM_EXPORT, MPFROMP(&lIndex), MPFROMP(&lBuflen));
        zBuf[lCopied] = '\0';
    }
    else
    {
        WNDPARAMS                   vParams;

        vParams.fsStatus = WPM_CCHTEXT;
        if (::WinSendMsg( GetHwnd()
                         ,WM_QUERYWINDOWPARAMS
                         ,&vParams
                         ,0
                        ))
         memcpy((char*)zBuf, vParams.pszText, vParams.cchText);
         zBuf[vParams.cchText] = '\0';
     }
     sStr = zBuf;
     delete [] zBuf;
     return sStr;
} // end of wxTextCtrl::GetLineText

// ----------------------------------------------------------------------------
// Undo/redo
// ----------------------------------------------------------------------------

void wxTextCtrl::Undo()
{
    if (CanUndo())
    {
        if (m_bIsMLE)
            ::WinSendMsg(GetHwnd(), MLM_UNDO, 0, 0);
        // Simple entryfields cannot be undone
    }
} // end of wxTextCtrl::Undo

void wxTextCtrl::Redo()
{
    if (CanRedo())
    {
        if (m_bIsMLE)
            ::WinSendMsg(GetHwnd(), MLM_UNDO, 0, 0);
        // Simple entryfields cannot be undone
    }
} // end of wxTextCtrl::Redo

bool wxTextCtrl::CanUndo() const
{
    bool                            bOk;

    if (m_bIsMLE)
        bOk = (::WinSendMsg(GetHwnd(), MLM_QUERYUNDO, 0, 0) != 0);
    else
        bOk = false; // can't undo regular edit fields in PM
    return bOk;
} // end of wxTextCtrl::CanUndo

bool wxTextCtrl::CanRedo() const
{
    bool                            bOk;

    if (m_bIsMLE)
        bOk = (::WinSendMsg(GetHwnd(), MLM_QUERYUNDO, 0, 0) != 0);
    else
        bOk = false; // can't undo regular edit fields in PM
    return bOk;
} // end of wxTextCtrl::CanRedo

// ----------------------------------------------------------------------------
// implemenation details
// ----------------------------------------------------------------------------

void wxTextCtrl::Command(
  wxCommandEvent&                   rEvent
)
{
    SetValue(rEvent.GetString());
    ProcessCommand (rEvent);
} // end of wxTextCtrl::Command

void wxTextCtrl::OnDropFiles(
  wxDropFilesEvent&                 rEvent
)
{
    // By default, load the first file into the text window.
    if (rEvent.GetNumberOfFiles() > 0)
    {
        LoadFile(rEvent.GetFiles()[0]);
    }
} // end of wxTextCtrl::OnDropFiles

WXHBRUSH wxTextCtrl::OnCtlColor( WXHDC    hWxDC,
                                 WXHWND   WXUNUSED(hWnd),
                                 WXUINT   WXUNUSED(uCtlColor),
                                 WXUINT   WXUNUSED(uMessage),
                                 WXWPARAM WXUNUSED(wParam),
                                 WXLPARAM WXUNUSED(lParam) )
{
    HPS      hPS = (HPS)hWxDC;
    wxColour vColBack = GetBackgroundColour();
    wxColour vColFore = GetForegroundColour();
    wxBrush* pBackgroundBrush = wxTheBrushList->FindOrCreateBrush( vColBack, wxSOLID );

    if (m_bUseCtl3D)
    {
        HBRUSH                      hBrush = NULLHANDLE;

        return hBrush;
    }
    if (GetParent()->GetTransparentBackground())
        ::GpiSetBackMix(hPS, BM_LEAVEALONE);
    else
        ::GpiSetBackMix(hPS, BM_OVERPAINT);
    if (!IsEnabled() && (GetWindowStyle() & wxTE_MULTILINE) == 0)
        vColBack = wxSystemSettings::GetColour(wxSYS_COLOUR_3DFACE);
    ::GpiSetBackColor(hPS, vColBack.GetPixel());
    ::GpiSetColor(hPS, vColFore.GetPixel());
    return (WXHBRUSH)pBackgroundBrush->GetResourceHandle();
} // end of wxTextCtrl::OnCtlColor

bool wxTextCtrl::OS2ShouldPreProcessMessage(
  WXMSG*                            pMsg
)
{
    return wxControl::OS2ShouldPreProcessMessage(pMsg);
} // end of wxTextCtrl::OS2ShouldPreProcessMessage

void wxTextCtrl::OnChar(
  wxKeyEvent&                       rEvent
)
{
    switch (rEvent.GetKeyCode())
    {
        case WXK_RETURN:
            if ( !(m_windowStyle & wxTE_MULTILINE) )
            {
                wxCommandEvent      vEvent(wxEVT_COMMAND_TEXT_ENTER, m_windowId);

                vEvent.SetEventObject(this);
                if ( HandleWindowEvent(vEvent))
                    return;
            }
            //else: multiline controls need Enter for themselves

            break;

        case WXK_TAB:
            // always produce navigation event - even if we process TAB
            // ourselves the fact that we got here means that the user code
            // decided to skip processing of this TAB - probably to let it
            // do its default job.
            //
            // NB: Notice that Ctrl-Tab is handled elsewhere and Alt-Tab is
            //     handled by Windows
            {
                wxNavigationKeyEvent    vEventNav;

                vEventNav.SetDirection(!rEvent.ShiftDown());
                vEventNav.SetWindowChange(false);
                vEventNav.SetEventObject(this);

                if ( HandleWindowEvent(vEventNav) )
                    return;
            }
            break;
    }
    rEvent.Skip();
} // end of wxTextCtrl::OnChar

bool wxTextCtrl::OS2Command(
  WXUINT                            uParam
, WXWORD                            WXUNUSED(vId)
)
{
    switch (uParam)
    {
        case EN_SETFOCUS:
        case EN_KILLFOCUS:
            {
                wxFocusEvent        vEvent( uParam == EN_KILLFOCUS ? wxEVT_KILL_FOCUS
                                                                   : wxEVT_SET_FOCUS
                                           ,m_windowId
                                          );

                vEvent.SetEventObject(this);
                HandleWindowEvent(vEvent);
            }
            break;

        case EN_CHANGE:
            {
                if (m_bSkipUpdate)
                {
                    m_bSkipUpdate = false;
                    break;
                }

                wxCommandEvent      vEvent( wxEVT_COMMAND_TEXT_UPDATED
                                           ,m_windowId
                                          );

                InitCommandEvent(vEvent);
                ProcessCommand(vEvent);
            }
            break;

        case EN_OVERFLOW:
            //
            // The text size limit has been hit - increase it
            //
            AdjustSpaceLimit();
            break;

        case EN_SCROLL:
        case EN_INSERTMODETOGGLE:
        case EN_MEMERROR:
            return false;
        default:
            return false;
    }

    //
    // Processed
    //
    return true;
} // end of wxTextCtrl::OS2Command

void wxTextCtrl::AdjustSpaceLimit()
{
    unsigned int                    uLen = 0;
    unsigned int                    uLimit = 0;

    uLen   = ::WinQueryWindowTextLength(GetHwnd());
    if (m_bIsMLE)
    {
        uLimit = (unsigned int)::WinSendMsg( GetHwnd()
                                            ,MLM_QUERYTEXTLIMIT
                                            ,0
                                            ,0
                                           );
    }
    else
    {
        ENTRYFDATA                  Efd;
        WNDPARAMS                   vParams;

        vParams.fsStatus = WPM_CBCTLDATA;
        vParams.pCtlData = &Efd;
        vParams.cbCtlData = sizeof(ENTRYFDATA);

        if (::WinSendMsg( GetHwnd()
                         ,WM_QUERYWINDOWPARAMS
                         ,&vParams
                         ,0
                        ))
            uLimit = (unsigned int)Efd.cchEditLimit;
        else
            uLimit = 32; //PM's default
    }
    if (uLen >= uLimit)
    {
        if (m_bIsMLE)
        {
            uLimit = uLen + 0x8000;    // 32Kb
            if (uLimit > 0xffff)
            {
                uLimit = 0L;
            }
        }
        else
            uLimit = 0x7fff;

        if (m_bIsMLE)
            ::WinSendMsg(GetHwnd(), MLM_SETTEXTLIMIT, MPFROMLONG(uLimit), 0);
        else
            ::WinSendMsg(GetHwnd(), EM_SETTEXTLIMIT, MPFROMSHORT(uLimit), 0);
    }
} // end of wxTextCtrl::AdjustSpaceLimit

bool wxTextCtrl::AcceptsFocus() const
{
    //
    // We don't want focus if we can't be edited unless we're a multiline
    // control because then it might be still nice to get focus from keyboard
    // to be able to scroll it without mouse
    //
    return (IsEditable() || IsMultiLine()) && wxControl::AcceptsFocus();
} // end of wxTextCtrl::Command

wxSize wxTextCtrl::DoGetBestSize() const
{
    int                             nCx;
    int                             nCy;
    wxFont                          vFont = (wxFont)GetFont();

    wxGetCharSize(GetHWND(), &nCx, &nCy, &vFont);

    int                             wText = DEFAULT_ITEM_WIDTH;
    int                             hText = (int)(EDIT_HEIGHT_FROM_CHAR_HEIGHT(nCy) * .8);

    if (m_windowStyle & wxTE_MULTILINE)
    {
        hText *= wxMax(GetNumberOfLines(), 5);
    }
    //else: for single line control everything is ok
    return wxSize(wText, hText);
} // end of wxTextCtrl::DoGetBestSize

// ----------------------------------------------------------------------------
// standard handlers for standard edit menu events
// ----------------------------------------------------------------------------

void wxTextCtrl::OnCut( wxCommandEvent& WXUNUSED(rEvent) )
{
    Cut();
} // end of wxTextCtrl::OnCut

void wxTextCtrl::OnCopy( wxCommandEvent& WXUNUSED(rEvent) )
{
    Copy();
} // end of wxTextCtrl::OnCopy

void wxTextCtrl::OnPaste( wxCommandEvent& WXUNUSED(rEvent) )
{
    Paste();
} // end of wxTextCtrl::OnPaste

void wxTextCtrl::OnUndo( wxCommandEvent& WXUNUSED(rEvent) )
{
    Undo();
} // end of wxTextCtrl::OnUndo

void wxTextCtrl::OnRedo( wxCommandEvent& WXUNUSED(rEvent) )
{
    Redo();
} // end of wxTextCtrl::OnRedo

void wxTextCtrl::OnDelete( wxCommandEvent& WXUNUSED(rEvent) )
{
    long lFrom, lTo;

    GetSelection( &lFrom, &lTo );

    if (lFrom != -1 && lTo != -1)
        Remove( lFrom, lTo );
} // end of wxTextCtrl::OnDelete

void wxTextCtrl::OnSelectAll( wxCommandEvent& WXUNUSED(rEvent) )
{
    SetSelection(-1, -1);
} // end of wxTextCtrl::OnSelectAll

void wxTextCtrl::OnUpdateCut( wxUpdateUIEvent& rEvent )
{
    rEvent.Enable(CanCut());
} // end of wxTextCtrl::OnUpdateCut

void wxTextCtrl::OnUpdateCopy( wxUpdateUIEvent& rEvent )
{
    rEvent.Enable(CanCopy());
} // end of wxTextCtrl::OnUpdateCopy

void wxTextCtrl::OnUpdatePaste( wxUpdateUIEvent& rEvent )
{
    rEvent.Enable(CanPaste());
} // end of wxTextCtrl::OnUpdatePaste

void wxTextCtrl::OnUpdateUndo( wxUpdateUIEvent& rEvent )
{
    rEvent.Enable(CanUndo());
} // end of wxTextCtrl::OnUpdateUndo

void wxTextCtrl::OnUpdateRedo( wxUpdateUIEvent& rEvent )
{
    rEvent.Enable(CanRedo());
} // end of wxTextCtrl::OnUpdateRedo

void wxTextCtrl::OnUpdateDelete( wxUpdateUIEvent& rEvent )
{
    long lFrom, lTo;

    GetSelection( &lFrom, &lTo );
    rEvent.Enable( lFrom != -1L && lTo != -1L && lFrom != lTo && IsEditable()) ;
} // end of wxTextCtrl::OnUpdateDelete

void wxTextCtrl::OnUpdateSelectAll( wxUpdateUIEvent& rEvent )
{
    rEvent.Enable(GetLastPosition() > 0);
} // end of wxTextCtrl::OnUpdateSelectAll

bool wxTextCtrl::SetBackgroundColour( const wxColour& rColour )
{
    if (m_bIsMLE)
        ::WinSendMsg(GetHwnd(), MLM_SETBACKCOLOR, (MPARAM)rColour.GetPixel(), MLE_INDEX);
    return true;
} // end of wxTextCtrl::SetBackgroundColour

bool wxTextCtrl::SetForegroundColour( const wxColour& rColour )
{
    if (m_bIsMLE)
        ::WinSendMsg(GetHwnd(), MLM_SETTEXTCOLOR, (MPARAM)rColour.GetPixel(), MLE_INDEX);
    return true;
} // end of wxTextCtrl::SetForegroundColour

bool wxTextCtrl::SetStyle( long lStart,
                           long lEnd,
                           const wxTextAttr& WXUNUSED(rStyle) )
{
    HWND hWnd = GetHwnd();

    if (lStart > lEnd)
    {
        long lTmp = lStart;

        lStart = lEnd;
        lEnd   = lTmp;
    }

    //
    // We can only change the format of the selection, so select the range we
    // want and restore the old selection later
    //
    long lStartOld, lEndOld;

    GetSelection( &lStartOld, &lEndOld );

    //
    // But do we really have to change the selection?
    //
    bool bChangeSel = lStart != lStartOld ||
                      lEnd != lEndOld;

    if (bChangeSel)
    {
        if (m_bIsMLE)
            ::WinSendMsg(hWnd, MLM_SETSEL, MPFROM2SHORT((USHORT)lStart, (USHORT)lEnd), 0);
        else
            ::WinSendMsg(hWnd, EM_SETSEL, MPFROM2SHORT((USHORT)lStart, (USHORT)lEnd), 0);
    }

    //
    // TODO:: finish this part
    //
    return true;
} // end of wxTextCtrl::SetStyle
