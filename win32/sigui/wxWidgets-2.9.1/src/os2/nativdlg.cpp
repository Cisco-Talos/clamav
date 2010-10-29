/////////////////////////////////////////////////////////////////////////////
// Name:        nativdlg.cpp
// Purpose:     Native dialog loading code (part of wxWindow)
// Author:      David Webster
// Modified by:
// Created:     10/12/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/wx.h"
#endif

#include "wx/os2/private.h"
#include "wx/spinbutt.h"

// ---------------------------------------------------------------------------
// global functions
// ---------------------------------------------------------------------------

extern wxWindow* wxWndHook;
extern MRESULT EXPENTRY wxDlgProc( HWND   hWnd
                                  ,UINT   message
                                  ,MPARAM wParam
                                  ,MPARAM lParam
                                 );

// ===========================================================================
// implementation
// ===========================================================================

bool wxWindow::LoadNativeDialog (
  wxWindow*                         pParent
, wxWindowID&                       vId
)
{
    wxWindow*                       pChild = NULL;
    HWND                            hWndOwner;
    HWND                            hWndNext = NULLHANDLE;
    HENUM                           hEnum;

    if (pParent)
        hWndOwner = GetHwndOf(pParent);
    else
        hWndOwner = HWND_DESKTOP;

    m_windowId = vId;
    wxWndHook  = this;

    m_hWnd = ::WinLoadDlg( HWND_DESKTOP
                          ,hWndOwner
                          ,(PFNWP)wxDlgProc
                          ,NULL
                          ,(ULONG)131 // Caption dialog from the resource file
                          ,(PVOID)this
                         );
    wxWndHook = NULL;

    if ( !m_hWnd )
        return FALSE;

    SubclassWin(GetHWND());

    if (pParent)
        pParent->AddChild(this);
    else
        wxTopLevelWindows.Append(this);

    //
    // Enumerate the children
    //
    hEnum = ::WinBeginEnumWindows(GetHwndOf(pParent));
    while ((hWndNext = ::WinGetNextWindow(hEnum)) != NULLHANDLE)
        pChild = CreateWindowFromHWND( this
                                      ,(WXHWND)hWndNext
                                     );
    ::WinEndEnumWindows(hEnum);
    return TRUE;
} // end of wxWindow::LoadNativeDialog

bool wxWindow::LoadNativeDialog (
  wxWindow*                         pParent
, const wxString&                   rsName
)
{
    HWND                            hWndOwner;

    if (pParent)
        hWndOwner = GetHwndOf(pParent);
    else
        hWndOwner = HWND_DESKTOP;
    SetName(rsName);

    wxWndHook = this;
    m_hWnd = ::WinLoadDlg( HWND_DESKTOP
                          ,hWndOwner
                          ,(PFNWP)wxDlgProc
                          ,NULL
                          ,(ULONG)131 // Caption dialog from the resource file
                          ,(PVOID)this
                         );
    wxWndHook = NULL;

    if (!m_hWnd)
        return FALSE;

    SubclassWin(GetHWND());

    if (pParent)
        pParent->AddChild(this);
    else
        wxTopLevelWindows.Append(this);
    return TRUE;
} // end of wxWindow::LoadNativeDialog

// ---------------------------------------------------------------------------
// look for child by id
// ---------------------------------------------------------------------------
wxWindow* wxWindow::GetWindowChild1 (
  wxWindowID                        vId
)
{
    if (m_windowId == vId)
        return this;

    wxWindowList::compatibility_iterator node = GetChildren().GetFirst();

    while (node)
    {
        wxWindow*                   pChild = node->GetData();
        wxWindow*                   pWin   = pChild->GetWindowChild1(vId);

        if (pWin)
            return pWin;

        node = node->GetNext();
    }
    return NULL;
} // end of wxWindow::GetWindowChild1

wxWindow* wxWindow::GetWindowChild (
  wxWindowID                        vId
)
{
    wxWindow*                       pWin = GetWindowChild1(vId);

    if (!pWin)
    {
        HWND                        hWnd = 0; // TODO: ::GetDlgItem((HWND) GetHWND(), id);

        if (hWnd)
        {
            wxWindow*               pChild = CreateWindowFromHWND( this
                                                                  ,(WXHWND)hWnd
                                                                 );
            if (pChild)
            {
                pChild->AddChild(this);
                return pChild;
            }
        }
    }
    return NULL;
} // end of wxWindow::GetWindowChild

// ---------------------------------------------------------------------------
// create wxWin window from a native HWND
// ---------------------------------------------------------------------------

wxWindow* wxWindow::CreateWindowFromHWND (
  wxWindow*                         pParent
, WXHWND                            hWnd
)
{
    wxString                        sStr(wxGetWindowClass(hWnd));
    long                            lId    = wxGetWindowId(hWnd);
    long                            lStyle = ::WinQueryWindowULong((HWND)hWnd
                                                                   ,QWL_STYLE
                                                                  );
    wxWindow*                       pWin = NULL;

    sStr.UpperCase();



    if (sStr == wxT("BUTTON"))
    {
        if (lStyle == BS_AUTOCHECKBOX)
        {
            pWin = new wxCheckBox;
        }
        else if (lStyle == BS_AUTORADIOBUTTON)
        {
            pWin = new wxRadioButton;
        }
        else if (lStyle & BS_BITMAP || lStyle == BS_USERBUTTON)
        {
            pWin = new wxBitmapButton;
        }
        else if (lStyle == BS_PUSHBUTTON)
        {
            pWin = new wxButton;
        }
        else if (lStyle == SS_GROUPBOX)
        {
            pWin = new wxStaticBox;
        }
        else
        {
            wxLogError(wxT("Don't know what kind of button this is: id = %ld"),
                       lId);
        }
    }
    else if (sStr == wxT("COMBOBOX"))
    {
        pWin = new wxComboBox;
    }
    else if (sStr == wxT("EDIT"))
    {
        pWin = new wxTextCtrl;
    }
    else if (sStr == wxT("LISTBOX"))
    {
        pWin = new wxListBox;
    }
    else if (sStr == wxT("SCROLLBAR"))
    {
        pWin = new wxScrollBar;
    }
    else if (sStr == wxT("MSCTLS_UPDOWN32"))
    {
        pWin = new wxSpinButton;
    }
    else if (sStr == wxT("MSCTLS_TRACKBAR32"))
    {
        pWin = new wxSlider;
    }
    else if (sStr == wxT("STATIC"))
    {
        if (lStyle == SS_TEXT)
            pWin = new wxStaticText;
        else if (lStyle == SS_ICON)
        {
            pWin = new wxStaticBitmap;
        }
    }
    else
    {
        wxString                    sMsg(wxT("Don't know how to convert from Windows class "));

        sMsg += sStr;
        wxLogError(sMsg);
    }
    if (pWin)
    {
        pParent->AddChild(pWin);
        pWin->SetEventHandler(pWin);
        pWin->SetHWND(hWnd);
        pWin->SetId(lId);
        pWin->SubclassWin(hWnd);
        pWin->AdoptAttributesFromHWND();
        pWin->SetupColours();
        return pWin;
    }
    else
        return NULL;
} // end of wxWindow::CreateWindowFromHWND

//
// Make sure the window style (etc.) reflects the HWND style (roughly)
//
void wxWindow::AdoptAttributesFromHWND()
{
  // Does nothing under OS/2
} // end of wxWindow::AdoptAttributesFromHWND

