/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/combobox.cpp
// Purpose:     wxComboBox class
// Author:      David Webster
// Modified by:
// Created:     10/13/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_COMBOBOX

#include "wx/combobox.h"

#ifndef WX_PRECOMP
    #include "wx/settings.h"
#endif

#include "wx/clipbrd.h"
#include "wx/os2/private.h"

#define OWNER_DRAWN_LISTBOX_EXTRA_SPACE    (1)

MRESULT EXPENTRY wxComboEditWndProc( HWND   hWnd
                                    ,UINT   uMessage
                                    ,MPARAM wParam
                                    ,MPARAM lParam
                                   );
//
// The pointer to standard wnd proc
//
static WXFARPROC gfnWndprocEdit     = (WXFARPROC)NULL;

IMPLEMENT_DYNAMIC_CLASS(wxComboBox, wxControl)

bool wxComboBox::OS2Command( WXUINT uParam, WXWORD WXUNUSED(wId) )
{
    long lSel = GetSelection();
    wxString sValue;

    switch (uParam)
    {
        case CBN_LBSELECT:
            if (lSel > -1)
            {
                wxCommandEvent vEvent( wxEVT_COMMAND_COMBOBOX_SELECTED, GetId() );

                vEvent.SetInt(lSel);
                vEvent.SetEventObject(this);
                vEvent.SetString(GetStringSelection());

                ProcessCommand(vEvent);
            }
            break;

        case CBN_EFCHANGE:
            {
                wxCommandEvent vEvent( wxEVT_COMMAND_TEXT_UPDATED, GetId() );

                if (lSel == -1L)
                    sValue = GetValue();
                else
                    sValue = GetStringSelection();
                vEvent.SetString(sValue);
                vEvent.SetEventObject(this);
                ProcessCommand(vEvent);
            }
            break;
    }
    //
    // There is no return value for the CBN_ notifications, so always return
    // false from here to pass the message to DefWindowProc()
    //
    return false;
} // end of wxComboBox::OS2Command

bool wxComboBox::Create(
  wxWindow*                         pParent
, wxWindowID                        vId
, const wxString&                   rsValue
, const wxPoint&                    rPos
, const wxSize&                     rSize
, const wxArrayString&              asChoices
, long                              lStyle
, const wxValidator&                rValidator
, const wxString&                   rsName
)
{
    wxCArrayString chs(asChoices);

    return Create(pParent, vId, rsValue, rPos, rSize, chs.GetCount(),
                  chs.GetStrings(), lStyle, rValidator, rsName);
}

bool wxComboBox::Create(
  wxWindow*                         pParent
, wxWindowID                        vId
, const wxString&                   rsValue
, const wxPoint&                    rPos
, const wxSize&                     rSize
, int                               n
, const wxString                    asChoices[]
, long                              lStyle
, const wxValidator&                rValidator
, const wxString&                   rsName
)
{
    m_isShown = false;

    if (!CreateControl( pParent
                       ,vId
                       ,rPos
                       ,rSize
                       ,lStyle
                       ,rValidator
                       ,rsName
                      ))
        return false;

    //
    // Get the right style
    //
    long                            lSstyle = 0L;

    lSstyle = WS_TABSTOP   |
              WS_VISIBLE;

    // clipping siblings does not yet work
    // if (lStyle & wxCLIP_SIBLINGS )
    //     lSstyle |= WS_CLIPSIBLINGS;
    if (lStyle & wxCB_READONLY)
        lSstyle |= CBS_DROPDOWNLIST;
    else if (lStyle & wxCB_SIMPLE)
        lSstyle |= CBS_SIMPLE; // A list (shown always) and edit control
    else
        lSstyle |= CBS_DROPDOWN;


    if (!OS2CreateControl( wxT("COMBOBOX")
                          ,lSstyle
                         ))
        return false;

    //
    // A choice/combobox normally has a white background (or other, depending
    // on global settings) rather than inheriting the parent's background colour.
    //
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW));

    for (int i = 0; i < n; i++)
    {
        Append(asChoices[i]);
    }

    SetSize( rPos.x
            ,rPos.y
            ,rSize.x
            ,rSize.y
           );

    // Set height to use with sizers i.e. without the dropdown listbox
    wxFont vFont = GetFont();
    int nEditHeight;
    wxGetCharSize( GetHWND(), NULL, &nEditHeight, &vFont );
    nEditHeight = EDIT_HEIGHT_FROM_CHAR_HEIGHT(nEditHeight);
    SetInitialSize(wxSize(-1,nEditHeight+4));   // +2x2 for the border

    if (!rsValue.empty())
    {
        SetValue(rsValue);
    }
    gfnWndprocEdit = (WXFARPROC)::WinSubclassWindow( (HWND)GetHwnd()
                                                    ,(PFNWP)wxComboEditWndProc
                                                   );
    ::WinSetWindowULong(GetHwnd(), QWL_USER, (ULONG)this);
    Show(true);
    return true;
} // end of wxComboBox::Create

wxString wxComboBox::GetValue() const
{
    return HasFlag(wxCB_READONLY) ? GetStringSelection()
                                  : wxTextEntry::GetValue();
}

void wxComboBox::SetValue(const wxString& value)
{
    if ( HasFlag(wxCB_READONLY) )
        SetStringSelection(value);
    else
        wxTextEntry::SetValue(value);
}

void wxComboBox::Clear()
{
    wxChoice::Clear();
    if ( !HasFlag(wxCB_READONLY) )
        wxTextEntry::Clear();
}

bool wxComboBox::IsEditable() const
{
    return !HasFlag(wxCB_READONLY) && wxTextEntry::IsEditable();
}

bool wxComboBox::ProcessEditMsg(
  WXUINT                            uMsg
, WXWPARAM                          wParam
, WXLPARAM                          lParam)
{
    SHORT                           vFlag;
    switch (uMsg)
    {
        case WM_CHAR:
            vFlag = SHORT1FROMMP(wParam);
            switch(vFlag)
            {
                case KC_CHAR:
                    return (HandleChar( wParam
                                       ,lParam
                                       ,true /* isASCII */
                                      ));

                case KC_PREVDOWN:
                    return (HandleKeyDown( wParam
                                          ,lParam
                                         ));

                case KC_KEYUP:
                    return (HandleKeyUp( wParam
                                        ,lParam
                                       ));
            }
            break;

        case WM_SETFOCUS:
            if (SHORT1FROMMP((MPARAM)lParam) == TRUE)
                return(HandleSetFocus((WXHWND)(HWND)wParam));
            else
                return(HandleKillFocus((WXHWND)(HWND)wParam));
    }
    return false;
} // end of wxComboBox::ProcessEditMsg

MRESULT EXPENTRY wxComboEditWndProc(
  HWND                              hWnd
, UINT                              uMessage
, MPARAM                            wParam
, MPARAM                            lParam
)
{
    switch (uMessage)
    {
        //
        // Forward some messages to the combobox
        //
        case WM_SETFOCUS:
        case WM_CHAR:
            {
                wxComboBox* pCombo = (wxComboBox *)::WinQueryWindowULong( hWnd
                                                                         ,QWL_USER
                                                                        );

                if (pCombo->ProcessEditMsg( uMessage
                                           ,wParam
                                           ,lParam
                                          ))
                    return ((MRESULT)0);
            }
            break;

        //
        // TODO: Deal with tooltips here
        //
    }
    return (gfnWndprocEdit(hWnd, (ULONG)uMessage, (MPARAM)wParam, (MPARAM)lParam));
} // end of wxComboEditWndProc

#endif
 // wxUSE_COMBOBOX
