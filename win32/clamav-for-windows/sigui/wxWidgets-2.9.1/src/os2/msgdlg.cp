/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/msgdlg.cpp
// Purpose:     wxMessageDialog
// Author:      David Webster
// Modified by:
// Created:     10/10/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/msgdlg.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/app.h"
    #include "wx/math.h"
#endif

#include "wx/os2/private.h"

#include <stdlib.h>
#include <string.h>

#define wxDIALOG_DEFAULT_X 300
#define wxDIALOG_DEFAULT_Y 300

IMPLEMENT_CLASS(wxMessageDialog, wxDialog)

int wxMessageDialog::ShowModal()
{
    HWND                            hWnd = 0;
    ULONG                           ulStyle = MB_OK;
    int                             nAns = wxOK;
    const long                      lStyle = GetMessageDialogStyle();

    if (!wxTheApp->GetTopWindow())
    {
        //
        // when the message box is shown from wxApp::OnInit() (i.e. before the
        // message loop is entered), this must be done or the next message box
        // will never be shown - just try putting 2 calls to wxMessageBox() in
        // OnInit() to see it
        //
        while (wxTheApp->Pending())
            wxTheApp->Dispatch();
    }

    if (m_parent)
        hWnd = (HWND) m_parent->GetHWND();
    else
        hWnd = HWND_DESKTOP;
    if (lStyle & wxYES_NO)
    {
        if (lStyle & wxCANCEL)
            ulStyle = MB_YESNOCANCEL;
        else
            ulStyle = MB_YESNO;

        if (lStyle & wxNO_DEFAULT)
            ulStyle |= MB_DEFBUTTON2;
    }

    if (lStyle & wxOK)
    {
        if (lStyle & wxCANCEL)
            ulStyle = MB_OKCANCEL;
        else
            ulStyle = MB_OK;
    }

    switch ( GetEffectiveIcon() )
    {
        case wxICON_ERROR:
            ulStyle |= MB_ERROR;
            break;

        case wxICON_WARNING:
            ulStyle |= MB_WARNING;
            break;

        case wxICON_QUESTION:
            ulStyle |= MB_QUERY;
            break;

        case wxICON_INFORMATION:
            ulStyle |= MB_INFORMATION;
            break;
    }

    if (hWnd != HWND_DESKTOP)
        ulStyle |= MB_APPLMODAL;
    else
        ulStyle |= MB_SYSTEMMODAL;

    //
    // This little line of code is get message boxes under OS/2 to
    // behve like the other ports.  In OS/2 if the parent is a window
    // it displays, clipped, in the window.  This centers it on the
    // desktop, like the other ports but still allows control over modality
    //
    hWnd = HWND_DESKTOP;

    ULONG                           ulAns = ::WinMessageBox( hWnd
                                                            ,hWnd
                                                            ,GetFullMessage().c_str()
                                                            ,m_caption.c_str()
                                                            ,0L
                                                            ,ulStyle);
    switch (ulAns)
    {
        case MBID_CANCEL:
            nAns = wxID_CANCEL;
            break;
        case MBID_OK:
            nAns = wxID_OK;
            break;
        case MBID_YES:
            nAns = wxID_YES;
            break;
        case MBID_NO:
            nAns = wxID_NO;
            break;
        default:
           nAns = wxID_CANCEL;
    }
    return nAns;
} // end of wxMessageDialog::ShowModal
