/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/fontdlg.cpp
// Purpose:     wxFontDialog class. NOTE: you can use the generic class
//              if you wish, instead of implementing this.
// Author:      David Webster
// Modified by:
// Created:     10/06/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/fontdlg.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/math.h"
    #include "wx/cmndata.h"
#endif

#include "wx/fontutil.h"

#define INCL_PM
#include <os2.h>

#include "wx/os2/private.h"

#include <stdlib.h>
#include <string.h>

IMPLEMENT_DYNAMIC_CLASS(wxFontDialog, wxDialog)

int wxFontDialog::ShowModal()
{
    FONTDLG      vFontDlg;
    char         zCurrentFont[FACESIZE];
    HWND         hWndFontDlg;
    FACENAMEDESC vFn;

    memset(&vFontDlg, '\0', sizeof(FONTDLG));
    zCurrentFont[0] = '\0';

    //
    // Set the fontdlg fields
    //
    vFontDlg.cbSize         = sizeof(FONTDLG);
    vFontDlg.hpsScreen      = ::WinGetScreenPS(HWND_DESKTOP);
    vFontDlg.hpsPrinter     = NULL;
    vFontDlg.pszFamilyname  = zCurrentFont;
    vFontDlg.fxPointSize    = MAKEFIXED(12,0);
    vFontDlg.usFamilyBufLen = FACESIZE;
    vFontDlg.fl             = FNTS_CENTER;
    vFontDlg.clrFore        = CLR_BLACK;
    vFontDlg.clrBack        = CLR_WHITE;

    hWndFontDlg = WinFontDlg( HWND_DESKTOP
                             ,GetParent()->GetHWND()
                             ,&vFontDlg
                            );
    if (hWndFontDlg && vFontDlg.lReturn == DID_OK)
    {
        wxColour                    vColour((unsigned long)0x00000000);
        wxNativeFontInfo            vInfo;

        m_fontData.m_fontColour = vColour;

        memset(&vFn, '\0', sizeof(FACENAMEDESC));
        vFn.usSize        = sizeof(FACENAMEDESC);
        vFn.usWeightClass = vFontDlg.usWeight;
        vFn.usWidthClass  = vFontDlg.usWidth;

        memset(&vInfo.fa, '\0', sizeof(FATTRS));
        memcpy(&vInfo.fn, &vFn, sizeof(FACENAMEDESC));

        vInfo.fa.usRecordLength = vFontDlg.fAttrs.usRecordLength;
        strcpy(vInfo.fa.szFacename, vFontDlg.fAttrs.szFacename);
        vInfo.fa.lMatch = vFontDlg.fAttrs.lMatch;

        //
        // Debugging
        //
        wxFont                      vChosenFont(vInfo);

        int                         nPointSize = vFontDlg.fxPointSize >> 16;

        vChosenFont.SetPointSize(nPointSize);
        m_fontData.m_chosenFont = vChosenFont;

        m_fontData.EncodingInfo().facename = (wxChar*)vFontDlg.fAttrs.szFacename;
        m_fontData.EncodingInfo().charset = vFontDlg.fAttrs.usCodePage;

        return wxID_OK;
    }
    return wxID_CANCEL;
} // end of wxFontDialg::ShowModal
