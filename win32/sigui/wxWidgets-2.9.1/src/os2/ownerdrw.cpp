///////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/ownerdrw.cpp
// Purpose:     implementation of wxOwnerDrawn class
// Author:      David Webster
// Modified by: Marcin Malich
// Created:     10/12/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_OWNER_DRAWN

#include "wx/ownerdrw.h"
#include "wx/os2/private.h"
#include "wx/os2/dcclient.h"

// ----------------------------------------------------------------------------
// constants for base class
// ----------------------------------------------------------------------------

int wxOwnerDrawnBase::ms_defaultMargin = 3;

// ============================================================================
// implementation of wxOwnerDrawn class
// ============================================================================

// draw the item
bool wxOwnerDrawn::OnDrawItem( wxDC& rDC,
                               const wxRect& rRect,
                               wxODAction eAction,
                               wxODStatus eStatus )
{

    //
    // Select the font and draw the text
    // ---------------------------------
    //

    CHARBUNDLE                      vCbnd;
    wxPMDCImpl                      *impl = (wxPMDCImpl*) rDC.GetImpl();
    HPS                             hPS= impl->GetHPS();
    wxFont                          vFont;
    wxColour                        vColBack;
    wxColour                        vColText;
    COLORREF                        vRef;
    RECTL                           vRect = {rRect.x + 4, rRect.y + 1, rRect.x + (rRect.width - 2), rRect.y + rRect.height};

    memset(&vCbnd, 0, sizeof(CHARBUNDLE));

    GetFontToUse(vFont);
    GetColourToUse(eStatus, vColText, vColBack);

    rDC.SetFont(vFont);
    rDC.SetTextBackground(vColBack);
    rDC.SetTextForeground(vColText);
    rDC.SetBackgroundMode(wxTRANSPARENT);

    vCbnd.lColor     = vColText.GetPixel();
    vCbnd.lBackColor = vColBack.GetPixel();
    ::GpiSetAttrs( hPS
                  ,PRIM_CHAR
                  ,CBB_BACK_COLOR | CBB_COLOR
                  ,0
                  ,&vCbnd
                 );
    ::GpiSetBackMix( hPS
                    ,BM_LEAVEALONE
                   );

    //
    // Paint the background
    //
    ::WinFillRect(hPS, &vRect, vColBack.GetPixel());

    //
    // Determine where to draw and leave space for a check-mark.
    //
    int nX = rRect.x + GetMarginWidth();

    //
    // Unfortunately, unlike Win32, PM has no owner drawn specific text
    // drawing methods like ::DrawState that can cleanly handle accel
    // mnemonics and deal, automatically, with various states, so we have
    // to handle them ourselves. Notice Win32 can't handle \t in ownerdrawn
    // strings either.  We cannot handle mnemonics either.  We display
    // them, though, in the hope we can figure them out some day.
    //

    //
    // Display main text
    //
    wxString sFullString = GetItemLabel(); // need to save the original text
    int      nIndex;
    size_t   nWidth;
    size_t   nCharWidth;
    size_t   nHeight;
    bool     bFoundMnemonic = false;

    //
    // Deal with the mnemonic character
    //
    nIndex = sFullString.Find(wxT("~"));
    if (nIndex != -1)
    {
        wxString sTmp = sFullString;

        bFoundMnemonic = true;
        sTmp.Remove(nIndex);
        rDC.GetTextExtent( sTmp
                          ,(wxCoord *)&nWidth
                          ,(wxCoord *)&nHeight
                         );
        sTmp = sFullString[(size_t)(nIndex + 1)];
        rDC.GetTextExtent( sTmp
                          ,(wxCoord *)&nCharWidth
                          ,(wxCoord *)&nHeight
                         );
        sFullString.Replace(sTgt.c_str(), wxEmptyString, true);
    }

    //
    // Draw the main item text sans the accel text
    //
    POINTL                      vPntStart = {nX, rRect.y + 4};
    ::GpiCharStringAt( impl->GetHPS()
                      ,&vPntStart
                      ,sFullString.length()
                      ,sFullString.char_str()
                     );
    if (bFoundMnemonic)
    {
        //
        // Underline the mnemonic -- still won't work, but at least it "looks" right
        //
        wxPen                       vPen;
        POINTL                      vPntEnd = {nX + nWidth + nCharWidth - 3, rRect.y + 2}; //CharWidth is bit wide

        vPntStart.x = nX + nWidth - 1;
        vPntStart.y = rRect.y + 2; // Make it look pretty!
        vPen = wxPen(vColText, 1, wxSOLID); // Assuming we are always black
        rDC.SetPen(vPen);
        ::GpiMove(hPS, &vPntStart);
        ::GpiLine(hPS, &vPntEnd);
    }

    return true;
} // end of wxOwnerDrawn::OnDrawItem

#endif //wxUSE_OWNER_DRAWN
