///////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/menuitem.cpp
// Purpose:     wxMenuItem implementation
// Author:      David Webster
// Modified by:
// Created:     10/10/98
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// headers & declarations
// ============================================================================

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/menuitem.h"
#include "wx/stockitem.h"

#ifndef WX_PRECOMP
    #include "wx/font.h"
    #include "wx/bitmap.h"
    #include "wx/settings.h"
    #include "wx/window.h"
    #include "wx/accel.h"
    #include "wx/menu.h"
    #include "wx/string.h"
    #include "wx/log.h"
#endif

#if wxUSE_ACCEL
    #include "wx/accel.h"
#endif // wxUSE_ACCEL

#include "wx/os2/private.h"

// ---------------------------------------------------------------------------
// macro
// ---------------------------------------------------------------------------

// hide the ugly cast
#define GetHMenuOf(menu)    ((HMENU)menu->GetHMenu())

// conditional compilation
#if wxUSE_OWNER_DRAWN
    #define OWNER_DRAWN_ONLY( code ) if ( IsOwnerDrawn() ) code
#else // !wxUSE_OWNER_DRAWN
    #define OWNER_DRAWN_ONLY( code )
#endif // wxUSE_OWNER_DRAWN/!wxUSE_OWNER_DRAWN

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// dynamic classes implementation
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxMenuItem, wxObject)

// ----------------------------------------------------------------------------
// wxMenuItem
// ----------------------------------------------------------------------------

// ctor & dtor
// -----------

wxMenuItem::wxMenuItem(
  wxMenu*                           pParentMenu
, int                               nId
, const wxString&                   rsText
, const wxString&                   rsHelp
, wxItemKind                        eKind
, wxMenu*                           pSubMenu
)
: wxMenuItemBase( pParentMenu
                 ,nId
                 ,wxPMTextToLabel(rsText)
                 ,rsHelp
                 ,eKind
                 ,pSubMenu
                )
{
    wxASSERT_MSG(pParentMenu != NULL, wxT("a menu item should have a parent"));
    memset(&m_vMenuData, '\0', sizeof(m_vMenuData));
    m_vMenuData.id = (USHORT)nId;

    Init();
} // end of wxMenuItem::wxMenuItem

wxMenuItem::wxMenuItem(
  wxMenu*                           pParentMenu
, int                               nId
, const wxString&                   rsText
, const wxString&                   rsHelp
, bool                              bIsCheckable
, wxMenu*                           pSubMenu
)
: wxMenuItemBase( pParentMenu
                 ,nId
                 ,wxPMTextToLabel(rsText)
                 ,rsHelp
                 ,bIsCheckable ? wxITEM_CHECK : wxITEM_NORMAL
                 ,pSubMenu
                )
{
    wxASSERT_MSG(pParentMenu != NULL, wxT("a menu item should have a parent"));
    memset(&m_vMenuData, '\0', sizeof(m_vMenuData));
    m_vMenuData.id = (USHORT)nId;

    Init();
} // end of wxMenuItem::wxMenuItem

void wxMenuItem::Init()
{
    m_vRadioGroup.m_nStart = -1;
    m_bIsRadioGroupStart = FALSE;

#if  wxUSE_OWNER_DRAWN
    //
    // Set default menu colors
    //
    SetTextColour(wxNullColour);
    SetBackgroundColour(wxNullColour);

    //
    // We don't want normal items be owner-drawn
    //
    SetOwnerDrawn(false);
#endif // wxUSE_OWNER_DRAWN
} // end of wxMenuItem::Init

wxMenuItem::~wxMenuItem()
{
} // end of wxMenuItem::~wxMenuItem

//
// Misc
// ----

//
// Return the id for calling Win32 API functions
//
int wxMenuItem::GetRealId() const
{
    return m_subMenu ? (int)m_subMenu->GetHMenu() : GetId();
} // end of wxMenuItem::GetRealId

//
// Get item state
// --------------
bool wxMenuItem::IsChecked() const
{
    USHORT uFlag = SHORT1FROMMR(::WinSendMsg( GetHMenuOf(m_parentMenu)
                                             ,MM_QUERYITEMATTR
                                             ,MPFROM2SHORT(GetId(), TRUE)
                                             ,MPFROMSHORT(MIA_CHECKED)
                                            ));

    return (uFlag & MIA_CHECKED) == MIA_CHECKED ;
} // end of wxMenuItem::IsChecked

wxString wxMenuItemBase::GetLabelText(
  const wxString&                   rsText
)
{
    wxString                        sLabel;

    for (const wxChar* zPc = rsText.c_str(); *zPc; zPc++)
    {
        if (*zPc == wxT('~') || *zPc == wxT('&'))
        {
            //
            // '~' is the escape character for OS/2PM and '&' is the one for
            // wxWidgets - skip both of them
            //
            continue;
        }
        sLabel += *zPc;
    }
    return sLabel;
} // end of wxMenuItemBase::GetLabelText

//
// Radio group stuff
// -----------------
//
void wxMenuItem::SetAsRadioGroupStart()
{
    m_bIsRadioGroupStart = true;
} // end of wxMenuItem::SetAsRadioGroupStart

void wxMenuItem::SetRadioGroupStart(
  int                               nStart
)
{
    wxASSERT_MSG( !m_bIsRadioGroupStart
                 ,wxT("should only be called for the next radio items")
                );

    m_vRadioGroup.m_nStart = nStart;
} // wxMenuItem::SetRadioGroupStart

void wxMenuItem::SetRadioGroupEnd(
  int                               nEnd
)
{
    wxASSERT_MSG( m_bIsRadioGroupStart
                 ,wxT("should only be called for the first radio item")
                );
    m_vRadioGroup.m_nEnd = nEnd;
} // end of wxMenuItem::SetRadioGroupEnd

// change item state
// -----------------

void wxMenuItem::Enable(
  bool                              bEnable
)
{
    bool                            bOk;

    if (m_isEnabled == bEnable)
        return;
    if (bEnable)
        bOk = (bool)::WinSendMsg( GetHMenuOf(m_parentMenu)
                                 ,MM_SETITEMATTR
                                 ,MPFROM2SHORT(GetRealId(), TRUE)
                                 ,MPFROM2SHORT(MIA_DISABLED, FALSE)
                                );
    else
        bOk = (bool)::WinSendMsg( GetHMenuOf(m_parentMenu)
                                 ,MM_SETITEMATTR
                                 ,MPFROM2SHORT(GetRealId(), TRUE)
                                 ,MPFROM2SHORT(MIA_DISABLED, MIA_DISABLED)
                                );
    if (!bOk)
    {
        wxLogLastError(wxT("EnableMenuItem"));
    }
    wxMenuItemBase::Enable(bEnable);
} // end of wxMenuItem::Enable

void wxMenuItem::Check(
  bool                              bCheck
)
{
    bool                            bOk;

    wxCHECK_RET( IsCheckable(), wxT("only checkable items may be checked") );
    if (m_isChecked == bCheck)
        return;

    HMENU                           hMenu = GetHmenuOf(m_parentMenu);

    if (GetKind() == wxITEM_RADIO)
    {
        //
        // It doesn't make sense to uncheck a radio item - what would this do?
        //
        if (!bCheck)
            return;

        //
        // Get the index of this item in the menu
        //
        const wxMenuItemList&       rItems = m_parentMenu->GetMenuItems();
        int                         nPos = rItems.IndexOf(this);

        wxCHECK_RET( nPos != wxNOT_FOUND
                    ,wxT("menuitem not found in the menu items list?")
                   );

        //
        // Get the radio group range
        //
        int                         nStart;
        int                         nEnd;

        if (m_bIsRadioGroupStart)
        {
            //
            // We already have all information we need
            //
            nStart = nPos;
            nEnd   = m_vRadioGroup.m_nEnd;
        }
        else // next radio group item
        {
            //
            // Get the radio group end from the start item
            //
            nStart = m_vRadioGroup.m_nStart;
            nEnd = rItems.Item(nStart)->GetData()->m_vRadioGroup.m_nEnd;
        }

        //
        // Also uncheck all the other items in this radio group
        //
        wxMenuItemList::compatibility_iterator node = rItems.Item(nStart);

        for (int n = nStart; n <= nEnd && node; n++)
        {
            if (n == nPos)
            {
                ::WinSendMsg( hMenu
                             ,MM_SETITEMATTR
                             ,MPFROM2SHORT(n, TRUE)
                             ,MPFROM2SHORT(MIA_CHECKED, MIA_CHECKED)
                            );
            }
            if (n != nPos)
            {
                node->GetData()->m_isChecked = FALSE;
                ::WinSendMsg( hMenu
                             ,MM_SETITEMATTR
                             ,MPFROM2SHORT(n, TRUE)
                             ,MPFROM2SHORT(MIA_CHECKED, FALSE)
                            );
            }
            node = node->GetNext();
        }
    }
    else // check item
    {
        if (bCheck)
            bOk = (bool)::WinSendMsg( hMenu
                                     ,MM_SETITEMATTR
                                     ,MPFROM2SHORT(GetRealId(), TRUE)
                                     ,MPFROM2SHORT(MIA_CHECKED, MIA_CHECKED)
                                    );
        else
            bOk = (bool)::WinSendMsg( hMenu
                                     ,MM_SETITEMATTR
                                     ,MPFROM2SHORT(GetRealId(), TRUE)
                                     ,MPFROM2SHORT(MIA_CHECKED, FALSE)
                                    );
    }
    if (!bOk)
    {
        wxLogLastError(wxT("CheckMenuItem"));
    }
    wxMenuItemBase::Check(bCheck);
} // end of wxMenuItem::Check

void wxMenuItem::SetItemLabel( const wxString& rText )
{
    //
    // Don't do anything if label didn't change
    //

    wxString                        sText = wxPMTextToLabel(rText);
    if (m_text == sText)
        return;

    // wxMenuItemBase will do stock ID checks
    wxMenuItemBase::SetItemLabel(sText);

    HWND hMenu = GetHmenuOf(m_parentMenu);

    wxCHECK_RET(hMenu, wxT("menuitem without menu"));

#if wxUSE_ACCEL
    m_parentMenu->UpdateAccel(this);
#endif // wxUSE_ACCEL

    USHORT   uId = (USHORT)GetRealId();
    MENUITEM vItem;
    USHORT   uFlagsOld;

    if (!::WinSendMsg( hMenu
                      ,MM_QUERYITEM
                      ,MPFROM2SHORT(uId, TRUE)
                      ,(MPARAM)&vItem
                     ))
    {
        wxLogLastError(wxT("GetMenuState"));
    }
    else
    {
        uFlagsOld = vItem.afStyle;
        if (IsSubMenu())
        {
            uFlagsOld |= MIS_SUBMENU;
        }

        char*                       pData;

#if wxUSE_OWNER_DRAWN
        if (IsOwnerDrawn())
        {
            uFlagsOld |= MIS_OWNERDRAW;
            pData = (char*)this;
        }
        else
#endif  //owner drawn
        {
            uFlagsOld |= MIS_TEXT;
            pData = (char*) m_text.wx_str();
        }

        //
        // Set the style
        //
        if (!::WinSendMsg( hMenu
                          ,MM_SETITEM
                          ,MPFROM2SHORT(uId, TRUE)
                          ,(MPARAM)&vItem
                         ))
        {
            wxLogLastError(wxT("ModifyMenu"));
        }

        //
        // Set the text
        //
        if (::WinSendMsg( hMenu
                         ,MM_SETITEMTEXT
                         ,MPFROMSHORT(uId)
                         ,(MPARAM)pData
                        ))
        {
            wxLogLastError(wxT("ModifyMenu"));
        }
    }
} // end of wxMenuItem::SetText

#if wxUSE_OWNER_DRAWN

wxString wxMenuItem::GetName() const
{
    return GetItemLabelText();
}

bool wxMenuItem::OnMeasureItem( size_t* pWidth, size_t* pHeight )
{
    wxMemoryDC vDC;

    wxString  sStr = GetName();

    //
    // If we have a valid accel string, then pad out
    // the menu string so that the menu and accel string are not
    // placed on top of each other.
    wxString accel = GetItemLabel().AfterFirst(wxT('\t'));
    if (!accel.empty() )
    {
        sStr.Pad(sStr.length()%8);
        sStr += accel;
    }
    vDC.SetFont(GetFont());
    vDC.GetTextExtent( sStr
                      ,(wxCoord *)pWidth
                      ,(wxCoord *)pHeight
                     );
    if (!accel.empty())
    {
        //
        // Measure the accelerator string, and add its width to
        // the total item width, plus 16 (Accelerators are right justified,
        // with the right edge of the text rectangle 16 pixels left of
        // the right edge of the menu)
        //
        int                         nAccelWidth;
        int                         nAccelHeight;

        vDC.GetTextExtent( m_strAccel
                          ,&nAccelWidth
                          ,&nAccelHeight
                         );
        *pWidth += nAccelWidth;
    }

    //
    // Add space at the end of the menu for the submenu expansion arrow.
    // This will also allow offsetting the accel string from the right edge
    //
    *pWidth = (size_t)(*pWidth + GetDefaultMarginWidth() * 1.5);

    //
    // JACS: items still look too tightly packed, so adding 5 pixels.
    //
    (*pHeight) += 5;

    //
    // Ray Gilbert's changes - Corrects the problem of a BMP
    // being placed next to text in a menu item, and the BMP does
    // not match the size expected by the system.  This will
    // resize the space so the BMP will fit.  Without this, BMPs
    // must be no larger or smaller than 16x16.
    //
    if (m_bmpChecked.Ok())
    {
        //
        // Is BMP height larger then text height?
        //
        size_t                      nAdjustedHeight = m_bmpChecked.GetHeight() +
                                                      wxSystemSettings::GetMetric(wxSYS_EDGE_Y);
        if (*pHeight < nAdjustedHeight)
            *pHeight = nAdjustedHeight;

        //
        // Does BMP encroach on default check menu position?
        //
        size_t                      nAdjustedWidth = m_bmpChecked.GetWidth() +
                                                     (wxSystemSettings::GetMetric(wxSYS_EDGE_X) * 2);

        //
        // Do we need to widen margin to fit BMP?
        //
        if ((size_t)GetMarginWidth() < nAdjustedWidth)
            SetMarginWidth(nAdjustedWidth);

        //
        // Add the size of the bitmap to our total size...
        //
        *pWidth += GetMarginWidth();
    }

    //
    // Add the size of the bitmap to our total size - even if we don't have
    // a bitmap we leave room for one...
    //
    *pWidth += GetMarginWidth();

    //
    // Make sure that this item is at least as
    // tall as the user's system settings specify
    //
    const size_t heightStd = 6; // FIXME: get value from the system
    if ( *pHeight < heightStd )
      *pHeight = heightStd;
    m_nHeight = *pHeight;                // remember height for use in OnDrawItem
    return true;
} // end of wxOwnerDrawn::OnMeasureItem

bool wxMenuItem::OnDrawItem( wxDC& rDC,
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
    // Display main text and accel text separately to align better
    //
    wxString sTgt = wxT("\t");
    wxString sFullString = GetItemLabel(); // need to save the original text
    wxString sAccel;
    int      nIndex;
    size_t   nWidth;
    size_t   nCharWidth;
    size_t   nHeight;
    bool     bFoundMnemonic = false;
    bool     bFoundAccel = false;

    //
    // Deal with the tab, extracting the Accel text
    //
    nIndex = sFullString.Find(sTgt);
    if (nIndex != -1)
    {
        bFoundAccel = true;
        sAccel = sFullString.Mid(nIndex + 1);
        sFullString.Remove(nIndex);
    }

    //
    // Deal with the mnemonic character
    //
    sTgt = wxT("~");
    nIndex = sFullString.Find(sTgt);
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

    //
    // Now draw the accel text
    //
    if (bFoundAccel)
    {
        size_t                      nWidth;
        size_t                      nHeight;

        rDC.GetTextExtent( sAccel
                          ,(wxCoord *)&nWidth
                          ,(wxCoord *)&nHeight
                         );
        //
        // Back off the starting position from the right edge
        //
        vPntStart.x = rRect.width - (nWidth + 7);
        vPntStart.y = rRect.y + 4;
        ::GpiCharStringAt( impl->GetHPS()
                          ,&vPntStart
                          ,sAccel.length()
                          ,sAccel.char_str()
                         );
    }

    //
    // Draw the bitmap
    // ---------------
    //
    if (IsCheckable() && !m_bmpChecked.Ok())
    {
        if (eStatus & wxODChecked)
        {
            RECTL                   vRect;
            HBITMAP                 hBmpCheck = ::WinGetSysBitmap(HWND_DESKTOP, SBMP_MENUCHECK);

            vRect.xLeft   = rRect.x;
            vRect.xRight  = rRect.x + GetMarginWidth();
            vRect.yBottom = rRect.y;
            vRect.yTop    = rRect.y + m_nHeight - 3;

            ::WinDrawBitmap( hPS             // PS for this menuitem
                            ,hBmpCheck       // system checkmark
                            ,NULL            // draw the whole bitmap
                            ,(PPOINTL)&vRect // destination -- bottom left corner of the menuitem area
                            ,0L              // ignored
                            ,0L              // draw a bitmap
                            ,DBM_NORMAL      // draw normal size
                           );
        }
    }
    else
    {
        //
        // For uncheckable item we use only the 'checked' bitmap
        //
        wxBitmap vBmp(GetBitmap(IsCheckable() ? ((eStatus & wxODChecked) != 0) : TRUE));

        if (vBmp.Ok())
        {

            wxMemoryDC              vDCMem(&rDC);
            wxMemoryDC*             pOldDC = (wxMemoryDC*)vBmp.GetSelectedInto();

            if(pOldDC != NULL)
            {
                vBmp.SetSelectedInto(NULL);
            }
            vDCMem.SelectObject(vBmp);

            //
            // Center bitmap
            //
            int                     nBmpWidth = vBmp.GetWidth();
            int                     nBmpHeight = vBmp.GetHeight();

            //
            // There should be enough space!
            //
            wxASSERT((nBmpWidth <= rRect.width) && (nBmpHeight <= rRect.height));

            int                     nHeightDiff = m_nHeight - nBmpHeight;

            rDC.Blit( rRect.x + (GetMarginWidth() - nBmpWidth) / 2
                     ,rRect.y + nHeightDiff / 2
                     ,nBmpWidth
                     ,nBmpHeight
                     ,&vDCMem
                     ,0
                     ,0
                     ,wxCOPY
                     ,true
                    );

            if (eStatus & wxODSelected)
            {
                POINTL              vPnt1 = {rRect.x + 1, rRect.y + 3}; // Leave a little background border
                POINTL              vPnt2 = {rRect.x + GetMarginWidth(), rRect.y + m_nHeight - 3};

                LINEBUNDLE          vLine;

                vLine.lColor = vColBack.GetPixel();
                ::GpiSetAttrs( hPS
                              ,PRIM_LINE
                              ,LBB_COLOR
                              ,0
                              ,&vLine
                             );
                ::GpiMove(hPS, &vPnt1);
                ::GpiBox( hPS
                         ,DRO_OUTLINE
                         ,&vPnt2
                         ,0L
                         ,0L
                        );
            }
            vBmp.SetSelectedInto(NULL);
        }
    }
    return true;
} // end of wxOwnerDrawn::OnDrawItem

#endif // wxUSE_OWNER_DRAWN

// ----------------------------------------------------------------------------
// wxMenuItemBase
// ----------------------------------------------------------------------------

wxMenuItem* wxMenuItemBase::New(
  wxMenu*                           pParentMenu
, int                               nId
, const wxString&                   rName
, const wxString&                   rHelp
, wxItemKind                        kind
, wxMenu*                           pSubMenu
)
{
    return new wxMenuItem( pParentMenu
                          ,nId
                          ,rName
                          ,rHelp
                          ,kind
                          ,pSubMenu
                         );
} // end of wxMenuItemBase::New
