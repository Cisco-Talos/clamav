///////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/listbox.cpp
// Purpose:     wxListBox
// Author:      David Webster
// Modified by:
// Created:     10/09/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_LISTBOX

#include "wx/listbox.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/settings.h"
    #include "wx/brush.h"
    #include "wx/font.h"
    #include "wx/dc.h"
    #include "wx/dcscreen.h"
    #include "wx/utils.h"
    #include "wx/scrolwin.h"
    #include "wx/log.h"
    #include "wx/window.h"
#endif

#include "wx/os2/dcclient.h"
#include "wx/os2/private.h"

#define INCL_M
#include <os2.h>

#if wxUSE_OWNER_DRAWN
    #include  "wx/ownerdrw.h"
#endif

IMPLEMENT_DYNAMIC_CLASS(wxListBox, wxControlWithItems)

// ============================================================================
// list box item declaration and implementation
// ============================================================================

#if wxUSE_OWNER_DRAWN

class wxListBoxItem : public wxOwnerDrawn
{
public:
    wxListBoxItem(wxListBox *parent)
        { m_parent = parent; }

    wxListBox *GetParent() const
        { return m_parent; }

    int GetIndex() const
        { return m_parent->GetItemIndex(const_cast<wxListBoxItem*>(this)); }

    wxString GetName() const
        { return m_parent->GetString(GetIndex()); }

private:
    wxListBox *m_parent;
};

wxOwnerDrawn* wxListBox::CreateItem( size_t WXUNUSED(n) )
{
    return new wxListBoxItem(this);
} // end of wxListBox::CreateItem

#endif  //USE_OWNER_DRAWN

// ============================================================================
// list box control implementation
// ============================================================================

// Listbox item
wxListBox::wxListBox()
{
    m_nNumItems = 0;
    m_nSelected = 0;
} // end of wxListBox::wxListBox

bool wxListBox::Create(
  wxWindow*                         pParent
, wxWindowID                        vId
, const wxPoint&                    rPos
, const wxSize&                     rSize
, const wxArrayString&              asChoices
, long                              lStyle
, const wxValidator&                rValidator
, const wxString&                   rsName
)
{
    wxCArrayString chs(asChoices);

    return Create(pParent, vId, rPos, rSize, chs.GetCount(), chs.GetStrings(),
                  lStyle, rValidator, rsName);
}

bool wxListBox::Create( wxWindow* pParent,
                        wxWindowID vId,
                        const wxPoint& rPos,
                        const wxSize& rSize,
                        int n,
                        const wxString asChoices[],
                        long lStyle,
                        const wxValidator& rValidator,
                        const wxString& rsName )
{
    m_nNumItems = 0;
    m_hWnd      = 0;
    m_nSelected = 0;

    SetName(rsName);
#if wxUSE_VALIDATORS
    SetValidator(rValidator);
#endif

    if (pParent)
        pParent->AddChild(this);

    wxSystemSettings                vSettings;

    SetBackgroundColour(vSettings.GetColour(wxSYS_COLOUR_WINDOW));
    SetForegroundColour(pParent->GetForegroundColour());

    m_windowId = (vId == -1) ? (int)NewControlId() : vId;

    int                             nX      = rPos.x;
    int                             nY      = rPos.y;
    int                             nWidth  = rSize.x;
    int                             nHeight = rSize.y;

    m_windowStyle = lStyle;

    lStyle = WS_VISIBLE;

    if (m_windowStyle & wxCLIP_SIBLINGS )
        lStyle |= WS_CLIPSIBLINGS;
    if (m_windowStyle & wxLB_MULTIPLE)
        lStyle |= LS_MULTIPLESEL;
    else if (m_windowStyle & wxLB_EXTENDED)
        lStyle |= LS_EXTENDEDSEL;
    if (m_windowStyle & wxLB_HSCROLL)
        lStyle |= LS_HORZSCROLL;
    if (m_windowStyle & wxLB_OWNERDRAW)
        lStyle |= LS_OWNERDRAW;

    //
    // Without this style, you get unexpected heights, so e.g. constraint layout
    // doesn't work properly
    //
    lStyle |= LS_NOADJUSTPOS;

    m_hWnd = (WXHWND)::WinCreateWindow( GetWinHwnd(pParent) // Parent
                                       ,WC_LISTBOX          // Default Listbox class
                                       ,"LISTBOX"           // Control's name
                                       ,lStyle              // Initial Style
                                       ,0, 0, 0, 0          // Position and size
                                       ,GetWinHwnd(pParent) // Owner
                                       ,HWND_TOP            // Z-Order
                                       ,(HMENU)m_windowId   // Id
                                       ,NULL                // Control Data
                                       ,NULL                // Presentation Parameters
                                      );
    if (m_hWnd == 0)
    {
        return false;
    }

    //
    // Subclass again for purposes of dialog editing mode
    //
    SubclassWin(m_hWnd);

    LONG                            lUi;

    for (lUi = 0; lUi < (LONG)n; lUi++)
    {
        Append(asChoices[lUi]);
    }
    wxFont*                          pTextFont = new wxFont( 10
                                                            ,wxMODERN
                                                            ,wxNORMAL
                                                            ,wxNORMAL
                                                           );
    SetFont(*pTextFont);

    //
    // Set OS/2 system colours for Listbox items and highlighting
    //
    wxColour                        vColour;

    vColour = wxSystemSettingsNative::GetColour(wxSYS_COLOUR_HIGHLIGHTTEXT);

    LONG                            lColor = (LONG)vColour.GetPixel();

    ::WinSetPresParam( m_hWnd
                      ,PP_HILITEFOREGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    vColour = wxSystemSettingsNative::GetColour(wxSYS_COLOUR_HIGHLIGHT);
    lColor = (LONG)vColour.GetPixel();
    ::WinSetPresParam( m_hWnd
                      ,PP_HILITEBACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );

    SetXComp(0);
    SetYComp(0);
    SetSize( nX
            ,nY
            ,nWidth
            ,nHeight
           );
    delete pTextFont;
    return true;
} // end of wxListBox::Create

wxListBox::~wxListBox()
{
    Clear();
} // end of wxListBox::~wxListBox

void wxListBox::SetupColours()
{
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW));
    SetForegroundColour(GetParent()->GetForegroundColour());
} // end of wxListBox::SetupColours

// ----------------------------------------------------------------------------
// implementation of wxListBoxBase methods
// ----------------------------------------------------------------------------

void wxListBox::DoSetFirstItem(int N)
{
    wxCHECK_RET( IsValid(N),
                 wxT("invalid index in wxListBox::SetFirstItem") );

    ::WinSendMsg(GetHwnd(), LM_SETTOPINDEX, MPFROMLONG(N), (MPARAM)0);
} // end of wxListBox::DoSetFirstItem

void wxListBox::DoDeleteOneItem(unsigned int n)
{
    wxCHECK_RET( IsValid(n),
                 wxT("invalid index in wxListBox::Delete") );

#if wxUSE_OWNER_DRAWN
    delete m_aItems[n];
    m_aItems.RemoveAt(n);
#endif // wxUSE_OWNER_DRAWN

    ::WinSendMsg(GetHwnd(), LM_DELETEITEM, (MPARAM)n, (MPARAM)0);
    m_nNumItems--;
} // end of wxListBox::DoSetFirstItem

int wxListBox::DoInsertItems(const wxArrayStringsAdapter & items,
                             unsigned int pos,
                             void **clientData,
                             wxClientDataType type)
{
    long lIndex = 0;
    LONG lIndexType = 0;
    bool incrementPos = false;

    if (IsSorted())
        lIndexType = LIT_SORTASCENDING;
    else if (pos == GetCount())
        lIndexType = LIT_END;
    else
    {
        lIndexType = (LONG)pos;
        incrementPos = true;
    }

    int n = wxNOT_FOUND;

    unsigned int count = items.GetCount();
    for (unsigned int i = 0; i < count; i++)
    {
        n = (int)::WinSendMsg(GetHwnd(), LM_INSERTITEM, (MPARAM)lIndexType, (MPARAM)items[i].wx_str());
        if (n < 0)
        {
            wxLogLastError(wxT("WinSendMsg(LM_INSERTITEM)"));
            n = wxNOT_FOUND;
            break;
        }
        ++m_nNumItems;

#if wxUSE_OWNER_DRAWN
        if (HasFlag(wxLB_OWNERDRAW))
        {
            wxOwnerDrawn* pNewItem = CreateItem(n); // dummy argument
            pNewItem->SetFont(GetFont());
            m_aItems.Insert(pNewItem, n);
        }
#endif
        AssignNewItemClientData(n, clientData, i, type);

        if (incrementPos)
            ++lIndexType;
    }

    return n;
} // end of wxListBox::DoInsertAppendItemsWithData

void wxListBox::DoClear()
{
#if wxUSE_OWNER_DRAWN
    if ( m_windowStyle & wxLB_OWNERDRAW )
    {
        WX_CLEAR_ARRAY(m_aItems);
    }
#endif // wxUSE_OWNER_DRAWN
    ::WinSendMsg(GetHwnd(), LM_DELETEALL, (MPARAM)0, (MPARAM)0);

    m_nNumItems = 0;
} // end of wxListBox::Clear

void wxListBox::DoSetSelection( int N, bool bSelect)
{
    wxCHECK_RET( IsValid(N),
                 wxT("invalid index in wxListBox::SetSelection") );
    ::WinSendMsg( GetHwnd()
                 ,LM_SELECTITEM
                 ,MPFROMLONG(N)
                 ,(MPARAM)bSelect
                );
    if(m_windowStyle & wxLB_OWNERDRAW)
        Refresh();
} // end of wxListBox::SetSelection

bool wxListBox::IsSelected( int N ) const
{
    wxCHECK_MSG( IsValid(N), false,
                 wxT("invalid index in wxListBox::Selected") );

    LONG                            lItem;

    if (GetWindowStyleFlag() & wxLB_EXTENDED)
    {
        if (N == 0)
            lItem = LONGFROMMR(::WinSendMsg(GetHwnd(), LM_QUERYSELECTION, (MPARAM)LIT_FIRST, (MPARAM)0));
        else
            lItem = LONGFROMMR(::WinSendMsg(GetHwnd(), LM_QUERYSELECTION, (MPARAM)(N - 1), (MPARAM)0));
    }
    else
    {
        lItem = LONGFROMMR(::WinSendMsg(GetHwnd(), LM_QUERYSELECTION, (MPARAM)LIT_FIRST, (MPARAM)0));
    }
    return (lItem == (LONG)N && lItem != LIT_NONE);
} // end of wxListBox::IsSelected

void* wxListBox::DoGetItemClientData(unsigned int n) const
{
    wxCHECK_MSG( IsValid(n), NULL,
                 wxT("invalid index in wxListBox::GetClientData") );

    return((void *)::WinSendMsg(GetHwnd(), LM_QUERYITEMHANDLE, MPFROMLONG(n), (MPARAM)0));
} // end of wxListBox::DoGetItemClientData

void wxListBox::DoSetItemClientData(unsigned int n, void* pClientData)
{
    wxCHECK_RET( IsValid(n),
                 wxT("invalid index in wxListBox::SetClientData") );

    ::WinSendMsg(GetHwnd(), LM_SETITEMHANDLE, MPFROMLONG(n), MPFROMP(pClientData));
} // end of wxListBox::DoSetItemClientData

bool wxListBox::HasMultipleSelection() const
{
    return (m_windowStyle & wxLB_MULTIPLE) || (m_windowStyle & wxLB_EXTENDED);
} // end of wxListBox::HasMultipleSelection

int wxListBox::GetSelections( wxArrayInt& raSelections ) const
{
    int  nCount = 0;
    LONG lItem;


    raSelections.Empty();
    if (HasMultipleSelection())
    {
        lItem = LONGFROMMR(::WinSendMsg( GetHwnd()
                                        ,LM_QUERYSELECTION
                                        ,(MPARAM)LIT_FIRST
                                        ,(MPARAM)0
                                       )
                          );
        if (lItem != LIT_NONE)
        {
            nCount++;
            while ((lItem = LONGFROMMR(::WinSendMsg( GetHwnd()
                                                    ,LM_QUERYSELECTION
                                                    ,(MPARAM)lItem
                                                    ,(MPARAM)0
                                                   )
                                      )) != LIT_NONE)
            {
                nCount++;
            }
            raSelections.Alloc(nCount);
            lItem = LONGFROMMR(::WinSendMsg( GetHwnd()
                                            ,LM_QUERYSELECTION
                                            ,(MPARAM)LIT_FIRST
                                            ,(MPARAM)0
                                           )
                              );

            raSelections.Add((int)lItem);
            while ((lItem = LONGFROMMR(::WinSendMsg( GetHwnd()
                                                    ,LM_QUERYSELECTION
                                                    ,(MPARAM)lItem
                                                    ,(MPARAM)0
                                                   )
                                      )) != LIT_NONE)
            {
                raSelections.Add((int)lItem);
            }
            return nCount;
        }
    }
    else  // single-selection listbox
    {
        lItem = LONGFROMMR(::WinSendMsg( GetHwnd()
                                        ,LM_QUERYSELECTION
                                        ,(MPARAM)LIT_FIRST
                                        ,(MPARAM)0
                                       )
                          );
        raSelections.Add((int)lItem);
        return 1;
    }
    return 0;
} // end of wxListBox::GetSelections

int wxListBox::GetSelection() const
{
    wxCHECK_MSG( !HasMultipleSelection(),
                 -1,
                 wxT("GetSelection() can't be used with multiple-selection "
                    "listboxes, use GetSelections() instead.") );

    return(LONGFROMMR(::WinSendMsg( GetHwnd()
                                   ,LM_QUERYSELECTION
                                   ,(MPARAM)LIT_FIRST
                                   ,(MPARAM)0
                                  )
                     ));
} // end of wxListBox::GetSelection

wxString wxListBox::GetString(unsigned int n) const
{
    LONG     lLen = 0;
    wxChar*  zBuf;
    wxString sResult;

    wxCHECK_MSG( IsValid(n), wxEmptyString,
                 wxT("invalid index in wxListBox::GetClientData") );

    lLen = LONGFROMMR(::WinSendMsg(GetHwnd(), LM_QUERYITEMTEXTLENGTH, (MPARAM)n, (MPARAM)0));
    zBuf = new wxChar[lLen + 1];
    ::WinSendMsg(GetHwnd(), LM_QUERYITEMTEXT, MPFROM2SHORT((SHORT)n, (SHORT)lLen), (MPARAM)zBuf);
    zBuf[lLen] = '\0';
    sResult = zBuf;
    delete [] zBuf;
    return sResult;
} // end of wxListBox::GetString

void wxListBox::SetString(unsigned int n, const wxString& rsString)
{
    wxCHECK_RET( IsValid(n),
                 wxT("invalid index in wxListBox::SetString") );

    //
    // Remember the state of the item
    //
    bool           bWasSelected = IsSelected(n);
    void*          pOldData = NULL;
    wxClientData*  pOldObjData = NULL;

    if ( HasClientUntypedData() )
        pOldData = GetClientData(n);
    else if ( HasClientObjectData() )
        pOldObjData = GetClientObject(n);

    //
    // Delete and recreate it
    //
    ::WinSendMsg( GetHwnd()
                 ,LM_DELETEITEM
                 ,(MPARAM)n
                 ,(MPARAM)0
                );

    int nNewN = n;

    if (n == (m_nNumItems - 1))
        nNewN = -1;

    ::WinSendMsg( GetHwnd()
                 ,LM_INSERTITEM
                 ,(MPARAM)nNewN
                 ,(MPARAM)rsString.wx_str()
                );

    //
    // Restore the client data
    //
    if (pOldData)
        SetClientData(n, pOldData);
    else if (pOldObjData)
        SetClientObject(n, pOldObjData);

    //
    // We may have lost the selection
    //
    if (bWasSelected)
        Select(n);
} // end of wxListBox::SetString

unsigned int wxListBox::GetCount() const
{
    return m_nNumItems;
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

wxSize wxListBox::DoGetBestSize() const
{
    //
    // Find the widest string
    //
    int        nLine;
    int        nListbox = 0;
    int        nCx;
    int        nCy;
    wxFont     vFont = (wxFont)GetFont();

    for (unsigned int i = 0; i < m_nNumItems; i++)
    {
        wxString vStr(GetString(i));

        GetTextExtent( vStr, &nLine, NULL );
        if (nLine > nListbox)
            nListbox = nLine;
    }

    //
    // Give it some reasonable default value if there are no strings in the
    // list.
    //
    if (nListbox == 0)
        nListbox = 100;

    //
    // The listbox should be slightly larger than the widest string
    //
    wxGetCharSize( GetHWND()
                  ,&nCx
                  ,&nCy
                  ,&vFont
                 );
    nListbox += 3 * nCx;

    int hListbox = EDIT_HEIGHT_FROM_CHAR_HEIGHT(nCy) * (wxMax(m_nNumItems, 7));

    return wxSize( nListbox
                  ,hListbox
                 );
} // end of wxListBox::DoGetBestSize

// ----------------------------------------------------------------------------
// callbacks
// ----------------------------------------------------------------------------

bool wxListBox::OS2Command(
  WXUINT                            uParam
, WXWORD                            WXUNUSED(wId))
{
    wxEventType                     eEvtType;

    if (uParam == LN_SELECT)
    {
        eEvtType = wxEVT_COMMAND_LISTBOX_SELECTED;
    }
    else if (uParam == LN_ENTER)
    {
        eEvtType = wxEVT_COMMAND_LISTBOX_DOUBLECLICKED;
    }
    else
    {
        //
        // Some event we're not interested in
        //
        return false;
    }
    wxCommandEvent                  vEvent( eEvtType
                                           ,m_windowId
                                          );

    vEvent.SetEventObject(this);

    wxArrayInt aSelections;
    int        n;
    int        nCount = GetSelections(aSelections);

    if (nCount > 0)
    {
        n = aSelections[0];
        if (HasClientObjectData())
            vEvent.SetClientObject(GetClientObject(n));
        else if ( HasClientUntypedData() )
            vEvent.SetClientData(GetClientData(n));
        vEvent.SetString(GetString(n));
    }
    else
    {
        n = -1;
    }
    vEvent.SetInt(n);
    return HandleWindowEvent(vEvent);
} // end of wxListBox::OS2Command

// ----------------------------------------------------------------------------
// wxCheckListBox support
// ----------------------------------------------------------------------------

#if wxUSE_OWNER_DRAWN

//
// Drawing
// -------
//
#define OWNER_DRAWN_LISTBOX_EXTRA_SPACE    (1)

long wxListBox::OS2OnMeasure(WXMEASUREITEMSTRUCT* pItem)
{
    if (!pItem)
        pItem = (WXMEASUREITEMSTRUCT*)new OWNERITEM;

    POWNERITEM                      pMeasureStruct = (POWNERITEM)pItem;
    wxScreenDC                      vDc;

    //
    // Only owner-drawn control should receive this message
    //
    wxCHECK( ((m_windowStyle & wxLB_OWNERDRAW) == wxLB_OWNERDRAW), FALSE );

    vDc.SetFont(GetFont());

    wxCoord                         vHeight;
    wxCoord                         vWidth;

    GetSize( &vWidth
            ,NULL
           );

    pMeasureStruct->rclItem.xRight = (USHORT)vWidth;
    pMeasureStruct->rclItem.xLeft  = 0;
    pMeasureStruct->rclItem.yTop   = 0;
    pMeasureStruct->rclItem.yBottom = 0;

    vHeight = (wxCoord)(vDc.GetCharHeight() * 2.5);
    pMeasureStruct->rclItem.yTop  = (USHORT)vHeight;

    return long(MRFROM2SHORT((USHORT)vHeight, (USHORT)vWidth));
} // end of wxListBox::OS2OnMeasure

bool wxListBox::OS2OnDraw (
  WXDRAWITEMSTRUCT*                 pItem
)
{
    POWNERITEM                      pDrawStruct = (POWNERITEM)pItem;
    int                             eAction = 0;
    int                             eStatus = 0;

    //
    // Only owner-drawn control should receive this message
    //
    wxCHECK(((m_windowStyle & wxLB_OWNERDRAW) == wxLB_OWNERDRAW), false);


    //
    // The item may be -1 for an empty listbox
    //
    if (pDrawStruct->idItem == -1L)
        return false;

    wxListBoxItem* pData = (wxListBoxItem*)m_aItems[pDrawStruct->idItem];

    wxClientDC    vDc(this);
    wxPMDCImpl *impl = (wxPMDCImpl*) vDc.GetImpl();
    wxPoint pt1( pDrawStruct->rclItem.xLeft, pDrawStruct->rclItem.yTop );
    wxPoint pt2( pDrawStruct->rclItem.xRight, pDrawStruct->rclItem.yBottom );
    wxRect  vRect( pt1, pt2 );

    impl->SetHPS(pDrawStruct->hps);

    if (pDrawStruct->fsAttribute == pDrawStruct->fsAttributeOld)
    {
        //
        // Entire Item needs to be redrawn (either it has reappeared from
        // behind another window or is being displayed for the first time
        //
        eAction = wxOwnerDrawn::wxODDrawAll;

        if (pDrawStruct->fsAttribute & MIA_HILITED)
        {
            //
            // If it is currently selected we let the system handle it
            //
            eStatus |= wxOwnerDrawn::wxODSelected;
        }
        if (pDrawStruct->fsAttribute & MIA_CHECKED)
        {
            //
            // If it is currently checked we draw our own
            //
            eStatus |= wxOwnerDrawn::wxODChecked;
            pDrawStruct->fsAttributeOld = pDrawStruct->fsAttribute &= ~MIA_CHECKED;
        }
        if (pDrawStruct->fsAttribute & MIA_DISABLED)
        {
            //
            // If it is currently disabled we let the system handle it
            //
            eStatus |= wxOwnerDrawn::wxODDisabled;
        }
        //
        // Don't really care about framed (indicationg focus) or NoDismiss
        //
    }
    else
    {
        if (pDrawStruct->fsAttribute & MIA_HILITED)
        {
            eAction = wxOwnerDrawn::wxODDrawAll;
            eStatus |= wxOwnerDrawn::wxODSelected;
            //
            // Keep the system from trying to highlight with its bogus colors
            //
            pDrawStruct->fsAttributeOld = pDrawStruct->fsAttribute &= ~MIA_HILITED;
        }
        else if (!(pDrawStruct->fsAttribute & MIA_HILITED))
        {
            eAction = wxOwnerDrawn::wxODDrawAll;
            eStatus = 0;
            //
            // Keep the system from trying to highlight with its bogus colors
            //
            pDrawStruct->fsAttribute = pDrawStruct->fsAttributeOld &= ~MIA_HILITED;
        }
        else
        {
            //
            // For now we don't care about anything else
            // just ignore the entire message!
            //
            return true;
        }
    }
    return pData->OnDrawItem( vDc
                             ,vRect
                             ,(wxOwnerDrawn::wxODAction)eAction
                             ,(wxOwnerDrawn::wxODStatus)(eStatus | wxOwnerDrawn::wxODHidePrefix)
                            );
} // end of wxListBox::OS2OnDraw

#endif // ndef for wxUSE_OWNER_DRAWN

#endif // wxUSE_LISTBOX
