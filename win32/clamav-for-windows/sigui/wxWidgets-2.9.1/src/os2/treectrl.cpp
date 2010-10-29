/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/treectrl.cpp
// Purpose:     wxTreeCtrl
// Author:      Julian Smart
// Modified by: Vadim Zeitlin to be less MSW-specific on 10.10.98
// Created:     1997
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_TREECTRL

#include "wx/treectrl.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/settings.h"
#endif

#include "wx/os2/private.h"

#include "wx/imaglist.h"

// a macro to hide the ugliness of nested casts
#define HITEM(item)     (HTREEITEM)(WXHTREEITEM)(item)

// the native control doesn't support multiple selections under MSW and we
// have 2 ways to emulate them: either using TVS_CHECKBOXES style and let
// checkboxes be the selection status (checked == selected) or by really
// emulating everything, i.e. intercepting mouse and key events &c. The first
// approach is much easier but doesn't work with comctl32.dll < 4.71 and also
// looks quite ugly.
#define wxUSE_CHECKBOXES_IN_MULTI_SEL_TREE 0

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

typedef struct _MYRECORD
{
    RECORDCORE                      m_vRecord;
    ULONG                           m_ulItemId;
    ULONG                           m_ulUserData;
} MYRECORD, *PMYRECORD;

struct wxTreeViewItem : public MYRECORD
{
    wxTreeViewItem(const wxTreeItemId& rItem)
    {
        m_ulItemId = (ULONG)rItem.m_pItem;
    }
}; // end of STRUCT wxTreeViewItem

class wxTreeItemInternalData
{
public:

    wxTreeItemInternalData() {}
    ~wxTreeItemInternalData()
    {
        wxDELETE(m_pAttr);
    }

    wxTreeItemAttr*                 m_pAttr;
    WXLPARAM                        m_lParam; // user data
#if defined(C_CM_COS232)
    PMYRECORD                       m_pMyRecord; // so we can set the m_ulUserData to 0 when this is deleted
#endif
}; // end of CLASS wxTreeItemInternalData

void BumpTreeRecordIds (
  HWND                              hWnd
, PMYRECORD                         pRecord
)
{
    while(pRecord)
    {
        pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( hWnd
                                                      ,CM_QUERYRECORD
                                                      ,MPFROMP(pRecord)
                                                      ,MPFROM2SHORT(CMA_NEXT, CMA_ITEMORDER)
                                                     ));
        if (pRecord)
            pRecord->m_ulItemId++;
    }
} // end of BumpTreeRecordIds

PMYRECORD FindOS2TreeRecordByID (
  HWND                              hWnd
, long                              lItemId
)
{
    PMYRECORD                       pRecord = NULL;
    CNRINFO                         vCnrInfo;
    unsigned long                   i;

    if (!::WinSendMsg( hWnd
                      ,CM_QUERYCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)(USHORT)sizeof(CNRINFO)
                     ))
        return NULL;
    for (i = 0; i < vCnrInfo.cRecords; i++)
    {
        if (i == 0)
            pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( hWnd
                                                          ,CM_QUERYRECORD
                                                          ,MPFROMP(pRecord)
                                                          ,MPFROM2SHORT(CMA_FIRST, CMA_ITEMORDER)
                                                         ));
        else
            pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( hWnd
                                                          ,CM_QUERYRECORD
                                                          ,MPFROMP(pRecord)
                                                          ,MPFROM2SHORT(CMA_NEXT, CMA_ITEMORDER)
                                                         ));
        if (!pRecord)
            return NULL;
        if (pRecord->m_ulItemId == (ULONG)lItemId)
            break;
    }
    return pRecord;
} // end of FindOS2ListRecordByID



class wxTreeTraversal
{
public:
    wxTreeTraversal(const wxTreeCtrl* pTree)
    {
        m_pTree = pTree;
    }

    //
    // Do traverse the tree: visit all items (recursively by default) under the
    // given one; return true if all items were traversed or false if the
    // traversal was aborted because OnVisit returned false
    //
    bool DoTraverse( const wxTreeItemId& rRoot
                    ,bool                bRecursively = true
                   );

    //
    // Override this function to do whatever is needed for each item, return
    // false to stop traversing
    //
    virtual bool OnVisit(const wxTreeItemId& rItem) = 0;

protected:
    const wxTreeCtrl* GetTree(void) const { return m_pTree; }

private:
    bool Traverse( const wxTreeItemId& rRoot
                  ,bool                bRecursively
                 );

    const wxTreeCtrl*               m_pTree;
    wxDECLARE_NO_COPY_CLASS(wxTreeTraversal);
}; // end of CLASS wxTreeTraversal

//
// Internal class for getting the selected items
//
class TraverseSelections : public wxTreeTraversal
{
public:
    TraverseSelections( const wxTreeCtrl*   pTree
                       ,wxArrayTreeItemIds& raSelections
                      )
                      : wxTreeTraversal(pTree)
                      , m_aSelections(raSelections)
    {
        m_aSelections.Empty();
        DoTraverse(pTree->GetRootItem());
    }

    virtual bool OnVisit(const wxTreeItemId& rItem)
    {
        //
        // Can't visit a virtual node.
        //
        if ((GetTree()->GetRootItem() == rItem) && (GetTree()->GetWindowStyle() & wxTR_HIDE_ROOT))
        {
            return true;
        }
        PMYRECORD                   pRecord = FindOS2TreeRecordByID( (HWND)GetTree()->GetHWND()
                                                                    ,rItem.m_pItem
                                                                   );
        if (pRecord->m_vRecord.flRecordAttr & CRA_SELECTED)
        {
            m_aSelections.Add(rItem);
        }
        return true;
    }

    size_t GetCount(void) const { return m_aSelections.GetCount(); }

private:
    wxArrayTreeItemIds&             m_aSelections;
}; // end of CLASS TraverseSelections

//
// Internal class for counting tree items
//
class TraverseCounter : public wxTreeTraversal
{
public:
    TraverseCounter( const wxTreeCtrl*   pTree
                    ,const wxTreeItemId& rRoot
                    ,bool                bRecursively
                   )
                   : wxTreeTraversal(pTree)
    {
        m_nCount = 0;
        DoTraverse(rRoot, bRecursively);
    }

    virtual bool OnVisit(const wxTreeItemId& WXUNUSED(rItem))
    {
        m_nCount++;
        return true;
    }

    size_t GetCount(void) const { return m_nCount; }

private:
    size_t                          m_nCount;
}; // end of CLASS TraverseCounter

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxTreeCtrl, wxControl)

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// indices in gs_expandEvents table below
enum
{
    IDX_COLLAPSE,
    IDX_EXPAND,
    IDX_WHAT_MAX
};

enum
{
    IDX_DONE,
    IDX_DOING,
    IDX_HOW_MAX
};

// handy table for sending events - it has to be initialized during run-time
// now so can't be const any more
static /* const */ wxEventType gs_expandEvents[IDX_WHAT_MAX][IDX_HOW_MAX];

/*
   but logically it's a const table with the following entries:
=
{
    { wxEVT_COMMAND_TREE_ITEM_COLLAPSED, wxEVT_COMMAND_TREE_ITEM_COLLAPSING },
    { wxEVT_COMMAND_TREE_ITEM_EXPANDED,  wxEVT_COMMAND_TREE_ITEM_EXPANDING  }
};
*/

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// tree traversal
// ----------------------------------------------------------------------------

bool wxTreeTraversal::DoTraverse (
  const wxTreeItemId&               rRoot
, bool                              bRecursively
)
{
    if (!OnVisit(rRoot))
        return false;

    return Traverse( rRoot
                    ,bRecursively
                   );
} // end of wxTreeTraversal::DoTraverse

bool wxTreeTraversal::Traverse (
  const wxTreeItemId&               rRoot
, bool                              bRecursively
)
{
    long                            lCookie;
    wxTreeItemId                    vChild = m_pTree->GetFirstChild( rRoot
                                                                    ,lCookie
                                                                   );
    while (vChild.IsOk())
    {
        //
        // Depth first traversal
        //
        if (bRecursively && !Traverse(vChild, true))
            return false;
        if (!OnVisit(vChild))
            return false;
        vChild = m_pTree->GetNextChild( rRoot
                                       ,lCookie
                                      );
    }
    return true;
} // end of wxTreeTraversal::Traverse

// ----------------------------------------------------------------------------
// construction and destruction
// ----------------------------------------------------------------------------

void wxTreeCtrl::Init ()
{
    m_pImageListNormal     = NULL;
    m_pImageListState      = NULL;
    m_bOwnsImageListNormal = false;
    m_bOwnsImageListState  = false;
    m_bHasAnyAttr          = false;
    m_pDragImage           = NULL;

    //
    // Initialize the global array of events now as it can't be done statically
    // with the wxEVT_XXX values being allocated during run-time only
    //
    gs_expandEvents[IDX_COLLAPSE][IDX_DONE]  = wxEVT_COMMAND_TREE_ITEM_COLLAPSED;
    gs_expandEvents[IDX_COLLAPSE][IDX_DOING] = wxEVT_COMMAND_TREE_ITEM_COLLAPSING;
    gs_expandEvents[IDX_EXPAND][IDX_DONE]    = wxEVT_COMMAND_TREE_ITEM_EXPANDED;
    gs_expandEvents[IDX_EXPAND][IDX_DOING]   = wxEVT_COMMAND_TREE_ITEM_EXPANDING;
} // end of wxTreeCtrl::Init

bool wxTreeCtrl::Create (
  wxWindow*                         pParent
, wxWindowID                        vId
, const wxPoint&                    rPos
, const wxSize&                     rSize
, long                              lStyle
, const wxValidator&                rValidator
, const wxString&                   rsName
)
{
    CNRINFO                         vCnrInfo;

    Init();
    if (!CreateControl( pParent
                       ,vId
                       ,rPos
                       ,rSize
                       ,lStyle
                       ,rValidator
                       ,rsName
                      ))
        return false;

    DWORD                           dwStyle = WS_VISIBLE | WS_TABSTOP;

    if (m_windowStyle & wxCLIP_SIBLINGS)
        dwStyle |= WS_CLIPSIBLINGS;

    // Create the tree control.
    if (!OS2CreateControl( "CONTAINER"
                          ,dwStyle
                         ))
        return false;

    //
    // Now set the display attributes to show a TREE/ICON view of the
    // OS/2 Container
    //
    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)(USHORT)sizeof(CNRINFO)
                     ))

    vCnrInfo.flWindowAttr = CV_TREE|CV_ICON;
    vCnrInfo.flWindowAttr |= CA_DRAWBITMAP;
    if (m_windowStyle & wxTR_NO_LINES)
        vCnrInfo.flWindowAttr |= CA_TREELINE;

    ::WinSendMsg( GetHWND()
                 ,CM_SETCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)CMA_FLWINDOWATTR
                );

    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW));
    SetForegroundColour(wxWindow::GetParent()->GetForegroundColour());
    SetFont(*wxSMALL_FONT);
    SetXComp(0);
    SetYComp(0);
    SetSize( rPos.x
            ,rPos.y
            ,rSize.x
            ,rSize.y
           );
    return true;
} // end of wxTreeCtrl::Create

wxTreeCtrl::~wxTreeCtrl ()
{
    //
    // Delete any attributes
    //
    if (m_bHasAnyAttr)
    {
        for (wxNode* pNode = m_vAttrs.Next(); pNode; pNode = m_vAttrs.Next())
        {
            delete (wxTreeItemAttr *)pNode->Data();
        }
        m_bHasAnyAttr = false;
    }
    DeleteTextCtrl();

    //
    // Delete user data to prevent memory leaks
    // also deletes hidden root node storage.
    //
    DeleteAllItems();
    if (m_bOwnsImageListNormal)
        delete m_pImageListNormal;
    if (m_bOwnsImageListState)
        delete m_pImageListState;
} // end of wxTreeCtrl::~wxTreeCtrl

// ----------------------------------------------------------------------------
// accessors
// ----------------------------------------------------------------------------

//
// simple wrappers which add error checking in debug mode.  These methods
// assume the items are properly filled out already.  If not, you get errors
//
bool wxTreeCtrl::DoGetItem (
  wxTreeViewItem*                   pTvItem
) const
{
    PMYRECORD                       pRecord = FindOS2TreeRecordByID( GetHWND()
                                                                    ,pTvItem->m_ulItemId
                                                                   );

    if (!pRecord)
    {
        wxLogLastError(wxT("Item not obtained"));
        return false;
    }
    return true;
} // end of wxTreeCtrl::DoGetItem

void wxTreeCtrl::DoSetItem (
  wxTreeViewItem*                   pTvItem
)
{
    //
    // Just invalidate the record to redisplay it
    //
    if (!::WinSendMsg( GetHWND()
                      ,CM_INVALIDATERECORD
                      ,MPFROMP(pTvItem)
                      ,MPFROM2SHORT(1, CMA_ERASE | CMA_REPOSITION | CMA_TEXTCHANGED)
                     ));
    {
        wxLogLastError(wxT("CM_INVALIDATERECORD"));
    }
} // end of wxTreeCtrl::DoSetItem

unsigned int wxTreeCtrl::GetCount () const
{
    CNRINFO  vCnrInfo;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)(USHORT)sizeof(CNRINFO)
                );

    return (unsigned int)vCnrInfo.cRecords;
} // end of wxTreeCtrl::GetCount

unsigned int wxTreeCtrl::GetIndent () const
{
    CNRINFO                         vCnrInfo;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)(USHORT)sizeof(CNRINFO)
                );
    return (unsigned int)vCnrInfo.cxTreeIndent;
} // end of wxTreeCtrl::GetIndent

void wxTreeCtrl::SetIndent (
  unsigned int                  uIndent
)
{
    CNRINFO                         vCnrInfo;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)(USHORT)sizeof(CNRINFO)
                );
    vCnrInfo.cxTreeIndent = (LONG)uIndent;
    ::WinSendMsg( GetHWND()
                 ,CM_SETCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)CMA_CXTREEINDENT
                );
} // end of wxTreeCtrl::SetIndent

wxImageList* wxTreeCtrl::GetImageList () const
{
    return m_pImageListNormal;
} // end of wxTreeCtrl::GetImageList

wxImageList* wxTreeCtrl::GetStateImageList () const
{
    return m_pImageListNormal;
} // end of wxTreeCtrl::GetStateImageList

//
// The SETS of imagelists really do nothing under OS2 as a RECORDCORE
// struct has the icon imbedded in it that it uses for the icon being
// displayed via the TREEITEMDESC member.  Provided for interface
// compatibility only
//
void wxTreeCtrl::SetAnyImageList (
  wxImageList*                      WXUNUSED(pImageList)
, int                               WXUNUSED(nWhich)
)
{
} // end of wxTreeCtrl::SetAnyImageList

void wxTreeCtrl::SetImageList (
  wxImageList*                      WXUNUSED(pImageList)
)
{
    if (m_bOwnsImageListNormal)
        delete m_pImageListNormal;
    m_bOwnsImageListNormal = false;
} // end of wxTreeCtrl::SetImageList

void wxTreeCtrl::SetStateImageList (
  wxImageList*                      WXUNUSED(pImageList)
)
{
    if (m_bOwnsImageListState)
        delete m_pImageListState;
    m_bOwnsImageListState = false;
} // end of wxTreeCtrl::SetStateImageList

void wxTreeCtrl::AssignImageList (
  wxImageList*                      WXUNUSED(pImageList)
)
{
    m_bOwnsImageListNormal = true;
} // end of wxTreeCtrl::AssignImageList

void wxTreeCtrl::AssignStateImageList (
  wxImageList*                      WXUNUSED(pImageList)
)
{
    m_bOwnsImageListState = true;
} // end of wxTreeCtrl::AssignStateImageList

size_t wxTreeCtrl::GetChildrenCount (
  const wxTreeItemId&               rItem
, bool                              bRecursively
) const
{
    TraverseCounter                 vCounter( this
                                             ,rItem
                                             ,bRecursively
                                            );
    return vCounter.GetCount() - 1;
} // end of wxTreeCtrl::GetChildrenCount

// ----------------------------------------------------------------------------
// control colours
// ----------------------------------------------------------------------------

bool wxTreeCtrl::SetBackgroundColour (
  const wxColour&                   rColour
)
{
    ULONG                           ulColor = wxColourToRGB(rColour);

    if ( !wxWindowBase::SetBackgroundColour(rColour) )
        return false;
    ::WinSetPresParam( GetHWND()
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(ULONG)
                      ,&ulColor
                     );
    return true;
} // end of wxTreeCtrl::SetBackgroundColour

bool wxTreeCtrl::SetForegroundColour (
  const wxColour&                   rColour
)
{
    ULONG                           ulColor = wxColourToRGB(rColour);

    if (!wxWindowBase::SetForegroundColour(rColour))
        return false;
    ::WinSetPresParam( GetHWND()
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(ULONG)
                      ,&ulColor
                     );
    return true;
} // end of wxTreeCtrl::SetForegroundColour

// ----------------------------------------------------------------------------
// Item access
// ----------------------------------------------------------------------------

wxString wxTreeCtrl::GetItemText (
  const wxTreeItemId&               rItem
) const
{
    wxChar                          zBuf[512];  // the size is arbitrary...
    wxTreeViewItem                  vTvItem(rItem);

    if (!DoGetItem(&vTvItem))
    {
        //
        // Don't return some garbage which was on stack, but an empty string
        //
        zBuf[0] = wxT('\0');
    }
    else
        strcpy(zBuf, vTvItem.m_vRecord.pszTree);
    return wxString(zBuf);
} // end of wxTreeCtrl::GetItemText

void wxTreeCtrl::SetItemText (
  const wxTreeItemId&               rItem
, const wxString&                   rsText
)
{
    wxTreeViewItem                  vTvItem(rItem);

    vTvItem.m_vRecord.pszTree = (wxChar *)rsText.c_str();  // conversion is ok
    DoSetItem(&vTvItem);
} // end of wxTreeCtrl::SetItemText

//
// These functions under OS/2 PM are not needed.  OS/2 containers in tree view
// provide for storing a custom expanded and collapsed icons and selected
// and non selected icons, natively.  For instance, by default, a disk display
// will display a tree list of folder icons with "+" icons (collapsed) beside
// those folder which contain child members.  Double clicking a folder changes
// the closed folder icon to an open folder icon with hatched selection
// highlighting indicating an ICON view container of the folder is open
// elsewhere on the desktop.  So the below is not really needed, but we will
// simply return the appropriate icon requested out of OS/2's native PM
// data structures.
//
int wxTreeCtrl::DoGetItemImageFromData (
  const wxTreeItemId&               WXUNUSED(rItem)
, wxTreeItemIcon                    nWhich
) const
{
    //
    // Image handles stored in CNRINFO.
    //
    CNRINFO                         vCnrInfo;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)(USHORT)sizeof(CNRINFO)
                );

    //
    // We really only have two to chose from.  If not custom (set in CNRINFO
    // then return the handle to system bitmap).  OS/2 automatically provides
    // in_use and selected bitmaps/icons
    //
    switch(nWhich)
    {
        case wxTreeItemIcon_Normal:
            if (vCnrInfo.hbmCollapsed == NULLHANDLE)
                return (int)::WinGetSysBitmap(HWND_DESKTOP, SBMP_TREEPLUS);
            return vCnrInfo.hbmCollapsed;


        case wxTreeItemIcon_Expanded:
            if (vCnrInfo.hbmExpanded == NULLHANDLE)
                return (int)::WinGetSysBitmap(HWND_DESKTOP, SBMP_TREEMINUS);
            return vCnrInfo.hbmExpanded;

        default:
            return vCnrInfo.hbmCollapsed;
    }
}

void wxTreeCtrl::DoSetItemImageFromData (
  const wxTreeItemId&               WXUNUSED(rItem)
, int                               nImage
, wxTreeItemIcon                    nWhich
) const
{
    //
    // Image handles stored in CNRINFO.
    //
    CNRINFO                         vCnrInfo;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)(USHORT)sizeof(CNRINFO)
                );
    if (nWhich == wxTreeItemIcon_Normal)
         vCnrInfo.hbmCollapsed = (HBITMAP)nImage;
    if (nWhich == wxTreeItemIcon_Expanded)
        vCnrInfo.hbmExpanded = (HBITMAP)nImage;
    ::WinSendMsg( GetHWND()
                 ,CM_SETCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)CMA_TREEBITMAP
                );
} // end of wxTreeCtrl::DoSetItemImageFromData

// Useless for OS/2
void wxTreeCtrl::DoSetItemImages (
  const wxTreeItemId&               rItem
, int                               nImage
, int                               nImageSel
)
{
} // end of wxTreeCtrl::DoSetItemImages

int wxTreeCtrl::GetItemImage (
  const wxTreeItemId&               rItem
, wxTreeItemIcon                    nWhich
) const
{
    if (HasIndirectData(rItem))
    {
        return DoGetItemImageFromData( rItem
                                      ,nWhich
                                     );
    }

    CNRINFO                         vCnrInfo;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)(USHORT)sizeof(CNRINFO)
                );
    switch (nWhich)
    {
        default:
            wxFAIL_MSG( wxT("unknown tree item image type") );

        case wxTreeItemIcon_Normal:
            if (vCnrInfo.hbmCollapsed == NULLHANDLE)
                return (int)::WinGetSysBitmap(HWND_DESKTOP, SBMP_TREEPLUS);
            return vCnrInfo.hbmCollapsed;


        case wxTreeItemIcon_Expanded:
            if (vCnrInfo.hbmExpanded == NULLHANDLE)
                return (int)::WinGetSysBitmap(HWND_DESKTOP, SBMP_TREEMINUS);
            return vCnrInfo.hbmExpanded;

        case wxTreeItemIcon_Selected:
        case wxTreeItemIcon_SelectedExpanded:
            return -1;
    }
}

void wxTreeCtrl::SetItemImage (
  const wxTreeItemId&               WXUNUSED(rItem)
, int                               nImage
, wxTreeItemIcon                    nWhich
)
{
    CNRINFO                         vCnrInfo;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)(USHORT)sizeof(CNRINFO)
                );
    switch (nWhich)
    {
        case wxTreeItemIcon_Normal:
            vCnrInfo.hbmCollapsed = (HBITMAP)nImage;
            break;

        case wxTreeItemIcon_Expanded:
            vCnrInfo.hbmExpanded = (HBITMAP)nImage;
            break;

        default:
            wxFAIL_MSG( wxT("unknown tree item image type") );
    }
    ::WinSendMsg( GetHWND()
                 ,CM_SETCNRINFO
                 ,MPFROMP(&vCnrInfo)
                 ,(MPARAM)CMA_TREEBITMAP
                );
} // end of wxTreeCtrl::SetItemImage

wxTreeItemData* wxTreeCtrl::GetItemData (
  const wxTreeItemId&               rItem
) const
{
    wxTreeViewItem                  vTvItem(rItem);

    if (!DoGetItem(&vTvItem))
    {
        return NULL;
    }

    return (wxTreeItemData *)vTvItem.m_ulUserData;
} // end of wxTreeCtrl::GetItemData

void wxTreeCtrl::SetItemData (
  const wxTreeItemId&               rItem
, wxTreeItemData*                   pData
)
{
    //
    // first, associate this piece of data with this item
    if (pData)
    {
        pData->SetId(rItem);
    }

    wxTreeViewItem                  vTvItem(rItem);

    vTvItem.m_ulUserData = (ULONG)pData;
    DoSetItem(&vTvItem);
} // end of wxTreeCtrl::SetItemData

// The following two do nothing under OS/2
void wxTreeCtrl::SetIndirectItemData (
  const wxTreeItemId&               WXUNUSED(rItem)
, wxTreeItemIndirectData*           WXUNUSED(pData)
)
{
} // end of wxTreeCtrl::SetIndirectItemData

bool wxTreeCtrl::HasIndirectData (
  const wxTreeItemId&               WXUNUSED(rItem)
) const
{
    return false;
} // end of wxTreeCtrl::HasIndirectData

// Irreleveant under OS/2 --- item either has child records or it doesn't.
void wxTreeCtrl::SetItemHasChildren (
  const wxTreeItemId&               WXUNUSED(rItem)
, bool                              WXUNUSED(bHas)
)
{
} // end of wxTreeCtrl::SetItemHasChildren

// Irreleveant under OS/2 --- function of the font in PM
void wxTreeCtrl::SetItemBold (
  const wxTreeItemId&               WXUNUSED(rItem)
, bool                              WXUNUSED(bBold)
)
{
} // end of wxTreeCtrl::SetItemBold

void wxTreeCtrl::SetItemDropHighlight (
  const wxTreeItemId&               rItem
, bool                              bHighlight
)
{
    wxTreeViewItem                  vTvItem(rItem);

    ::WinSendMsg( GetHWND()
                 ,CM_SETRECORDEMPHASIS
                 ,MPFROMP(&vTvItem)
                 ,MPFROM2SHORT(bHighlight, CRA_SELECTED)
                );
    DoSetItem(&vTvItem);
} // end of wxTreeCtrl::SetItemDropHighlight

void wxTreeCtrl::RefreshItem (
  const wxTreeItemId&               rItem
)
{
    wxTreeViewItem                  vTvItem(rItem);

    //
    // This just does a record invalidate causing it to be re-displayed
    //
    DoSetItem(&vTvItem);
} // end of wxTreeCtrl::RefreshItem

wxColour wxTreeCtrl::GetItemTextColour (
  const wxTreeItemId&               rItem
) const
{
    long                            lId = (long)rItem.m_pItem;
    wxTreeItemAttr*                 pAttr = (wxTreeItemAttr *)m_vAttrs.Get(lId);

    if (!pAttr)
    {
        return wxNullColour;
    }
    return pAttr->GetTextColour();
} // end of wxTreeCtrl::GetItemTextColour

wxColour wxTreeCtrl::GetItemBackgroundColour (
  const wxTreeItemId&               rItem
) const
{
    long                            lId = (long)rItem.m_pItem;
    wxTreeItemAttr*                 pAttr = (wxTreeItemAttr *)m_vAttrs.Get(lId);

    if (!pAttr)
    {
        return wxNullColour;
    }
    return pAttr->GetBackgroundColour();
} // end of wxTreeCtrl::GetItemBackgroundColour

wxFont wxTreeCtrl::GetItemFont (
  const wxTreeItemId&               rItem
) const
{
    long                            lId = (long)rItem.m_pItem;
    wxTreeItemAttr*                 pAttr = (wxTreeItemAttr *)m_vAttrs.Get(lId);

    if (!pAttr)
    {
        return wxNullFont;
    }
    return pAttr->GetFont();
} // end of wxTreeCtrl::GetItemFont

void wxTreeCtrl::SetItemTextColour (
  const wxTreeItemId&               rItem
, const wxColour&                   rCol
)
{
    m_bHasAnyAttr = true;

    long                            lId = (long)rItem.m_pItem;
    wxTreeItemAttr*                 pAttr = (wxTreeItemAttr *)m_vAttrs.Get(lId);

    if (!pAttr)
    {
        pAttr = new wxTreeItemAttr;
        m_vAttrs.Put(lId, (wxObject *)pAttr);
    }
    pAttr->SetTextColour(rCol);
    RefreshItem(rItem);
} // end of wxTreeCtrl::SetItemTextColour

void wxTreeCtrl::SetItemBackgroundColour (
  const wxTreeItemId&               rItem
, const wxColour&                   rCol
)
{
    m_bHasAnyAttr = true;

    long                            lId = (long)rItem.m_pItem;
    wxTreeItemAttr*                 pAttr = (wxTreeItemAttr *)m_vAttrs.Get(lId);

    if (!pAttr)
    {
        pAttr = new wxTreeItemAttr;
        m_vAttrs.Put(lId, (wxObject *)pAttr);
    }
    pAttr->SetBackgroundColour(rCol);
    RefreshItem(rItem);
} // end of wxTreeCtrl::SetItemBackgroundColour

void wxTreeCtrl::SetItemFont (
  const wxTreeItemId&               rItem
, const wxFont&                     rFont
)
{
    m_bHasAnyAttr = true;

    long                            lId = (long)rItem.m_pItem;
    wxTreeItemAttr*                 pAttr = (wxTreeItemAttr *)m_vAttrs.Get(lId);

    if (!pAttr)
    {
        pAttr = new wxTreeItemAttr;
        m_vAttrs.Put(lId, (wxObject *)pAttr);
    }
    pAttr->SetFont(rFont);
    RefreshItem(rItem);
} // end of wxTreeCtrl::SetItemFont

// ----------------------------------------------------------------------------
// Item status
// ----------------------------------------------------------------------------

bool wxTreeCtrl::IsVisible (
  const wxTreeItemId&               rItem
) const
{
    // Bug in Gnu-Win32 headers, so don't use the macro TreeView_GetItemRect
    RECTL                           vRectRecord;
    RECTL                           vRectContainer;
    wxRect                          vWxRectRecord;
    wxRect                          vWxRectContainer;
    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rItem.m_pItem
                                                                    );
    QUERYRECORDRECT                 vQuery;

    vQuery.cb                = sizeof(QUERYRECORDRECT);
    vQuery.pRecord           = (PRECORDCORE)pRecord;
    vQuery.fRightSplitWindow = FALSE;
    vQuery.fsExtent          = CMA_TREEICON;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYVIEWPORTRECT
                 ,MPFROMP(&vRectContainer)
                 ,MPFROM2SHORT(CMA_WINDOW, FALSE)
                );
    ::WinSendMsg( GetHWND()
                 ,CM_QUERYRECORDRECT
                 ,MPFROMP(&vRectRecord)
                 ,MPFROMP(&vQuery)
                );
    vWxRectRecord.SetLeft(vRectRecord.xLeft);
    vWxRectRecord.SetTop(vRectRecord.yTop);
    vWxRectRecord.SetRight(vRectRecord.xRight);
    vWxRectRecord.SetBottom(vRectRecord.yBottom);

    vWxRectContainer.SetLeft(vRectContainer.xLeft);
    vWxRectContainer.SetTop(vRectContainer.yTop);
    vWxRectContainer.SetRight(vRectContainer.xRight);
    vWxRectContainer.SetBottom(vRectContainer.yBottom);
    return (vWxRectContainer.Contains(wxPoint(vWxRectRecord.x, vWxRectRecord.y)));
} // end of wxTreeCtrl::IsVisible

bool wxTreeCtrl::ItemHasChildren (
  const wxTreeItemId&               rItem
) const
{
    wxTreeViewItem                  vTvItem(rItem);
    DoGetItem(&vTvItem);

    //
    // A tree record with children will have one of these attributes
    //
    return (vTvItem.m_vRecord.flRecordAttr & CRA_EXPANDED ||
            vTvItem.m_vRecord.flRecordAttr & CRA_COLLAPSED) != 0;
}

bool wxTreeCtrl::IsExpanded (
  const wxTreeItemId&               rItem
) const
{
    wxTreeViewItem                  vTvItem(rItem);
    DoGetItem(&vTvItem);

    return (vTvItem.m_vRecord.flRecordAttr & CRA_EXPANDED) != 0;
} // end of wxTreeCtrl::IsExpanded

bool wxTreeCtrl::IsSelected (
  const wxTreeItemId&               rItem
) const
{
    wxTreeViewItem                  vTvItem(rItem);
    DoGetItem(&vTvItem);

    return (vTvItem.m_vRecord.flRecordAttr & CRA_SELECTED) != 0;
} // end of wxTreeCtrl::IsSelected

// Not supported
bool wxTreeCtrl::IsBold (
  const wxTreeItemId&               rItem
) const
{
    return false;
} // end of wxTreeCtrl::IsBold

// ----------------------------------------------------------------------------
// navigation
// ----------------------------------------------------------------------------

wxTreeItemId wxTreeCtrl::GetRootItem () const
{
    PMYRECORD                       pRecord = NULL;

    pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                  ,CM_QUERYRECORD
                                                  ,MPFROMP(pRecord)
                                                  ,MPFROM2SHORT(CMA_FIRST, CMA_ITEMORDER)
                                                 ));

    if (!pRecord)
        return wxTreeItemId(-1L);
    return wxTreeItemId((long)pRecord->m_ulItemId);
} // end of wxTreeCtrl::GetRootItem

wxTreeItemId wxTreeCtrl::GetSelection () const
{
    wxCHECK_MSG( !(m_windowStyle & wxTR_MULTIPLE), (long)(WXHTREEITEM)0,
                 wxT("this only works with single selection controls") );

    PMYRECORD                       pRecord = NULL;

    pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                  ,CM_QUERYRECORDEMPHASIS
                                                  ,MPARAM(CMA_FIRST)
                                                  ,MPARAM(CRA_SELECTED)
                                                 ));
    if (!pRecord)
        return wxTreeItemId(-1L);
    return wxTreeItemId((long)pRecord->m_ulItemId);
} // end of wxTreeCtrl::GetSelection

wxTreeItemId wxTreeCtrl::GetItemParent (
  const wxTreeItemId&               rItem
) const
{
    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rItem.m_pItem
                                                                    );

    if (!pRecord)
        return wxTreeItemId(-1L);
    pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                  ,CM_QUERYRECORD
                                                  ,MPFROMP(pRecord)
                                                  ,MPFROM2SHORT(CMA_PARENT, CMA_ITEMORDER)
                                                 ));
    if (!pRecord)
        return wxTreeItemId(-1L);
    return wxTreeItemId((long)pRecord->m_ulItemId);
} // end of wxTreeCtrl::GetItemParent

wxTreeItemId wxTreeCtrl::GetFirstChild (
  const wxTreeItemId&               rItem
, long&                             rCookie
) const
{
    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rItem.m_pItem
                                                                    );

    if (!pRecord)
        return wxTreeItemId(-1L);
    pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                  ,CM_QUERYRECORD
                                                  ,MPFROMP(pRecord)
                                                  ,MPFROM2SHORT(CMA_FIRSTCHILD, CMA_ITEMORDER)
                                                 ));
    if (!pRecord)
        return wxTreeItemId(-1L);
    //
    // Remember the last child returned in 'cookie'
    //
    rCookie = (long)pRecord->m_ulItemId;
    return wxTreeItemId(rCookie);
} // end of wxTreeCtrl::GetFirstChild

wxTreeItemId wxTreeCtrl::GetNextChild (
  const wxTreeItemId&               WXUNUSED(rItem)
, long&                             rCookie
) const
{
    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rCookie
                                                                    );

    if (!pRecord)
        return wxTreeItemId(-1L);
    pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                  ,CM_QUERYRECORD
                                                  ,MPFROMP(pRecord)
                                                  ,MPFROM2SHORT(CMA_NEXT, CMA_ITEMORDER)
                                                 ));
    if (!pRecord)
        return wxTreeItemId(-1L);
    rCookie = (long)pRecord->m_ulItemId;
    return wxTreeItemId(rCookie);
} // end of wxTreeCtrl::GetNextChild

wxTreeItemId wxTreeCtrl::GetLastChild (
  const wxTreeItemId&               rItem
) const
{
    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rItem.m_pItem
                                                                    );

    if (!pRecord)
        return wxTreeItemId(-1L);
    pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                  ,CM_QUERYRECORD
                                                  ,MPFROMP(pRecord)
                                                  ,MPFROM2SHORT(CMA_LASTCHILD, CMA_ITEMORDER)
                                                 ));
    if (!pRecord)
        return wxTreeItemId(-1L);
    return wxTreeItemId((long)pRecord->m_ulItemId);
} // end of wxTreeCtrl::GetLastChild

wxTreeItemId wxTreeCtrl::GetNextSibling (
  const wxTreeItemId&               rItem
) const
{
    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rItem.m_pItem
                                                                    );

    if (!pRecord)
        return wxTreeItemId(-1L);
    pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                  ,CM_QUERYRECORD
                                                  ,MPFROMP(pRecord)
                                                  ,MPFROM2SHORT(CMA_NEXT, CMA_ITEMORDER)
                                                 ));
    if (!pRecord)
        return wxTreeItemId(-1L);
    return wxTreeItemId((long)pRecord->m_ulItemId);
} // end of wxTreeCtrl::GetNextSibling

wxTreeItemId wxTreeCtrl::GetPrevSibling (
  const wxTreeItemId&               rItem
) const
{
    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rItem.m_pItem
                                                                    );

    if (!pRecord)
        return wxTreeItemId(-1L);
    pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                  ,CM_QUERYRECORD
                                                  ,MPFROMP(pRecord)
                                                  ,MPFROM2SHORT(CMA_PREV, CMA_ITEMORDER)
                                                 ));
    if (!pRecord)
        return wxTreeItemId(-1L);
    return wxTreeItemId((long)pRecord->m_ulItemId);
} // end of wxTreeCtrl::GetPrevSibling

wxTreeItemId wxTreeCtrl::GetFirstVisibleItem () const
{
    PMYRECORD                       pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                                                  ,CM_QUERYRECORD
                                                                                  ,MPFROMP(pRecord)
                                                                                  ,MPFROM2SHORT(CMA_FIRST, CMA_ITEMORDER)
                                                                                 ));
    if (!pRecord)
        return wxTreeItemId(-1L);

    if (IsVisible(wxTreeItemId((long)pRecord->m_ulItemId)))
        return wxTreeItemId((long)pRecord->m_ulItemId);
    while(pRecord)
    {
        pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                      ,CM_QUERYRECORD
                                                      ,MPFROMP(pRecord)
                                                      ,MPFROM2SHORT(CMA_NEXT, CMA_ITEMORDER)
                                                     ));
        if (!pRecord)
            return wxTreeItemId(-1L);
        if (IsVisible(wxTreeItemId((long)pRecord->m_ulItemId)))
            return wxTreeItemId((long)pRecord->m_ulItemId);
    }
    return wxTreeItemId(-1L);
} // end of wxTreeCtrl::GetFirstVisibleItem

wxTreeItemId wxTreeCtrl::GetNextVisible (
  const wxTreeItemId&               rItem
) const
{
    wxASSERT_MSG(IsVisible(rItem), wxT("The item you call GetNextVisible() for must be visible itself!"));

    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rItem.m_pItem
                                                                    );

    if (!pRecord)
        return wxTreeItemId(-1L);
    while(pRecord)
    {
        pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                      ,CM_QUERYRECORD
                                                      ,MPFROMP(pRecord)
                                                      ,MPFROM2SHORT(CMA_NEXT, CMA_ITEMORDER)
                                                     ));
        if (!pRecord)
            return wxTreeItemId(-1L);
        if (IsVisible(wxTreeItemId((long)pRecord->m_ulItemId)))
            return wxTreeItemId((long)pRecord->m_ulItemId);
    }
    return wxTreeItemId(-1L);
} // end of wxTreeCtrl::GetNextVisible

wxTreeItemId wxTreeCtrl::GetPrevVisible (
  const wxTreeItemId&               rItem
) const
{
    wxASSERT_MSG( IsVisible(rItem), wxT("The item you call GetPrevVisible() for must be visible itself!"));

    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rItem.m_pItem
                                                                    );

    if (!pRecord)
        return wxTreeItemId(-1L);
    while(pRecord)
    {
        pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                      ,CM_QUERYRECORD
                                                      ,MPFROMP(pRecord)
                                                      ,MPFROM2SHORT(CMA_PREV, CMA_ITEMORDER)
                                                     ));
        if (!pRecord)
            return wxTreeItemId(-1L);
        if (IsVisible(wxTreeItemId((long)pRecord->m_ulItemId)))
            return wxTreeItemId((long)pRecord->m_ulItemId);
    }
    return wxTreeItemId(-1L);
} // end of wxTreeCtrl::GetPrevVisible

// ----------------------------------------------------------------------------
// multiple selections emulation -- under OS/2 checked tree items is not
// supported, but multisel is.  So we'll just check for selections here.
// ----------------------------------------------------------------------------

bool wxTreeCtrl::IsItemChecked (
  const wxTreeItemId&               rItem
) const
{
    wxTreeViewItem                  vTvItem(rItem);

    DoGetItem(&vTvItem);
    return (vTvItem.m_vRecord.flRecordAttr & CRA_SELECTED);
} // end of wxTreeCtrl::IsItemChecked

void wxTreeCtrl::SetItemCheck (
  const wxTreeItemId&               rItem
, bool                              bCheck
)
{
    wxTreeViewItem                  vTvItem(rItem);

    DoGetItem(&vTvItem);
    ::WinSendMsg( GetHWND()
                 ,CM_SETRECORDEMPHASIS
                 ,MPFROMP(&vTvItem)
                 ,MPFROM2SHORT(TRUE, CRA_SELECTED)
                );
    DoSetItem(&vTvItem);
} // end of wxTreeCtrl::SetItemCheck

size_t wxTreeCtrl::GetSelections (
  wxArrayTreeItemIds&               raSelections
) const
{
    TraverseSelections              vSelector( this
                                              ,raSelections
                                             );
    return vSelector.GetCount();
} // end of wxTreeCtrl::GetSelections

// ----------------------------------------------------------------------------
// Usual operations
// ----------------------------------------------------------------------------

wxTreeItemId wxTreeCtrl::DoInsertItem (
  const wxTreeItemId&               rParent
, wxTreeItemId                      vInsertAfter
, const wxString&                   rsText
, int                               nImage
, int                               selectedImage
, wxTreeItemData*                   pData
)
{
    PMYRECORD                       pRecordAfter = FindOS2TreeRecordByID( GetHWND()
                                                                         ,vInsertAfter.m_pItem
                                                                        );

    PMYRECORD                       pRecordParent = FindOS2TreeRecordByID( GetHWND()
                                                                          ,rParent.m_pItem
                                                                         );

    PMYRECORD                       pRecord = (PMYRECORD)::WinSendMsg( GetHWND()
                                                                      ,CM_ALLOCRECORD
                                                                      ,MPFROMLONG(sizeof(MYRECORD) - sizeof(RECORDCORE))
                                                                      ,MPFROMLONG(1)
                                                                     );
    RECORDINSERT                    vInsert;

    vInsert.cb                = sizeof(RECORDINSERT);
    if (rParent.m_pItem == 0L)
    {
        if (vInsertAfter.m_pItem == -1)
            vInsert.pRecordOrder      = (PRECORDCORE)CMA_END;
        else
            vInsert.pRecordOrder      = (PRECORDCORE)CMA_FIRST;
        vInsert.pRecordParent     = NULL;
    }
    else
    {
        if (vInsertAfter.m_pItem == 0)
            vInsert.pRecordOrder      = (PRECORDCORE)CMA_FIRST;
        else if (vInsertAfter.m_pItem == -1)
            vInsert.pRecordOrder      = (PRECORDCORE)CMA_END;
        else
            vInsert.pRecordOrder  = (PRECORDCORE)pRecordAfter;
        vInsert.pRecordParent     = (PRECORDCORE)pRecordParent;
    }
    vInsert.fInvalidateRecord = TRUE;
    vInsert.zOrder            = CMA_TOP;
    vInsert.cRecordsInsert    = 1;

    pRecord->m_vRecord.pszTree   = (wxChar*)rsText.c_str();
    pRecord->m_vRecord.hbmBitmap = nImage;
    pRecord->m_ulItemId = pRecordAfter->m_ulItemId + 1;
    if (pData != NULL)
    {
        pRecord->m_ulUserData = (ULONG)pData;
    }
    ::WinSendMsg( GetHWND()
                 ,CM_INSERTRECORD
                 ,MPFROMP(pRecord)
                 ,MPFROMP(&vInsert)
                );

    //
    // OS/2 must mannually bump the index's of following records
    //
    BumpTreeRecordIds( GetHWND()
                  ,pRecord
                 );
    if (pData != NULL)
    {
        //
        // Associate the application tree item with PM tree item handle
        //
        pData->SetId((long)pRecord->m_ulItemId);
    }
    return wxTreeItemId((long)pRecord->m_ulItemId);
}

wxTreeItemId wxTreeCtrl::AddRoot (
  const wxString&                   rsText
, int                               nImage
, int                               nSelectedImage
, wxTreeItemData*                   pData)
{

    return DoInsertItem( wxTreeItemId((long)0)
                        ,wxTreeItemId((long)-1)
                        ,rsText
                        ,nImage
                        ,nSelectedImage
                        ,pData
                       );
} // end of wxTreeCtrl::AddRoot

wxTreeItemId wxTreeCtrl::PrependItem (
  const wxTreeItemId&               rParent
, const wxString&                   rsText
, int                               nImage
, int                               nSelectedImage
, wxTreeItemData*                   pData
)
{
    return DoInsertItem( rParent
                        ,wxTreeItemId((long)0)
                        ,rsText
                        ,nImage
                        ,nSelectedImage
                        ,pData
                       );
} // end of wxTreeCtrl::PrependItem

wxTreeItemId wxTreeCtrl::InsertItem (
  const wxTreeItemId&               rParent
, const wxTreeItemId&               rIdPrevious
, const wxString&                   rsText
, int                               nImage
, int                               nSelectedImage
, wxTreeItemData*                   pData
)
{
    return DoInsertItem( rParent
                        ,rIdPrevious
                        ,rsText
                        ,nImage
                        ,nSelectedImage
                        ,pData
                       );
} // end of wxTreeCtrl::InsertItem

wxTreeItemId wxTreeCtrl::InsertItem (
  const wxTreeItemId&               rParent
, size_t                            nIndex
, const wxString&                   rsText
, int                               nImage
, int                               nSelectedImage
, wxTreeItemData*                   pData
)
{
    return DoInsertItem( rParent
                        ,wxTreeItemId((long)nIndex)
                        ,rsText
                        ,nImage
                        ,nSelectedImage
                        ,pData
                       );
} // end of wxTreeCtrl::InsertItem

wxTreeItemId wxTreeCtrl::AppendItem (
  const wxTreeItemId&               rParent
, const wxString&                   rsText
, int                               nImage
, int                               nSelectedImage
, wxTreeItemData*                   pData
)
{
    return DoInsertItem( rParent
                        ,wxTreeItemId((long)-1)
                        ,rsText
                        ,nImage
                        ,nSelectedImage
                        ,pData
                       );
} // end of wxTreeCtrl::AppendItem

void wxTreeCtrl::Delete (
  const wxTreeItemId&               rItem
)
{
    //
    // OS/2 does not generate DELETEITEM events so do it here
    //
    wxEventType                     vEventType = wxEVT_NULL;
    wxTreeEvent                     vEvent( wxEVT_NULL
                                           ,m_windowId
                                          );
    PMYRECORD                       pRecord = FindOS2TreeRecordByID( GetHWND()
                                                                    ,rItem.m_pItem
                                                                   );
    vEvent.SetEventObject(this);
    ::WinSendMsg( GetHWND()
                 ,CM_REMOVERECORD
                 ,MPFROMP(pRecord)
                 ,(MPARAM)(CMA_FREE | CMA_INVALIDATE)
                );
    vEvent.m_item = rItem.m_pItem;
    if (m_bHasAnyAttr)
    {
        delete (wxTreeItemAttr *)m_vAttrs.Delete((long)rItem.m_pItem);
    }
    vEvent.SetEventType(vEventType);
    HandleWindowEvent(vEvent);
} // end of wxTreeCtrl::Delete

// delete all children (but don't delete the item itself)
void wxTreeCtrl::DeleteChildren (
  const wxTreeItemId&               rItem
)
{
    long                            lCookie;
    wxArrayLong                     aChildren;
    wxTreeItemId                    vChild = GetFirstChild( rItem
                                                           ,lCookie
                                                          );

    while (vChild.IsOk())
    {
        aChildren.Add((long)(WXHTREEITEM)vChild);
        vChild = GetNextChild( rItem
                              ,lCookie
                             );
    }

    size_t                          nCount = aChildren.Count();

    for (size_t n = 0; n < nCount; n++)
    {
        Delete(aChildren[n]);
    }
} // end of wxTreeCtrl::DeleteChildren

void wxTreeCtrl::DeleteAllItems ()
{
    ::WinSendMsg( GetHWND()
                 ,CM_REMOVERECORD
                 ,NULL                // Remove all
                 ,(MPARAM)(CMA_FREE | CMA_INVALIDATE)
                );
} // end of wxTreeCtrl::DeleteAllItems

void wxTreeCtrl::DoExpand (
  const wxTreeItemId&               rItem
, int                               nFlag
)
{
    PMYRECORD                       pRecord = FindOS2TreeRecordByID( GetHWND()
                                                                    ,rItem.m_pItem
                                                                   );
    switch(nFlag)
    {
        case wxTREE_EXPAND_EXPAND:
            ::WinSendMsg( GetHWND()
                         ,CM_EXPANDTREE
                         ,MPFROMP(pRecord)
                         ,NULL
                        );
            break;

        case wxTREE_EXPAND_COLLAPSE:
            ::WinSendMsg( GetHWND()
                         ,CM_COLLAPSETREE
                         ,MPFROMP(pRecord)
                         ,NULL
                        );
            break;

        case wxTREE_EXPAND_COLLAPSE_RESET:
            ::WinSendMsg( GetHWND()
                         ,CM_COLLAPSETREE
                         ,MPFROMP(pRecord)
                         ,NULL
                        );
            DeleteChildren(rItem);
            break;

        case wxTREE_EXPAND_TOGGLE:
            if (pRecord->m_vRecord.flRecordAttr & CRA_COLLAPSED)
                ::WinSendMsg( GetHWND()
                             ,CM_EXPANDTREE
                             ,MPFROMP(pRecord)
                             ,NULL
                            );
            else if (pRecord->m_vRecord.flRecordAttr & CRA_EXPANDED)
                ::WinSendMsg( GetHWND()
                             ,CM_COLLAPSETREE
                             ,MPFROMP(pRecord)
                             ,NULL
                            );
            break;

    }
} // end of wxTreeCtrl::DoExpand

void wxTreeCtrl::Expand (
  const wxTreeItemId&               rItem
)
{
    DoExpand( rItem
             ,wxTREE_EXPAND_EXPAND
            );
} // end of wxTreeCtrl::Expand

void wxTreeCtrl::Collapse (
  const wxTreeItemId&               rItem
)
{
    DoExpand( rItem
             ,wxTREE_EXPAND_COLLAPSE
            );
} // end of wxTreeCtrl::Collapse

void wxTreeCtrl::CollapseAndReset (
  const wxTreeItemId&               rItem
)
{
    DoExpand( rItem
             ,wxTREE_EXPAND_COLLAPSE_RESET
            );
} // end of wxTreeCtrl::CollapseAndReset

void wxTreeCtrl::Toggle (
  const wxTreeItemId&               rItem
)
{
    DoExpand( rItem
             ,wxTREE_EXPAND_TOGGLE
            );
} // end of wxTreeCtrl::Toggle

void wxTreeCtrl::Unselect ()
{
    wxASSERT_MSG( !(m_windowStyle & wxTR_MULTIPLE),
                  wxT("doesn't make sense, may be you want UnselectAll()?") );

    //
    // Just remove the selection
    //
    SelectItem(wxTreeItemId((long)0));
} // end of wxTreeCtrl::Unselect

void wxTreeCtrl::UnselectAll ()
{
    if (m_windowStyle & wxTR_MULTIPLE)
    {
        wxArrayTreeItemIds          aSelections;
        size_t                      nCount = GetSelections(aSelections);

        for (size_t n = 0; n < nCount; n++)
        {
            SetItemCheck( aSelections[n]
                         ,false
                        );
        }
    }
    else
    {
        //
        // Just remove the selection
        //
        Unselect();
    }
} // end of wxTreeCtrl::UnselectAll

void wxTreeCtrl::SelectItem (
  const wxTreeItemId&               rItem
)
{
    SetItemCheck(rItem);
} // end of wxTreeCtrl::SelectItem

void wxTreeCtrl::EnsureVisible (
  const wxTreeItemId&               rItem
)
{
    wxTreeViewItem                  vTvItem(rItem);

    DoGetItem(&vTvItem);
    if (!::WinSendMsg( GetHWND()
                      ,CM_INVALIDATERECORD
                      ,MPFROMP(&vTvItem)
                      ,MPFROM2SHORT(1, CMA_ERASE | CMA_REPOSITION | CMA_TEXTCHANGED)
                     ));
} // end of wxTreeCtrl::EnsureVisible

void wxTreeCtrl::ScrollTo (
  const wxTreeItemId&               rItem
)
{
    wxTreeViewItem                  vTvItem(rItem);

    DoGetItem(&vTvItem);
    if (!::WinSendMsg( GetHWND()
                      ,CM_INVALIDATERECORD
                      ,MPFROMP(&vTvItem)
                      ,MPFROM2SHORT(1, CMA_ERASE | CMA_REPOSITION | CMA_TEXTCHANGED)
                     ));
}

wxTextCtrl* wxTreeCtrl::EditLabel (
  const wxTreeItemId&               rItem
, wxClassInfo*                      WXUNUSED(pTextControlClass)
)
{
    CNREDITDATA                     vEdit;
    PMYRECORD                       pRecord = FindOS2TreeRecordByID( GetHWND()
                                                                    ,rItem.m_pItem
                                                                   );

    vEdit.cb         = sizeof(CNREDITDATA);
    vEdit.hwndCnr    = GetHWND();
    vEdit.pRecord    = &pRecord->m_vRecord;
    vEdit.pFieldInfo = NULL;
    vEdit.ppszText   = NULL;
    vEdit.cbText     = 0;
    vEdit.id         = 0;

    ::WinSendMsg( GetHWND()
                 ,CM_OPENEDIT
                 ,MPFROMP(&vEdit)
                 ,(MPARAM)0
                );
    return NULL;
} // end of wxTreeCtrl::EditLabel

// End label editing, optionally cancelling the edit
void wxTreeCtrl::EndEditLabel (
  const wxTreeItemId&               WXUNUSED(rItem)
, bool                              WXUNUSED(bDiscardChanges)
)
{
    ::WinSendMsg( GetHWND()
                 ,CM_CLOSEEDIT
                 ,(MPARAM)0
                 ,(MPARAM)0
                );
} // end of wxTreeCtrl::EndEditLabel

wxTreeItemId wxTreeCtrl::HitTest (
  const wxPoint&                    rPoint
, int&                              WXUNUSED(rFlags)
)
{
    PMYRECORD                       pRecord = NULL;
    QUERYRECFROMRECT                vQueryRect;
    RECTL                           vRect;
    long                            lHeight;

    //
    // Get height for OS/2 point conversion
    //
    ::WinSendMsg( GetHWND()
                 ,CM_QUERYVIEWPORTRECT
                 ,MPFROMP(&vRect)
                 ,MPFROM2SHORT(CMA_WINDOW, TRUE)
                );
    lHeight = vRect.yTop - vRect.yBottom;

    //
    // For now just try and get a record in the general vicinity and forget
    // the flag
    //
    vRect.xLeft   = rPoint.x - 2;
    vRect.xRight  = rPoint.x + 2;
    vRect.yTop    = (lHeight - rPoint.y) + 2;
    vRect.yBottom = (lHeight - rPoint.y) - 2;

    vQueryRect.cb = sizeof(QUERYRECFROMRECT);
    vQueryRect.rect = vRect;
    vQueryRect.fsSearch = CMA_PARTIAL;

    pRecord = (PMYRECORD)::WinSendMsg( GetHWND()
                                      ,CM_QUERYRECORDFROMRECT
                                      ,(MPARAM)CMA_FIRST
                                      ,MPFROMP(&vQueryRect)
                                    );

    if (!pRecord)
        return -1L;
    return wxTreeItemId((long)pRecord->m_ulItemId);
} // end of wxTreeCtrl::HitTest

bool wxTreeCtrl::GetBoundingRect (
  const wxTreeItemId&               rItem
, wxRect&                           rRect
, bool                              bTextOnly
) const
{
    RECTL                           vRectRecord;
    PMYRECORD                       pRecord = FindOS2TreeRecordByID ( GetHWND()
                                                                     ,rItem.m_pItem
                                                                    );
    QUERYRECORDRECT                 vQuery;

    vQuery.cb                = sizeof(QUERYRECORDRECT);
    vQuery.pRecord           = (PRECORDCORE)pRecord;
    vQuery.fRightSplitWindow = FALSE;
    if (bTextOnly)
        vQuery.fsExtent          = CMA_TEXT;
    else
        vQuery.fsExtent          = CMA_TREEICON | CMA_TEXT;

    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYRECORDRECT
                      ,MPFROMP(&vRectRecord)
                      ,MPFROMP(&vQuery)
                     ))
        return false;
    rRect.SetLeft(vRectRecord.xLeft);
    rRect.SetTop(vRectRecord.yTop);
    rRect.SetRight(vRectRecord.xRight);
    rRect.SetBottom(vRectRecord.yBottom);
    return true;
} // end of wxTreeCtrl::GetBoundingRect

// ----------------------------------------------------------------------------
// sorting stuff
// ----------------------------------------------------------------------------

SHORT EXPENTRY InternalDataCompareTreeFunc (
  PMYRECORD                         p1
, PMYRECORD                         p2
, PVOID                             pStorage
)
{
    wxCHECK_MSG( p1 && p2, 0,
                 wxT("sorting tree without data doesn't make sense") );

    wxTreeCtrl*                     pTree = (wxTreeCtrl*)pStorage;

    return pTree->OnCompareItems( p1->m_ulItemId
                                 ,p2->m_ulItemId
                                );
} // end of wxTreeSortHelper::Compare

int wxTreeCtrl::OnCompareItems (
  const wxTreeItemId&               rItem1
, const wxTreeItemId&               rItem2
)
{
    return wxStrcmp( GetItemText(rItem1)
                    ,GetItemText(rItem2)
                   );
} // end of wxTreeCtrl::OnCompareItems

void wxTreeCtrl::SortChildren (
  const wxTreeItemId&               rItem
)
{
    ::WinSendMsg( GetHWND()
                 ,CM_SORTRECORD
                 ,(PFN)InternalDataCompareTreeFunc
                 ,NULL
                );
} // end of wxTreeCtrl::SortChildren

// ----------------------------------------------------------------------------
// implementation
// ----------------------------------------------------------------------------

bool wxTreeCtrl::OS2Command (
  WXUINT                            uCmd
, WXWORD                            wId
)
{
    if (uCmd == CN_ENDEDIT)
    {
        wxCommandEvent              vEvent( wxEVT_COMMAND_TEXT_UPDATED
                                           ,wId
                                          );

        vEvent.SetEventObject( this );
        ProcessCommand(vEvent);
        return true;
    }
    else if (uCmd == CN_KILLFOCUS)
    {
        wxCommandEvent              vEvent( wxEVT_KILL_FOCUS
                                           ,wId
                                          );
        vEvent.SetEventObject( this );
        ProcessCommand(vEvent);
        return true;
    }
    else
        return false;
} // end of wxTreeCtrl::OS2Command

//
// TODO:  Fully implement direct manipulation when I figure it out
//
MRESULT wxTreeCtrl::OS2WindowProc (
  WXUINT                            uMsg
, WXWPARAM                          wParam
, WXLPARAM                          lParam
)
{
    bool                            bProcessed = false;
    MRESULT                         mRc = 0;
    wxTreeEvent                     vEvent( wxEVT_NULL
                                           ,m_windowId
                                          );
    wxEventType                     vEventType = wxEVT_NULL;
    PCNRDRAGINIT                    pDragInit = NULL;
    PCNREDITDATA                    pEditData = NULL;
    PNOTIFYRECORDENTER              pNotifyEnter = NULL;

    vEvent.SetEventObject(this);
    switch (uMsg)
    {
        case WM_CONTROL:
            switch(SHORT2FROMMP(wParam))
            {
                case CN_INITDRAG:
                    pDragInit = (PCNRDRAGINIT)lParam;
                    if (pDragInit)
                    {
                        PMYRECORD       pRecord = (PMYRECORD)pDragInit->pRecord;

                        vEventType = wxEVT_COMMAND_TREE_BEGIN_DRAG;
                        vEvent.m_item        = pRecord->m_ulItemId;
                        vEvent.m_pointDrag.x = pDragInit->x;
                        vEvent.m_pointDrag.y = pDragInit->y;
                    }
                    break;

                case CN_BEGINEDIT:
                    pEditData = (PCNREDITDATA)lParam;
                    if (pEditData)
                    {
                        PMYRECORD       pRecord = (PMYRECORD)pEditData->pRecord;

                        vEventType = wxEVT_COMMAND_TREE_BEGIN_LABEL_EDIT;
                        vEvent.m_item = pRecord->m_ulItemId;
                        vEvent.m_label = pRecord->m_vRecord.pszTree;
                        vEvent.m_editCancelled = false;
                    }
                    break;

                case CN_ENDEDIT:
                    pEditData = (PCNREDITDATA)lParam;
                    if (pEditData)
                    {
                        PMYRECORD       pRecord = (PMYRECORD)pEditData->pRecord;

                        vEventType = wxEVT_COMMAND_TREE_END_LABEL_EDIT;
                        vEvent.m_item = pRecord->m_ulItemId;
                        vEvent.m_label = pRecord->m_vRecord.pszTree;
                        if (pRecord->m_vRecord.pszTree == NULL)
                        {
                            vEvent.m_editCancelled = true;
                        }
                        else
                        {
                            vEvent.m_editCancelled = false;
                        }
                    }
                    break;

                case CN_EXPANDTREE:
                    {
                        PMYRECORD       pRecord = (PMYRECORD)lParam;

                        vEventType = gs_expandEvents[IDX_EXPAND][IDX_DONE];
                        vEvent.m_item = pRecord->m_ulItemId;
                    }
                    break;
            }
            vEvent.SetEventType(vEventType);
            bProcessed = HandleWindowEvent(vEvent);
            break;
    }
    if (!bProcessed)
        mRc = wxControl::OS2WindowProc( uMsg
                                       ,wParam
                                       ,lParam
                                      );
    return mRc;
} // end of wxTreeCtrl::OS2WindowProc

#endif // wxUSE_TREECTRL
