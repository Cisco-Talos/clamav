/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/listctrl.cpp
// Purpose:     wxListCtrl
// Author:      David Webster
// Modified by:
// Created:     01/21/03
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
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

#if wxUSE_LISTCTRL

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/settings.h"
    #include "wx/dcclient.h"
    #include "wx/textctrl.h"
#endif

#include "wx/imaglist.h"
#include "wx/listctrl.h"

#include "wx/os2/private.h"

//
// FIELDOFFSET in DETAIL view as defined in the OS2TK45 simply doesn't work
// We use this, which does!
//
#undef  FIELDOFFSET
#define FIELDOFFSET(type, field)    ((ULONG)&(((type *)0)->field))

// ----------------------------------------------------------------------------
// private helper classes
// ----------------------------------------------------------------------------

/////////////////////////////////////////////////////////////////////////////
// STRUCT SMYRECORD
//   Under OS/2 we have to use our own RECORDCORE based struct if we have
//   user data to store in a PM Container Control (and wxListCtrl is a PM
//   Container in ICON, NAME, TEXT or DETAIL view). m_ulUserData is a four
//   byte value containing a pointer to our CListIntemInternalData class
//   instance.
//
//   And now for the big time OS/2 Kludge.  In traditional OS/2 PM
//   applications using containers, programmers determine BEFORE creation
//   how many records the view will have, initially, and how many columns
//   the detail view of the container will have, as the container represents
//   a known data block.  Thus the OS/2 PM CV_DETAIL view, i.e.
//   the wxWidgets wxLC_REPORT view, relies on STATIC structure for its
//   columnar data.  It gets the data to display by telling it the specific
//   offset of the field in the struct containing the displayable data.  That
//   data has be of OS/2 Types, PSZ (char string), CDATE or CTIME format.
//   wxWidgets is dynamic in nature, however.  We insert columns, one at a
//   time and do not know how many until the app is done inserting them. So
//   for OS/2 I have to set a max allowable since they are fixed.  We return
//   an error to the app if they include more than we can handle.
//
//   For example to display the data "Col 4 of Item 6" in a report view, I'd
//   have to do:
//   pRecord->m_pzColumn4 = "Col 4 of Item 6";
//   pField->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn4);
//   and then call the PM API to set it.
//
//   This really stinks but I can't use a pointer to another struct as the
//   FIELDOFFSET call could only tell OS/2 the four byte value offset of
//   pointer field and it would display giberish in the column.
/////////////////////////////////////////////////////////////////////////////
typedef struct _MYRECORD
{
    RECORDCORE                      m_vRecord;
    unsigned long                   m_ulItemId;
    unsigned long                   m_ulUserData; //actually a pointer value to real data (a CListItemInternalData class instance)
    PSZ                             m_pzColumn1;
    PSZ                             m_pzColumn2;
    PSZ                             m_pzColumn3;
    PSZ                             m_pzColumn4;
    PSZ                             m_pzColumn5;
    PSZ                             m_pzColumn6;
    PSZ                             m_pzColumn7;
    PSZ                             m_pzColumn8;
    PSZ                             m_pzColumn9;
    PSZ                             m_pzColumn10;
} MYRECORD, *PMYRECORD;

/////////////////////////////////////////////////////////////////////////////
// CLASS CListItemInternalData
//
// Problem:
//  The MSW version had problems with SetTextColour() et al as the
//  CListItemAttr's were stored keyed on the item index. If a item was
//  inserted anywhere but the end of the list the the text attributes
//  (colour etc) for the following items were out of sync.
//
// Solution:
//  Under MSW the only way to associate data with a
//  List item independent of its position in the list is to store a pointer
//  to it in its lParam attribute. However user programs are already using
//  this (via the SetItemData() GetItemData() calls).
//
//  However what we can do is store a pointer to a structure which contains
//  the attributes we want *and* a lParam for the users data, e.g.
//
//  class CListItemInternalData
//  {
//  public:
//       GuiAdvCtrl_CListItemAttr* pAttr;
//       long                      lParam; // user data
//  };
//
//  To conserve memory, a CListItemInternalData is only allocated for a
//  LV_ITEM if text attributes or user data(lparam) are being set.
//
//  For OS/2, the lParam value points to whatever actual data we have
/////////////////////////////////////////////////////////////////////////////
class CListItemInternalData
{
public:

    CListItemInternalData(): m_pAttr(NULL)
                            ,m_lParam(0)
    {}

    ~CListItemInternalData()
    {
        wxDELETE(m_pAttr);
    }

    wxListItemAttr*                 m_pAttr;
    WXLPARAM                        m_lParam; // user data
    PMYRECORD                       m_pMyRecord; // so we can set the m_ulUserData to 0 when this is deleted
}; // end of CLASS CListItemInternalData

/////////////////////////////////////////////////////////////////////////////
// STRUCT SInternalDataSort
//
// Sort items.
//
// fn is a function which takes 3 long arguments: item1, item2, data.
// item1 is the long data associated with a first item (NOT the index).
// item2 is the long data associated with a second item (NOT the index).
// data is the same value as passed to SortItems.
//
// The return value is a negative number if the first item should precede the
// second item, a positive number of the second item should precede the first,
// or zero if the two items are equivalent.
//
// data is arbitrary data to be passed to the sort function.
//
// Internal structures for proxying the user compare function
// so that we can pass it the *real* user data
/////////////////////////////////////////////////////////////////////////////
typedef struct internalDataSort
{
    wxListCtrlCompare               m_fnUser;
    long                            m_lData;
} SInternalDataSort; // end of STRUCT SInternalDataSort

// ----------------------------------------------------------------------------
// private helper functions
// ----------------------------------------------------------------------------

/////////////////////////////////////////////////////////////////////////////
//
// FindOS2ListFieldByColNum
//
//  There is no way, under OS/2 to get a field in a container by index,
//  directly, so you must get the first one, then cycle through the list
//  until you get to where you want to be.
//
// PARAMETERS
//  hWnd   -- window handle of container to search
//  lIndex -- index to set
//
// RETURN VALUE
//  pointer to the FIELDINFO struct at the index in the container record
//
/////////////////////////////////////////////////////////////////////////////
PFIELDINFO FindOS2ListFieldByColNum (
  HWND                              hWnd
, long                              lIndex
)
{
    PFIELDINFO                      pFieldInfo = NULL;
    CNRINFO                         vCnrInfo;
    ULONG                           i;

    if (!::WinSendMsg( hWnd
                      ,CM_QUERYCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)(USHORT)sizeof(CNRINFO)
                     ))
        return NULL;
    for (i = 0; i < vCnrInfo.cFields; i++)
    {
        if (i == 0)
            pFieldInfo = (PFIELDINFO)PVOIDFROMMR(::WinSendMsg( hWnd
                                                              ,CM_QUERYDETAILFIELDINFO
                                                              ,MPFROMP(pFieldInfo)
                                                              ,(MPARAM)CMA_FIRST
                                                             ));
        else
            pFieldInfo = (PFIELDINFO)PVOIDFROMMR(::WinSendMsg( hWnd
                                                              ,CM_QUERYDETAILFIELDINFO
                                                              ,MPFROMP(pFieldInfo)
                                                              ,(MPARAM)CMA_NEXT
                                                             ));
        if (!pFieldInfo)
            return NULL;
        if (i == (ULONG)lIndex)
            break;
    }
    if (!pFieldInfo)
        return NULL;
    return pFieldInfo;
} // end of FindOS2ListFieldByColNum

/////////////////////////////////////////////////////////////////////////////
//
// FindOS2ListRecordByID
//
//  There is no way, under OS/2 to get a record in a container by index,
//  directly, so you must get the first one, then cycle through the list
//  until you get to where you want to be.
//
// PARAMETERS
//  hWnd    -- window handle of container to search
//  lItemId -- index to set
//
// RETURN VALUE
//  pointer to the internal RECORDCORE struct at the index in the container
//
/////////////////////////////////////////////////////////////////////////////
PMYRECORD FindOS2ListRecordByID (
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

/////////////////////////////////////////////////////////////////////////////
//
// BumpRecordIds
//
//  Since OS/2 does not keep native record id's but wx insists on inserting
//  and selecting via ID's, when we insert a record in the middle we need
//  to bump the id's of each record after the one we just inserted.
//
// PARAMETERS
//  hWnd    -- window handle of container to search
//  pRecord -- record after which we starting bumping id's
//
// RETURN VALUE
//  none
//
/////////////////////////////////////////////////////////////////////////////
void BumpRecordIds (
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
} // end of BumpRecordIds

/////////////////////////////////////////////////////////////////////////////
//
// GetInternalData
//
//  Get the internal data given a handle and an id
//
// PARAMETERS
//  hWnd    -- window handle to the control in which item is located
//  lItemId -- ID to get
//
// RETURN VALUE
//  pointer to the internal data
//
// Note:
//  Under OS/2 PM a container item cannot be obtained via a simple index or
//  id retrieval.  We have to walk the record list if we are looking for
//  a record at a specific index location
/////////////////////////////////////////////////////////////////////////////
CListItemInternalData* GetInternalData (
  HWND                              hWnd
, long                              lItemId
)
{
    PMYRECORD                       pRecord = FindOS2ListRecordByID( hWnd
                                                                    ,lItemId
                                                                   );
    //
    // Internal user data is stored AFTER the last field of the RECORDCORE
    //
    if (!pRecord)
        return NULL;
    return((CListItemInternalData *)(pRecord->m_ulUserData));
} // end of GetInternalData

/////////////////////////////////////////////////////////////////////////////
//
// GetInternalData
//
//  Get the internal data given a pointer to a list control and an id
//
// PARAMETERS
//  pCtl    -- pointer to control inwhich item is located
//  lItemId -- ID to get
//
// RETURN VALUE
//  pointer to the internal data
//
/////////////////////////////////////////////////////////////////////////////
CListItemInternalData* GetInternalData (
  wxListCtrl*                       pCtl
, long                              lItemId
)
{
    return(GetInternalData( (HWND)pCtl->GetHWND()
                           ,lItemId
                          ));
} // end of GetInternalData

/////////////////////////////////////////////////////////////////////////////
//
// DeleteInternalData
//
//  Delete the internal data for a record
//
// PARAMETERS
//  pCtl    -- pointer to the list control containing the record
//  lItemId -- the record index to delete the internal data from
//
// RETURN VALUE
//  pointer to the internal data attribute
//
/////////////////////////////////////////////////////////////////////////////
void DeleteInternalData (
  wxListCtrl*                       pCtl
, long                              lItemId
)
{
    CListItemInternalData*          pData = GetInternalData( pCtl
                                                            ,lItemId
                                                           );
    if (pData)
    {
        if (pData->m_pMyRecord)
            pData->m_pMyRecord->m_ulUserData = 0;
        delete pData;
    }
} // end of DeleteInternalData

// #pragma page   "GetInternalDataAttr"
/////////////////////////////////////////////////////////////////////////////
//
// GetInternalDataAttr
//
//  Get the internal data item attribute given a pointer to a list control
//  and an id
//
// PARAMETERS
//  pCtl    -- pointer to control to set
//  lItemId -- ID to set
//
// RETURN VALUE
//  pointer to the internal data attribute
//
/////////////////////////////////////////////////////////////////////////////
wxListItemAttr* GetInternalDataAttr (
  wxListCtrl*                       pCtl
, long                              lItemId
)
{
    CListItemInternalData*          pData = GetInternalData( pCtl
                                                            ,lItemId
                                                           );

    if (pData)
        return(pData->m_pAttr);
    else
        return NULL;
} // end of GetInternalDataAttr

/////////////////////////////////////////////////////////////////////////////
//
// InternalDataCompareFunc
//
//  This is compare function we pass to PM.  It wraps the real compare
//  function in SInternalDataSort
//
// PARAMETERS
//  p1       -- is the first record structure to compare
//  p2       -- is the second record structure to compare
//  lStorage -- is the same value as passed to SortItems.
//
// RETURN VALUE
//  pointer to the internal data attribute
//
/////////////////////////////////////////////////////////////////////////////
SHORT EXPENTRY InternalDataCompareFunc (
  PMYRECORD                         p1
, PMYRECORD                         p2
, PVOID                             pStorage
)
{
    SInternalDataSort*              pInternalData = (SInternalDataSort *)pStorage;
    CListItemInternalData*          pData1 = (CListItemInternalData *)p1->m_ulUserData;
    CListItemInternalData*          pData2 = (CListItemInternalData *)p2->m_ulUserData;
    long                            lD1 = (pData1 == NULL ? 0 : (long)pData1->m_lParam);
    long                            lD2 = (pData2 == NULL ? 0 : (long)pData2->m_lParam);

    return(pInternalData->m_fnUser( lD1
                                   ,lD2
                                   ,pInternalData->m_lData
                                  ));
} // end of InternalDataCompareFunc

/////////////////////////////////////////////////////////////////////////////
//
// ConvertFromOS2ListItem
//
//  Convert from an internal PM List item to a Toolkit List item
//
// PARAMETERS
//  hWndListCtrl -- the control's windows handle
//  rInfo        -- the library list control to convert to
//  pRecord      -- the OS list control to convert from
//
// RETURN VALUE
//  none
//
/////////////////////////////////////////////////////////////////////////////
void ConvertFromOS2ListItem ( HWND hWndListCtrl,
                              wxListItem& rInfo,
                              PMYRECORD pRecord )
{
    CListItemInternalData* pInternaldata = (CListItemInternalData *)pRecord->m_ulUserData;
    bool bNeedText = false;

    if (pInternaldata)
        rInfo.SetData(pInternaldata->m_lParam);

    rInfo.SetMask(0);
    rInfo.SetState(0);
    rInfo.SetStateMask(0);
    rInfo.SetId((long)pRecord->m_ulItemId);
    if (hWndListCtrl != 0)
    {
        pRecord = FindOS2ListRecordByID( hWndListCtrl
                                        ,rInfo.GetId()
                                       );
    }

    //
    // The wxListItem class is really set up to handle the WIN32 list item
    // and OS/2 are not as complicated.  Just set both state members to the
    // same thing under OS/2
    //
    if (pRecord->m_vRecord.flRecordAttr & CRA_DROPONABLE)
    {
        rInfo.SetStateMask(rInfo.m_stateMask | wxLIST_STATE_DROPHILITED);
        rInfo.SetState(rInfo.m_state | wxLIST_STATE_DROPHILITED);
    }
    if (pRecord->m_vRecord.flRecordAttr & CRA_SELECTED)
    {
        rInfo.SetStateMask(rInfo.m_stateMask | wxLIST_STATE_SELECTED);
        rInfo.SetState(rInfo.m_state | wxLIST_STATE_SELECTED);
    }
    if (pRecord->m_vRecord.flRecordAttr & CRA_DISABLED)
    {
        rInfo.SetStateMask(rInfo.m_stateMask | wxLIST_STATE_DISABLED);
        rInfo.SetState(rInfo.m_state | wxLIST_STATE_DISABLED);
    }
    if (pRecord->m_vRecord.flRecordAttr & CRA_FILTERED)
    {
        rInfo.SetStateMask(rInfo.m_stateMask | wxLIST_STATE_FILTERED);
        rInfo.SetState(rInfo.m_state | wxLIST_STATE_FILTERED);
    }
    if (pRecord->m_vRecord.flRecordAttr & CRA_INUSE)
    {
        rInfo.SetStateMask(rInfo.m_stateMask | wxLIST_STATE_INUSE);
        rInfo.SetState(rInfo.m_state | wxLIST_STATE_INUSE);
    }
    if (pRecord->m_vRecord.flRecordAttr & CRA_PICKED)
    {
        rInfo.SetStateMask(rInfo.m_stateMask | wxLIST_STATE_PICKED);
        rInfo.SetState(rInfo.m_state | wxLIST_STATE_PICKED);
    }
    if (pRecord->m_vRecord.flRecordAttr & CRA_SOURCE)
    {
        rInfo.SetStateMask(rInfo.m_stateMask | wxLIST_STATE_SOURCE);
        rInfo.SetState(rInfo.m_state | wxLIST_STATE_SOURCE);
    }

    if (pRecord->m_vRecord.pszText != (PSZ)NULL)
    {
        rInfo.SetMask(rInfo.GetMask() | wxLIST_MASK_TEXT);
        rInfo.SetText(pRecord->m_vRecord.pszText);
    }
    if (pRecord->m_vRecord.pszIcon != (PSZ)NULL ||
        pRecord->m_vRecord.pszName != (PSZ)NULL)
    {
        rInfo.SetMask(rInfo.GetMask() | wxLIST_MASK_IMAGE);
        rInfo.SetImage(pRecord->m_vRecord.hptrIcon);
    }
    if (pRecord->m_ulUserData)
        rInfo.SetMask(rInfo.GetMask() | wxLIST_MASK_DATA);
} // end of ConvertFromOS2ListItem

/////////////////////////////////////////////////////////////////////////////
//
// ConvertToOS2Flags
//
//  Convert from an library states to OS states
//
// PARAMETERS
//  lState       -- the state
//  pRecord      -- the OS list control to use
//
// RETURN VALUE
//  none
//
/////////////////////////////////////////////////////////////////////////////
void ConvertToOS2Flags (
  long                              lState
, PMYRECORD                         pRecord
)
{
    if (lState & wxLIST_STATE_DROPHILITED)
        pRecord->m_vRecord.flRecordAttr |= CRA_DROPONABLE;
    if (lState & wxLIST_STATE_SELECTED)
        pRecord->m_vRecord.flRecordAttr |= CRA_SELECTED;
    if (lState & wxLIST_STATE_DISABLED)
        pRecord->m_vRecord.flRecordAttr |= CRA_DISABLED;
    if (lState & wxLIST_STATE_FILTERED)
        pRecord->m_vRecord.flRecordAttr |= CRA_FILTERED;
    if (lState & wxLIST_STATE_INUSE)
        pRecord->m_vRecord.flRecordAttr |= CRA_INUSE;
    if (lState & wxLIST_STATE_PICKED)
        pRecord->m_vRecord.flRecordAttr |= CRA_PICKED;
    if (lState & wxLIST_STATE_SOURCE)
        pRecord->m_vRecord.flRecordAttr |= CRA_SOURCE;
} // end of ConvertToOS2Flags

/////////////////////////////////////////////////////////////////////////////
//
// ConvertToOS2ListItem
//
//  Convert from a library List item to an internal OS2 List item. We set
//  only the fields we need to set.  Some of them are set by the API when
//  they are added to the container.
//
// PARAMETERS
//  pCtrl      -- the control to use
//  rInfo      -- the item to convert
//  pRecord    -- the OS list control to use, should be zeroed out
//  pFieldinfo -- a field struct that may contain columnar data for detail view
//
// RETURN VALUE
//  none
//
/////////////////////////////////////////////////////////////////////////////
void ConvertToOS2ListItem (
  const wxListCtrl*                 pCtrl
, const wxListItem&                 rInfo
, PMYRECORD                         pRecord
, PFIELDINFO                        pFieldInfo
)
{
    pRecord->m_ulItemId    = (ULONG)rInfo.GetId();
    pRecord->m_vRecord.cb = sizeof(RECORDCORE);
    if (rInfo.GetMask() & wxLIST_MASK_STATE)
    {
        ConvertToOS2Flags( rInfo.m_state
                          ,pRecord
                         );
    }
    if (pCtrl->GetWindowStyleFlag() & wxLC_ICON ||
        pCtrl->GetWindowStyleFlag() & wxLC_SMALL_ICON)
    {
        pRecord->m_vRecord.pszIcon = (char*)rInfo.GetText().c_str();
    }
    if (pCtrl->GetWindowStyleFlag() & wxLC_LIST) // PM TEXT view
    {
        pRecord->m_vRecord.pszText = (char*)rInfo.GetText().c_str();
    }
    //
    // In the case of a report view the text will be the data in the lead column
    // ???? Don't know why, but that is how it works in other ports.
    //
    if (pCtrl->GetWindowStyleFlag() & wxLC_REPORT)
    {
        if (pFieldInfo)
        {
            switch(rInfo.GetColumn())
            {
                case 0:
                    pRecord->m_pzColumn1 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn1);
                    break;

                case 1:
                    pRecord->m_pzColumn2 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn2);
                    break;

                case 2:
                    pRecord->m_pzColumn3 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn3);
                    break;

                case 3:
                    pRecord->m_pzColumn4 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn4);
                    break;

                case 4:
                    pRecord->m_pzColumn5 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn5);
                    break;

                case 5:
                    pRecord->m_pzColumn6 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn6);
                    break;

                case 6:
                    pRecord->m_pzColumn7 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn7);
                    break;

                case 7:
                    pRecord->m_pzColumn8 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn8);
                    break;

                case 8:
                    pRecord->m_pzColumn9 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn9);
                    break;

                case 9:
                    pRecord->m_pzColumn10 = (char*)rInfo.GetText().c_str();
                    pFieldInfo->offStruct = FIELDOFFSET(MYRECORD, m_pzColumn10);
                    break;

                default:
                    wxFAIL_MSG( wxT("wxOS2 does not support more than 10 columns in REPORT view") );
                    break;
            }
        }
    }
    if (rInfo.GetMask() & wxLIST_MASK_IMAGE)
    {
        pRecord->m_vRecord.hptrIcon      = (HPOINTER)rInfo.GetImage();
        pRecord->m_vRecord.hptrMiniIcon  = (HPOINTER)rInfo.m_miniImage;
    }
} // end of ConvertToOS2ListItem

/////////////////////////////////////////////////////////////////////////////
//
// ConvertToOS2ListCol
//
//  Convert from a library List column to an internal PM List column
//
// PARAMETERS
//  lCol   -- the columnd to convert
//  rItem  -- the item to convert
//  pField -- the OS list column to use
//
// RETURN VALUE
//  none
//
/////////////////////////////////////////////////////////////////////////////
void ConvertToOS2ListCol (
  long                              lCol
, const wxListItem&                 rItem
, PFIELDINFO                        pField
)
{
    memset(pField, '\0', sizeof(FIELDINFO));
    pField->cb = sizeof(FIELDINFO);

    //
    // Default some settings
    //
    pField->flData  = CFA_HORZSEPARATOR | CFA_SEPARATOR;
    pField->flTitle = CFA_CENTER;

    if (rItem.GetMask() & wxLIST_MASK_TEXT)
    {
        pField->flData |= CFA_STRING;
        pField->pTitleData = (PVOID)rItem.GetText().c_str(); // text is column title not data
    }
    if (rItem.GetMask() & wxLIST_MASK_FORMAT)
    {
        if (rItem.m_format == wxLIST_FORMAT_LEFT)
            pField->flData |= CFA_LEFT;
        else if (rItem.m_format == wxLIST_FORMAT_RIGHT)
            pField->flData |= CFA_RIGHT;
        else if (rItem.m_format == wxLIST_FORMAT_CENTRE)
            pField->flData |= CFA_CENTER;
    }
    else
        pField->flData |= CFA_CENTER;  // Just ensure the default is centered
    if (rItem.GetMask() & wxLIST_MASK_WIDTH)
    {
        if (!(rItem.GetWidth() == wxLIST_AUTOSIZE ||
             rItem.GetWidth() == wxLIST_AUTOSIZE_USEHEADER))
            pField->cxWidth = rItem.GetWidth();
        // else: OS/2 automatically sets the width if created with the approppriate style
    }

    //
    // Still need to set the actual data
    //
    pField->offStruct = 0;
} // end of ConvertToOS2ListCol


IMPLEMENT_DYNAMIC_CLASS(wxListCtrl, wxControl)
IMPLEMENT_DYNAMIC_CLASS(wxListView, wxListCtrl)
IMPLEMENT_DYNAMIC_CLASS(wxListItem, wxObject)

IMPLEMENT_DYNAMIC_CLASS(wxListEvent, wxNotifyEvent)

BEGIN_EVENT_TABLE(wxListCtrl, wxControl)
    EVT_PAINT(wxListCtrl::OnPaint)
END_EVENT_TABLE()

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxListCtrl construction
// ----------------------------------------------------------------------------

void wxListCtrl::Init ()
{
    m_pImageListNormal     = NULL;
    m_pImageListSmall      = NULL;
    m_pImageListState      = NULL;
    m_bOwnsImageListNormal = false;
    m_bOwnsImageListSmall  = false;
    m_bOwnsImageListState  = false;
    m_lBaseStyle           = 0L;
    m_nColCount            = 0;
    m_pTextCtrl            = NULL;
    m_bAnyInternalData     = false;
    m_bHasAnyAttr          = false;
} // end of wxListCtrl::Init

bool wxListCtrl::Create ( wxWindow* pParent,
                          wxWindowID vId,
                          const wxPoint& rPos,
                          const wxSize& rSize,
                          long lStyle,
                          const wxValidator& rValidator,
                          const wxString& rsName )
{
    int nX = rPos.x;
    int nY = rPos.y;
    int nWidth = rSize.x;
    int nHeight = rSize.y;

#if wxUSE_VALIDATORS
    SetValidator(rValidator);
#endif // wxUSE_VALIDATORS

    SetName(rsName);
    SetWindowStyleFlag(lStyle);
    SetParent(pParent);
    if (nWidth <= 0)
        nWidth = 100;
    if (nHeight <= 0)
        nHeight = 30;
    if (nX < 0)
        nX = 0;
    if (nY < 0)
        nY = 0;

    m_windowId = (vId == -1) ? NewControlId() : vId;

    long lSstyle = WS_VISIBLE | WS_TABSTOP;

    if (GetWindowStyleFlag() & wxCLIP_SIBLINGS)
        lSstyle |= WS_CLIPSIBLINGS;
    m_lBaseStyle = lSstyle;
    if (!DoCreateControl( nX
                         ,nY
                         ,nWidth
                         ,nHeight
                        ))
        return false;
    if (pParent)
        pParent->AddChild(this);
   return true;
} // end of wxListCtrl::Create

bool wxListCtrl::DoCreateControl ( int nX, int nY,
                                   int nWidth, int nHeight )
{
    DWORD lWstyle = m_lBaseStyle;
    long lOldStyle = 0; // Dummy

    CNRINFO vCnrInfo;

    lWstyle |= ConvertToOS2Style( lOldStyle
                                 ,GetWindowStyleFlag()
                                );

    m_hWnd = (WXHWND)::WinCreateWindow( GetParent()->GetHWND()
                                       ,WC_CONTAINER
                                       ,NULL
                                       ,m_lBaseStyle
                                       ,0, 0, 0, 0
                                       ,GetParent()->GetHWND()
                                       ,HWND_BOTTOM
                                       ,(ULONG)m_windowId
                                       ,NULL
                                       ,NULL
                                      );
    if (!m_hWnd)
    {
        return false;
    }

    //
    // Now set the display attributes of the container
    //
    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)(USHORT)sizeof(CNRINFO)
                     ))
        return false;
    lWstyle = ConvertViewToOS2Style(GetWindowStyleFlag());
    vCnrInfo.flWindowAttr |= lWstyle;
    if (!::WinSendMsg( GetHWND()
                      ,CM_SETCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)CMA_FLWINDOWATTR
                     ))
        return false;

    //
    // And now set needed arrangement flags
    //
    lWstyle = ConvertArrangeToOS2Style(GetWindowStyleFlag());
    if (!::WinSendMsg( GetHWND()
                      ,CM_ARRANGE
                      ,(MPARAM)CMA_ARRANGEGRID
                      ,(MPARAM)lWstyle
                     ))
        return false;
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW));
    SetForegroundColour(GetParent()->GetForegroundColour());
    SubclassWin(m_hWnd);
    SetFont(*wxSMALL_FONT);
    SetXComp(0);
    SetYComp(0);
    SetSize( nX, nY, nWidth, nHeight );
    return true;
} // end of wxListCtrl::DoCreateControl

void wxListCtrl::UpdateStyle ()
{
    if (GetHWND())
    {
        long lDummy;
        DWORD dwStyleNew = ConvertToOS2Style( lDummy, GetWindowStyleFlag() );

        dwStyleNew |= m_lBaseStyle;

        //
        // Get the current window style.
        //
        ULONG dwStyleOld = ::WinQueryWindowULong(GetHWND(), QWL_STYLE);

        //
        // Only set the window style if the view bits have changed.
        //
        if (dwStyleOld != dwStyleNew)
        {
            ::WinSetWindowULong(GetHWND(), QWL_STYLE, dwStyleNew);
        }
    }
} // end of wxListCtrl::UpdateStyle

void wxListCtrl::FreeAllInternalData ()
{
    if (m_bAnyInternalData)
    {
        int n = GetItemCount();
        int i = 0;

        for (i = 0; i < n; i++)
            DeleteInternalData(this, (long)i);
        m_bAnyInternalData = false;
    }
} // end of wxListCtrl::FreeAllInternalData

wxListCtrl::~wxListCtrl ()
{
    FreeAllInternalData();
    if (m_pTextCtrl )
    {
        m_pTextCtrl->SetHWND(0);
        m_pTextCtrl->UnsubclassWin();
        wxDELETE(m_pTextCtrl);
    }

    if (m_bOwnsImageListNormal)
        delete m_pImageListNormal;
    if (m_bOwnsImageListSmall)
        delete m_pImageListSmall;
    if (m_bOwnsImageListState)
        delete m_pImageListState;
} // end of wxListCtrl::~wxListCtrl

// ----------------------------------------------------------------------------
// set/get/change style
// ----------------------------------------------------------------------------

// Add or remove a single window style
void wxListCtrl::SetSingleStyle (
  long                              lStyle
, bool                              bAdd
)
{
    long                            lFlag = GetWindowStyleFlag();

    //
    // Get rid of conflicting styles
    //
    if (bAdd)
    {
        if (lStyle & wxLC_MASK_TYPE)
            lFlag = lFlag & ~wxLC_MASK_TYPE;
        if (lStyle & wxLC_MASK_ALIGN )
            lFlag = lFlag & ~wxLC_MASK_ALIGN;
        if (lStyle & wxLC_MASK_SORT )
            lFlag = lFlag & ~wxLC_MASK_SORT;
    }
    if (lFlag & lStyle)
    {
        if (!bAdd)
            lFlag -= lStyle;
    }
    else
    {
        if (bAdd)
        {
            lFlag |= lStyle;
        }
    }
    m_windowStyle = lFlag;
    UpdateStyle();
} // end of wxListCtrl::SetSingleStyle

// Set the whole window style
void wxListCtrl::SetWindowStyleFlag (
  long                              lFlag
)
{
    m_windowStyle = lFlag;
    UpdateStyle();
} // end of wxListCtrl::SetWindowStyleFlag

long wxListCtrl::ConvertToOS2Style (
  long&                             rOldStyle
, long                              lStyle
) const
{
    long                            lWstyle = 0L;

    //
    // The only styles OS2 uses on creation are auto arrange, read only, and
    // and selection styles.  This lib does not support OS/2 MINIRECORDCORE
    // or VERIFYPOINTER styles
    //
    if (lStyle & wxLC_AUTOARRANGE)
        lWstyle |= CCS_AUTOPOSITION;
    if (lStyle & wxLC_SINGLE_SEL)
        lWstyle |= CCS_SINGLESEL;
    else
        lWstyle |= CCS_EXTENDSEL;
    if (!(lStyle & wxLC_EDIT_LABELS))
        lWstyle |= CCS_READONLY;
    return lWstyle;
} // end of wxListCtrl::ConvertToOS2Style

long wxListCtrl::ConvertArrangeToOS2Style (
  long                              lStyle
)
{
    long                            lWstyle = 0;

    if (lStyle & wxLC_ALIGN_LEFT)
    {
        lWstyle |= CMA_LEFT;
    }

    if (lStyle & wxLC_ALIGN_TOP)
    {
        lWstyle |= CMA_TOP;
    }
    return lWstyle;
} // end of wxListCtrl::ConvertArrangeToOS2Style

long wxListCtrl::ConvertViewToOS2Style (
  long                              lStyle
)
{
    long                            lWstyle = CA_DRAWICON; // we will only use icons

    if (lStyle & wxLC_ICON)
    {
        lWstyle |= CV_ICON;
    }
    if (lStyle & wxLC_SMALL_ICON)
    {
        lWstyle |= (CV_ICON | CV_MINI);
    }
    if (lStyle & wxLC_LIST)
    {
        lWstyle |= CV_TEXT;
    }
    if (lStyle & wxLC_REPORT)
    {
        lWstyle |= CV_DETAIL;
    }
    if (lStyle & wxLC_VIRTUAL)
    {
        lWstyle |= CA_OWNERDRAW;
    }
    if (lStyle & wxLC_AUTOARRANGE)
    {
        lWstyle |= CV_FLOW;
    }
    if (!(lStyle & wxLC_NO_HEADER))
    {
        lWstyle |= CA_DETAILSVIEWTITLES;
    }
    return lWstyle;
} // end of wxListCtrl::ConvertViewToOS2Style

// ----------------------------------------------------------------------------
// accessors
// ----------------------------------------------------------------------------

// Sets the foreground, i.e. text, colour
bool wxListCtrl::SetForegroundColour (const wxColour& rCol)
{
    ULONG ulColor = wxColourToRGB(rCol);

    if (!wxWindow::SetForegroundColour(rCol))
        return false;

    ::WinSetPresParam( GetHWND()
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(ULONG)
                      ,&ulColor
                     );
    return true;
} // end of wxListCtrl::SetForegroundColour

// Sets the background colour
bool wxListCtrl::SetBackgroundColour ( const wxColour& rCol )
{
    if (!wxWindow::SetBackgroundColour(rCol))
        return false;

    //
    // We set the same colour for both the "empty" background and the items
    // background
    //
    ULONG ulColor = wxColourToRGB(rCol);

    ::WinSetPresParam( GetHWND()
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(ULONG)
                      ,&ulColor
                     );
    return true;
} // end of wxListCtrl::SetBackgroundColour

// Gets information about this column
bool wxListCtrl::GetColumn ( int nCol, wxListItem& rItem ) const
{
    PFIELDINFO pFieldInfo = FindOS2ListFieldByColNum ( GetHWND(), nCol );

    if (!pFieldInfo)
        return false;
    rItem.SetWidth(pFieldInfo->cxWidth);
    if ((rItem.GetMask() & wxLIST_MASK_TEXT) &&
        (pFieldInfo->flData & CFA_STRING) &&
        (pFieldInfo->pUserData != NULL))
    {
        rItem.SetText((char*)pFieldInfo->pUserData);
    }
    if (rItem.GetMask() & wxLIST_MASK_FORMAT )
    {
        if (pFieldInfo->flData & CFA_LEFT)
            rItem.m_format = wxLIST_FORMAT_LEFT;
        else if (pFieldInfo->flData & CFA_RIGHT)
            rItem.m_format = wxLIST_FORMAT_RIGHT;
        else if (pFieldInfo->flData & CFA_CENTER)
            rItem.m_format = wxLIST_FORMAT_CENTRE;
    }
    return true;
} // end of wxListCtrl::GetColumn

// Sets information about this column
bool wxListCtrl::SetColumn ( int nCol, wxListItem& rItem )
{
    PFIELDINFO pFieldInfo = FindOS2ListFieldByColNum( GetHWND(), nCol );
    ConvertToOS2ListCol( nCol, rItem, pFieldInfo );
    //
    // Since we changed the field pointed to, we invalidate to see the result
    //
    ::WinSendMsg(GetHWND(), CM_INVALIDATEDETAILFIELDINFO, NULL, NULL);
    return true;
} // end of wxListCtrl::SetColumn

// Gets the column width
int wxListCtrl::GetColumnWidth ( int nCol ) const
{
    PFIELDINFO pFieldInfo = FindOS2ListFieldByColNum ( GetHWND(), nCol );

    if (!pFieldInfo)
        return 0;
    return((int)pFieldInfo->cxWidth);
} // end of wxListCtrl::GetColumnWidth

// Sets the column width
bool wxListCtrl::SetColumnWidth ( int nCol, int nWidth )
{
    int nCol2 = nCol;
    int nWidth2 = nWidth;

    if (GetWindowStyleFlag() & wxLC_LIST)
        nCol2 = -1;

    PFIELDINFO pFieldInfo = FindOS2ListFieldByColNum( GetHWND(), nCol );
    pFieldInfo->cxWidth = nWidth;
    ::WinSendMsg(GetHWND(), CM_INVALIDATEDETAILFIELDINFO, NULL, NULL);
    return true;
} // end of wxListCtrl::SetColumnWidth

// Gets the number of items that can fit vertically in the
// visible area of the list control (list or report view)
// or the total number of items in the list control (icon
// or small icon view)
int wxListCtrl::GetCountPerPage () const
{
    QUERYRECORDRECT                 vQueryRect;
    CNRINFO                         vCnrInfo;
    RECTL                           vRectRecord;
    RECTL                           vRectControl;
    int                             nCount;

    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)(USHORT)sizeof(CNRINFO)
                     ))
        return 0;
    memset(&vQueryRect, '\0', sizeof(QUERYRECORDRECT));
    vQueryRect.cb = sizeof(QUERYRECORDRECT);
    if (vCnrInfo.flWindowAttr & CV_ICON)
        vQueryRect.fsExtent = CMA_ICON | CMA_TEXT;
    else if (vCnrInfo.flWindowAttr & CV_NAME)
        vQueryRect.fsExtent = CMA_ICON | CMA_TEXT;
    else if (vCnrInfo.flWindowAttr & CV_TEXT)
        vQueryRect.fsExtent = CMA_TEXT;
    else if (vCnrInfo.flWindowAttr & CV_DETAIL)
        vQueryRect.fsExtent = CMA_TEXT;
    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYRECORDRECT
                      ,MPFROMP(&vRectRecord)
                      ,MPFROMP(&vQueryRect)
                     ))
        return 0;
    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYVIEWPORTRECT
                      ,MPFROMP(&vRectControl)
                      ,MPFROM2SHORT(CMA_WINDOW, (USHORT)FALSE)
                     ))
        return 0;
    nCount = (int)((int)((vRectControl.xRight - vRectControl.xLeft) / (vRectRecord.xRight - vRectRecord.xLeft)) *
                   (int)((vRectControl.yTop - vRectControl.yBottom) / (vRectRecord.yTop - vRectRecord.yBottom))
                     );
    if (nCount > (int)vCnrInfo.cFields)
        nCount = (int)vCnrInfo.cFields;
    return nCount;
} // end of wxListCtrl::GetCountPerPage

// Gets the edit control for editing labels.
wxTextCtrl* wxListCtrl::GetEditControl() const
{
    return m_pTextCtrl;
}

// Gets information about the item
bool wxListCtrl::GetItem ( wxListItem& rInfo ) const
{
    PMYRECORD pRecord = FindOS2ListRecordByID( GetHWND(), rInfo.GetId() );

    //
    // Give NULL as hwnd as we already have everything we need
    //
    ConvertFromOS2ListItem( NULL, rInfo, pRecord );
    return true;
} // end of wxListCtrl::GetItem

// Sets information about the item
bool wxListCtrl::SetItem ( wxListItem& rInfo )
{
    PFIELDINFO pFieldInfo = FindOS2ListFieldByColNum ( GetHWND(), rInfo.GetColumn() );
    PMYRECORD pRecord = FindOS2ListRecordByID( GetHWND(), rInfo.GetId() );

    ConvertToOS2ListItem( this
                         ,rInfo
                         ,pRecord
                         ,pFieldInfo
                        );

    //
    // Check if setting attributes or lParam
    //
    if (rInfo.HasAttributes() || (rInfo.GetMask()  & wxLIST_MASK_DATA))
    {
        //
        // Get internal item data
        // perhaps a cache here ?
        //
        CListItemInternalData*      pData = GetInternalData( this
                                                            ,rInfo.GetId()
                                                           );

        if (!pData)
        {
            //
            // Need to set it
            //
            m_bAnyInternalData    = true;
            pData                 = new CListItemInternalData();
            pRecord->m_ulUserData = (unsigned long)pData;
        };

        //
        // User data
        //
        if (rInfo.GetMask()  & wxLIST_MASK_DATA)
            pData->m_lParam = (WXLPARAM)rInfo.GetData();

        // attributes
        if (rInfo.HasAttributes())
        {
            if (pData->m_pAttr)
                *pData->m_pAttr = *rInfo.GetAttributes();
            else
                pData->m_pAttr = new wxListItemAttr(*rInfo.GetAttributes());
        }
        pData->m_pMyRecord = pRecord;  // they point to each other
    }

    //
    // We need to update the item immediately to show the new image
    //
    bool bUpdateNow = (rInfo.GetMask() & wxLIST_MASK_IMAGE) != 0;

    //
    // Check whether it has any custom attributes
    //
    if (rInfo.HasAttributes())
    {
        m_bHasAnyAttr = true;

        //
        // If the colour has changed, we must redraw the item
        //
        bUpdateNow = true;
    }
    if (::WinIsWindowVisible(GetHWND()))
    {
        ::WinSendMsg( GetHWND()
                     ,CM_INVALIDATERECORD
                     ,MPFROMP(pRecord)
                     ,MPFROM2SHORT(1, CMA_ERASE | CMA_REPOSITION | CMA_TEXTCHANGED)
                    );
        RefreshItem(pRecord->m_ulItemId);
    }
    ::WinSendMsg( GetHWND()
                 ,CM_INVALIDATEDETAILFIELDINFO
                 ,NULL
                 ,NULL
                );
    return true;
} // end of wxListCtrl::SetItem

long wxListCtrl::SetItem (
  long                              lIndex
, int                               nCol
, const wxString&                   rsLabel
, int                               nImageId
)
{
    wxListItem                      vInfo;

    vInfo.m_text   = rsLabel;
    vInfo.m_mask   = wxLIST_MASK_TEXT;
    vInfo.m_itemId = lIndex;
    vInfo.m_col    = nCol;
    if (nImageId > -1)
    {
        vInfo.m_image = nImageId;
        vInfo.m_mask |= wxLIST_MASK_IMAGE;
    }
    return SetItem(vInfo);
} // end of wxListCtrl::SetItem

// Gets the item state
int wxListCtrl::GetItemState (
  long                              lItem
, long                              lStateMask
) const
{
    wxListItem                      vInfo;

    vInfo.m_mask      = wxLIST_MASK_STATE;
    vInfo.m_stateMask = lStateMask;
    vInfo.m_itemId    = lItem;

    if (!GetItem(vInfo))
        return 0;
    return vInfo.m_state;
} // end of wxListCtrl::GetItemState

// Sets the item state
bool wxListCtrl::SetItemState ( long lItem, long lState, long lStateMask )
{
    PMYRECORD pRecord = FindOS2ListRecordByID( GetHWND(), lItem );

    //
    // Don't use SetItem() here as it doesn't work with the virtual list
    // controls
    //
    ConvertToOS2Flags( lState, pRecord );

    //
    // for the virtual list controls we need to refresh the previously focused
    // item manually when changing focus without changing selection
    // programmatically because otherwise it keeps its focus rectangle until
    // next repaint (yet another comctl32 bug)
    //
    long                            lFocusOld;

    if (IsVirtual() &&
        (lStateMask & wxLIST_STATE_FOCUSED) &&
         (lState & wxLIST_STATE_FOCUSED) )
    {
        lFocusOld = GetNextItem( -1
                                ,wxLIST_NEXT_ALL
                                ,wxLIST_STATE_FOCUSED
                               );
    }
    else
    {
        lFocusOld = -1;
    }
    ::WinSendMsg( GetHWND()
                 ,CM_INVALIDATERECORD
                 ,MPFROMP(pRecord)
                 ,MPFROM2SHORT(1, CMA_ERASE | CMA_REPOSITION | CMA_TEXTCHANGED)
                );

    if (lFocusOld != -1)
    {
        //
        // No need to refresh the item if it was previously selected, it would
        // only result in annoying flicker
        //
        if (!(GetItemState( lFocusOld
                           ,wxLIST_STATE_SELECTED
                          ) & wxLIST_STATE_SELECTED))
        {
            RefreshItem(lFocusOld);
        }
    }
    return true;
} // end of wxListCtrl::SetItemState

// Sets the item image
bool wxListCtrl::SetItemImage (
  long                              lItem
, int                               nImage
, int                               WXUNUSED(nSelImage))
{
    return SetItemColumnInfo(lItem, 0, nImage);
} // end of wxListCtrl::SetItemImage

// Sets the item image
bool wxListCtrl::SetItemColumnImage (
  long                              lItem
, long                              lColumn
, int                               nImage)
{
    wxListItem                      vInfo;

    vInfo.m_mask   = wxLIST_MASK_IMAGE;
    vInfo.m_image  = nImage;
    vInfo.m_itemId = lItem;
    vInfo.m_col    = lColumn;
    return SetItem(vInfo);
} // end of wxListCtrl::SetItemColumnImage

// Gets the item text
wxString wxListCtrl::GetItemText (
  long                              lItem
) const
{
    wxListItem                      vInfo;

    vInfo.m_mask   = wxLIST_MASK_TEXT;
    vInfo.m_itemId = lItem;

    if (!GetItem(vInfo))
        return wxEmptyString;
    return vInfo.m_text;
} // end of wxListCtrl::GetItemText

// Sets the item text
void wxListCtrl::SetItemText (
  long                              lItem
, const wxString&                   rsStr
)
{
    wxListItem                      vInfo;

    vInfo.m_mask   = wxLIST_MASK_TEXT;
    vInfo.m_itemId = lItem;
    vInfo.m_text   = rsStr;
    SetItem(vInfo);
} // end of wxListCtrl::SetItemText

// Gets the item data
long wxListCtrl::GetItemData (
  long                              lItem
) const
{
    wxListItem                      vInfo;

    vInfo.m_mask   = wxLIST_MASK_DATA;
    vInfo.m_itemId = lItem;
    if (!GetItem(vInfo))
        return 0;
    return vInfo.m_data;
} // end of wxListCtrl::GetItemData

// Sets the item data
bool wxListCtrl::SetItemPtrData (
  long                              lItem
, wxUIntPtr                         lData
)
{
    wxListItem                      vInfo;

    vInfo.m_mask   = wxLIST_MASK_DATA;
    vInfo.m_itemId = lItem;
    vInfo.m_data   = lData;
    return SetItem(vInfo);
} // end of wxListCtrl::SetItemPtrData

// Gets the item rectangle
bool wxListCtrl::GetItemRect ( long lItem,
                               wxRect& rRect,
                               int nCode ) const
{
    bool bSuccess;
    PMYRECORD pRecord = FindOS2ListRecordByID( GetHWND(), lItem );
    QUERYRECORDRECT vQueryRect;
    RECTL vRect;
    int nHeight;

    if (!pRecord)
        return false;
    vQueryRect.cb                = sizeof(QUERYRECORDRECT);
    vQueryRect.pRecord           = &pRecord->m_vRecord;
    vQueryRect.fRightSplitWindow = TRUE;
    vQueryRect.fsExtent          = CMA_ICON | CMA_TEXT;
    ::WinSendMsg( GetHWND()
                 ,CM_QUERYRECORDRECT
                 ,MPFROMP(&vRect)
                 ,MPFROMP(&vQueryRect)
                );
    //
    // remember OS/2 is backwards
    //
    GetClientSize( NULL, &nHeight );
    rRect.x      = vRect.xLeft;
    rRect.y      = nHeight - vRect.yTop;
    rRect.width  = vRect.xRight;
    rRect.height = nHeight - vRect.yBottom;
    bSuccess = true;
    return bSuccess;
} // end of wxListCtrl::GetItemRect

// Gets the item position
bool wxListCtrl::GetItemPosition ( long lItem, wxPoint& rPos ) const
{
    bool bSuccess;
    PMYRECORD pRecord = FindOS2ListRecordByID( GetHWND() , lItem );
    QUERYRECORDRECT vQueryRect;
    RECTL vRect;
    int nHeight;

    if (!pRecord)
        return false;
    vQueryRect.cb                = sizeof(QUERYRECORDRECT);
    vQueryRect.pRecord           = &pRecord->m_vRecord;
    vQueryRect.fRightSplitWindow = TRUE;
    vQueryRect.fsExtent          = CMA_ICON | CMA_TEXT;
    ::WinSendMsg( GetHWND()
                 ,CM_QUERYRECORDRECT
                 ,MPFROMP(&vRect)
                 ,MPFROMP(&vQueryRect)
                );
    //
    // remember OS/2 is backwards
    //
    GetClientSize( NULL, &nHeight );
    rPos.x   = vRect.xLeft;
    rPos.y   = nHeight - vRect.yTop;
    bSuccess = true;
    return bSuccess;
} // end of wxListCtrl::GetItemPosition

// Sets the item position.
bool wxListCtrl::SetItemPosition ( long lItem, const wxPoint& rPos )
{
    //
    // Items cannot be positioned in X/Y coord in OS/2
    //
    return false;
} // end of wxListCtrl::SetItemPosition

// Gets the number of items in the list control
int wxListCtrl::GetItemCount () const
{
    CNRINFO                         vCnrInfo;

    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)(USHORT)sizeof(CNRINFO)
                     ))
        return -1;
    return vCnrInfo.cRecords;
} // end of wxListCtrl::GetItemCount

// Retrieves the spacing between icons in pixels.
// If bIsSmall is true, gets the spacing for the small icon
// view, otherwise the large icon view.
int wxListCtrl::GetItemSpacing ( bool bIsSmall ) const
{
    CNRINFO                         vCnrInfo;

    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)(USHORT)sizeof(CNRINFO)
                     ))
        return -1;
    return vCnrInfo.cyLineSpacing;
} // end of wxListCtrl::GetItemSpacing

void wxListCtrl::SetItemTextColour (
  long                              lItem
, const wxColour&                   rCol
)
{
    wxListItem                      vInfo;

    vInfo.m_itemId = lItem;
    vInfo.SetTextColour(rCol);
    SetItem(vInfo);
} // end of wxListCtrl::SetItemTextColour

wxColour wxListCtrl::GetItemTextColour (
  long                              lItem
) const
{
    wxListItem                      vInfo;

    vInfo.m_itemId = lItem;
    GetItem(vInfo);
    return vInfo.GetTextColour();
} // end of wxListCtrl::GetItemTextColour

void wxListCtrl::SetItemBackgroundColour (
  long                              lItem
, const wxColour&                   rCol
)
{
    wxListItem                      vInfo;

    vInfo.m_itemId = lItem;
    vInfo.SetBackgroundColour(rCol);
    SetItem(vInfo);
} // end of wxListCtrl::SetItemBackgroundColour

wxColour wxListCtrl::GetItemBackgroundColour (
  long                              lItem
) const
{
    wxListItem                      vInfo;

    vInfo.m_itemId = lItem;
    GetItem(vInfo);
    return vInfo.GetBackgroundColour();
} // end of wxListCtrl::GetItemBackgroundColour

// Gets the number of selected items in the list control
int wxListCtrl::GetSelectedItemCount () const
{
    PMYRECORD                       pRecord = NULL;
    int                             nCount = 0;
    pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                  ,CM_QUERYRECORDEMPHASIS
                                                  ,(MPARAM)CMA_FIRST
                                                  ,(MPARAM)CRA_SELECTED
                                                 ));
    if (pRecord)
        nCount++;
    else
        return 0;
    while (pRecord)
    {
        pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                      ,CM_QUERYRECORDEMPHASIS
                                                      ,MPFROMP(pRecord)
                                                      ,(MPARAM)CRA_SELECTED
                                                     ));
        if (pRecord)
            nCount++;
    }
    return nCount;
} // end of wxListCtrl::GetSelectedItemCount

// Gets the text colour of the listview
wxColour wxListCtrl::GetTextColour () const
{
    wxColour                        vCol;
    ULONG                           ulColor;

    ::WinQueryPresParam( GetHWND()
                        ,PP_FOREGROUNDCOLOR
                        ,0
                        ,NULL
                        ,sizeof(ULONG)
                        ,&ulColor
                        ,QPF_PURERGBCOLOR
                       );
    vCol.Set(ulColor);
    return vCol;
} // end of wxListCtrl::GetTextColour

// Sets the text colour of the listview
void wxListCtrl::SetTextColour (
  const wxColour&                   rCol
)
{
    ULONG                           ulColor = wxColourToRGB(rCol);

    ::WinSetPresParam( GetHWND()
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(ULONG)
                      ,&ulColor
                     );
} // end of wxListCtrl::SetTextColour

// Gets the index of the topmost visible item when in
// list or report view
long wxListCtrl::GetTopItem () const
{
    PMYRECORD                       pRecord = NULL;
    QUERYRECFROMRECT                vQueryRect;
    RECTL                           vRect;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYVIEWPORTRECT
                 ,MPFROMP(&vRect)
                 ,MPFROM2SHORT(CMA_WINDOW, TRUE)
                );
    vQueryRect.cb        = sizeof(QUERYRECFROMRECT);
    vQueryRect.rect      = vRect;
    vQueryRect.fsSearch = CMA_PARTIAL;

    pRecord = (PMYRECORD)::WinSendMsg( GetHWND()
                                      ,CM_QUERYRECORDFROMRECT
                                      ,(MPARAM)CMA_FIRST
                                      ,MPFROMP(&vQueryRect)
                                    );

    if (!pRecord)
        return -1L;
    return (long)pRecord->m_ulItemId;
} // end of wxListCtrl::GetTopItem

// Searches for an item, starting from 'item'.
// 'geometry' is one of
// wxLIST_NEXT_ABOVE/ALL/BELOW/LEFT/RIGHT.
// 'state' is a state bit flag, one or more of
// wxLIST_STATE_DROPHILITED/FOCUSED/SELECTED/CUT.
// item can be -1 to find the first item that matches the
// specified flags.
// Returns the item or -1 if unsuccessful.
long wxListCtrl::GetNextItem (
  long                              lItem
, int                               WXUNUSED(nGeom)
, int                               WXUNUSED(nState)
) const
{
    PMYRECORD                       pRecord = FindOS2ListRecordByID( GetHWND()
                                                                    ,lItem
                                                                   );

    pRecord = (PMYRECORD)pRecord->m_vRecord.preccNextRecord;
    if (pRecord)
        return((long)pRecord->m_ulItemId);
    return -1L;
} // end of wxListCtrl::GetNextItem

wxImageList* wxListCtrl::GetImageList (
  int                               nWhich
) const
{
    if (nWhich == wxIMAGE_LIST_NORMAL )
    {
        return m_pImageListNormal;
    }
    else if (nWhich == wxIMAGE_LIST_SMALL )
    {
        return m_pImageListSmall;
    }
    else if (nWhich == wxIMAGE_LIST_STATE )
    {
        return m_pImageListState;
    }
    return NULL;
} // end of wxListCtrl::GetImageList

void wxListCtrl::SetImageList ( wxImageList* pImageList,
                                int nWhich )
{
    if (nWhich == wxIMAGE_LIST_NORMAL)
    {
        if (m_bOwnsImageListNormal)
            delete m_pImageListNormal;
        m_pImageListNormal     = pImageList;
        m_bOwnsImageListNormal = false;
    }
    else if (nWhich == wxIMAGE_LIST_SMALL)
    {
        if (m_bOwnsImageListSmall)
            delete m_pImageListSmall;
        m_pImageListSmall    = pImageList;
        m_bOwnsImageListSmall = false;
    }
    else if (nWhich == wxIMAGE_LIST_STATE)
    {
        if (m_bOwnsImageListState)
            delete m_pImageListState;
        m_pImageListState     = pImageList;
        m_bOwnsImageListState = false;
    }
} // end of wxListCtrl::SetImageList

void wxListCtrl::AssignImageList ( wxImageList* pImageList, int nWhich )
{
    SetImageList( pImageList, nWhich );

    if (nWhich == wxIMAGE_LIST_NORMAL )
        m_bOwnsImageListNormal = true;
    else if (nWhich == wxIMAGE_LIST_SMALL )
        m_bOwnsImageListSmall = true;
    else if (nWhich == wxIMAGE_LIST_STATE )
        m_bOwnsImageListState = true;
} // end of wxListCtrl::AssignImageList

// ----------------------------------------------------------------------------
// Operations
// ----------------------------------------------------------------------------

// Arranges the items
bool wxListCtrl::Arrange ( int nFlag )
{
    ULONG ulType = 0L;
    ULONG ulFlags = 0L;

    if (nFlag == wxLIST_ALIGN_SNAP_TO_GRID)
    {
        ulType = CMA_ARRANGEGRID;
        if (nFlag == wxLIST_ALIGN_LEFT)
            ulFlags |= CMA_LEFT;
        else if (nFlag == wxLIST_ALIGN_TOP)
            ulFlags |= CMA_TOP;
        else if (nFlag == wxLIST_ALIGN_DEFAULT)
            ulFlags |= CMA_LEFT;
    }
    else
        ulType = CMA_ARRANGESTANDARD;
    ::WinSendMsg( GetHWND()
                 ,CM_ARRANGE
                 ,(MPARAM)ulType
                 ,(MPARAM)ulFlags
                );
    //
    // We do not support CMA_ARRANGESELECTED
    //
    return true;
} // end of wxListCtrl::Arrange

// Deletes an item
bool wxListCtrl::DeleteItem ( long lItem )
{
    PMYRECORD pRecord = FindOS2ListRecordByID( GetHWND(), lItem );
    if (LONGFROMMR(::WinSendMsg( GetHWND()
                                ,CM_REMOVERECORD
                                ,(MPARAM)pRecord
                                ,MPFROM2SHORT(1, CMA_FREE)
                               )) == -1L)
    {
        return false;
    }

    //
    // The virtual list control doesn't refresh itself correctly, help it
    //
    if (IsVirtual())
    {
        //
        // We need to refresh all the lines below the one which was deleted
        //
        wxRect                      vRectItem;

        if (lItem > 0 && GetItemCount())
        {
            GetItemRect( lItem - 1
                        ,vRectItem
                       );
        }
        else
        {
            vRectItem.y = vRectItem.height = 0;
        }
        wxRect                      vRectWin = GetRect();

        vRectWin.height = vRectWin.GetBottom() - vRectItem.GetBottom();
        vRectWin.y      = vRectItem.GetBottom();
        RefreshRect(vRectWin);
    }
    return true;
} // end of wxListCtrl::DeleteItem

// Deletes all items
bool wxListCtrl::DeleteAllItems ()
{
    return((LONG)::WinSendMsg( GetHWND()
                              ,CM_REMOVERECORD
                              ,NULL
                              ,MPFROM2SHORT(0, CMA_FREE)
                             ) != -1L);
} // end of wxListCtrl::DeleteAllItems

// Deletes all items
bool wxListCtrl::DeleteAllColumns ()
{
    while (m_nColCount > 0)
    {
        DeleteColumn(m_nColCount - 1);
        m_nColCount--;
    }

    wxASSERT_MSG(m_nColCount == 0, wxT("no columns should be left"));
    return true;
} // end of wxListCtrl::DeleteAllColumns

// Deletes a column
bool wxListCtrl::DeleteColumn ( int nCol )
{
    bool bSuccess = false;
    PFIELDINFO pField = FindOS2ListFieldByColNum( GetHWND(), nCol );
    bSuccess = ((LONG)::WinSendMsg( GetHWND()
                                   ,CM_REMOVEDETAILFIELDINFO
                                   ,MPFROMP(pField)
                                   ,MPFROM2SHORT((SHORT)1, CMA_FREE)
                                  ) == -1L);
    if (bSuccess && (m_nColCount > 0))
        m_nColCount--;
    return bSuccess;
} // end of wxListCtrl::DeleteColumn

// Clears items, and columns if there are any.
void wxListCtrl::ClearAll ()
{
    DeleteAllItems();
    if (m_nColCount > 0)
        DeleteAllColumns();
} // end of wxListCtrl::ClearAll

//
// OS/2 does not use a text control for its container labels.  You merely
// "open" a record for editting.
//
wxTextCtrl* wxListCtrl::EditLabel (
  long                              lItem
, wxClassInfo*                      WXUNUSED(pTextControlClass)
)
{
    CNREDITDATA                     vEdit;
    PMYRECORD                       pRecord = FindOS2ListRecordByID( GetHWND()
                                                                    ,lItem
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
    return m_pTextCtrl;
} // end of wxListCtrl::EditLabel

// End label editing, optionally cancelling the edit.  Under OS/2 you close
// the record for editting
bool wxListCtrl::EndEditLabel ( bool WXUNUSED(bCancel) )
{
    ::WinSendMsg( GetHWND()
                 ,CM_CLOSEEDIT
                 ,(MPARAM)0
                 ,(MPARAM)0
                );
    return true;
} // end of wxListCtrl::EndEditLabel

// Ensures this item is visible
bool wxListCtrl::EnsureVisible ( long lItem )
{
    PMYRECORD pRecord = FindOS2ListRecordByID( GetHWND(), lItem );
    ::WinSendMsg( GetHWND()
                 ,CM_INVALIDATERECORD
                 ,MPFROMP(pRecord)
                 ,MPFROM2SHORT((SHORT)1, CMA_NOREPOSITION)
                );
    return true;
} // end of wxListCtrl::EnsureVisible

// Find an item whose label matches this string, starting from the item after 'start'
// or the beginning if 'start' is -1.
long wxListCtrl::FindItem (
  long                              lStart
, const wxString&                   rsStr
, bool                              bPartial
)
{
    CNRINFO                         vCnrInfo;
    SEARCHSTRING                    vSearch;
    PMYRECORD                       pRecord = FindOS2ListRecordByID( GetHWND()
                                                                    ,lStart
                                                                   );
    ULONG                           ulFlag;


    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)(USHORT)sizeof(CNRINFO)
                     ))
        return -1L;

    if (vCnrInfo.flWindowAttr & CV_ICON)
        ulFlag = CV_ICON;
    if (vCnrInfo.flWindowAttr & CV_NAME)
        ulFlag = CV_NAME;
    if (vCnrInfo.flWindowAttr & CV_TEXT)
        ulFlag = CV_TEXT;
    if (vCnrInfo.flWindowAttr & CV_DETAIL)
        ulFlag = CV_DETAIL;
    if (!bPartial)
        ulFlag |= CV_EXACTLENGTH;

    vSearch.cb              = sizeof(SEARCHSTRING);
    vSearch.pszSearch       = (char*)rsStr.c_str();
    vSearch.fsPrefix        = TRUE;
    vSearch.fsCaseSensitive = TRUE;
    vSearch.usView          = ulFlag;

    if (lStart == -1)
    {
        pRecord = (PMYRECORD)::WinSendMsg( GetHWND()
                                          ,CM_SEARCHSTRING
                                          ,MPFROMP(&vSearch)
                                          ,(MPARAM)CMA_FIRST
                                         );
    }
    else
    {
        pRecord = (PMYRECORD)::WinSendMsg( GetHWND()
                                          ,CM_SEARCHSTRING
                                          ,MPFROMP(&vSearch)
                                          ,MPFROMP(pRecord)
                                         );
    }
    if (!pRecord)
        return -1L;
    return pRecord->m_ulItemId;
} // end of wxListCtrl::FindItem

// Find an item whose data matches this data, starting from the item after 'start'
// or the beginning if 'start' is -1.
long wxListCtrl::FindItem (
  long                              lStart
, long                              lData
)
{
    long                            lIdx = lStart + 1;
    long                            lCount = GetItemCount();

    while (lIdx < lCount)
    {
        if (GetItemData(lIdx) == lData)
            return lIdx;
        lIdx++;
    };
    return -1;
} // end of wxListCtrl::FindItem

// Find an item nearest this position in the specified direction, starting from
// the item after 'start' or the beginning if 'start' is -1.
long wxListCtrl::FindItem (
  long                              lStart
, const wxPoint&                    rPoint
, int                               nDirection
)
{
    RECTL                           vRect;
    QUERYRECORDRECT                 vQueryRect;
    PMYRECORD                       pRecord = FindOS2ListRecordByID( GetHWND()
                                                                    ,lStart
                                                                   );
    CNRINFO                         vCnrInfo;
    ULONG                           i;
    wxRect                          vLibRect;

    if (!::WinSendMsg( GetHWND()
                      ,CM_QUERYCNRINFO
                      ,MPFROMP(&vCnrInfo)
                      ,(MPARAM)(USHORT)sizeof(CNRINFO)
                     ))
        return -1L;

    vQueryRect.cb                = sizeof(QUERYRECORDRECT);
    vQueryRect.pRecord           = &pRecord->m_vRecord;
    vQueryRect.fRightSplitWindow = TRUE;
    vQueryRect.fsExtent          = CMA_ICON | CMA_TEXT;

    ::WinSendMsg( GetHWND()
                 ,CM_QUERYRECORDRECT
                 ,MPFROMP(&vRect)
                 ,MPFROMP(&vQueryRect)
                );
    vLibRect.SetLeft(vRect.xLeft);
    vLibRect.SetTop(vRect.yTop);
    vLibRect.SetRight(vRect.xRight);
    vLibRect.SetBottom(vRect.yBottom);
    if (vLibRect.Contains(rPoint))
        return pRecord->m_ulItemId;

    for (i = lStart + 1; i < vCnrInfo.cRecords; i++)
    {
        pRecord = (PMYRECORD)PVOIDFROMMR(::WinSendMsg( GetHWND()
                                                      ,CM_QUERYRECORD
                                                      ,MPFROMP(pRecord)
                                                      ,MPFROM2SHORT(CMA_NEXT, CMA_ITEMORDER)
                                                     ));
        vQueryRect.pRecord = (PRECORDCORE)pRecord;
        ::WinSendMsg( GetHWND()
                     ,CM_QUERYRECORDRECT
                     ,MPFROMP(&vRect)
                     ,MPFROMP(&vQueryRect)
                    );
        vLibRect.SetLeft(vRect.xLeft);
        vLibRect.SetTop(vRect.yTop);
        vLibRect.SetRight(vRect.xRight);
        vLibRect.SetBottom(vRect.yBottom);
        if (vLibRect.Contains(rPoint))
            return pRecord->m_ulItemId;
    }
    return -1L;
} // end of wxListCtrl::FindItem

// Determines which item (if any) is at the specified point,
// giving details in 'flags' (see wxLIST_HITTEST_... flags above)
long wxListCtrl::HitTest (
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
    return pRecord->m_ulItemId;
} // end of wxListCtrl::HitTest

// Inserts an item, returning the index of the new item if successful,
// -1 otherwise.
long wxListCtrl::InsertItem (
  wxListItem&                       rInfo
)
{
    wxASSERT_MSG( !IsVirtual(), wxT("can't be used with virtual controls") );

    PFIELDINFO                      pFieldInfo = FindOS2ListFieldByColNum ( GetHWND()
                                                                           ,rInfo.GetColumn()
                                                                          );
    PMYRECORD                       pRecordAfter = NULL;
    PMYRECORD                       pRecord = (PMYRECORD)::WinSendMsg( GetHWND()
                                                                      ,CM_ALLOCRECORD
                                                                      ,MPFROMLONG(sizeof(MYRECORD) - sizeof(RECORDCORE))
                                                                      ,MPFROMSHORT(1)
                                                                     );

    ConvertToOS2ListItem( this
                         ,rInfo
                         ,pRecord
                         ,pFieldInfo
                        );

    if (rInfo.GetId() > 0)
        pRecordAfter = FindOS2ListRecordByID( GetHWND()
                                             ,rInfo.GetId() - 1
                                            );

    RECORDINSERT                    vInsert;

    vInsert.cb                = sizeof(RECORDINSERT);
    vInsert.pRecordParent     = NULL;
    if (!pRecordAfter)
        vInsert.pRecordOrder  = (PRECORDCORE)CMA_FIRST;
    else
        vInsert.pRecordOrder  = (PRECORDCORE)pRecordAfter;
    vInsert.zOrder            = CMA_TOP;
    vInsert.cRecordsInsert    = 1;
    vInsert.fInvalidateRecord = TRUE;

    //
    // Check wether we need to allocate our internal data
    //
    bool                            bNeedInternalData = ((rInfo.GetMask() & wxLIST_MASK_DATA) ||
                                                          rInfo.HasAttributes()
                                                        );
    if (bNeedInternalData)
    {
        m_bAnyInternalData = true;

        //
        // Internal stucture that manages data
        //
        CListItemInternalData*      pData = new CListItemInternalData();

        pRecord->m_ulUserData = (unsigned long)pData;
        if (rInfo.GetMask() & wxLIST_MASK_DATA)
            pData->m_lParam = (WXLPARAM)rInfo.GetData();

        //
        // Check whether it has any custom attributes
        //
        if (rInfo.HasAttributes())
        {
            //
            // Take copy of attributes
            //
            pData->m_pAttr = new wxListItemAttr(*rInfo.GetAttributes());
        }
    }
    if (!::WinSendMsg( GetHWND()
                      ,CM_INSERTRECORD
                      ,MPFROMP(pRecord)
                      ,MPFROMP(&vInsert)
                     ))
        return -1;
    //
    // OS/2 must mannually bump the index's of following records
    //
    BumpRecordIds( GetHWND()
                  ,pRecord
                 );
    ::WinSendMsg( GetHWND()
                 ,CM_INVALIDATEDETAILFIELDINFO
                 ,NULL
                 ,NULL
                );
    return pRecord->m_ulItemId;
} // end of wxListCtrl::InsertItem

long wxListCtrl::InsertItem (
  long                              lIndex
, const wxString&                   rsLabel
)
{
    wxListItem                      vInfo;

    memset(&vInfo, '\0', sizeof(wxListItem));
    vInfo.m_text   = rsLabel;
    vInfo.m_mask   = wxLIST_MASK_TEXT;
    vInfo.m_itemId = lIndex;
    return InsertItem(vInfo);
} // end of wxListCtrl::InsertItem

// Inserts an image item
long wxListCtrl::InsertItem (
  long                              lIndex
, int                               nImageIndex
)
{
    wxListItem                      vInfo;

    vInfo.m_image  = nImageIndex;
    vInfo.m_mask   = wxLIST_MASK_IMAGE;
    vInfo.m_itemId = lIndex;
    return InsertItem(vInfo);
} // end of wxListCtrl::InsertItem

// Inserts an image/string item
long wxListCtrl::InsertItem (
  long                              lIndex
, const wxString&                   rsLabel
, int                               nImageIndex
)
{
    wxListItem                      vInfo;

    vInfo.m_image  = nImageIndex;
    vInfo.m_text   = rsLabel;
    vInfo.m_mask   = wxLIST_MASK_IMAGE | wxLIST_MASK_TEXT;
    vInfo.m_itemId = lIndex;
    return InsertItem(vInfo);
} // end of wxListCtrl::InsertItem

// For details view mode (only), inserts a column.
long wxListCtrl::InsertColumn (
  long                              lCol
, wxListItem&                       rItem
)
{
    bool                            bSuccess;
    PFIELDINFO                      pField = (PFIELDINFO)::WinSendMsg( GetHWND()
                                                                      ,CM_ALLOCDETAILFIELDINFO
                                                                      ,MPFROMLONG(1)
                                                                      ,NULL
                                                                     );
    PFIELDINFO                      pFieldAfter = FindOS2ListFieldByColNum ( GetHWND()
                                                                            ,lCol - 1
                                                                           );
    FIELDINFOINSERT                 vInsert;

    ConvertToOS2ListCol ( lCol
                         ,rItem
                         ,pField
                        );

    vInsert.cb                   = sizeof(FIELDINFOINSERT);
    vInsert.pFieldInfoOrder      = pFieldAfter;
    vInsert.fInvalidateFieldInfo = TRUE;
    vInsert.cFieldInfoInsert     = 1;

    bSuccess = ::WinSendMsg( GetHWND()
                            ,CM_INSERTDETAILFIELDINFO
                            ,MPFROMP(pField)
                            ,MPFROMP(&vInsert)
                           ) != (MRESULT)0;
    return bSuccess;
} // end of wxListCtrl::InsertColumn

long wxListCtrl::InsertColumn (
  long                              lCol
, const wxString&                   rsHeading
, int                               nFormat
, int                               nWidth
)
{
    wxListItem                      vItem;

    vItem.m_mask = wxLIST_MASK_TEXT | wxLIST_MASK_FORMAT;
    vItem.m_text = rsHeading;
    if (nWidth > -1)
    {
        vItem.m_mask |= wxLIST_MASK_WIDTH;
        vItem.m_width = nWidth;
    }
    vItem.m_format = nFormat;

    return InsertColumn( lCol
                        ,vItem
                       );
} // end of wxListCtrl::InsertColumn

// scroll the control by the given number of pixels (exception: in list view,
// dx is interpreted as number of columns)
bool wxListCtrl::ScrollList ( int nDx, int nDy )
{
    if (nDx > 0)
        ::WinSendMsg( GetHWND()
                     ,CM_SCROLLWINDOW
                     ,(MPARAM)CMA_HORIZONTAL
                     ,(MPARAM)nDx
                    );
    if (nDy > 0)
        ::WinSendMsg( GetHWND()
                     ,CM_SCROLLWINDOW
                     ,(MPARAM)CMA_VERTICAL
                     ,(MPARAM)nDy
                    );
    return true;
} // end of wxListCtrl::ScrollList

bool wxListCtrl::SortItems ( wxListCtrlCompare fn, long lData )
{
    SInternalDataSort vInternalData;

    vInternalData.m_fnUser = fn;
    vInternalData.m_lData  = lData;

    // WPARAM cast is needed for mingw/cygwin
    if (!::WinSendMsg( GetHWND()
                      ,CM_SORTRECORD
                      ,(PFN)InternalDataCompareFunc
                      ,(PVOID)&vInternalData
                     ))
    {
        wxLogDebug(wxT("CM_SORTRECORD failed"));
        return false;
    }
    return true;
} // end of wxListCtrl::SortItems

// ----------------------------------------------------------------------------
// message processing
// ----------------------------------------------------------------------------

bool wxListCtrl::OS2Command ( WXUINT uCmd, WXWORD wId )
{
    if (uCmd == CN_ENDEDIT)
    {
        wxCommandEvent vEvent( wxEVT_COMMAND_TEXT_UPDATED, wId );

        vEvent.SetEventObject( this );
        ProcessCommand(vEvent);
        return true;
    }
    else if (uCmd == CN_KILLFOCUS)
    {
        wxCommandEvent vEvent( wxEVT_KILL_FOCUS, wId );
        vEvent.SetEventObject( this );
        ProcessCommand(vEvent);
        return true;
    }
    else
        return false;
} // end of wxListCtrl::OS2Command

// Necessary for drawing hrules and vrules, if specified
void wxListCtrl::OnPaint ( wxPaintEvent& rEvent )
{
    wxPaintDC                       vDc(this);
    wxPen                           vPen(wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT)
                                                                     ,1
                                                                     ,wxSOLID
                                                                    );
    wxSize                          vClientSize = GetClientSize();
    wxRect                          vItemRect;
    int                             nItemCount = GetItemCount();
    int                             nCy = 0;
    int                             i;
    bool                            bDrawHRules = ((GetWindowStyle() & wxLC_HRULES) != 0);
    bool                            bDrawVRules = ((GetWindowStyle() & wxLC_VRULES) != 0);

    wxControl::OnPaint(rEvent);

    //
    // Reset the device origin since it may have been set
    //
    vDc.SetDeviceOrigin(0, 0);
    if (!bDrawHRules && !bDrawVRules)
        return;
    if ((GetWindowStyle() & wxLC_REPORT) == 0)
        return;
    vDc.SetPen(vPen);
    vDc.SetBrush(*wxTRANSPARENT_BRUSH);

    if (bDrawHRules)
    {
        long                        lTop = GetTopItem();

        for (i = lTop; i < lTop + GetCountPerPage() + 1; i++)
        {
            if (GetItemRect( i
                            ,vItemRect
                           ))
            {
                nCy = vItemRect.GetTop();
                if (i != 0) // Don't draw the first one
                {
                    vDc.DrawLine( 0
                                 ,nCy
                                 ,vClientSize.x
                                 ,nCy
                                );
                }
                // Draw last line
                if (i == nItemCount - 1)
                {
                    nCy = vItemRect.GetBottom();
                    vDc.DrawLine( 0
                                 ,nCy
                                 ,vClientSize.x
                                 ,nCy
                                );
                }
            }
        }
    }
    i = nItemCount - 1;
    if (bDrawVRules && (i > -1))
    {
        wxRect                      vFirstItemRect;

        GetItemRect( 0
                    ,vFirstItemRect
                   );
        if (GetItemRect( i
                        ,vItemRect
                       ))
        {
            int                     nCol;
            int                     nX = vItemRect.GetX();

            for (nCol = 0; nCol < GetColumnCount(); nCol++)
            {
                int                 nColWidth = GetColumnWidth(nCol);

                nX += nColWidth ;
                vDc.DrawLine( nX - 1
                             ,vFirstItemRect.GetY() - 2
                             ,nX - 1
                             ,vItemRect.GetBottom()
                            );
            }
        }
    }
} // end of wxListCtrl::OnPaint

// ----------------------------------------------------------------------------
// virtual list controls
// ----------------------------------------------------------------------------

wxString wxListCtrl::OnGetItemText (
  long                              WXUNUSED(lItem)
, long                              WXUNUSED(lCol)
) const
{
    // this is a pure virtual function, in fact - which is not really pure
    // because the controls which are not virtual don't need to implement it
    wxFAIL_MSG( wxT("not supposed to be called") );
    return wxEmptyString;
} // end of wxListCtrl::OnGetItemText

int wxListCtrl::OnGetItemImage (
  long                              WXUNUSED(lItem)
) const
{
    // same as above
    wxFAIL_MSG( wxT("not supposed to be called") );
    return -1;
} // end of wxListCtrl::OnGetItemImage

int wxListCtrl::OnGetItemColumnImage (
  long                              lItem,
  long                              lColumn
) const
{
    if (!lColumn)
        return OnGetItemImage(lItem);

    return -1;
} // end of wxListCtrl::OnGetItemColumnImage

wxListItemAttr* wxListCtrl::OnGetItemAttr (
  long                              WXUNUSED_UNLESS_DEBUG(lItem)
) const
{
    wxASSERT_MSG( lItem >= 0 && lItem < GetItemCount(),
                  wxT("invalid item index in OnGetItemAttr()") );

    //
    // No attributes by default
    //
    return NULL;
} // end of wxListCtrl::OnGetItemAttr

void wxListCtrl::SetItemCount (
  long                              lCount
)
{
    wxASSERT_MSG( IsVirtual(), wxT("this is for virtual controls only") );

    //
    // Cannot explicitly set the record count in OS/2
    //
} // end of wxListCtrl::SetItemCount

void wxListCtrl::RefreshItem (
  long                              lItem
)
{
    wxRect                          vRect;

    GetItemRect( lItem
                ,vRect
               );
    RefreshRect(vRect);
} // end of wxListCtrl::RefreshItem

void wxListCtrl::RefreshItems ( long lItemFrom, long lItemTo )
{
    wxRect vRect1;
    wxRect vRect2;

    GetItemRect( lItemFrom , vRect1 );
    GetItemRect( lItemTo , vRect2 );

    wxRect vRect = vRect1;

    vRect.height = vRect2.GetBottom() - vRect1.GetTop();
    RefreshRect(vRect);
} // end of wxListCtrl::RefreshItems

MRESULT wxListCtrl::OS2WindowProc( WXUINT uMsg,
                                   WXWPARAM wParam,
                                   WXLPARAM lParam )
{
    bool                            bProcessed = false;
    MRESULT                         lRc;
    wxListEvent                     vEvent( wxEVT_NULL
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
            //
            // First off let's set some internal data
            //
            switch(SHORT2FROMMP(wParam))
            {
                case CN_INITDRAG:
                case CN_DRAGOVER:
                case CN_DRAGAFTER:
                    {
                        CListItemInternalData*  pInternaldata = (CListItemInternalData *)lParam;

                        if (pInternaldata)
                        {
                            wxListItem*     pItem = (wxListItem*)&vEvent.GetItem();

                            pItem->SetData((long)pInternaldata->m_lParam);
                        }
                    }
                    break;
            }
            //
            // Now let's go through the codes we're interested in
            //
            switch(SHORT2FROMMP(wParam))
            {
                case CN_INITDRAG:
                    pDragInit = (PCNRDRAGINIT)lParam;
                    if (pDragInit)
                    {
                        PMYRECORD       pRecord = (PMYRECORD)pDragInit->pRecord;

                        vEventType = wxEVT_COMMAND_LIST_BEGIN_RDRAG;
                        vEvent.m_itemIndex   = pRecord->m_ulItemId;
                        vEvent.m_pointDrag.x = pDragInit->x;
                        vEvent.m_pointDrag.y = pDragInit->y;
                    }
                    break;

                case CN_BEGINEDIT:
                    pEditData = (PCNREDITDATA)lParam;
                    if (pEditData)
                    {
                        vEventType = wxEVT_COMMAND_LIST_BEGIN_LABEL_EDIT;
                        ConvertFromOS2ListItem( GetHWND()
                                               ,(wxListItem &)vEvent.GetItem()
                                               ,(PMYRECORD)pEditData->pRecord
                                              );
                        vEvent.m_itemIndex = vEvent.GetItem().GetId();
                    }
                    break;

                case CN_ENDEDIT:
                    pEditData = (PCNREDITDATA)lParam;
                    if (pEditData)
                    {
                        vEventType = wxEVT_COMMAND_LIST_END_LABEL_EDIT;
                        ConvertFromOS2ListItem( GetHWND()
                                               ,(wxListItem &)vEvent.GetItem()
                                               ,(PMYRECORD)pEditData->pRecord
                                              );
                        if (pEditData->cbText == 0)
                            return (MRESULT)FALSE;
                        vEvent.m_itemIndex = vEvent.GetItem().GetId();
                    }
                    break;

                case CN_ENTER:
                    pNotifyEnter = (PNOTIFYRECORDENTER)lParam;
                    if (pNotifyEnter)
                    {
                        wxListItem*     pItem = (wxListItem*)&vEvent.GetItem();
                        PMYRECORD       pMyRecord = (PMYRECORD)pNotifyEnter->pRecord;

                        vEventType             = wxEVT_COMMAND_LIST_ITEM_ACTIVATED;
                        vEvent.m_itemIndex = pMyRecord->m_ulItemId;
                        pItem->SetText(GetItemText(pMyRecord->m_ulItemId));
                        pItem->SetData(GetItemData(pMyRecord->m_ulItemId));
                    }
                    break;

                    //
                    // Add the CN_DROP messages for Direct Manipulation
                    //
            }
            vEvent.SetEventType(vEventType);
            bProcessed = HandleWindowEvent(vEvent);
            break;
    }
    if (!bProcessed)
        lRc = wxControl::OS2WindowProc( uMsg
                                       ,wParam
                                       ,lParam
                                      );
    return lRc;
} // end of wxListCtrl::WindowProc

#endif // wxUSE_LISTCTRL
