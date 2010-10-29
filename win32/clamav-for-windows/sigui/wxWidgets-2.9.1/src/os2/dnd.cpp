///////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/dnd.cpp
// Purpose:     wxDropTarget, wxDropSource, wxDataObject implementation
// Author:      David Webster
// Modified by:
// Created:     10/21/99
// RCS-ID:      $Id$
// Copyright:   (c) 1998 AUTHOR
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_DRAG_AND_DROP

#include "wx/dnd.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/window.h"
    #include "wx/gdicmn.h"
#endif

#define INCL_PM
#define INCL_DOS
#include <os2.h>

// ----------------------------------------------------------------------------
// global
// ----------------------------------------------------------------------------

/////////////////////////////////////////////////////////////////////////////
// Private functions
/////////////////////////////////////////////////////////////////////////////

#if 0
static wxDragResult ConvertDragEffectToResult (
  DWORD                             dwEffect
)
{
    switch (dwEffect)
    {
        case DO_COPY:
            return wxDragCopy;

        case DO_LINK:
            return wxDragLink;

        case DO_MOVE:
            return wxDragMove;

        default:
        case DO_DEFAULT:
            return wxDragNone;
    }
} // end of ConvertDragEffectToResult

static DWORD ConvertDragResultToEffect (
  wxDragResult                      eResult
)
{
    switch (eResult)
    {
        case wxDragCopy:
            return DO_COPY;

        case wxDragLink:
            return DO_LINK;

        case wxDragMove:
            return DO_MOVE;

        default:
        case wxDragNone:
            return DO_DEFAULT;
    }
} // end of ConvertDragResultToEffect
#endif

class CIDropTarget
{
public:
    CIDropTarget(wxDropTarget* pTarget)
    {
        m_pTarget   = pTarget;
        m_pDragItem = NULL;
    }
    virtual ~CIDropTarget() { }

    //
    // Accessors for CDropTarget
    //
    void      Free(void) { ::DrgFreeDraginfo(m_pDragInfo); }
    PDRAGINFO GetDataSource(void) { return m_pDragInfo; }
    void      SetDataSource(PDRAGINFO pDragInfo) { m_pDragInfo = pDragInfo; }
    void      SetHWND(HWND hWnd) { m_hWnd = hWnd; }

    //
    // CIDropTarget methods
    //
           bool    DragLeave(void);
           MRESULT DragOver(void);
           MRESULT Drop(void);

protected:

    PDRAGINFO                       m_pDragInfo;
    PDRAGITEM                       m_pDragItem; // !NULL between DragEnter and DragLeave/Drop
    wxDropTarget*                   m_pTarget;   // the real target (we're just a proxy)
    HWND                            m_hWnd;      // window we're associated with
}; // end of CLASS CIDropTarget

bool CIDropTarget::DragLeave()
{
    //
    // Remove the UI feedback
    //
    m_pTarget->OnLeave();

    //
    // Release the held object
    //
    Free();
    return true;
} // end of CIDropTarget::DragLeave

MRESULT CIDropTarget::DragOver ()
{
    char                            zBuffer[128];
    ULONG                           ulBytes;
    USHORT                          uOp = 0;
    USHORT                          uIndicator;
    ULONG                           ulItems;
    ULONG                           i;

    ::DrgAccessDraginfo(m_pDragInfo);
    switch(m_pDragInfo->usOperation)
    {
        case DO_UNKNOWN:
            Free();
            return (MRFROM2SHORT(DOR_NODROPOP, 0));

        case DO_DEFAULT:
            m_pDragItem = ::DrgQueryDragitemPtr(m_pDragInfo, 0);
            ulBytes     = ::DrgQueryStrName( m_pDragItem->hstrContainerName
                                            ,128
                                            ,zBuffer
                                           );
            if (!ulBytes)
                return (MRFROM2SHORT(DOR_NODROPOP, 0));
            else
                uOp = DO_MOVE;
            break;

        case DO_COPY:
        case DO_MOVE:
            uOp = m_pDragInfo->usOperation;
            break;
    }
    uIndicator = DOR_DROP;
    ulItems = (ULONG)::DrgQueryDragitemCount(m_pDragInfo);
    for (i = 0; i < ulItems; i++)
    {
        m_pDragItem = ::DrgQueryDragitemPtr(m_pDragInfo, i);
        if (((m_pDragItem->fsSupportedOps & DO_COPYABLE) &&
             (uOp == (USHORT)DO_COPY))                   ||
            ((m_pDragItem->fsSupportedOps & DO_MOVEABLE) &&
             (uOp == (USHORT)DO_COPY)))
        {
            if (::DrgVerifyRMF(m_pDragItem, "DRM_OS2FILE", "DRF_UNKNOWN"))
                uIndicator = (USHORT)DOR_DROP;
            else
                uIndicator = (USHORT)DOR_NEVERDROP;
        }
    }
    Free();
    return (MRFROM2SHORT(uIndicator, uOp));
} // end of CIDropTarget::DragOver

// #pragma page   "CIDropTarget::Drop"
/////////////////////////////////////////////////////////////////////////////
//
// CIDropTarget::Drop
//
//   Instructs the drop target to paste data that was just now dropped on it.
//
// PARAMETERS
//   pIDataSource -- the data to paste
//   dwKeyState   -- kbd & mouse state
//   pt           -- mouse coordinates
//   pdwEffect    -- effect flag
//
// RETURN VALUE
//  STDMETHODIMP S_OK
//
/////////////////////////////////////////////////////////////////////////////
MRESULT CIDropTarget::Drop ()
{
    char                            zBuffer[128];
    ULONG                           ulBytes;
    USHORT                          uOp = 0;
    USHORT                          uIndicator;
    ULONG                           ulItems;
    ULONG                           i;

    ::DrgAccessDraginfo(m_pDragInfo);
    switch(m_pDragInfo->usOperation)
    {
        case DO_UNKNOWN:
            Free();
            return (MRFROM2SHORT(DOR_NODROPOP, 0));

        case DO_DEFAULT:
            m_pDragItem = ::DrgQueryDragitemPtr(m_pDragInfo, 0);
            ulBytes     = ::DrgQueryStrName( m_pDragItem->hstrContainerName
                                            ,128
                                            ,zBuffer
                                           );
            if (!ulBytes)
                return (MRFROM2SHORT(DOR_NODROPOP, 0));
            else
                uOp = DO_MOVE;
            break;

        case DO_COPY:
        case DO_MOVE:
            uOp = m_pDragInfo->usOperation;
            break;
    }
    uIndicator = DOR_DROP;
    ulItems = (ULONG)::DrgQueryDragitemCount(m_pDragInfo);
    for (i = 0; i < ulItems; i++)
    {
        m_pDragItem = ::DrgQueryDragitemPtr(m_pDragInfo, i);
        if (((m_pDragItem->fsSupportedOps & DO_COPYABLE) &&
             (uOp == (USHORT)DO_COPY))                   ||
            ((m_pDragItem->fsSupportedOps & DO_MOVEABLE) &&
             (uOp == (USHORT)DO_COPY)))
        {
            if (::DrgVerifyRMF(m_pDragItem, "DRM_OS2FILE", "DRF_UNKNOWN"))
                uIndicator = (USHORT)DOR_DROP;
            else
                uIndicator = (USHORT)DOR_NEVERDROP;
        }
    }

    //
    // First ask the drop target if it wants data
    //
    if (m_pTarget->OnDrop( m_pDragInfo->xDrop
                          ,m_pDragInfo->yDrop
                         ))
    {
        wxDragResult                 eRc = wxDragNone;

        //
        // And now it has the data
        //
        eRc = m_pTarget->OnData( m_pDragInfo->xDrop
                                ,m_pDragInfo->yDrop
                                ,eRc
                               );
    }
    //else: OnDrop() returned false, no need to copy data

    //
    // Release the held object
    //
    Free();
    return (MRFROM2SHORT(uIndicator, uOp));
} // end of CIDropTarget::Drop

// ----------------------------------------------------------------------------
// wxDropTarget
// ----------------------------------------------------------------------------

wxDropTarget::wxDropTarget (
  wxDataObject*                     pDataObject
)
{
    m_dataObject  = pDataObject;
    m_pDropTarget = new CIDropTarget(this);
} // end of wxDropTarget::wxDropTarget

wxDropTarget::~wxDropTarget()
{
    Release();
} // end of wxDropTarget::~wxDropTarget

bool wxDropTarget::GetData ()
{
    wxDataFormat                    vFormat = GetSupportedFormat(m_pDropTarget->GetDataSource());

    if (vFormat == wxDF_INVALID)
    {
        return false;
    }
    //
    // Under OS/2 we already have the data via the attached DRAGITEM's
    //
    return true;
} // end of wxDropTarget::GetData

wxDataFormat wxDropTarget::GetSupportedFormat (
  PDRAGINFO                         pDataSource
) const
{
    PDRAGITEM                       pDragItem;
    wxDataFormat                    vFormat;
    wxDataFormat*                   pFormats;
    ULONG                           ulFormats = m_dataObject->GetFormatCount(wxDataObject::Set);
    ULONG                           ulItems = (ULONG)::DrgQueryDragitemCount(pDataSource);
    ULONG                           i;
    ULONG                           n;
    wxString                        sMechanism;
    wxString                        sFormat;
    bool                            bValid = false;

    pFormats = ulFormats == 1 ? &vFormat :  new wxDataFormat[ulFormats];
    m_dataObject->GetAllFormats( pFormats
                                ,wxDataObject::Set
                               );

    for (n = 0; n < ulFormats; n++)
    {
        switch(pFormats[n].GetType())
        {
            case wxDF_TEXT:
            case wxDF_FILENAME:
            case wxDF_HTML:
                sMechanism = wxT("DRM_OS2FILE");
                sFormat    = wxT("DRF_TEXT");
                break;

            case wxDF_OEMTEXT:
                sMechanism = wxT("DRM_OS2FILE");
                sFormat    = wxT("DRF_OEMTEXT");
                break;

            case wxDF_BITMAP:
                sMechanism = wxT("DRM_OS2FILE");
                sFormat    = wxT("DRF_BITMAP");
                break;

            case wxDF_METAFILE:
            case wxDF_ENHMETAFILE:
                sMechanism = wxT("DRM_OS2FILE");
                sFormat    = wxT("DRF_METAFILE");
                break;

            case wxDF_TIFF:
                sMechanism = wxT("DRM_OS2FILE");
                sFormat    = wxT("DRF_TIFF");
                break;

            case wxDF_SYLK:
                sMechanism = wxT("DRM_OS2FILE");
                sFormat    = wxT("DRF_SYLK");
                break;

            case wxDF_DIF:
                sMechanism = wxT("DRM_OS2FILE");
                sFormat    = wxT("DRF_DIF");
                break;

            case wxDF_DIB:
                sMechanism = wxT("DRM_OS2FILE");
                sFormat    = wxT("DRF_DIB");
                break;

            case wxDF_PALETTE:
            case wxDF_PENDATA:
            case wxDF_RIFF:
            case wxDF_WAVE:
            case wxDF_UNICODETEXT:
            case wxDF_LOCALE:
                sMechanism = wxT("DRM_OS2FILE");
                sFormat    = wxT("DRF_UNKNOWN");
                break;

            case wxDF_PRIVATE:
                sMechanism = wxT("DRM_OBJECT");
                sFormat    = wxT("DRF_UNKNOWN");
                break;
        }
        for (i = 0; i < ulItems; i++)
        {
            pDragItem = ::DrgQueryDragitemPtr(pDataSource, i);
            if (::DrgVerifyRMF(pDragItem, sMechanism.c_str(), sFormat.c_str()))
            {
                bValid = true;
                break;
            }
        }
        if (bValid)
        {
            vFormat = pFormats[n];
            break;
        }
    }
    if (pFormats != &vFormat)
    {
        //
        // Free memory if we allocated it
        //
        delete [] pFormats;
    }
    return (n < ulFormats ? vFormat : wxFormatInvalid);
} // end of wxDropTarget::GetSupportedFormat

bool wxDropTarget::IsAcceptedData (
  PDRAGINFO                         pDataSource
) const
{
    return (GetSupportedFormat(pDataSource) != wxDF_INVALID);
} // end of wxDropTarget::IsAcceptedData

void wxDropTarget::Release ()
{
    m_pDropTarget->Free();
} // end of wxDropTarget::Release


wxDragResult wxDropTarget::OnData (
  wxCoord                           WXUNUSED(vX)
, wxCoord                           WXUNUSED(y)
, wxDragResult                      WXUNUSED(vResult)
)
{
    return (wxDragResult)0;
} // end of wxDropTarget::OnData

bool wxDropTarget::OnDrop (
  wxCoord                           WXUNUSED(x)
, wxCoord                           WXUNUSED(y)
)
{
    return true;
} // end of wxDropTarget::OnDrop

//-------------------------------------------------------------------------
// wxDropSource
//-------------------------------------------------------------------------

wxDropSource::wxDropSource ( wxWindow* WXUNUSED(pWin) )
{
    Init();
} // end of wxDropSource::wxDropSource

wxDropSource::wxDropSource ( wxDataObject& rData, wxWindow* WXUNUSED(pWin) )
{
    Init();
    SetData(rData);
} // end of wxDropSource::wxDropSource

wxDropSource::~wxDropSource ()
{
    ::DrgFreeDraginfo(m_pDragInfo);
} // end of wxDropSource::~wxDropSource

wxDragResult wxDropSource::DoDragDrop (
  int                              WXUNUSED(flags)
)
{
    //
    // Need to specify drag items in derived classes that know their data types
    // before calling DoDragDrop
    //
    if (::DrgDrag( m_pWindow->GetHWND()
                  ,m_pDragInfo
                  ,&m_vDragImage
                  ,m_ulItems
                  ,VK_BUTTON2
                  ,NULL
                 ) != NULLHANDLE)
    {
        switch(m_pDragInfo->usOperation)
        {
            case DO_COPY:
                return wxDragCopy;

            case DO_MOVE:
                return wxDragCopy;

            case DO_LINK:
                return wxDragCopy;

            default:
                return wxDragNone;
        }
    }
    return wxDragError;
} // end of wxDropSource::DoDragDrop

bool wxDropSource::GiveFeedback (
  wxDragResult                      eEffect
)
{
    const wxCursor&                 rCursor = GetCursor(eEffect);

    if (rCursor.Ok())
    {
        ::WinSetPointer(HWND_DESKTOP, (HPOINTER)rCursor.GetHCURSOR());
        m_vDragImage.hImage = (LHANDLE)rCursor.GetHCURSOR();
        switch(eEffect)
        {
            case wxDragCopy:
                m_pDragInfo->usOperation = DO_COPY;
                break;

            case wxDragMove:
                m_pDragInfo->usOperation = DO_MOVE;
                break;

            case wxDragLink:
                m_pDragInfo->usOperation = DO_LINK;
                break;

            case wxDragNone:
            case wxDragCancel:
            case wxDragError:
                break;
        }
        return true;
    }
    else
    {
        return false;
    }
} // end of GuiAdvDnd_CDropSource::GiveFeedback

void wxDropSource::Init ()
{
    m_pDragInfo = ::DrgAllocDraginfo(m_ulItems);

    //
    // Set a default drag image struct with what we know so far
    //
    m_vDragImage.cb             = sizeof(DRAGIMAGE);
    m_vDragImage.cptl           = 0;  // non-zero if fl is DRG_POLYGON
    m_vDragImage.hImage         = 0;  // Set in GiveFeedback
    m_vDragImage.sizlStretch.cx = 20L;
    m_vDragImage.sizlStretch.cy = 20L;
    m_vDragImage.fl             = DRG_ICON | DRG_STRETCH;
    m_vDragImage.cxOffset       = 0;
    m_vDragImage.cyOffset       = 0;

    HSTR    hStrType = ::DrgAddStrHandle(DRT_UNKNOWN);
    HSTR    hStrRMF;
    HSTR    hStrContainer;
    wxChar  zFormats[128];
    wxChar  zContainer[128];
    USHORT  uSize = (USHORT)(GetDataObject()->GetDataSize(GetDataObject()->GetPreferredFormat()) + 1);
    wxChar* pzBuffer = new wxChar[uSize];

    memset(pzBuffer, '\0', GetDataObject()->GetDataSize(GetDataObject()->GetPreferredFormat()));
    pzBuffer[GetDataObject()->GetDataSize(GetDataObject()->GetPreferredFormat())] = '\0';
    GetDataObject()->GetDataHere( GetDataObject()->GetPreferredFormat()
                                 ,(void*)pzBuffer
                                );

    wxStrcpy(zFormats, wxT("<DRM_OS2FILE, DRF_UNKNOWN>"));
    wxStrcpy(zContainer, GetDataObject()->GetPreferredFormat().GetId());

    hStrRMF       = ::DrgAddStrHandle((PSZ)zFormats);
    hStrContainer = ::DrgAddStrHandle((PSZ)zContainer);

    m_pDragItem = new DRAGITEM[m_ulItems];
    for (ULONG i = 0; i < m_ulItems; i++)
    {
        m_pDragItem[i].hwndItem          = m_pWindow->GetHWND();
        m_pDragItem[i].hstrType          = hStrType;
        m_pDragItem[i].hstrRMF           = hStrRMF;
        m_pDragItem[i].hstrContainerName = hStrContainer;
        m_pDragItem[i].fsControl         = 0;
        m_pDragItem[i].fsSupportedOps    = DO_COPYABLE | DO_MOVEABLE | DO_LINKABLE;
        m_pDragItem[i].hstrSourceName    = ::DrgAddStrHandle((PSZ)pzBuffer);
        m_pDragItem[i].hstrTargetName    = m_pDragItem[i].hstrSourceName;
        m_pDragItem[i].ulItemID          = i;
        ::DrgSetDragitem( m_pDragInfo
                         ,&m_pDragItem[i]
                         ,sizeof(DRAGITEM)
                         ,0
                        );
    }
    delete [] pzBuffer;
    delete [] m_pDragItem;
} // end of wxDropSource::Init

#endif //wxUSE_DRAG_AND_DROP
