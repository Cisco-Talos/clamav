/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/bitmap.cpp
// Purpose:     wxBitmap
// Author:      David Webster
// Modified by:
// Created:     08/08/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/bitmap.h"

#ifndef WX_PRECOMP
    #include <stdio.h>

    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/palette.h"
    #include "wx/dcmemory.h"
    #include "wx/icon.h"
    #include "wx/log.h"
    #include "wx/image.h"
#endif

#include "wx/os2/dc.h"
#include "wx/os2/private.h"

#include "wx/xpmdecod.h"

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxBitmap, wxGDIObject)
IMPLEMENT_DYNAMIC_CLASS(wxMask, wxObject)

IMPLEMENT_DYNAMIC_CLASS(wxBitmapHandler, wxObject)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxBitmapRefData
// ----------------------------------------------------------------------------

wxBitmapRefData::wxBitmapRefData()
{
    m_nQuality      = 0;
    m_pSelectedInto = NULL;
    m_nNumColors    = 0;
    m_pBitmapMask   = NULL;
    m_hBitmap       = (WXHBITMAP) NULL;
} // end of wxBitmapRefData::wxBitmapRefData

wxBitmapRefData::wxBitmapRefData(const wxBitmapRefData &tocopy)
{
    m_nQuality = tocopy.m_nQuality;
    m_pSelectedInto = NULL;     // don't copy this
    m_nNumColors    = tocopy.m_nNumColors;

    // copy the mask
    if (tocopy.m_pBitmapMask)
        m_pBitmapMask = new wxMask(*tocopy.m_pBitmapMask);

    m_hBitmap = wxCopyBmp(tocopy.m_hBitmap);
}

void wxBitmapRefData::Free()
{
    if ( m_pSelectedInto )
    {
        wxLogLastError(wxT("GpiDeleteBitmap(hbitmap)"));
    }
    if (m_hBitmap)
    {
        if (!::GpiDeleteBitmap((HBITMAP)m_hBitmap))
        {
            wxLogLastError(wxT("GpiDeleteBitmap(hbitmap)"));
        }
    }
    wxDELETE(m_pBitmapMask);
} // end of wxBitmapRefData::Free

// ----------------------------------------------------------------------------
// wxBitmap creation
// ----------------------------------------------------------------------------

wxGDIRefData* wxBitmap::CloneGDIRefData(const wxGDIRefData* data) const
{
    return new wxBitmapRefData(*static_cast<const wxBitmapRefData *>(data));
}

// this function should be called from all wxBitmap ctors
void wxBitmap::Init()
{
    m_bIsMono = false;
    //
    // True for all bitmaps created from bits, wxImages, Xpms
    //
} // end of wxBitmap::Init

bool wxBitmap::CopyFromIconOrCursor(const wxGDIImage& rIcon)
{
    HPOINTER                        hIcon = (HPOINTER)rIcon.GetHandle();
    POINTERINFO                     SIconInfo;

    if (!::WinQueryPointerInfo(hIcon, &SIconInfo))
    {
        wxLogLastError(wxT("WinQueryPointerInfo"));
        return false;
    }
    wxBitmapRefData*                pRefData = new wxBitmapRefData;

    m_refData = pRefData;

    int                             nWidth = rIcon.GetWidth();
    int                             nHeight = rIcon.GetHeight();

    pRefData->m_nWidth  = nWidth;
    pRefData->m_nHeight = nHeight;
    pRefData->m_nDepth  = wxDisplayDepth();

    pRefData->m_hBitmap = (WXHBITMAP)SIconInfo.hbmColor;

    wxMask*                         pMask = new wxMask(SIconInfo.hbmPointer);

    pMask->SetMaskBitmap(GetHBITMAP());
    SetMask(pMask);

    return true;
} // end of wxBitmap::CopyFromIconOrCursor

bool wxBitmap::CopyFromCursor(
  const wxCursor&                   rCursor
)
{
    UnRef();

    if (!rCursor.Ok())
        return(false);
    return(CopyFromIconOrCursor(rCursor));
} // end of wxBitmap::CopyFromCursor

bool wxBitmap::CopyFromIcon(
  const wxIcon&                     rIcon
)
{
    UnRef();

    if (!rIcon.Ok())
        return(false);

    return CopyFromIconOrCursor(rIcon);
} // end of wxBitmap::CopyFromIcon

wxBitmap::~wxBitmap()
{
} // end of wxBitmap::~wxBitmap

wxBitmap::wxBitmap(
  const char                        zBits[]
, int                               nWidth
, int                               nHeight
, int                               nDepth
)
{
    Init();

    wxBitmapRefData*                pRefData = new wxBitmapRefData;
    BITMAPINFOHEADER2               vHeader;
    BITMAPINFO2                     vInfo;
    HDC                             hDc;
    HPS                             hPs;
    DEVOPENSTRUC                    vDop = { NULL, "DISPLAY", NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    SIZEL                           vSize = {0, 0};
    char*                           pzData;

    wxASSERT(vHabmain != NULL);

    m_refData = pRefData;

    pRefData->m_nWidth        = nWidth;
    pRefData->m_nHeight       = nHeight;
    pRefData->m_nDepth        = nDepth;
    pRefData->m_nNumColors    = 0;
    pRefData->m_pSelectedInto = NULL;

    hDc   = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    hPs = ::GpiCreatePS(vHabmain, hDc, &vSize, GPIA_ASSOC | PU_PELS);
    if (hPs == 0)
    {
        wxLogLastError(wxT("GpiCreatePS Failure"));
    }

    if (nDepth == 1)
    {
        //
        // We assume that it is in XBM format which is not quite the same as
        // the format CreateBitmap() wants because the order of bytes in the
        // line is reversed!
        //
        const size_t                nBytesPerLine = (nWidth + 7) / 8;
        const size_t                nPadding = nBytesPerLine % 2;
        const size_t                nLen = nHeight * (nPadding + nBytesPerLine);
        const char*                 pzSrc = zBits;
        int                         nRows;
        size_t                      nCols;

        pzData = (char *)malloc(nLen);

        char*                       pzDst = pzData;

        for (nRows = 0; nRows < nHeight; nRows++)
        {
            for (nCols = 0; nCols < nBytesPerLine; nCols++)
            {
                unsigned char ucVal = *pzSrc++;
                unsigned char ucReversed = 0;
                int nBits;

                for (nBits = 0; nBits < 8; nBits++)
                {
                    ucReversed <<= 1;
                    ucReversed = (unsigned char)(ucReversed | (ucVal & 0x01));
                    ucVal >>= 1;
                }
                *pzDst++ = ucReversed;
            }
            if (nPadding)
                *pzDst++ = 0;
        }
    }
    else
    {
        //
        // Bits should already be in Windows standard format
        //
        pzData = (char *)zBits;    // const_cast is harmless
    }

    if (nDepth > 24)
        nDepth = 24; // MAX supported in PM
    memset(&vHeader, '\0', 16);
    vHeader.cbFix           = 16;
    vHeader.cx              = (USHORT)nWidth;
    vHeader.cy              = (USHORT)nHeight;
    vHeader.cPlanes         = 1L;
    vHeader.cBitCount       = (USHORT)nDepth;
    vHeader.usReserved      = 0;

    memset(&vInfo, '\0', 16);
    vInfo.cbFix           = 16;
    vInfo.cx              = (USHORT)nWidth;
    vInfo.cy              = (USHORT)nHeight;
    vInfo.cPlanes         = 1L;
    vInfo.cBitCount       = (USHORT)nDepth;

    HBITMAP                         hBmp = ::GpiCreateBitmap(hPs, &vHeader, CBM_INIT, (PBYTE)pzData, &vInfo);

    if (!hBmp)
    {
        wxLogLastError(wxT("CreateBitmap"));
    }
    ::GpiDestroyPS(hPs);
    ::DevCloseDC(hDc);
    SetHBITMAP((WXHBITMAP)hBmp);
} // end of wxBitmap::wxBitmap

wxBitmap::wxBitmap(
  const void*                       pData
, wxBitmapType                      lType
, int                               nWidth
, int                               nHeight
, int                               nDepth
)
{
    Init();

    (void)Create( pData
                 ,lType
                 ,nWidth
                 ,nHeight
                 ,nDepth
                );
} // end of wxBitmap::wxBitmap

wxBitmap::wxBitmap(
  int                               nId
, wxBitmapType                      lType
)
{
    Init();
    LoadFile( nId
             ,lType
            );
    SetId(nId);
} // end of wxBitmap::wxBitmap

bool wxBitmap::Create(
  int                               nW
, int                               nH
, int                               nD
)
{
    HBITMAP                         hBmp;
    BITMAPINFOHEADER2               vHeader;

    wxASSERT(vHabmain != NULL);
    UnRef();
    m_refData = new wxBitmapRefData;
    GetBitmapData()->m_nWidth = nW;
    GetBitmapData()->m_nHeight = nH;
    GetBitmapData()->m_nDepth = nD;

    //
    // Xpms and bitmaps from other images can also be mono's, but only
    // mono's need help changing their colors with MemDC changes
    //
    if (nD > 0)
    {
        DEVOPENSTRUC                vDop  = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
        SIZEL                       vSize = {0, 0};
        HDC                         hDC   = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
        HPS                         hPS   = ::GpiCreatePS(vHabmain, hDC, &vSize, PU_PELS | GPIA_ASSOC);

        if (nD == 1)
            m_bIsMono = true;
        memset(&vHeader, '\0', 16);
        vHeader.cbFix     =  16;
        vHeader.cx        = nW;
        vHeader.cy        = nH;
        vHeader.cPlanes   = 1;
        vHeader.cBitCount = 24; //nD;

        hBmp = ::GpiCreateBitmap( hPS
                                 ,&vHeader
                                 ,0L
                                 ,NULL
                                 ,NULL
                                );
        ::GpiDestroyPS(hPS);
        ::DevCloseDC(hDC);
    }
    else
    {
        HPS                             hPSScreen;
        HDC                             hDCScreen;
        LONG                            lBitCount;

        hPSScreen = ::WinGetScreenPS(HWND_DESKTOP);
        hDCScreen = ::GpiQueryDevice(hPSScreen);
        ::DevQueryCaps(hDCScreen, CAPS_COLOR_BITCOUNT, 1L, &lBitCount);

        if (lBitCount > 24)
            lBitCount = 24;

        memset(&vHeader, '\0', 16);
        vHeader.cbFix     =  16;
        vHeader.cx        = nW;
        vHeader.cy        = nH;
        vHeader.cPlanes   = 1;
        vHeader.cBitCount = (USHORT)lBitCount;

        hBmp = ::GpiCreateBitmap( hPSScreen
                                 ,&vHeader
                                 ,0L
                                 ,NULL
                                 ,NULL
                                );

        GetBitmapData()->m_nDepth = wxDisplayDepth();
        ::WinReleasePS(hPSScreen);
    }
    SetHBITMAP((WXHBITMAP)hBmp);

    return Ok();
} // end of wxBitmap::Create

bool wxBitmap::LoadFile(const wxString& filename, wxBitmapType type)
{
    UnRef();

    wxBitmapHandler *handler = wxDynamicCast(FindHandler(type), wxBitmapHandler);

    if ( handler )
    {
        m_refData = new wxBitmapRefData;

        return handler->LoadFile(this, filename, type, -1, -1);
    }
#if wxUSE_IMAGE
    else // no bitmap handler found
    {
        wxImage image;
        if ( image.LoadFile( filename, type ) && image.Ok() )
        {
            *this = wxBitmap(image);

            return true;
        }
    }
#endif // wxUSE_IMAGE

    return false;
}

bool wxBitmap::LoadFile(
  int                               nId
, wxBitmapType                      lType
)
{
    UnRef();

    wxBitmapHandler*                pHandler = wxDynamicCast( FindHandler(lType)
                                                             ,wxBitmapHandler
                                                            );

    if (pHandler)
    {
        m_refData = new wxBitmapRefData;

        return(pHandler->LoadFile( this
                                  ,nId
                                  ,lType
                                  , -1
                                  , -1
                                 ));
    }
    else
    {
        return false;
    }
} // end of wxBitmap::LoadFile

bool wxBitmap::Create(
  const void*                       pData
, wxBitmapType                      lType
, int                               nWidth
, int                               nHeight
, int                               nDepth
)
{
    UnRef();

    wxBitmapHandler*                pHandler = wxDynamicCast( FindHandler(lType)
                                                             ,wxBitmapHandler
                                                            );

    if (!pHandler)
    {
        wxLogDebug(wxT("Failed to create bitmap: no bitmap handler for type %ld defined."), lType);

        return false;
    }

    m_refData = new wxBitmapRefData;

    return(pHandler->Create( this
                            ,pData
                            ,lType
                            ,nWidth
                            ,nHeight
                            ,nDepth
                           ));
} // end of wxBitmap::Create

bool wxBitmap::SaveFile(
  const wxString&                   rFilename
, wxBitmapType                      lType
, const wxPalette*                  pPalette
)
{
    wxBitmapHandler*                pHandler = wxDynamicCast( FindHandler(lType)
                                                             ,wxBitmapHandler
                                                            );

    if (pHandler)
    {
        return pHandler->SaveFile( this
                                  ,rFilename
                                  ,lType
                                  ,pPalette
                                 );
    }
    else
    {
        // FIXME what about palette? shouldn't we use it?
        wxImage                     vImage = ConvertToImage();

        if (!vImage.Ok())
            return false;

        return(vImage.SaveFile( rFilename
                               ,lType
                              ));
    }
} // end of wxBitmap::SaveFile


// ----------------------------------------------------------------------------
// wxImage-wxBitmap conversion
// ----------------------------------------------------------------------------

bool wxBitmap::CreateFromImage (
  const wxImage&                    rImage
, int                               nDepth
)
{
    wxCHECK_MSG(rImage.Ok(), false, wxT("invalid image"));
    m_refData = new wxBitmapRefData();

    int                             nSizeLimit = 1024 * 768 * 3;
    int                             nWidth = rImage.GetWidth();
    int                             nBmpHeight = rImage.GetHeight();
    int                             nBytePerLine = nWidth * 3;
    int                             nSizeDWORD = sizeof(DWORD);
    int                             nLineBoundary = nBytePerLine % nSizeDWORD;
    int                             nPadding = 0;

    if (nLineBoundary > 0)
    {
        nPadding = nSizeDWORD - nLineBoundary;
        nBytePerLine += nPadding;
    }

    //
    // Calc the number of DIBs and heights of DIBs
    //
    int                             nNumDIB = 1;
    int                             nHRemain = 0;
    int                             nHeight = nSizeLimit / nBytePerLine;

    if (nHeight >= nBmpHeight)
        nHeight = nBmpHeight;
    else
    {
        nNumDIB  = nBmpHeight / nHeight;
        nHRemain = nBmpHeight % nHeight;
        if (nHRemain > 0)
            nNumDIB++;
    }

    //
    // Set bitmap parameters
    //
    wxCHECK_MSG(rImage.Ok(), false, wxT("invalid image"));
    SetWidth(nWidth);
    SetHeight(nBmpHeight);
    if (nDepth == 1)
        m_bIsMono = true;
    else
        m_bIsMono = false;
    if (nDepth == -1)
        nDepth = wxDisplayDepth();
    SetDepth(nDepth);

#if wxUSE_PALETTE
    //
    // Copy the palette from the source image
    //
    SetPalette(rImage.GetPalette());
#endif // wxUSE_PALETTE

    //
    // Create a DIB header
    //
    BITMAPINFOHEADER2               vHeader;
    BITMAPINFO2                     vInfo;

    //
    // Fill in the DIB header
    //
    memset(&vHeader, '\0', 16);
    vHeader.cbFix           = 16;
    vHeader.cx              = (ULONG)nWidth;
    vHeader.cy              = (ULONG)nHeight;
    vHeader.cPlanes         = 1L;
    vHeader.cBitCount       = 24;

    //
    // Memory for DIB data
    //
    unsigned char*                  pucBits;

    pucBits = (unsigned char *)malloc(nBytePerLine * nHeight);
    if(!pucBits)
    {
        wxFAIL_MSG(wxT("could not allocate memory for DIB"));
        return false;
    }
    memset(pucBits, '\0', (nBytePerLine * nHeight));

    //
    // Create and set the device-dependent bitmap
    //
    DEVOPENSTRUC                    vDop  = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    SIZEL                           vSize = {0, 0};
    HDC                             hDC   = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HPS                             hPS   = ::GpiCreatePS(vHabmain, hDC, &vSize, PU_PELS | GPIA_ASSOC);
    LONG                            lScans;
    HDC                             hDCScreen = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HPS                             hPSScreen;
    HBITMAP                         hBmp;
    HBITMAP                         hBmpOld;

    memset(&vInfo, '\0', 16);
    vInfo.cbFix           = 16;
    vInfo.cx              = (ULONG)nWidth;
    vInfo.cy              = (ULONG)nHeight;
    vInfo.cPlanes         = 1;
    vInfo.cBitCount       = 24; // Set to desired count going in

    hBmp = ::GpiCreateBitmap( hPS
                             ,&vHeader
                             ,0L
                             ,NULL
                             ,NULL
                            );
#if wxUSE_PALETTE
    HPAL                            hOldPalette = NULLHANDLE;
    if (rImage.GetPalette().Ok())
    {
        hOldPalette = ::GpiSelectPalette(hPS, (HPAL)rImage.GetPalette().GetHPALETTE());
    }
#endif // wxUSE_PALETTE

    //
    // Copy image data into DIB data and then into DDB (in a loop)
    //
    unsigned char*                  pData = rImage.GetData();
    int                             i;
    int                             j;
    int                             n;
    int                             nOrigin = 0;
    unsigned char*                  ptdata = pData;
    unsigned char*                  ptbits;

    if ((hBmpOld = ::GpiSetBitmap(hPS, hBmp)) == HBM_ERROR)
    {
        ERRORID                 vError;
        wxString                sError;

        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    for (n = 0; n < nNumDIB; n++)
    {
        if (nNumDIB > 1 && n == nNumDIB - 1 && nHRemain > 0)
        {
            //
            // Redefine height and size of the (possibly) last smaller DIB
            // memory is not reallocated
            //
            nHeight         = nHRemain;
            vHeader.cy      = (DWORD)(nHeight);
            vHeader.cbImage = nBytePerLine * nHeight;
        }
        ptbits = pucBits;
        for (j = 0; j < nHeight; j++)
        {
            for (i = 0; i < nWidth; i++)
            {
                *(ptbits++) = *(ptdata + 2);
                *(ptbits++) = *(ptdata + 1);
                *(ptbits++) = *(ptdata);
                ptdata += 3;
            }
            for (i = 0; i < nPadding; i++)
                *(ptbits++) = 0;
        }

        //
        // Have to do something similar to WIN32's StretchDIBits, use GpiBitBlt
        // in combination with setting the bits into the selected bitmap
        //
        if ((lScans = ::GpiSetBitmapBits( hPS
                                         ,0             // Start at the bottom
                                         ,(LONG)nHeight // One line per scan
                                         ,(PBYTE)pucBits
                                         ,&vInfo
                                       )) == GPI_ALTERROR)
        {
            ERRORID                 vError;
            wxString                sError;

            vError = ::WinGetLastError(vHabmain);
            sError = wxPMErrorToStr(vError);
        }
        hPSScreen = ::GpiCreatePS( vHabmain
                                  ,hDCScreen
                                  ,&vSize
                                  ,PU_PELS | GPIA_ASSOC
                                 );

        POINTL                      vPoint[4] = { {0, nOrigin},
                                                  {nWidth, nHeight},
                                                  {0, 0}, {nWidth, nHeight}
                                                };


        ::GpiBitBlt( hPSScreen
                    ,hPS
                    ,4
                    ,vPoint
                    ,ROP_SRCCOPY
                    ,BBO_IGNORE
                   );
        ::GpiDestroyPS(hPSScreen);
        nOrigin += nHeight;
    }
    SetHBITMAP((WXHBITMAP)hBmp);
#if wxUSE_PALETTE
    if (hOldPalette)
        ::GpiSelectPalette(hPS, hOldPalette);
#endif // wxUSE_PALETTE

    //
    // Similarly, created an mono-bitmap for the possible mask
    //
    if (rImage.HasMask())
    {
        vHeader.cbFix     = 16;
        vHeader.cx        = nWidth;
        vHeader.cy        = nHeight;
        vHeader.cPlanes   = 1;
        vHeader.cBitCount = 24;
        hBmp = ::GpiCreateBitmap( hPS
                                 ,&vHeader
                                 ,0L
                                 ,NULL
                                 ,NULL
                                );
        hBmpOld = ::GpiSetBitmap(hPS, hBmp);
        if (nNumDIB == 1)
            nHeight = nBmpHeight;
        else
            nHeight = nSizeLimit / nBytePerLine;
        vHeader.cy = (DWORD)(nHeight);
        nOrigin = 0;

        unsigned char               cRed   = rImage.GetMaskRed();
        unsigned char               cGreen = rImage.GetMaskGreen();
        unsigned char               cBlue  = rImage.GetMaskBlue();
        unsigned char               cZero = 0;
        unsigned char               cOne = 255;

        ptdata = pData;
        for (n = 0; n < nNumDIB; n++)
        {
            if (nNumDIB > 1 && n == nNumDIB - 1 && nHRemain > 0)
            {
                //
                // Redefine height and size of the (possibly) last smaller DIB
                // memory is not reallocated
                //
                nHeight         = nHRemain;
                vHeader.cy      = (DWORD)(nHeight);
                vHeader.cbImage = nBytePerLine * nHeight;
            }
            ptbits = pucBits;
            for (int j = 0; j < nHeight; j++)
            {
                for (i = 0; i < nWidth; i++)
                {
                    unsigned char cRedImage   = (*(ptdata++)) ;
                    unsigned char cGreenImage = (*(ptdata++)) ;
                    unsigned char cBlueImage  = (*(ptdata++)) ;

                    if ((cRedImage != cRed) || (cGreenImage != cGreen) || (cBlueImage != cBlue))
                    {
                        *(ptbits++) = cOne;
                        *(ptbits++) = cOne;
                        *(ptbits++) = cOne;
                    }
                    else
                    {
                        *(ptbits++) = cZero;
                        *(ptbits++) = cZero;
                        *(ptbits++) = cZero;
                    }
                }
                for (i = 0; i < nPadding; i++)
                    *(ptbits++) = cZero;
            }
            lScans = ::GpiSetBitmapBits( hPS
                                        ,0              // Start at the bottom
                                        ,(LONG)nHeight // One line per scan
                                        ,(PBYTE)pucBits
                                        ,&vInfo
                                       );
            hPSScreen = ::GpiCreatePS( vHabmain
                                      ,hDCScreen
                                      ,&vSize
                                      ,PU_PELS | GPIA_ASSOC
                                     );
            POINTL vPoint2[4] = { {0, nOrigin},
                                  {nWidth, nHeight},
                                  {0, 0}, {nWidth, nHeight}
                                };
            ::GpiBitBlt( hPSScreen
                        ,hPS
                        ,4
                        ,vPoint2
                        ,ROP_SRCCOPY
                        ,BBO_IGNORE
                   );
            ::GpiDestroyPS(hPSScreen);
            nOrigin += nHeight;
        }

        //
        // Create a wxMask object
        //
        wxMask*                     pMask = new wxMask();

        pMask->SetMaskBitmap((WXHBITMAP)hBmp);
        SetMask(pMask);
        hBmpOld = ::GpiSetBitmap(hPS, hBmpOld);
    }

    //
    // Free allocated resources
    //
    ::GpiSetBitmap(hPS, NULLHANDLE);
    ::GpiDestroyPS(hPS);
    ::DevCloseDC(hDCScreen);
    ::DevCloseDC(hDC);
    free(pucBits);
    return true;
} // end of wxBitmap::CreateFromImage

wxImage wxBitmap::ConvertToImage() const
{
    wxImage                         vImage;
    wxDC*                           pDC;

    wxCHECK_MSG( Ok(), wxNullImage, wxT("invalid bitmap") );

    //
    // Create an wxImage object
    //
    int                             nWidth        = GetWidth();
    int                             nHeight       = GetHeight();
    int                             nDevWidth;
    int                             nDevHeight;
    int                             nBytePerLine  = nWidth * 3;
    int                             nSizeDWORD    = sizeof(DWORD);
    int                             nLineBoundary = nBytePerLine % nSizeDWORD;
    int                             nPadding = 0;
    unsigned char*                  pData;
    unsigned char*                  lpBits;
    long                            lScans;
    BITMAPINFOHEADER2               vDIBh;
    BITMAPINFO2                     vDIBInfo;
    HPS                             hPSMem;
    HBITMAP                         hBitmap;
    HBITMAP                         hOldBitmap;
    DEVOPENSTRUC                    vDop  = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    SIZEL                           vSizlPage = {0,0};
    HDC                             hDCMem = NULLHANDLE;

    vImage.Create( nWidth
                  ,nHeight
                 );
    pData = vImage.GetData();
    if(!pData)
    {
        wxFAIL_MSG( wxT("could not allocate data for image") );
        return wxNullImage;
    }
    if(nLineBoundary > 0)
    {
        nPadding     = nSizeDWORD - nLineBoundary;
        nBytePerLine += nPadding;
    }
    wxDisplaySize( &nDevWidth
                  ,&nDevHeight
                 );
    //
    // Create and fill a DIB header
    //
    memset(&vDIBh, '\0', 16);
    vDIBh.cbFix     =  16;
    vDIBh.cx        = nWidth;
    vDIBh.cy        = nHeight;
    vDIBh.cPlanes   = 1;
    vDIBh.cBitCount = 24;

    memset(&vDIBInfo, '\0', 16);
    vDIBInfo.cbFix           = 16;
    vDIBInfo.cx              = nWidth;
    vDIBInfo.cy              = nHeight;
    vDIBInfo.cPlanes         = 1;
    vDIBInfo.cBitCount       = 24;

    lpBits = (unsigned char *)malloc(nBytePerLine * nHeight);
    if (!lpBits)
    {
        wxFAIL_MSG(wxT("could not allocate data for DIB"));
        free(pData);
        return wxNullImage;
    }
    memset(lpBits, '\0', (nBytePerLine * nHeight));
    hBitmap = (HBITMAP)GetHBITMAP();

    //
    // May already be selected into a PS
    //
    pDC = GetSelectedInto();
    const wxPMDCImpl *impl;
    if (pDC != NULL &&
        (impl = wxDynamicCast( pDC->GetImpl(), wxPMDCImpl )) != NULL)
    {
        hPSMem = impl->GetHPS();
    }
    else
    {
        hDCMem = ::DevOpenDC( vHabmain
                             ,OD_MEMORY
                             ,"*"
                             ,5L
                             ,(PDEVOPENDATA)&vDop
                             ,NULLHANDLE
                            );
        hPSMem = ::GpiCreatePS( vHabmain
                               ,hDCMem
                               ,&vSizlPage
                               ,PU_PELS | GPIA_ASSOC
                              );
    }
    if ((hOldBitmap = ::GpiSetBitmap(hPSMem, hBitmap)) == HBM_ERROR)
    {
        ERRORID                 vError;
        wxString                sError;

        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }

    //
    // Copy data from the device-dependent bitmap to the DIB
    //
    if ((lScans = ::GpiQueryBitmapBits( hPSMem
                                       ,0L
                                       ,(LONG)nHeight
                                       ,(PBYTE)lpBits
                                       ,&vDIBInfo
                                      )) == GPI_ALTERROR)
    {
        ERRORID                     vError;
        wxString                    sError;

        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }

    //
    // Copy DIB data into the wxImage object
    //
    int                             i;
    int                             j;
    unsigned char*                  ptdata = pData;
    unsigned char*                  ptbits = lpBits;

    for (i = 0; i < nHeight; i++)
    {
        for (j = 0; j < nWidth; j++)
        {
            *(ptdata++) = *(ptbits+2);
            *(ptdata++) = *(ptbits+1);
            *(ptdata++) = *(ptbits  );
            ptbits += 3;
        }
        ptbits += nPadding;
    }
    if ((pDC = GetSelectedInto()) == NULL)
    {
        ::GpiSetBitmap(hPSMem, NULLHANDLE);
        ::GpiDestroyPS(hPSMem);
        ::DevCloseDC(hDCMem);
    }

    //
    // Similarly, set data according to the possible mask bitmap
    //
    if (GetMask() && GetMask()->GetMaskBitmap())
    {
        hBitmap = (HBITMAP)GetMask()->GetMaskBitmap();

        //
        // Memory DC/PS created, color set, data copied, and memory DC/PS deleted
        //
        HDC                        hMemDC = ::DevOpenDC( vHabmain
                                                        ,OD_MEMORY
                                                        ,"*"
                                                        ,5L
                                                        ,(PDEVOPENDATA)&vDop
                                                        ,NULLHANDLE
                                                       );
        HPS                         hMemPS = ::GpiCreatePS( vHabmain
                                                           ,hMemDC
                                                           ,&vSizlPage
                                                           ,PU_PELS | GPIA_ASSOC
                                                          );
        ::GpiSetColor(hMemPS, OS2RGB(0, 0, 0));
        ::GpiSetBackColor(hMemPS, OS2RGB(255, 255, 255) );
        ::GpiSetBitmap(hMemPS, hBitmap);
        ::GpiQueryBitmapBits( hPSMem
                             ,0L
                             ,(LONG)nHeight
                             ,(PBYTE)lpBits
                             ,&vDIBInfo
                            );
        ::GpiSetBitmap(hMemPS, NULLHANDLE);
        ::GpiDestroyPS(hMemPS);
        ::DevCloseDC(hMemDC);

        //
        // Background color set to RGB(16,16,16) in consistent with wxGTK
        //
        unsigned char               ucRed = 16;
        unsigned char               ucGreen = 16;
        unsigned char               ucBlue = 16;

        ptdata = pData;
        ptbits = lpBits;
        for (i = 0; i < nHeight; i++)
        {
            for (j = 0; j < nWidth; j++)
            {
                if (*ptbits != 0)
                    ptdata += 3;
                else
                {
                    *(ptdata++)  = ucRed;
                    *(ptdata++)  = ucGreen;
                    *(ptdata++)  = ucBlue;
                }
                ptbits += 3;
            }
            ptbits += nPadding;
        }
        vImage.SetMaskColour( ucRed
                             ,ucGreen
                             ,ucBlue
                            );
        vImage.SetMask(true);
    }
    else
    {
        vImage.SetMask(false);
    }

    //
    // Free allocated resources
    //
    free(lpBits);
    return vImage;
} // end of wxBitmap::ConvertToImage

// ----------------------------------------------------------------------------
// sub bitmap extraction
// ----------------------------------------------------------------------------

wxBitmap wxBitmap::GetSubBitmap(
  const wxRect&                     rRect
) const
{
    wxCHECK_MSG( Ok() &&
                 (rRect.x >= 0) && (rRect.y >= 0) &&
                 (rRect.x + rRect.width <= GetWidth()) &&
                 (rRect.y + rRect.height <= GetHeight()),
                 wxNullBitmap, wxT("Invalid bitmap or bitmap region") );

    wxBitmap                        vRet( rRect.width
                                         ,rRect.height
                                         ,GetDepth()
                                        );
    wxASSERT_MSG( vRet.Ok(), wxT("GetSubBitmap error") );


    //
    // Copy bitmap data
    //
    SIZEL                           vSize = {0, 0};
    DEVOPENSTRUC                    vDop = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    HDC                             hDCSrc = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HDC                             hDCDst = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HPS                             hPSSrc = ::GpiCreatePS(vHabmain, hDCSrc, &vSize, PU_PELS | GPIA_ASSOC);
    HPS                             hPSDst = ::GpiCreatePS(vHabmain, hDCDst, &vSize, PU_PELS | GPIA_ASSOC);
    POINTL                          vPoint[4] = { {0, 0}, {rRect.width, rRect.height},
                                                  {rRect.x, rRect.y},
                                                  {rRect.x + rRect.width, rRect.y + rRect.height}
                                                };

    ::GpiSetBitmap(hPSSrc, (HBITMAP) GetHBITMAP());
    ::GpiSetBitmap(hPSDst, (HBITMAP) vRet.GetHBITMAP());
    ::GpiBitBlt( hPSDst
                ,hPSSrc
                ,4L
                ,vPoint
                ,ROP_SRCCOPY
                ,BBO_IGNORE
               );

    //
    // Copy mask if there is one
    //
    if (GetMask())
    {
        BITMAPINFOHEADER2           vBmih;

        memset(&vBmih, '\0', sizeof(BITMAPINFOHEADER2));
        vBmih.cbFix     = sizeof(BITMAPINFOHEADER2);
        vBmih.cx        = rRect.width;
        vBmih.cy        = rRect.height;
        vBmih.cPlanes   = 1;
        vBmih.cBitCount = 24;

        HBITMAP                     hBmpMask = ::GpiCreateBitmap( hPSDst
                                                                 ,&vBmih
                                                                 ,0L
                                                                 ,NULL
                                                                 ,NULL
                                                                );

        ::GpiSetBitmap(hPSSrc, (HBITMAP) GetHBITMAP());
        ::GpiSetBitmap(hPSDst, (HBITMAP) vRet.GetHBITMAP());

        ::GpiSetBitmap(hPSSrc, (HBITMAP) GetMask()->GetMaskBitmap());
        ::GpiSetBitmap(hPSDst, (HBITMAP) hBmpMask);
        ::GpiBitBlt( hPSDst
                    ,hPSSrc
                    ,4L
                    ,vPoint
                    ,ROP_SRCCOPY
                    ,BBO_IGNORE
                   );

        wxMask*                     pMask = new wxMask((WXHBITMAP)hBmpMask);
        vRet.SetMask(pMask);
    }

    ::GpiSetBitmap(hPSSrc, NULL);
    ::GpiSetBitmap(hPSDst, NULL);
    ::GpiDestroyPS(hPSSrc);
    ::GpiDestroyPS(hPSDst);
    ::DevCloseDC(hDCSrc);
    ::DevCloseDC(hDCDst);
    return vRet;
} // end of wxBitmap::GetSubBitmap

// ----------------------------------------------------------------------------
// wxBitmap accessors
// ----------------------------------------------------------------------------

void wxBitmap::SetQuality(
  int                               nQ
)
{
    EnsureHasData();

    GetBitmapData()->m_nQuality = nQ;
} // end of wxBitmap::SetQuality

void wxBitmap::SetPalette(
  const wxPalette&                  rPalette
)
{
    EnsureHasData();

    GetBitmapData()->m_vBitmapPalette = rPalette;
} // end of wxBitmap::SetPalette

void wxBitmap::SetMask(
  wxMask*                           pMask
)
{
    EnsureHasData();

    GetBitmapData()->m_pBitmapMask = pMask;
} // end of wxBitmap::SetMask

wxBitmap wxBitmap::GetBitmapForDC(wxDC& WXUNUSED(rDc)) const
{
    return(*this);
} // end of wxBitmap::GetBitmapForDC

// ----------------------------------------------------------------------------
// wxMask
// ----------------------------------------------------------------------------

wxMask::wxMask()
{
    m_hMaskBitmap = 0;
} // end of wxMask::wxMask

wxMask::wxMask(const wxMask& tocopy)
{
    m_hMaskBitmap = wxCopyBmp(tocopy.m_hMaskBitmap);
} // end of wxMask::wxMask

// Construct a mask from a bitmap and a colour indicating
// the transparent area
wxMask::wxMask(
  const wxBitmap&                   rBitmap
, const wxColour&                   rColour
)
{
    m_hMaskBitmap = 0;
    Create( rBitmap
           ,rColour
          );
} // end of wxMask::wxMask

// Construct a mask from a bitmap and a palette index indicating
// the transparent area
wxMask::wxMask(
  const wxBitmap&                   rBitmap
, int                               nPaletteIndex
)
{
    m_hMaskBitmap = 0;
    Create( rBitmap
           ,nPaletteIndex
          );
} // end of wxMask::wxMask

// Construct a mask from a mono bitmap (copies the bitmap).
wxMask::wxMask(
  const wxBitmap&                   rBitmap
)
{
    m_hMaskBitmap = 0;
    Create(rBitmap);
} // end of wxMask::wxMask

wxMask::~wxMask()
{
    if (m_hMaskBitmap)
        ::GpiDeleteBitmap((HBITMAP)m_hMaskBitmap);
} // end of wxMask::~wxMask

// Create a mask from a mono bitmap (copies the bitmap).
bool wxMask::Create(
  const wxBitmap&                   rBitmap
)
{
    BITMAPINFOHEADER2               vBmih;
    SIZEL                           vSize = {0, 0};
    DEVOPENSTRUC                    vDop = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    HDC                             hDCSrc = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HDC                             hDCDst = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HPS                             hPSSrc = ::GpiCreatePS(vHabmain, hDCSrc, &vSize, PU_PELS | GPIA_ASSOC);
    HPS                             hPSDst = ::GpiCreatePS(vHabmain, hDCDst, &vSize, PU_PELS | GPIA_ASSOC);
    POINTL                          vPoint[4] = { {0 ,0}, {rBitmap.GetWidth(), rBitmap.GetHeight()},
                                                  {0, 0}, {rBitmap.GetWidth(), rBitmap.GetHeight()}
                                                };

    if (m_hMaskBitmap)
    {
        ::GpiDeleteBitmap((HBITMAP) m_hMaskBitmap);
        m_hMaskBitmap = 0;
    }
    if (!rBitmap.Ok() || rBitmap.GetDepth() != 1)
    {
        return false;
    }

    memset(&vBmih, '\0', sizeof(BITMAPINFOHEADER2));
    vBmih.cbFix     =  sizeof(BITMAPINFOHEADER2);
    vBmih.cx        = rBitmap.GetWidth();
    vBmih.cy        = rBitmap.GetHeight();
    vBmih.cPlanes   = 1;
    vBmih.cBitCount = 24;

    m_hMaskBitmap = ::GpiCreateBitmap( hPSDst
                                      ,&vBmih
                                      ,0L
                                      ,NULL
                                      ,NULL
                                     );

    ::GpiSetBitmap(hPSSrc, (HBITMAP) rBitmap.GetHBITMAP());
    ::GpiSetBitmap(hPSDst, (HBITMAP) m_hMaskBitmap);
    ::GpiBitBlt( hPSDst
                ,hPSSrc
                ,4L
                ,vPoint
                ,ROP_SRCCOPY
                ,BBO_IGNORE
               );

    ::GpiDestroyPS(hPSSrc);
    ::GpiDestroyPS(hPSDst);
    ::DevCloseDC(hDCSrc);
    ::DevCloseDC(hDCDst);
    return true;
} // end of wxMask::Create

// Create a mask from a bitmap and a palette index indicating
// the transparent area
bool wxMask::Create(
  const wxBitmap&                   rBitmap
, int                               nPaletteIndex
)
{
    if (m_hMaskBitmap)
    {
        ::GpiDeleteBitmap((HBITMAP) m_hMaskBitmap);
        m_hMaskBitmap = 0;
    }
    if (rBitmap.Ok() && rBitmap.GetPalette()->Ok())
    {
        unsigned char               cRed;
        unsigned char               cGreen;
        unsigned char               cBlue;

        if (rBitmap.GetPalette()->GetRGB( nPaletteIndex
                                         ,&cRed
                                         ,&cGreen
                                         ,&cBlue
                                        ))
        {
            wxColour                vTransparentColour( cRed
                                                       ,cGreen
                                                       ,cBlue
                                                      );

            return (Create( rBitmap
                           ,vTransparentColour
                          ));
        }
    }
    return false;
} // end of wxMask::Create

// Create a mask from a bitmap and a colour indicating
// the transparent area
bool wxMask::Create(
  const wxBitmap&                   rBitmap
, const wxColour&                   rColour
)
{
    bool                            bOk = true;
    COLORREF                        vMaskColour = OS2RGB( rColour.Red()
                                                         ,rColour.Green()
                                                         ,rColour.Blue()
                                                        );
    BITMAPINFOHEADER2               vBmih;
    SIZEL                           vSize = {0, 0};
    DEVOPENSTRUC                    vDop = { NULL, "DISPLAY", NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    HDC                             hDCSrc = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HDC                             hDCDst = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HPS                             hPSSrc = ::GpiCreatePS(vHabmain, hDCSrc, &vSize, PU_PELS | GPIA_ASSOC);
    HPS                             hPSDst = ::GpiCreatePS(vHabmain, hDCDst, &vSize, PU_PELS | GPIA_ASSOC);

    if (m_hMaskBitmap)
    {
        ::GpiDeleteBitmap((HBITMAP) m_hMaskBitmap);
        m_hMaskBitmap = 0;
    }
    if (!rBitmap.Ok())
    {
        return false;
    }

    //
    // Scan the bitmap for the transparent colour and set
    // the corresponding pixels in the mask to BLACK and
    // the rest to WHITE
    //

    memset(&vBmih, '\0', sizeof(BITMAPINFOHEADER2));
    vBmih.cbFix     =  sizeof(BITMAPINFOHEADER2);
    vBmih.cx        = rBitmap.GetWidth();
    vBmih.cy        = rBitmap.GetHeight();
    vBmih.cPlanes   = 1;
    vBmih.cBitCount = 1;

    m_hMaskBitmap = ::GpiCreateBitmap( hPSDst
                                      ,&vBmih
                                      ,0L
                                      ,NULL
                                      ,NULL
                                     );

    ::GpiSetBitmap(hPSSrc, (HBITMAP) rBitmap.GetHBITMAP());
    ::GpiSetBitmap(hPSDst, (HBITMAP) m_hMaskBitmap);

    //
    // This is not very efficient, but I can't think
    // of a better way of doing it
    //
    for (int w = 0; w < rBitmap.GetWidth(); w++)
    {
        for (int h = 0; h < rBitmap.GetHeight(); h++)
        {
            POINTL                  vPt = {w, h};
            COLORREF                vCol = (COLORREF)::GpiQueryPel(hPSSrc, &vPt);
            if (vCol == (COLORREF)CLR_NOINDEX)
            {
                //
                // Doesn't make sense to continue
                //
                bOk = false;
                break;
            }

            if (vCol == vMaskColour)
            {
                ::GpiSetColor(hPSDst, OS2RGB(0, 0, 0));
                ::GpiSetPel(hPSDst, &vPt);
            }
            else
            {
                ::GpiSetColor(hPSDst, OS2RGB(255, 255, 255));
                ::GpiSetPel(hPSDst, &vPt);
            }
        }
    }
    ::GpiSetBitmap(hPSSrc, NULL);
    ::GpiSetBitmap(hPSDst, NULL);
    ::GpiDestroyPS(hPSSrc);
    ::GpiDestroyPS(hPSDst);
    ::DevCloseDC(hDCSrc);
    ::DevCloseDC(hDCDst);
    return true;
} // end of wxMask::Create

// ----------------------------------------------------------------------------
// wxBitmapHandler
// ----------------------------------------------------------------------------

bool wxBitmapHandler::Create( wxGDIImage* pImage,
                              const void* pData,
                              wxBitmapType lType,
                              int         nWidth,
                              int         nHeight,
                              int         nDepth)
{
    wxBitmap* pBitmap = wxDynamicCast( pImage
                                      ,wxBitmap
                                       );

    return(pBitmap ? Create( pBitmap
                            ,pData
                            ,lType
                            ,nWidth
                            ,nHeight
                            ,nDepth
                           ) : false);
}

bool wxBitmapHandler::Load(
  wxGDIImage*                       pImage
, int                               nId
, wxBitmapType                      lFlags
, int                               nWidth
, int                               nHeight
)
{
    wxBitmap*                       pBitmap = wxDynamicCast( pImage
                                                            ,wxBitmap
                                                           );

    return(pBitmap ? LoadFile( pBitmap
                              ,nId
                              ,lFlags
                              ,nWidth
                              ,nHeight
                             ) : false);
}

bool wxBitmapHandler::Save(
  const wxGDIImage*                 pImage
, const wxString&                   rName
, wxBitmapType                      lType
) const
{
    wxBitmap*                       pBitmap = wxDynamicCast( pImage
                                                            ,wxBitmap
                                                           );

    return(pBitmap ? SaveFile( pBitmap
                              ,rName
                              ,lType
                             ) : false);
}

bool wxBitmapHandler::Create(
  wxBitmap*                         WXUNUSED(pBitmap)
, const void*                       WXUNUSED(pData)
, wxBitmapType                      WXUNUSED(lType)
, int                               WXUNUSED(nWidth)
, int                               WXUNUSED(nHeight)
, int                               WXUNUSED(nDepth)
)
{
    return false;
}

bool wxBitmapHandler::LoadFile(
  wxBitmap*                         WXUNUSED(pBitmap)
, int                               WXUNUSED(nId)
, wxBitmapType                      WXUNUSED(lType)
, int                               WXUNUSED(nDesiredWidth)
, int                               WXUNUSED(nDesiredHeight)
)
{
    return false;
}

bool wxBitmapHandler::LoadFile(
  wxBitmap*                         WXUNUSED(pBitmap)
, const wxString&                   WXUNUSED(rName)
, wxBitmapType                      WXUNUSED(lType)
, int                               WXUNUSED(nDesiredWidth)
, int                               WXUNUSED(nDesiredHeight)
)
{
    return false;
}

bool wxBitmapHandler::SaveFile(
  wxBitmap*                         WXUNUSED(pBitmap)
, const wxString&                   WXUNUSED(rName)
, wxBitmapType                      WXUNUSED(nType)
, const wxPalette*                  WXUNUSED(pPalette)
) const
{
    return false;
}

// ----------------------------------------------------------------------------
// Utility functions
// ----------------------------------------------------------------------------
HBITMAP wxInvertMask(
  HBITMAP                           hBmpMask
, int                               nWidth
, int                               nHeight
)
{
    HBITMAP                         hBmpInvMask = 0;

    wxCHECK_MSG( hBmpMask, 0, wxT("invalid bitmap in wxInvertMask") );

    //
    // Get width/height from the bitmap if not given
    //
    if (!nWidth || !nHeight)
    {
        BITMAPINFOHEADER2           vBmhdr;

        ::GpiQueryBitmapInfoHeader( hBmpMask
                                   ,&vBmhdr
                                  );
        nWidth  = (int)vBmhdr.cx;
        nHeight = (int)vBmhdr.cy;
    }

    BITMAPINFOHEADER2               vBmih;
    SIZEL                           vSize = {0, 0};
    DEVOPENSTRUC                    vDop = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    HDC                             hDCSrc = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HDC                             hDCDst = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HPS                             hPSSrc = ::GpiCreatePS(vHabmain, hDCSrc, &vSize, PU_PELS | GPIA_ASSOC);
    HPS                             hPSDst = ::GpiCreatePS(vHabmain, hDCDst, &vSize, PU_PELS | GPIA_ASSOC);
    POINTL                          vPoint[4] = { {0 ,0}, {nWidth, nHeight},
                                                  {0, 0}, {nWidth, nHeight}
                                                };

    memset(&vBmih, '\0', 16);
    vBmih.cbFix     = 16;
    vBmih.cx        = nWidth;
    vBmih.cy        = nHeight;
    vBmih.cPlanes   = 1;
    vBmih.cBitCount = 24;

    hBmpInvMask = ::GpiCreateBitmap( hPSDst
                                    ,&vBmih
                                    ,0L
                                    ,NULL
                                    ,NULL
                                   );

    ::GpiSetBitmap(hPSSrc, (HBITMAP) hBmpMask);
    ::GpiSetBitmap(hPSDst, (HBITMAP) hBmpInvMask);

    ::GpiBitBlt( hPSDst
                ,hPSSrc
                ,4L
                ,vPoint
                ,ROP_SRCINVERT
                ,BBO_IGNORE
               );

    ::GpiDestroyPS(hPSSrc);
    ::GpiDestroyPS(hPSDst);
    ::DevCloseDC(hDCSrc);
    ::DevCloseDC(hDCDst);

    return hBmpInvMask;
} // end of WxWinGdi_InvertMask

HBITMAP wxCopyBmp( HBITMAP hBmp, bool flip, int nWidth, int nHeight )
{
    wxCHECK_MSG( hBmp, 0, wxT("invalid bitmap in wxCopyBmp") );

    //
    // Get width/height from the bitmap if not given
    //
    if (!nWidth || !nHeight)
    {
        BITMAPINFOHEADER2 vBmhdr;

        vBmhdr.cbFix  = 16;
        ::GpiQueryBitmapInfoHeader( hBmp,
                                    &vBmhdr );
        nWidth        = (int)vBmhdr.cx;
        nHeight       = (int)vBmhdr.cy;
    }

    BITMAPINFOHEADER2 vBmih;
    SIZEL             vSize     = {0, 0};
    DEVOPENSTRUC      vDop      = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    HDC               hDCSrc    = ::DevOpenDC(  vHabmain,
                                                OD_MEMORY,
                                                "*",
                                                5L,
                                                (PDEVOPENDATA)&vDop,
                                                NULLHANDLE  );
    HDC               hDCDst    = ::DevOpenDC(  vHabmain,
                                                OD_MEMORY,
                                                "*",
                                                5L,
                                                (PDEVOPENDATA)&vDop,
                                                NULLHANDLE  );
    HPS               hPSSrc    = ::GpiCreatePS(  vHabmain,
                                                  hDCSrc,
                                                  &vSize,
                                                  PU_PELS | GPIA_ASSOC  );
    HPS               hPSDst    = ::GpiCreatePS(  vHabmain,
                                                  hDCDst,
                                                  &vSize,
                                                  PU_PELS | GPIA_ASSOC  );
    POINTL            vPoint[4] = { {0,      nHeight},
                                    {nWidth, 0},
                                    {0,      0},
                                    {nWidth, nHeight} };
    if (!flip)
    {
        vPoint[0].y = 0;
        vPoint[1].y = nHeight;
    }
    memset(&vBmih, '\0', 16);
    vBmih.cbFix     = 16;
    vBmih.cx        = nWidth;
    vBmih.cy        = nHeight;
    vBmih.cPlanes   = 1;
    vBmih.cBitCount = 24;

    HBITMAP hInvBmp = ::GpiCreateBitmap(  hPSDst,
                                          &vBmih,
                                          0L,
                                          NULL,
                                          NULL  );

    ::GpiSetBitmap(hPSSrc, (HBITMAP) hBmp);
    ::GpiSetBitmap(hPSDst, (HBITMAP) hInvBmp);

    ::GpiBitBlt(  hPSDst,
                  hPSSrc,
                  4L,
                  vPoint,
                  ROP_SRCCOPY,
                  BBO_IGNORE  );

    ::GpiDestroyPS(hPSSrc);
    ::GpiDestroyPS(hPSDst);
    ::DevCloseDC(hDCSrc);
    ::DevCloseDC(hDCDst);

    return hInvBmp;
} // end of wxFlipBmp
