///////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/gdiimage.cpp
// Purpose:     wxGDIImage implementation
// Author:      Vadim Zeitlin
// Modified by:
// Created:     20.11.99
// RCS-ID:      $Id$
// Copyright:   (c) 1999 Vadim Zeitlin <zeitlin@dptmaths.ens-cachan.fr>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"


#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/app.h"
#endif // WX_PRECOMP

#include "wx/os2/private.h"
#include "wx/os2/gdiimage.h"

#include "wx/listimpl.cpp"
WX_DEFINE_LIST(wxGDIImageHandlerList)

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

// all image handlers are declared/defined in this file because the outside
// world doesn't have to know about them (but only about wxBITMAP_TYPE_XXX ids)

class WXDLLEXPORT wxBMPFileHandler : public wxBitmapHandler
{
public:
    wxBMPFileHandler() : wxBitmapHandler(wxT("Windows bitmap file"), wxT("bmp"),
                                         wxBITMAP_TYPE_BMP)
    {
    }

    virtual bool LoadFile( wxBitmap*       pBitmap
                          ,const wxString& rName
                          ,HPS             hPs
                          ,wxBitmapType    lFlags
                          ,int             nDesiredWidth
                          ,int             nDesiredHeight
                         );
    virtual bool SaveFile( wxBitmap*        pBitmap
                          ,const wxString&  rName
                          ,wxBitmapType     lType
                          ,const wxPalette* pPalette = NULL
                         );

private:
    inline virtual bool LoadFile( wxBitmap*       pBitmap
                                 ,int             nId
                                 ,wxBitmapType    lFlags
                                 ,int             nDesiredWidth
                                 ,int             nDesiredHeight
                                )
    {
        return wxBitmapHandler::LoadFile( pBitmap
                                         ,nId
                                         ,lFlags
                                         ,nDesiredWidth
                                         ,nDesiredHeight
                                        );
    }
    DECLARE_DYNAMIC_CLASS(wxBMPFileHandler)
};

class WXDLLEXPORT wxBMPResourceHandler: public wxBitmapHandler
{
public:
    wxBMPResourceHandler() : wxBitmapHandler(wxT("Windows bitmap resource"),
                                             wxEmptyString,
                                             wxBITMAP_TYPE_BMP_RESOURCE)
    {
    }

    virtual bool LoadFile( wxBitmap*       pBitmap
                          ,int             nId
                          ,wxBitmapType    lFlags
                          ,int             nDesiredWidth
                          ,int             nDesiredHeight
                         );

private:
    DECLARE_DYNAMIC_CLASS(wxBMPResourceHandler)
};

class WXDLLEXPORT wxIconHandler : public wxGDIImageHandler
{
public:
    wxIconHandler( const wxString& rName
                  ,const wxString& rExt
                  ,wxBitmapType    lType
                 ) : wxGDIImageHandler( rName
                                       ,rExt
                                       ,lType
                                      )
    {
    }

    // creating and saving icons is not supported
    virtual bool Create( wxGDIImage* WXUNUSED(pImage)
                        ,const void* WXUNUSED(pData)
                        ,wxBitmapType WXUNUSED(lFlags)
                        ,int         WXUNUSED(nWidth)
                        ,int         WXUNUSED(nHeight)
                        ,int         WXUNUSED(nDepth) = 1
                       )
    {
        return false;
    }

    virtual bool Save( const wxGDIImage* WXUNUSED(pImage)
                      ,const wxString&   WXUNUSED(rName)
                      ,wxBitmapType      WXUNUSED(nType)
                     ) const
    {
        return false;
    }
    virtual bool Load( wxGDIImage*     pImage
                      ,const wxString& rName
                      ,HPS             hPs
                      ,wxBitmapType    lFlags
                      ,int             nDesiredWidth
                      ,int             nDesiredHeight
                     )
    {
        wxIcon*                     pIcon = wxDynamicCast(pImage, wxIcon);
        wxCHECK_MSG(pIcon, false, wxT("wxIconHandler only works with icons"));

        return LoadIcon( pIcon
                        ,rName
                        ,hPs
                        ,lFlags
                        ,nDesiredWidth
                        ,nDesiredHeight
                       );
    }

protected:
    virtual bool LoadIcon( wxIcon*         pIcon
                          ,const wxString& rName
                          ,HPS             hPs
                          ,wxBitmapType    lFlags
                          ,int             nDesiredWidth = -1
                          ,int             nDesiredHeight = -1
                         ) = 0;
private:
    inline virtual bool Load( wxGDIImage* WXUNUSED(pImage),
                              int         WXUNUSED(nId),
                              wxBitmapType WXUNUSED(lFlags),
                              int         WXUNUSED(nDesiredWidth),
                              int         WXUNUSED(nDesiredHeight) )
    {
        return false;
    }
};

class WXDLLEXPORT wxICOFileHandler : public wxIconHandler
{
public:
    wxICOFileHandler() : wxIconHandler(wxT("ICO icon file"),
                                       wxT("ico"),
                                       wxBITMAP_TYPE_ICO)
    {
    }

    virtual bool LoadIcon( wxIcon *        pIcon
                          ,const wxString& rName
                          ,HPS             hPs
                          ,wxBitmapType    lFlags
                          ,int             nDesiredWidth = -1
                          ,int             nDesiredHeight = -1
                         );

private:
    DECLARE_DYNAMIC_CLASS(wxICOFileHandler)
};

class WXDLLEXPORT wxICOResourceHandler: public wxIconHandler
{
public:
    wxICOResourceHandler() : wxIconHandler(wxT("ICO resource"),
                                           wxT("ico"),
                                           wxBITMAP_TYPE_ICO_RESOURCE)
    {
    }

    virtual bool LoadIcon( wxIcon*         pIcon
                          ,const wxString& rName
                          ,HPS             hPs
                          ,wxBitmapType    lFlags
                          ,int             nDesiredWidth = -1
                          ,int             nDesiredHeight = -1
                         );

private:
    DECLARE_DYNAMIC_CLASS(wxICOResourceHandler)
};

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxBMPFileHandler, wxBitmapHandler)
IMPLEMENT_DYNAMIC_CLASS(wxBMPResourceHandler, wxBitmapHandler)
IMPLEMENT_DYNAMIC_CLASS(wxICOFileHandler, wxObject)
IMPLEMENT_DYNAMIC_CLASS(wxICOResourceHandler, wxObject)

// ============================================================================
// implementation
// ============================================================================

wxGDIImageHandlerList wxGDIImage::ms_handlers;

// ----------------------------------------------------------------------------
// wxGDIImage functions forwarded to wxGDIImageRefData
// ----------------------------------------------------------------------------

bool wxGDIImage::FreeResource( bool WXUNUSED(bForce) )
{
    if ( !IsNull() )
    {
        GetGDIImageData()->Free();
        GetGDIImageData()->m_hHandle = 0;
    }

    return true;
}

WXHANDLE wxGDIImage::GetResourceHandle() const
{
    return GetHandle();
}

// ----------------------------------------------------------------------------
// wxGDIImage handler stuff
// ----------------------------------------------------------------------------

void wxGDIImage::AddHandler( wxGDIImageHandler* pHandler )
{
    ms_handlers.Append(pHandler);
}

void wxGDIImage::InsertHandler( wxGDIImageHandler* pHandler )
{
    ms_handlers.Insert(pHandler);
}

bool wxGDIImage::RemoveHandler( const wxString& rName )
{
    wxGDIImageHandler*              pHandler = FindHandler(rName);

    if (pHandler)
    {
        ms_handlers.DeleteObject(pHandler);
        return true;
    }
    else
        return false;
}

wxGDIImageHandler* wxGDIImage::FindHandler(
  const wxString&                   rName
)
{
    wxGDIImageHandlerList::compatibility_iterator   pNode = ms_handlers.GetFirst();

    while ( pNode )
    {
        wxGDIImageHandler*          pHandler = pNode->GetData();

        if ( pHandler->GetName() == rName )
            return pHandler;
        pNode = pNode->GetNext();
    }
    return(NULL);
}

wxGDIImageHandler* wxGDIImage::FindHandler(
  const wxString&                   rExtension
, wxBitmapType                      lType
)
{
    wxGDIImageHandlerList::compatibility_iterator   pNode = ms_handlers.GetFirst();
    while ( pNode )
    {
        wxGDIImageHandler*          pHandler = pNode->GetData();

        if ( (pHandler->GetExtension() == rExtension) &&
             (lType == -1 || pHandler->GetType() == lType) )
        {
            return pHandler;
        }
        pNode = pNode->GetNext();
    }
    return(NULL);
}

wxGDIImageHandler* wxGDIImage::FindHandler(
  wxBitmapType                           lType
)
{
    wxGDIImageHandlerList::compatibility_iterator   pNode = ms_handlers.GetFirst();

    while ( pNode )
    {
        wxGDIImageHandler*          pHandler = pNode->GetData();

        if ( pHandler->GetType() == lType )
            return pHandler;
        pNode = pNode->GetNext();
    }
    return(NULL);
}

void wxGDIImage::CleanUpHandlers()
{
    wxGDIImageHandlerList::compatibility_iterator   pNode = ms_handlers.GetFirst();

    while ( pNode )
    {
        wxGDIImageHandler*                              pHandler = pNode->GetData();
        wxGDIImageHandlerList::compatibility_iterator   pNext = pNode->GetNext();

        delete pHandler;
        ms_handlers.Erase( pNode );
        pNode = pNext;
    }
}

void wxGDIImage::InitStandardHandlers()
{
    AddHandler(new wxBMPResourceHandler);
    AddHandler(new wxBMPFileHandler);
    AddHandler(new wxICOResourceHandler);
    AddHandler(new wxICOFileHandler);
}

// ----------------------------------------------------------------------------
// wxBitmap handlers
// ----------------------------------------------------------------------------

bool wxBMPResourceHandler::LoadFile( wxBitmap* pBitmap,
                                     int       nId,
                                     wxBitmapType WXUNUSED(lFlags),
                                     int       WXUNUSED(nDesiredWidth),
                                     int       WXUNUSED(nDesiredHeight) )
{
    SIZEL                               vSize = {0, 0};
    DEVOPENSTRUC                        vDop  = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    HDC                                 hDC   = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HPS                                 hPS   = ::GpiCreatePS(vHabmain, hDC, &vSize, PU_PELS | GPIA_ASSOC);

    pBitmap->SetHBITMAP((WXHBITMAP)::GpiLoadBitmap( hPS
                                                   ,NULLHANDLE
                                                   ,nId
                                                   ,0
                                                   ,0
                                                  ));
    ::GpiDestroyPS(hPS);
    ::DevCloseDC(hDC);

    wxBitmapRefData*                pData = pBitmap->GetBitmapData();

    if ( pBitmap->Ok() )
    {
        BITMAPINFOHEADER            vBmph;

        ::GpiQueryBitmapParameters(GetHbitmapOf(*pBitmap), &vBmph);
        pData->m_nWidth  = vBmph.cx;
        pData->m_nHeight = vBmph.cy;
        pData->m_nDepth  = vBmph.cBitCount;
    }
    return(pBitmap->Ok());
} // end of wxBMPResourceHandler::LoadFile

bool wxBMPFileHandler::LoadFile( wxBitmap*       pBitmap,
                                 const wxString& WXUNUSED(rName),
                                 HPS             WXUNUSED(hPs),
                                 wxBitmapType    WXUNUSED(lFlags),
                                 int             WXUNUSED(nDesiredWidth),
                                 int             WXUNUSED(nDesiredHeight) )
{
#if defined(wxUSE_IMAGE_LOADING_IN_OS2) && wxUSE_IMAGE_LOADING_IN_OS2
    wxPalette* pPalette = NULL;

    bool bSuccess = false; /* wxLoadIntoBitmap( WXSTRINGCAST rName
                                               ,pBitmap
                                               ,&pPalette
                                              ) != 0; */
    if (bSuccess && pPalette)
    {
        pBitmap->SetPalette(*pPalette);
    }

    // it was copied by the bitmap if it was loaded successfully
    delete pPalette;

    return(bSuccess);
#else
    wxUnusedVar(pBitmap);
    return false;
#endif
}

bool wxBMPFileHandler::SaveFile( wxBitmap*        pBitmap,
                                 const wxString&  WXUNUSED(rName),
                                 wxBitmapType     WXUNUSED(nType),
                                 const wxPalette* pPal )
{
#if defined(wxUSE_IMAGE_LOADING_IN_OS2) && wxUSE_IMAGE_LOADING_IN_OS2
    wxPalette* pActualPalette = (wxPalette *)pPal;

    if (!pActualPalette)
        pActualPalette = pBitmap->GetPalette();
    /* return(wxSaveBitmap( WXSTRINGCAST rName
                        ,pBitmap
                        ,pActualPalette
                       ) != 0); */
    return false;
#else
    wxUnusedVar(pBitmap);
    wxUnusedVar(pPal);
    return false;
#endif
}

// ----------------------------------------------------------------------------
// wxIcon handlers
// ----------------------------------------------------------------------------

bool wxICOFileHandler::LoadIcon( wxIcon*         pIcon,
                                 const wxString& WXUNUSED(rName),
                                 HPS             WXUNUSED(hPs),
                                 wxBitmapType    WXUNUSED(lFlags),
                                 int             WXUNUSED(nDesiredWidth),
                                 int             WXUNUSED(nDesiredHeight) )
{
#if defined(wxUSE_RESOURCE_LOADING_IN_OS2) && wxUSE_RESOURCE_LOADING_IN_OS2
    pIcon->UnRef();

    return false;
#else
    wxUnusedVar(pIcon);
    return false;
#endif
}

bool wxICOResourceHandler::LoadIcon( wxIcon*         pIcon,
                                     const wxString& rName,
                                     HPS             WXUNUSED(hPs),
                                     wxBitmapType    WXUNUSED(lFlags),
                                     int             WXUNUSED(nDesiredWidth),
                                     int             WXUNUSED(nDesiredHeight) )
{
    HPOINTER                        hIcon;

    hIcon = ::WinLoadFileIcon( rName.c_str()
                              ,TRUE // load for private use
                             );

    pIcon->SetSize(32, 32); // all OS/2 icons are 32 x 32

    pIcon->SetHICON((WXHICON)hIcon);

    return pIcon->Ok();
} // end of wxICOResourceHandler::LoadIcon
