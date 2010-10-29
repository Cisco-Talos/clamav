/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/metafile.cpp
// Purpose:     wxMetaFile, wxMetaFileDC etc. These classes are optional.
// Author:      David Webster
// Modified by:
// Created:     10/10/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_METAFILE

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/app.h"
#endif

#include "wx/metafile.h"
#include "wx/clipbrd.h"
#include "wx/os2/private.h"

#include <stdio.h>
#include <string.h>

extern bool wxClipboardIsOpen;

IMPLEMENT_DYNAMIC_CLASS(wxMetafile, wxObject)
IMPLEMENT_ABSTRACT_CLASS(wxMetafileDC, wxDC)

/*
 * Metafiles
 * Currently, the only purpose for making a metafile is to put
 * it on the clipboard.
 */

wxMetafileRefData::wxMetafileRefData(void)
{
    m_metafile = 0;
    m_windowsMappingMode = MM_ANISOTROPIC;
}

wxMetafileRefData::~wxMetafileRefData(void)
{
    if (m_metafile)
    {
// TODO: DeleteMetaFile((HMETAFILE) m_metafile);
         m_metafile = 0;
    }
}

wxMetafile::wxMetafile(const wxString& file)
{
    m_refData = new wxMetafileRefData;

    M_METAFILEDATA->m_windowsMappingMode = MM_ANISOTROPIC;
    M_METAFILEDATA->m_metafile = 0;
    if (!file.empty())
        M_METAFILEDATA->m_metafile = (WXHANDLE)0; // TODO: GetMetaFile(file);
}

wxMetafile::~wxMetafile(void)
{
}

wxGDIRefData *wxMetafile::CreateGDIRefData() const
{
    return new wxMetafileRefData;
}

wxGDIRefData *wxMetafile::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxMetafileRefData(*static_cast<const wxMetafileRefData *>(data));
}

bool wxMetafile::SetClipboard(int width, int height)
{
#if !wxUSE_CLIPBOARD
    wxUnusedVar(width);
    wxUnusedVar(height);
    return false;
#else
    if (!m_refData)
        return false;

    bool alreadyOpen=wxClipboardOpen();
    if (!alreadyOpen)
    {
        wxOpenClipboard();
        if (!wxEmptyClipboard()) return false;
    }
    bool success = wxSetClipboardData(wxDF_METAFILE, this, width,height);
    if (!alreadyOpen) wxCloseClipboard();
    return (bool) success;
#endif
}

bool wxMetafile::Play(wxDC *dc)
{
    if (!m_refData)
        return false;

 //   if (dc->GetHDC() && M_METAFILEDATA->m_metafile)
 //       PlayMetaFile((HDC) dc->GetHDC(), (HMETAFILE) M_METAFILEDATA->m_metafile);

    return true;
}

void wxMetafile::SetHMETAFILE(WXHANDLE mf)
{
    if (m_refData)
        m_refData = new wxMetafileRefData;

    M_METAFILEDATA->m_metafile = mf;
}

void wxMetafile::SetWindowsMappingMode(int mm)
{
    if (m_refData)
        m_refData = new wxMetafileRefData;

    M_METAFILEDATA->m_windowsMappingMode = mm;
}

/*
 * Metafile device context
 *
 */

// Original constructor that does not takes origin and extent. If you use this,
// *DO* give origin/extent arguments to wxMakeMetafilePlaceable.
wxMetafileDCImpl::wxMetafileDCImpl(wxDC *owner, const wxString& file)
    : wxPMDCImpl(owner)
{
  m_metaFile = NULL;
  m_minX = 10000;
  m_minY = 10000;
  m_maxX = -10000;
  m_maxY = -10000;
//  m_title = NULL;

  if (!file.IsNull() && wxFileExists(file))
    wxRemoveFile(file);

  // TODO
/*
  if (!file.empty())
    m_hDC = (WXHDC) CreateMetaFile(file);
  else
    m_hDC = (WXHDC) CreateMetaFile(NULL);
*/

  m_ok = (m_hDC != (WXHDC) 0) ;

  // Actual Windows mapping mode, for future reference.
  m_windowsMappingMode = wxMM_TEXT;

  SetMapMode(wxMM_TEXT); // NOTE: does not set HDC mapmode (this is correct)
}

// New constructor that takes origin and extent. If you use this, don't
// give origin/extent arguments to wxMakeMetafilePlaceable.
wxMetafileDCImpl::wxMetafileDCImpl( wxDC *owner, const wxString& file,
                                    int WXUNUSED(xext),
                                    int WXUNUSED(yext),
                                    int WXUNUSED(xorg),
                                    int WXUNUSED(yorg) )
    : wxPMDCImpl(owner)
{
    m_minX = 10000;
    m_minY = 10000;
    m_maxX = -10000;
    m_maxY = -10000;
    if (!file.empty() && wxFileExists(file))
        wxRemoveFile(file);

//  m_hDC = (WXHDC) CreateMetaFile(file);

    m_ok = true;

//  ::SetWindowOrgEx((HDC) m_hDC,xorg,yorg, NULL);
//  ::SetWindowExtEx((HDC) m_hDC,xext,yext, NULL);

    // Actual Windows mapping mode, for future reference.
    m_windowsMappingMode = MM_ANISOTROPIC;

    SetMapMode(wxMM_TEXT); // NOTE: does not set HDC mapmode (this is correct)
}

wxMetafileDCImpl::~wxMetafileDCImpl(void)
{
  m_hDC = 0;
}

void wxMetafileDCImpl::DoGetTextExtent(const wxString& WXUNUSED(string),
                                     wxCoord *WXUNUSED(x),
                                     wxCoord *WXUNUSED(y),
                                     wxCoord *WXUNUSED(descent),
                                     wxCoord *WXUNUSED(externalLeading),
                                     const wxFont *theFont) const
{
    const wxFont *fontToUse = theFont;
    if (!fontToUse)
        fontToUse = &m_font;

    // TODO:
/*
    HDC dc = GetDC(NULL);

    SIZE sizeRect;
    TEXTMETRIC tm;
    GetTextExtentPoint(dc, WXSTRINGCAST string, wxStrlen(WXSTRINGCAST string), &sizeRect);
    GetTextMetrics(dc, &tm);

    ReleaseDC(NULL, dc);

    if ( x )
        *x = sizeRect.cx;
    if ( y )
        *y = sizeRect.cy;
    if ( descent )
        *descent = tm.tmDescent;
    if ( externalLeading )
        *externalLeading = tm.tmExternalLeading;
*/
}

wxMetafile *wxMetafileDCImpl::Close(void)
{
  SelectOldObjects(m_hDC);
  HANDLE mf = 0; // TODO: CloseMetaFile((HDC) m_hDC);
  m_hDC = 0;
  if (mf)
  {
    wxMetafile *wx_mf = new wxMetafile;
    wx_mf->SetHMETAFILE((WXHANDLE) mf);
    wx_mf->SetWindowsMappingMode(m_windowsMappingMode);
    return wx_mf;
  }
  return NULL;
}

void wxMetafileDCImpl::SetMapMode(wxMappingMode mode)
{
  m_mappingMode = mode;

//  int pixel_width = 0;
//  int pixel_height = 0;
//  int mm_width = 0;
//  int mm_height = 0;

  float mm2pixelsX = 10.0;
  float mm2pixelsY = 10.0;

  switch (mode)
  {
    case wxMM_TWIPS:
    {
      m_logicalScaleX = (float)(twips2mm * mm2pixelsX);
      m_logicalScaleY = (float)(twips2mm * mm2pixelsY);
      break;
    }
    case wxMM_POINTS:
    {
      m_logicalScaleX = (float)(pt2mm * mm2pixelsX);
      m_logicalScaleY = (float)(pt2mm * mm2pixelsY);
      break;
    }
    case wxMM_METRIC:
    {
      m_logicalScaleX = mm2pixelsX;
      m_logicalScaleY = mm2pixelsY;
      break;
    }
    case wxMM_LOMETRIC:
    {
      m_logicalScaleX = (float)(mm2pixelsX/10.0);
      m_logicalScaleY = (float)(mm2pixelsY/10.0);
      break;
    }
    default:
    case wxMM_TEXT:
    {
      m_logicalScaleX = 1.0;
      m_logicalScaleY = 1.0;
      break;
    }
  }
  m_nWindowExtX = 100;
  m_nWindowExtY = 100;
}

#ifdef __WIN32__
struct RECT32
{
  short left;
  short top;
  short right;
  short bottom;
};

struct mfPLACEABLEHEADER {
    DWORD  key;
    short  hmf;
    RECT32 bbox;
    WORD   inch;
    DWORD  reserved;
    WORD   checksum;
};
#else
struct mfPLACEABLEHEADER {
    DWORD  key;
    HANDLE hmf;
    RECT   bbox;
    WORD   inch;
    DWORD  reserved;
    WORD   checksum;
};
#endif

/*
 * Pass filename of existing non-placeable metafile, and bounding box.
 * Adds a placeable metafile header, sets the mapping mode to anisotropic,
 * and sets the window origin and extent to mimic the wxMM_TEXT mapping mode.
 *
 */

bool wxMakeMetafilePlaceable(const wxString& filename, float scale)
{
  return wxMakeMetafilePlaceable(filename, 0, 0, 0, 0, scale, FALSE);
}

bool wxMakeMetafilePlaceable(const wxString& WXUNUSED(filename),
                             int WXUNUSED(x1),
                             int WXUNUSED(y1),
                             int WXUNUSED(x2),
                             int WXUNUSED(y2),
                             float WXUNUSED(scale),
                             bool WXUNUSED(useOriginAndExtent))
{
// TODO:  the OS/2 PM/MM way to do this
/*
    // I'm not sure if this is the correct way of suggesting a scale
    // to the client application, but it's the only way I can find.
    int unitsPerInch = (int)(576/scale);

    mfPLACEABLEHEADER header;
    header.key = 0x9AC6CDD7L;
    header.hmf = 0;
    header.bbox.xLeft = (int)(x1);
    header.bbox.yTop = (int)(y1);
    header.bbox.xRight = (int)(x2);
    header.bbox.yBottom = (int)(y2);
    header.inch = unitsPerInch;
    header.reserved = 0;

    // Calculate checksum
    WORD *p;
    mfPLACEABLEHEADER *pMFHead = &header;
    for (p =(WORD *)pMFHead,pMFHead -> checksum = 0; p < (WORD *)&pMFHead ->checksum; ++p)
        pMFHead ->checksum ^= *p;

    FILE *fd = fopen(filename.fn_str(), "rb");
    if (!fd)
        return false;

    wxChar tempFileBuf[256];
    wxGetTempFileName(wxT("mf"), tempFileBuf);
    FILE *fHandle = fopen(wxConvFile.cWX2MB(tempFileBuf), "wb");
    if (!fHandle)
        return false;
    fwrite((void *)&header, sizeof(unsigned char), sizeof(mfPLACEABLEHEADER), fHandle);

    // Calculate origin and extent
    int originX = x1;
    int originY = y1;
    int extentX = x2 - x1;
    int extentY = (y2 - y1);

    // Read metafile header and write
    METAHEADER metaHeader;
    fread((void *)&metaHeader, sizeof(unsigned char), sizeof(metaHeader), fd);

    if (useOriginAndExtent)
        metaHeader.mtSize += 15;
    else
        metaHeader.mtSize += 5;

    fwrite((void *)&metaHeader, sizeof(unsigned char), sizeof(metaHeader), fHandle);

    // Write SetMapMode, SetWindowOrigin and SetWindowExt records
    char modeBuffer[8];
    char originBuffer[10];
    char extentBuffer[10];
    METARECORD *modeRecord = (METARECORD *)&modeBuffer;

    METARECORD *originRecord = (METARECORD *)&originBuffer;
    METARECORD *extentRecord = (METARECORD *)&extentBuffer;

    modeRecord->rdSize = 4;
    modeRecord->rdFunction = META_SETMAPMODE;
    modeRecord->rdParm[0] = MM_ANISOTROPIC;

    originRecord->rdSize = 5;
    originRecord->rdFunction = META_SETWINDOWORG;
    originRecord->rdParm[0] = originY;
    originRecord->rdParm[1] = originX;

    extentRecord->rdSize = 5;
    extentRecord->rdFunction = META_SETWINDOWEXT;
    extentRecord->rdParm[0] = extentY;
    extentRecord->rdParm[1] = extentX;

    fwrite((void *)modeBuffer, sizeof(char), 8, fHandle);

    if (useOriginAndExtent)
    {
        fwrite((void *)originBuffer, sizeof(char), 10, fHandle);
        fwrite((void *)extentBuffer, sizeof(char), 10, fHandle);
    }

    int ch = -2;
    while (ch != EOF)
    {
        ch = getc(fd);
        if (ch != EOF)
        {
            putc(ch, fHandle);
        }
    }
    fclose(fHandle);
    fclose(fd);
    wxRemoveFile(filename);
    wxCopyFile(tempFileBuf, filename);
    wxRemoveFile(tempFileBuf);
*/
    return true;
}

#endif // wxUSE_METAFILE
