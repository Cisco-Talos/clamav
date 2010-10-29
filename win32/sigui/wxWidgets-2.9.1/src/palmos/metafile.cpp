/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/metafile.cpp
// Purpose:     wxMetafileDC etc.
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
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

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/app.h"
#endif

#include "wx/metafile.h"

#if wxUSE_METAFILE && !defined(wxMETAFILE_IS_ENH)

#include "wx/clipbrd.h"
#include "wx/palmos/private.h"

#include <stdio.h>
#include <string.h>

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxMetafile, wxObject)
IMPLEMENT_ABSTRACT_CLASS(wxMetafileDC, wxDC)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxMetafileRefData
// ----------------------------------------------------------------------------

/*
 * Metafiles
 * Currently, the only purpose for making a metafile is to put
 * it on the clipboard.
 */

wxMetafileRefData::wxMetafileRefData()
{
}

wxMetafileRefData::~wxMetafileRefData()
{
}

// ----------------------------------------------------------------------------
// wxMetafile
// ----------------------------------------------------------------------------

wxMetafile::wxMetafile(const wxString& file)
{
}

wxMetafile::~wxMetafile()
{
}

bool wxMetafile::SetClipboard(int width, int height)
{
    return false;
}

bool wxMetafile::Play(wxDC *dc)
{
    return false;
}

void wxMetafile::SetHMETAFILE(WXHANDLE mf)
{
}

void wxMetafile::SetWindowsMappingMode(int mm)
{
}

// ----------------------------------------------------------------------------
// Metafile device context
// ----------------------------------------------------------------------------

// Original constructor that does not takes origin and extent. If you use this,
// *DO* give origin/extent arguments to wxMakeMetafilePlaceable.
wxMetafileDC::wxMetafileDC(const wxString& file)
{
}

// New constructor that takes origin and extent. If you use this, don't
// give origin/extent arguments to wxMakeMetafilePlaceable.
wxMetafileDC::wxMetafileDC(const wxString& file, int xext, int yext, int xorg, int yorg)
{
}

wxMetafileDC::~wxMetafileDC()
{
}

void wxMetafileDC::GetTextExtent(const wxString& string, long *x, long *y,
                                 long *descent, long *externalLeading,
                                 const wxFont *theFont, bool WXUNUSED(use16bit)) const
{
}

wxMetafile *wxMetafileDC::Close()
{
    return NULL;
}

void wxMetafileDC::SetMapMode(wxMappingMode mode)
{
}

// ----------------------------------------------------------------------------
// wxMakeMetafilePlaceable
// ----------------------------------------------------------------------------
struct mfPLACEABLEHEADER {
    DWORD    key;
    HANDLE    hmf;
    RECT    bbox;
    WORD    inch;
    DWORD    reserved;
    WORD    checksum;
};

/*
 * Pass filename of existing non-placeable metafile, and bounding box.
 * Adds a placeable metafile header, sets the mapping mode to anisotropic,
 * and sets the window origin and extent to mimic the wxMM_TEXT mapping mode.
 *
 */

bool wxMakeMetafilePlaceable(const wxString& filename, float scale)
{
  return false;
}

bool wxMakeMetafilePlaceable(const wxString& filename, int x1, int y1, int x2, int y2, float scale, bool useOriginAndExtent)
{
    return false;
}


#if wxUSE_DRAG_AND_DROP

// ----------------------------------------------------------------------------
// wxMetafileDataObject
// ----------------------------------------------------------------------------

size_t wxMetafileDataObject::GetDataSize() const
{
    return 0;
}

bool wxMetafileDataObject::GetDataHere(void *buf) const
{
    return false;
}

bool wxMetafileDataObject::SetData(size_t WXUNUSED(len), const void *buf)
{
    return false;
}

#endif // wxUSE_DRAG_AND_DROP

#endif // wxUSE_METAFILE
