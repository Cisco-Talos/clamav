///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/enhmeta.cpp
// Purpose:     implementation of wxEnhMetaFileXXX classes
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10.13.04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
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

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_ENH_METAFILE

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/log.h"
#endif //WX_PRECOMP

#include "wx/metafile.h"
#include "wx/clipbrd.h"

#include "wx/palmos/private.h"

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxEnhMetaFile, wxObject)
IMPLEMENT_ABSTRACT_CLASS(wxEnhMetaFileDC, wxDC)

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

#define GetEMF()            ((HENHMETAFILE)m_hMF)
#define GetEMFOf(mf)        ((HENHMETAFILE)((mf).m_hMF))

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// we must pass NULL if the string is empty to metafile functions
static inline const wxChar *GetMetaFileName(const wxString& fn)
    { return !fn ? NULL : fn.c_str(); }

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxEnhMetaFile
// ----------------------------------------------------------------------------

void wxEnhMetaFile::Assign(const wxEnhMetaFile& mf)
{
}

void wxEnhMetaFile::Free()
{
}

bool wxEnhMetaFile::Play(wxDC *dc, wxRect *rectBound)
{
    return false;
}

wxSize wxEnhMetaFile::GetSize() const
{
    wxSize size = wxDefaultSize;

    return size;
}

bool wxEnhMetaFile::SetClipboard(int WXUNUSED(width), int WXUNUSED(height))
{
    return false;
}

// ----------------------------------------------------------------------------
// wxEnhMetaFileDC
// ----------------------------------------------------------------------------

wxEnhMetaFileDC::wxEnhMetaFileDC(const wxString& filename,
                                 int width, int height,
                                 const wxString& description)
{
}

wxEnhMetaFile *wxEnhMetaFileDC::Close()
{
    return NULL;
}

wxEnhMetaFileDC::~wxEnhMetaFileDC()
{
}

#if wxUSE_DRAG_AND_DROP

// ----------------------------------------------------------------------------
// wxEnhMetaFileDataObject
// ----------------------------------------------------------------------------

wxDataFormat
wxEnhMetaFileDataObject::GetPreferredFormat(Direction WXUNUSED(dir)) const
{
    return wxDF_ENHMETAFILE;
}

size_t wxEnhMetaFileDataObject::GetFormatCount(Direction WXUNUSED(dir)) const
{
    // wxDF_ENHMETAFILE and wxDF_METAFILE
    return 2;
}

void wxEnhMetaFileDataObject::GetAllFormats(wxDataFormat *formats,
                                            Direction WXUNUSED(dir)) const
{
}

size_t wxEnhMetaFileDataObject::GetDataSize(const wxDataFormat& format) const
{
    return 0u;
}

bool wxEnhMetaFileDataObject::GetDataHere(const wxDataFormat& format, void *buf) const
{
    return false;
}

bool wxEnhMetaFileDataObject::SetData(const wxDataFormat& format,
                                      size_t WXUNUSED(len),
                                      const void *buf)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxEnhMetaFileSimpleDataObject
// ----------------------------------------------------------------------------

size_t wxEnhMetaFileSimpleDataObject::GetDataSize() const
{
    return 0u;
}

bool wxEnhMetaFileSimpleDataObject::GetDataHere(void *buf) const
{
    return false;
}

bool wxEnhMetaFileSimpleDataObject::SetData(size_t WXUNUSED(len),
                                            const void *buf)
{
    return false;
}


#endif // wxUSE_DRAG_AND_DROP

#endif // wxUSE_ENH_METAFILE
