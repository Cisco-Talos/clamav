/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/metafile.h
// Purpose:     wxMetaFile, wxMetaFileDC and wxMetaFileDataObject classes
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_METAFIILE_H_
#define _WX_METAFIILE_H_

#include "wx/dc.h"
#include "wx/gdiobj.h"

#if wxUSE_DRAG_AND_DROP
    #include "wx/dataobj.h"
#endif

// ----------------------------------------------------------------------------
// Metafile and metafile device context classes
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxMetafile;

class WXDLLIMPEXP_CORE wxMetafileRefData: public wxGDIRefData
{
public:
    wxMetafileRefData();
    virtual ~wxMetafileRefData();

    virtual bool IsOk() const { return m_metafile != 0; }

public:
    WXHANDLE m_metafile;
    int m_windowsMappingMode;
    int m_width, m_height;

    friend class WXDLLIMPEXP_FWD_CORE wxMetafile;
};

#define M_METAFILEDATA ((wxMetafileRefData *)m_refData)

class WXDLLIMPEXP_CORE wxMetafile: public wxGDIObject
{
public:
    wxMetafile(const wxString& file = wxEmptyString);
    virtual ~wxMetafile();

    // After this is called, the metafile cannot be used for anything
    // since it is now owned by the clipboard.
    virtual bool SetClipboard(int width = 0, int height = 0);

    virtual bool Play(wxDC *dc);

    // set/get the size of metafile for clipboard operations
    wxSize GetSize() const { return wxSize(GetWidth(), GetHeight()); }
    int GetWidth() const { return M_METAFILEDATA->m_width; }
    int GetHeight() const { return M_METAFILEDATA->m_height; }

    void SetWidth(int width) { M_METAFILEDATA->m_width = width; }
    void SetHeight(int height) { M_METAFILEDATA->m_height = height; }

    // Implementation
    WXHANDLE GetHMETAFILE() const { return M_METAFILEDATA->m_metafile; }
    void SetHMETAFILE(WXHANDLE mf) ;
    int GetWindowsMappingMode() const { return M_METAFILEDATA->m_windowsMappingMode; }
    void SetWindowsMappingMode(int mm);

private:
    DECLARE_DYNAMIC_CLASS(wxMetafile)
};

class WXDLLIMPEXP_CORE wxMetafileDC: public wxDC
{
public:
    // Don't supply origin and extent
    // Supply them to wxMakeMetaFilePlaceable instead.
    wxMetafileDC(const wxString& file = wxEmptyString);

    // Supply origin and extent (recommended).
    // Then don't need to supply them to wxMakeMetaFilePlaceable.
    wxMetafileDC(const wxString& file, int xext, int yext, int xorg, int yorg);

    virtual ~wxMetafileDC();

    // Should be called at end of drawing
    virtual wxMetafile *Close();
    virtual void SetMapMode(wxMappingMode mode);
    virtual void GetTextExtent(const wxString& string, long *x, long *y,
            long *descent = NULL, long *externalLeading = NULL,
            const wxFont *theFont = NULL, bool use16bit = FALSE) const;

    // Implementation
    wxMetafile *GetMetaFile() const { return m_metaFile; }
    void SetMetaFile(wxMetafile *mf) { m_metaFile = mf; }
    int GetWindowsMappingMode() const { return m_windowsMappingMode; }
    void SetWindowsMappingMode(int mm) { m_windowsMappingMode = mm; }

protected:
    int           m_windowsMappingMode;
    wxMetafile*   m_metaFile;

private:
    DECLARE_DYNAMIC_CLASS(wxMetafileDC)
};

/*
 * Pass filename of existing non-placeable metafile, and bounding box.
 * Adds a placeable metafile header, sets the mapping mode to anisotropic,
 * and sets the window origin and extent to mimic the wxMM_TEXT mapping mode.
 *
 */

// No origin or extent
bool WXDLLIMPEXP_CORE wxMakeMetafilePlaceable(const wxString& filename, float scale = 1.0);

// Optional origin and extent
bool WXDLLIMPEXP_CORE wxMakeMetaFilePlaceable(const wxString& filename, int x1, int y1, int x2, int y2, float scale = 1.0, bool useOriginAndExtent = TRUE);

// ----------------------------------------------------------------------------
// wxMetafileDataObject is a specialization of wxDataObject for metafile data
// ----------------------------------------------------------------------------

#if wxUSE_DRAG_AND_DROP

class WXDLLIMPEXP_CORE wxMetafileDataObject : public wxDataObjectSimple
{
public:
    // ctors
    wxMetafileDataObject() : wxDataObjectSimple(wxDF_METAFILE)
        { }
    wxMetafileDataObject(const wxMetafile& metafile)
        : wxDataObjectSimple(wxDF_METAFILE), m_metafile(metafile) { }

    // virtual functions which you may override if you want to provide data on
    // demand only - otherwise, the trivial default versions will be used
    virtual void SetMetafile(const wxMetafile& metafile)
        { m_metafile = metafile; }
    virtual wxMetafile GetMetafile() const
        { return m_metafile; }

    // implement base class pure virtuals
    virtual size_t GetDataSize() const;
    virtual bool GetDataHere(void *buf) const;
    virtual bool SetData(size_t len, const void *buf);

protected:
    wxMetafile m_metafile;
};

#endif // wxUSE_DRAG_AND_DROP

#endif
    // _WX_METAFIILE_H_

