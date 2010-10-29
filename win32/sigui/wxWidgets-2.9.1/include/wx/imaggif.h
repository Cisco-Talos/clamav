/////////////////////////////////////////////////////////////////////////////
// Name:        wx/imaggif.h
// Purpose:     wxImage GIF handler
// Author:      Vaclav Slavik & Guillermo Rodriguez Garcia
// RCS-ID:      $Id$
// Copyright:   (c) Guillermo Rodriguez Garcia
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_IMAGGIF_H_
#define _WX_IMAGGIF_H_

#include "wx/image.h"


//-----------------------------------------------------------------------------
// wxGIFHandler
//-----------------------------------------------------------------------------

#if wxUSE_GIF

class WXDLLIMPEXP_CORE wxGIFHandler : public wxImageHandler
{
public:
    inline wxGIFHandler()
    {
        m_name = wxT("GIF file");
        m_extension = wxT("gif");
        m_type = wxBITMAP_TYPE_GIF;
        m_mime = wxT("image/gif");
    }

#if wxUSE_STREAMS
    virtual bool LoadFile(wxImage *image, wxInputStream& stream,
                          bool verbose = true, int index = -1);
    virtual bool SaveFile(wxImage *image, wxOutputStream& stream,
                          bool verbose=true);

protected:
    virtual int DoGetImageCount(wxInputStream& stream);
    virtual bool DoCanRead(wxInputStream& stream);
#endif // wxUSE_STREAMS

private:
    DECLARE_DYNAMIC_CLASS(wxGIFHandler)
};

#endif // wxUSE_GIF

#endif // _WX_IMAGGIF_H_

