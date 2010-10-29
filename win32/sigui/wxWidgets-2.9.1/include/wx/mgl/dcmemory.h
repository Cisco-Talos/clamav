/////////////////////////////////////////////////////////////////////////////
// Name:        dcmemory.h
// Purpose:
// Author:      Vaclav Slavik
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __WX_DCMEMORY_H__
#define __WX_DCMEMORY_H__

#include "wx/defs.h"
#include "wx/dcclient.h"

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxMemoryDC;

//-----------------------------------------------------------------------------
// wxMemoryDC
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxMemoryDC : public wxDC, public wxMemoryDCBase
{
public:
    wxMemoryDC() { Init(); }
    wxMemoryDC(wxBitmap& bitmap) { Init(); SelectObject(bitmap); }
    wxMemoryDC(wxDC *dc); // Create compatible DC
    virtual ~wxMemoryDC();

    // these get reimplemented for mono-bitmaps to behave
    // more like their Win32 couterparts. They now interpret
    // wxWHITE, wxWHITE_BRUSH and wxWHITE_PEN as drawing 0
    // and everything else as drawing 1.
    virtual void SetPen(const wxPen &pen);
    virtual void SetBrush(const wxBrush &brush);
    virtual void SetTextForeground(const wxColour &col);
    virtual void SetTextBackground(const wxColour &col);

    // implementation
    wxBitmap  m_selected;

    wxBitmap GetSelectedObject() const { return m_selected; }

protected:
    virtual void DoSelect(const wxBitmap& bitmap);

private:
    void Init();

    DECLARE_DYNAMIC_CLASS(wxMemoryDC)
};

#endif
    // __WX_DCMEMORY_H__

