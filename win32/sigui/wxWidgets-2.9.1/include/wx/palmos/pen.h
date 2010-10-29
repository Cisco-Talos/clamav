/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/pen.h
// Purpose:     wxPen class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Yunhui Fu
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PEN_H_
#define _WX_PEN_H_

#include "wx/gdiobj.h"
#include "wx/bitmap.h"
#include "wx/colour.h"

typedef WXDWORD wxMSWDash;

class WXDLLIMPEXP_FWD_CORE wxPen;

// VZ: this class should be made private
class WXDLLIMPEXP_CORE wxPenRefData : public wxGDIRefData
{
public:
    wxPenRefData();
    wxPenRefData(const wxPenRefData& data);
    virtual ~wxPenRefData();

    bool operator==(const wxPenRefData& data) const
    {
        // we intentionally don't compare m_hPen fields here
        return m_style == data.m_style &&
               m_width == data.m_width &&
               m_join == data.m_join &&
               m_cap == data.m_cap &&
               m_colour == data.m_colour &&
               (m_style != wxSTIPPLE || m_stipple.IsSameAs(data.m_stipple)) &&
               (m_style != wxUSER_DASH ||
                (m_nbDash == data.m_nbDash &&
                    memcmp(m_dash, data.m_dash, m_nbDash*sizeof(wxDash)) == 0));
    }

protected:
    int           m_width;
    wxPenStyle    m_style;
    int           m_join;
    int           m_cap;
    wxBitmap      m_stipple;
    int           m_nbDash;
    wxDash *      m_dash;
    wxColour      m_colour;
    WXHPEN        m_hPen;

private:
    friend class WXDLLIMPEXP_FWD_CORE wxPen;

    // Cannot use
    //  wxDECLARE_NO_COPY_CLASS(wxPenRefData);
    // because copy constructor is explicitly declared above;
    // but no copy assignment operator is defined, so declare
    // it private to prevent the compiler from defining it:
    wxPenRefData& operator=(const wxPenRefData&);
};

#define M_PENDATA ((wxPenRefData *)m_refData)
#define wxPENDATA(x) ((wxPenRefData *)(x).m_refData)

// ----------------------------------------------------------------------------
// Pen
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxPen : public wxPenBase
{
public:
    wxPen();
    wxPen(const wxColour& col, int width = 1, wxPenStyle style = wxPENSTYLE_SOLID);
#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxDEPRECATED_FUTURE( wxPen(const wxColour& col, int width, int style) );
#endif

    wxPen(const wxBitmap& stipple, int width);
    virtual ~wxPen();

    bool operator==(const wxPen& pen) const
    {
        const wxPenRefData *penData = (wxPenRefData *)pen.m_refData;

        // an invalid pen is only equal to another invalid pen
        return m_refData ? penData && *M_PENDATA == *penData : !penData;
    }

    bool operator!=(const wxPen& pen) const { return !(*this == pen); }

    // Override in order to recreate the pen
    void SetColour(const wxColour& col);
    void SetColour(unsigned char r, unsigned char g, unsigned char b);

    void SetWidth(int width);
    void SetStyle(wxPenStyle style);
    void SetStipple(const wxBitmap& stipple);
    void SetDashes(int nb_dashes, const wxDash *dash);
    void SetJoin(wxPenJoin join);
    void SetCap(wxPenCap cap);

    wxColour& GetColour() const { return (M_PENDATA ? M_PENDATA->m_colour : wxNullColour); };
    int GetWidth() const { return (M_PENDATA ? M_PENDATA->m_width : 0); };
    wxPenStyle GetStyle() const { return (M_PENDATA ? M_PENDATA->m_style : 0); };
    wxPenJoin GetJoin() const { return (M_PENDATA ? M_PENDATA->m_join : 0); };
    wxPenCap GetCap() const { return (M_PENDATA ? M_PENDATA->m_cap : 0); };
    int GetDashes(wxDash **ptr) const
    {
        *ptr = (M_PENDATA ? (wxDash*)M_PENDATA->m_dash : NULL);
        return (M_PENDATA ? M_PENDATA->m_nbDash : 0);
    }
    wxDash* GetDash() const { return (M_PENDATA ? (wxDash*)M_PENDATA->m_dash : NULL); };
    inline int GetDashCount() const { return (M_PENDATA ? M_PENDATA->m_nbDash : 0); };

    inline wxBitmap *GetStipple() const { return (M_PENDATA ? (& M_PENDATA->m_stipple) : NULL); };

    // Internal
    bool RealizeResource();
    bool FreeResource(bool force = false);
    WXHANDLE GetResourceHandle() const;
    bool IsFree() const;

#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxDEPRECATED_FUTURE( void SetStyle(int style) )
        { SetStyle((wxPenStyle)style); }
#endif

protected:
    virtual wxGDIRefData* CreateGDIRefData() const;
    virtual wxGDIRefData* CloneGDIRefData(const wxGDIRefData* data) const;
    // same as FreeResource() + RealizeResource()
    bool Recreate();

private:
    DECLARE_DYNAMIC_CLASS(wxPen)
};

#endif // _WX_PEN_H_
