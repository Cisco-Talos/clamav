/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/pen.cpp
// Purpose:     wxPen
// Author:      David Webster
// Modified by:
// Created:     10/10/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/pen.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/log.h"
#endif

#include "wx/os2/private.h"

class WXDLLIMPEXP_FWD_CORE wxPen;

// ----------------------------------------------------------------------------
// wxPenRefData: contains information about an HPEN and its handle
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxPenRefData: public wxGDIRefData
{
    friend class WXDLLIMPEXP_FWD_CORE wxPen;
public:
    wxPenRefData();
    wxPenRefData(const wxPenRefData& rData);
    wxPenRefData(const wxColour& col, int width, wxPenStyle style);
    wxPenRefData(const wxBitmap& stipple, int width);
    virtual ~wxPenRefData();

    bool operator==(const wxPenRefData& data) const
    {
        // we intentionally don't compare m_hPen fields here
        return m_nStyle == data.m_nStyle &&
               m_nWidth == data.m_nWidth &&
               m_nJoin == data.m_nJoin &&
               m_nCap == data.m_nCap &&
               m_vColour == data.m_vColour &&
               (m_nStyle != wxPENSTYLE_STIPPLE || m_vStipple.IsSameAs(data.m_vStipple)) &&
               (m_nStyle != wxPENSTYLE_USER_DASH ||
                (m_dash == data.m_dash &&
                    memcmp(m_dash, data.m_dash, m_nbDash*sizeof(wxDash)) == 0));
    }

private:
    // initialize the fields which have reasonable default values
    //
    // doesn't initialize m_width and m_style which must be initialize in ctor
    void Init()
    {
        m_nJoin = wxJOIN_ROUND;
        m_nCap = wxCAP_ROUND;
        m_nbDash = 0;
        m_dash = NULL;
        m_hPen = 0;
    }

    int                             m_nWidth;
    wxPenStyle                      m_nStyle;
    wxPenJoin                       m_nJoin;
    wxPenCap                        m_nCap;
    wxBitmap                        m_vStipple;
    int                             m_nbDash;
    wxDash *                        m_dash;
    wxColour                        m_vColour;
    WXHPEN                          m_hPen;// in OS/2 GPI this will be the PS the pen is associated with

    wxDECLARE_NO_ASSIGN_CLASS(wxPenRefData);
};

#define M_PENDATA ((wxPenRefData *)m_refData)

// ----------------------------------------------------------------------------
// wxPenRefData ctors/dtor
// ----------------------------------------------------------------------------

wxPenRefData::wxPenRefData()
{
    Init();

    m_nStyle  = wxPENSTYLE_SOLID;
    m_nWidth  = 1;
} // end of wxPenRefData::wxPenRefData

wxPenRefData::wxPenRefData(
  const wxPenRefData&               rData
)
{
    m_nStyle  = rData.m_nStyle;
    m_nWidth  = rData.m_nWidth;
    m_nJoin   = rData.m_nJoin;
    m_nCap    = rData.m_nCap;
    m_nbDash  = rData.m_nbDash;
    m_dash    = rData.m_dash;
    m_vColour = rData.m_vColour;
    m_hPen    = 0L;
} // end of wxPenRefData::wxPenRefData

wxPenRefData::wxPenRefData(const wxColour& col, int width, wxPenStyle style)
{
    Init();

    m_nStyle = style;
    m_nWidth = width;

    m_vColour = col;
}

wxPenRefData::wxPenRefData(const wxBitmap& stipple, int width)
{
    Init();

    m_nStyle = wxPENSTYLE_STIPPLE;
    m_nWidth = width;

    m_vStipple = stipple;
}

wxPenRefData::~wxPenRefData()
{
} // end of wxPenRefData::~wxPenRefData

// ----------------------------------------------------------------------------
// wxPen
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxPen, wxGDIObject)

wxPen::wxPen(
  const wxColour&                   rColour
, int                               nWidth
, wxPenStyle                        nStyle
)
{
    m_refData = new wxPenRefData(rColour, nWidth, nStyle);

    RealizeResource();
} // end of wxPen::wxPen

#if FUTURE_WXWIN_COMPATIBILITY_3_0
wxPen::wxPen(const wxColour& colour, int width, int style)
{
    m_refData = new wxPenRefData(colour, width, (wxPenStyle)style);

    RealizeResource();
}
#endif

wxPen::wxPen(
  const wxBitmap&                   rStipple
, int                               nWidth
)
{
    m_refData = new wxPenRefData (rStipple, nWidth);

    RealizeResource();
} // end of wxPen::wxPen

bool wxPen::operator==(const wxPen& pen) const
{
    const wxPenRefData *
        penData = static_cast<const wxPenRefData *>(pen.m_refData);

    // an invalid pen is only equal to another invalid pen
    return m_refData ? penData && *M_PENDATA == *penData : !penData;
}

int wx2os2PenStyle(
  wxPenStyle                               nWxStyle
);

bool wxPen::RealizeResource()
{
    BOOL                            bOk;
    ERRORID                         vError;
    wxString                        sError;

    if (M_PENDATA && M_PENDATA->m_hPen == 0L)
    {
        SIZEL                   vSize = {0, 0};
        DEVOPENSTRUC            vDop = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
        HDC                     hDC = ::DevOpenDC( vHabmain
                                                  ,OD_MEMORY
                                                  ,"*"
                                                  ,5L
                                                  ,(PDEVOPENDATA)&vDop
                                                  ,NULLHANDLE
                                                 );
        M_PENDATA->m_hPen = (WXHPEN)::GpiCreatePS( vHabmain
                                                  ,hDC
                                                  ,&vSize
                                                  ,PU_PELS | GPIT_MICRO | GPIA_ASSOC
                                                 );
    }
    if (M_PENDATA)
    {
        //
        // Set the color table to RGB mode
        //
        if (!::GpiCreateLogColorTable( (HPS)M_PENDATA->m_hPen
                                      ,0L
                                      ,LCOLF_RGB
                                      ,0L
                                      ,0L
                                      ,NULL
                                     ))
        {
            vError = ::WinGetLastError(vHabmain);
            sError = wxPMErrorToStr(vError);
            wxLogError(wxT("Unable to set current color table to RGB mode. Error: %s\n"), sError.c_str());
            return false;
        }
        if (M_PENDATA->m_nStyle == wxPENSTYLE_TRANSPARENT)
        {
            return true;
        }

        COLORREF vPmColour = 0L;
        USHORT   uLineType = (USHORT)wx2os2PenStyle(M_PENDATA->m_nStyle);

        vPmColour = M_PENDATA->m_vColour.GetPixel();

        USHORT                      uJoin = 0L;

        switch(M_PENDATA->m_nJoin)
        {
            case wxJOIN_BEVEL:
                uJoin = LINEJOIN_BEVEL;
                break;

            case wxJOIN_MITER:
                uJoin = LINEJOIN_MITRE;
                break;

            case wxJOIN_ROUND:
                uJoin = LINEJOIN_ROUND;
                break;
        }

        USHORT                      uCap = 0L;

        switch(M_PENDATA->m_nCap)
        {
            case wxCAP_PROJECTING:
                uCap = LINEEND_SQUARE;
                break;

            case wxCAP_BUTT:
                uCap = LINEEND_FLAT;
                break;

            case wxCAP_ROUND:
                uCap = LINEEND_ROUND;
                break;
        }
        m_vLineBundle.lColor     = (LONG)vPmColour;
        m_vLineBundle.usMixMode  = FM_OVERPAINT;
        if (M_PENDATA->m_nWidth < 1)
            M_PENDATA->m_nWidth = 1;
        m_vLineBundle.fxWidth    = M_PENDATA->m_nWidth;
        m_vLineBundle.lGeomWidth = M_PENDATA->m_nWidth;
        m_vLineBundle.usType     = uLineType;
        m_vLineBundle.usEnd      = uCap;
        m_vLineBundle.usJoin     = uJoin;

        bOk = ::GpiSetAttrs( M_PENDATA->m_hPen
                            ,PRIM_LINE
                            ,LBB_COLOR | LBB_MIX_MODE | LBB_WIDTH | LBB_GEOM_WIDTH | LBB_TYPE | LBB_END | LBB_JOIN
                            ,0L
                            ,&m_vLineBundle
                           );
        if (!bOk)
        {
            vError = ::WinGetLastError(vHabmain);
            sError = wxPMErrorToStr(vError);
            wxLogError(wxT("Can't set Gpi attributes for a LINEBUNDLE. Error: %s\n"), sError.c_str());
            return false;
        }

        ULONG                           flAttrMask = 0L;
        ULONG                           flDefMask = 0L;
        switch(M_PENDATA->m_nStyle)
        {
            case wxPENSTYLE_STIPPLE:
                ::GpiSetBitmapId( M_PENDATA->m_hPen
                                 ,(USHORT)M_PENDATA->m_vStipple.GetHBITMAP()
                                 ,(USHORT)M_PENDATA->m_vStipple.GetId()
                                );
                ::GpiSetPatternSet( M_PENDATA->m_hPen
                                   ,(USHORT)M_PENDATA->m_vStipple.GetId()
                                  );
                flAttrMask = ABB_COLOR | ABB_BACK_COLOR | ABB_MIX_MODE | ABB_BACK_MIX_MODE | ABB_SET | ABB_SYMBOL;
                flDefMask = ABB_REF_POINT;
                break;

            case wxPENSTYLE_BDIAGONAL_HATCH:
                m_vAreaBundle.usSymbol = PATSYM_DIAG3;
                m_vAreaBundle.usSet = LCID_DEFAULT;
                flAttrMask = ABB_COLOR | ABB_BACK_COLOR | ABB_MIX_MODE | ABB_BACK_MIX_MODE | ABB_SYMBOL;
                flDefMask = ABB_SET | ABB_REF_POINT;
                break;

            case wxPENSTYLE_CROSSDIAG_HATCH:
                m_vAreaBundle.usSymbol = PATSYM_DIAGHATCH;
                m_vAreaBundle.usSet = LCID_DEFAULT;
                flAttrMask = ABB_COLOR | ABB_BACK_COLOR | ABB_MIX_MODE | ABB_BACK_MIX_MODE | ABB_SYMBOL;
                flDefMask = ABB_SET | ABB_REF_POINT;
                break;

            case wxPENSTYLE_FDIAGONAL_HATCH:
                m_vAreaBundle.usSymbol = PATSYM_DIAG1;
                m_vAreaBundle.usSet = LCID_DEFAULT;
                flAttrMask = ABB_COLOR | ABB_BACK_COLOR | ABB_MIX_MODE | ABB_BACK_MIX_MODE | ABB_SYMBOL;
                flDefMask = ABB_SET | ABB_REF_POINT;
                break;

            case wxPENSTYLE_CROSS_HATCH:
                m_vAreaBundle.usSymbol = PATSYM_HATCH;
                m_vAreaBundle.usSet = LCID_DEFAULT;
                flAttrMask = ABB_COLOR | ABB_BACK_COLOR | ABB_MIX_MODE | ABB_BACK_MIX_MODE | ABB_SYMBOL;
                flDefMask = ABB_SET | ABB_REF_POINT;
                break;

            case wxPENSTYLE_HORIZONTAL_HATCH:
                m_vAreaBundle.usSymbol = PATSYM_HORIZ;
                m_vAreaBundle.usSet = LCID_DEFAULT;
                flAttrMask = ABB_COLOR | ABB_BACK_COLOR | ABB_MIX_MODE | ABB_BACK_MIX_MODE | ABB_SYMBOL;
                flDefMask = ABB_SET | ABB_REF_POINT;
                break;

            case wxPENSTYLE_VERTICAL_HATCH:
                m_vAreaBundle.usSymbol = PATSYM_VERT;
                m_vAreaBundle.usSet = LCID_DEFAULT;
                flAttrMask = ABB_COLOR | ABB_BACK_COLOR | ABB_MIX_MODE | ABB_BACK_MIX_MODE | ABB_SYMBOL;
                flDefMask = ABB_SET | ABB_REF_POINT;
                break;

            default:
                m_vAreaBundle.usSymbol = PATSYM_SOLID;
                m_vAreaBundle.usSet = LCID_DEFAULT;
                flAttrMask = ABB_COLOR | ABB_BACK_COLOR | ABB_MIX_MODE | ABB_BACK_MIX_MODE | ABB_SYMBOL;
                flDefMask = ABB_SET | ABB_REF_POINT;
                break;
        }

        m_vAreaBundle.lColor        = vPmColour;
        m_vAreaBundle.lBackColor    = RGB_WHITE;
        m_vAreaBundle.usMixMode     = FM_OVERPAINT;
        m_vAreaBundle.usBackMixMode = BM_OVERPAINT;

        bOk = ::GpiSetAttrs( M_PENDATA->m_hPen
                            ,PRIM_AREA
                            ,flAttrMask
                            ,flDefMask
                            ,&m_vAreaBundle
                           );
        if (!bOk)
        {
            vError = ::WinGetLastError(vHabmain);
            sError = wxPMErrorToStr(vError);
            wxLogError(wxT("Can't set Gpi attributes for an AREABUNDLE. Error: %s\n"), sError.c_str());
        }

        return (bool)bOk;
    }
    return false;
} // end of wxPen::RealizeResource

WXHANDLE wxPen::GetResourceHandle() const
{
    if (!M_PENDATA)
        return 0;
    else
        return (WXHANDLE)M_PENDATA->m_hPen;
} // end of wxPen::GetResourceHandle

bool wxPen::FreeResource( bool WXUNUSED(bForce) )
{
    if (M_PENDATA && (M_PENDATA->m_hPen != 0))
    {
        M_PENDATA->m_hPen = 0;
        return true;
    }
    else return false;
} // end of wxPen::FreeResource

bool wxPen::IsFree() const
{
    return (M_PENDATA && M_PENDATA->m_hPen == 0);
}

wxGDIRefData* wxPen::CreateGDIRefData() const
{
    return new wxPenRefData;
}

wxGDIRefData* wxPen::CloneGDIRefData(const wxGDIRefData* data) const
{
    return new wxPenRefData(*static_cast<const wxPenRefData*>(data));
}

void wxPen::SetColour( const wxColour& rColour )
{
    AllocExclusive();
    M_PENDATA->m_vColour = rColour;
    RealizeResource();
} // end of wxPen::SetColour

void wxPen::SetColour( unsigned char cRed, unsigned char cGreen, unsigned char cBlue)
{
    AllocExclusive();
    M_PENDATA->m_vColour.Set(cRed, cGreen, cBlue);
    RealizeResource();
} // end of wxPen::SetColour

void wxPen::SetPS( HPS hPS )
{
    AllocExclusive();
    if (M_PENDATA->m_hPen)
        ::GpiDestroyPS(M_PENDATA->m_hPen);
    M_PENDATA->m_hPen = hPS;
    RealizeResource();
} // end of WxWinGdi_CPen::SetPS

void wxPen::SetWidth(
  int                               nWidth
)
{
    AllocExclusive();
    M_PENDATA->m_nWidth = nWidth;
    RealizeResource();
} // end of wxPen::SetWidth

void wxPen::SetStyle(
  wxPenStyle                               nStyle
)
{
    AllocExclusive();
    M_PENDATA->m_nStyle = nStyle;
    RealizeResource();
} // end of wxPen::SetStyle

void wxPen::SetStipple(
  const wxBitmap&                   rStipple
)
{
    AllocExclusive();
    M_PENDATA->m_vStipple = rStipple;
    M_PENDATA->m_nStyle = wxPENSTYLE_STIPPLE;
    RealizeResource();
} // end of wxPen::SetStipple

void wxPen::SetDashes( int WXUNUSED(nNbDashes),
                       const wxDash* WXUNUSED(pDash) )
{
    //
    // Does nothing under OS/2
    //
} // end of wxPen::SetDashes

void wxPen::SetJoin(
  wxPenJoin                               nJoin
)
{
    AllocExclusive();
    M_PENDATA->m_nJoin = nJoin;
    RealizeResource();
} // end of wxPen::SetJoin

void wxPen::SetCap(
  wxPenCap                               nCap
)
{
    AllocExclusive();
    M_PENDATA->m_nCap = nCap;
    RealizeResource();
} // end of wxPen::SetCap

wxColour wxPen::GetColour() const
{
    wxCHECK_MSG( Ok(), wxNullColour, wxT("invalid pen") );

    return M_PENDATA->m_vColour;
}

int wxPen::GetWidth() const
{
    wxCHECK_MSG( Ok(), -1, wxT("invalid pen") );

    return M_PENDATA->m_nWidth;
}

wxPenStyle wxPen::GetStyle() const
{
    wxCHECK_MSG( Ok(), wxPENSTYLE_INVALID, wxT("invalid pen") );

    return M_PENDATA->m_nStyle;
}

wxPenJoin wxPen::GetJoin() const
{
    wxCHECK_MSG( Ok(), wxJOIN_INVALID, wxT("invalid pen") );

    return M_PENDATA->m_nJoin;
}

wxPenCap wxPen::GetCap() const
{
    wxCHECK_MSG( Ok(), wxCAP_INVALID, wxT("invalid pen") );

    return M_PENDATA->m_nCap;
}

int wxPen::GetPS() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid pen") );

    return M_PENDATA->m_hPen;
}

int wxPen::GetDashes(wxDash** ptr) const
{
    wxCHECK_MSG( Ok(), -1, wxT("invalid pen") );

    *ptr = M_PENDATA->m_dash;
    return M_PENDATA->m_nbDash;
}

wxDash* wxPen::GetDash() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid pen") );

    return M_PENDATA->m_dash;
}

int wxPen::GetDashCount() const
{
    wxCHECK_MSG( Ok(), -1, wxT("invalid pen") );

    return M_PENDATA->m_nbDash;
}

wxBitmap* wxPen::GetStipple() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid pen") );

    return &(M_PENDATA->m_vStipple);
}

int wx2os2PenStyle(
  wxPenStyle                               nWxStyle
)
{
    int                             nPMStyle = 0;

    switch (nWxStyle)
    {
        case wxPENSTYLE_DOT:
            nPMStyle = LINETYPE_DOT;
            break;

        case wxPENSTYLE_DOT_DASH:
            nPMStyle = LINETYPE_DASHDOT;
            break;

        case wxPENSTYLE_SHORT_DASH:
            nPMStyle = LINETYPE_SHORTDASH;
            break;

        case wxPENSTYLE_LONG_DASH:
            nPMStyle = LINETYPE_LONGDASH;
            break;

        case wxPENSTYLE_TRANSPARENT:
            nPMStyle = LINETYPE_INVISIBLE;
            break;

        case wxPENSTYLE_USER_DASH:
            nPMStyle = LINETYPE_DASHDOUBLEDOT; // We must make a choice... This is mine!
            break;

        case wxPENSTYLE_SOLID:
        default:
            nPMStyle = LINETYPE_SOLID;
            break;
    }
    return nPMStyle;
} // end of wx2os2PenStyle
