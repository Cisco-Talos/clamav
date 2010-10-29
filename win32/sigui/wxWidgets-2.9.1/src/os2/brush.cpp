/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/brush.cpp
// Purpose:     wxBrush
// Author:      David Webster
// Modified by:
// Created:     10/13/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/brush.h"
    #include "wx/log.h"
#endif

#include "wx/os2/private.h"

class WXDLLEXPORT wxBrushRefData: public wxGDIRefData
{
    friend class WXDLLIMPEXP_FWD_CORE wxBrush;
public:
    wxBrushRefData(const wxColour& colour = wxNullColour, wxBrushStyle style = wxBRUSHSTYLE_SOLID);
    wxBrushRefData(const wxBitmap& stipple);
    wxBrushRefData(const wxBrushRefData& rData);
    virtual ~wxBrushRefData();

    bool operator == (const wxBrushRefData& data) const
    {
        return (m_nStyle == data.m_nStyle &&
                m_vStipple.IsSameAs(data.m_vStipple) &&
                m_vColour == data.m_vColour);
    }

protected:
    wxBrushStyle m_nStyle;
    wxBitmap     m_vStipple;
    wxColour     m_vColour;
    WXHBRUSH     m_hBrush; // in OS/2 GPI this will be the PS the pen is associated with
    AREABUNDLE   m_vBundle;
};

#define M_BRUSHDATA ((wxBrushRefData *)m_refData)

// ============================================================================
// wxBrushRefData implementation
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxBrush, wxGDIObject)

// ----------------------------------------------------------------------------
// wxBrushRefData ctors/dtor
// ----------------------------------------------------------------------------

wxBrushRefData::wxBrushRefData(const wxColour& colour, wxBrushStyle style)
              : m_vColour(colour)
{
    m_nStyle = style;
    m_hBrush = 0;
    memset(&m_vBundle, '\0', sizeof(AREABUNDLE));
} // end of wxBrushRefData::wxBrushRefData

wxBrushRefData::wxBrushRefData(const wxBitmap& stipple)
{
    m_vStipple = stipple;
    m_nStyle = stipple.GetMask() ? wxBRUSHSTYLE_STIPPLE_MASK_OPAQUE
                                 : wxBRUSHSTYLE_STIPPLE;

    m_hBrush = NULL;
    memset(&m_vBundle, '\0', sizeof(AREABUNDLE));
}

wxBrushRefData::wxBrushRefData(const wxBrushRefData& rData)
              : wxGDIRefData(),
                m_vStipple(rData.m_vStipple),
                m_vColour(rData.m_vColour)
{
    m_nStyle   = rData.m_nStyle;
    m_hBrush   = 0;
    memcpy(&m_vBundle, &rData.m_vBundle, sizeof(AREABUNDLE));
} // end of wxBrushRefData::wxBrushRefData

wxBrushRefData::~wxBrushRefData()
{
} // end of wxBrushRefData::~wxBrushRefData

// ============================================================================
// wxBrush implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxBrush ctors/dtor
// ----------------------------------------------------------------------------

wxBrush::wxBrush()
{
} // end of wxBrush::wxBrush

wxBrush::~wxBrush()
{
} // end of wxBrush::~wxBrush

wxBrush::wxBrush(
  const wxColour&                   rColour
, wxBrushStyle                      nStyle
)
{
    m_refData = new wxBrushRefData(rColour, nStyle);

    RealizeResource();
} // end of wxBrush::wxBrush

#if FUTURE_WXWIN_COMPATIBILITY_3_0
wxBrush::wxBrush(const wxColour& col, int style)
{
    m_refData = new wxBrushRefData(col, (wxBrushStyle)style);

    RealizeResource();
}
#endif

wxBrush::wxBrush(const wxBitmap& rStipple)
{
    m_refData = new wxBrushRefData(rStipple);

    RealizeResource();
} // end of wxBrush::wxBrush

bool wxBrush::RealizeResource()
{
    bool     bOk;
    ERRORID  vError;
    wxString sError;

    if (M_BRUSHDATA && M_BRUSHDATA->m_hBrush == 0L)
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
        M_BRUSHDATA->m_hBrush = (WXHPEN)::GpiCreatePS( vHabmain
                                                      ,hDC
                                                      ,&vSize
                                                      ,PU_PELS | GPIT_MICRO | GPIA_ASSOC
                                                     );
    }
    if (M_BRUSHDATA)
    {
        //
        // Set the color table to RGB mode
        //
        if (!::GpiCreateLogColorTable( (HPS)M_BRUSHDATA->m_hBrush
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

        if (M_BRUSHDATA->m_nStyle==wxTRANSPARENT)
        {
            return true;
        }
        COLORREF                    vPmColour = 0L;

        vPmColour = M_BRUSHDATA->m_vColour.GetPixel() ;

        M_BRUSHDATA->m_vBundle.usSet = LCID_DEFAULT;
        switch (M_BRUSHDATA->m_nStyle)
        {
            case wxTRANSPARENT:
                M_BRUSHDATA->m_hBrush = NULL;  // Must always select a suitable background brush
                break;                         // - could choose white always for a quick solution

            case wxBDIAGONAL_HATCH:
                M_BRUSHDATA->m_vBundle.usSymbol = PATSYM_DIAG3;
                break;

            case wxCROSSDIAG_HATCH:
                M_BRUSHDATA->m_vBundle.usSymbol = PATSYM_DIAGHATCH;
                break;

            case wxFDIAGONAL_HATCH:
                M_BRUSHDATA->m_vBundle.usSymbol = PATSYM_DIAG1;
                break;

            case wxCROSS_HATCH:
                M_BRUSHDATA->m_vBundle.usSymbol = PATSYM_HATCH;
                break;

            case wxHORIZONTAL_HATCH:
                M_BRUSHDATA->m_vBundle.usSymbol = PATSYM_HORIZ;
                break;

            case wxVERTICAL_HATCH:
                M_BRUSHDATA->m_vBundle.usSymbol = PATSYM_VERT;
                break;

            case wxSTIPPLE:
                if (M_BRUSHDATA->m_vStipple.Ok())
                {
                    ::GpiSetBitmapId( M_BRUSHDATA->m_hBrush
                                     ,(USHORT)M_BRUSHDATA->m_vStipple.GetHBITMAP()
                                     ,(USHORT)M_BRUSHDATA->m_vStipple.GetId()
                                    );
                    ::GpiSetPatternSet( M_BRUSHDATA->m_hBrush
                                       ,(USHORT)M_BRUSHDATA->m_vStipple.GetId()
                                      );
                }
                else
                    M_BRUSHDATA->m_vBundle.usSymbol = PATSYM_SOLID;
                break ;

            case wxSOLID:
            default:
                M_BRUSHDATA->m_vBundle.usSymbol = PATSYM_SOLID;
                break;
        }
#ifdef WXDEBUG_CREATE
        if (M_BRUSHDATA->m_hBrush==NULL) wxError("Cannot create brush","Internal error") ;
#endif
        M_BRUSHDATA->m_vBundle.lColor        = vPmColour;
        M_BRUSHDATA->m_vBundle.lBackColor    = RGB_WHITE;
        M_BRUSHDATA->m_vBundle.usMixMode     = FM_OVERPAINT;
        M_BRUSHDATA->m_vBundle.usBackMixMode = BM_OVERPAINT;

        bOk = (bool)::GpiSetAttrs( M_BRUSHDATA->m_hBrush
                                  ,PRIM_AREA
                                  ,ABB_COLOR | ABB_BACK_COLOR | ABB_MIX_MODE | ABB_BACK_MIX_MODE |
                                   ABB_SET | ABB_SYMBOL | ABB_REF_POINT
                                  ,ABB_SET | ABB_SYMBOL | ABB_REF_POINT
                                  ,&M_BRUSHDATA->m_vBundle
                                 );
        if (!bOk)
        {
            vError = ::WinGetLastError(vHabmain);
            sError = wxPMErrorToStr(vError);
            wxLogError(wxT("Can't set Gpi attributes for an AREABUNDLE. Error: %s\n"), sError.c_str());
        }
        return bOk;
    }
    return false;
} // end of wxBrush::RealizeResource

// ----------------------------------------------------------------------------
// wxBrush accessors
// ----------------------------------------------------------------------------

wxColour wxBrush::GetColour() const
{
    wxCHECK_MSG( Ok(), wxNullColour, wxT("invalid brush") );

    return M_BRUSHDATA->m_vColour;
}

wxBrushStyle wxBrush::GetStyle() const
{
    wxCHECK_MSG( Ok(), wxBRUSHSTYLE_INVALID, wxT("invalid brush") );

    return M_BRUSHDATA->m_nStyle;
}

wxBitmap *wxBrush::GetStipple() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid brush") );

    return &(M_BRUSHDATA->m_vStipple);
}

int wxBrush::GetPS() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid brush") );

    return M_BRUSHDATA->m_hBrush;
}

WXHANDLE wxBrush::GetResourceHandle() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid brush") );

    return (WXHANDLE)M_BRUSHDATA->m_hBrush;
} // end of wxBrush::GetResourceHandle

bool wxBrush::FreeResource( bool WXUNUSED(bForce) )
{
    if (M_BRUSHDATA && (M_BRUSHDATA->m_hBrush != 0))
    {
        M_BRUSHDATA->m_hBrush = 0;
        return true;
    }
    else return false;
} // end of wxBrush::FreeResource

bool wxBrush::IsFree() const
{
  return (M_BRUSHDATA && (M_BRUSHDATA->m_hBrush == 0));
} // end of wxBrush::IsFree

// ----------------------------------------------------------------------------
// wxBrush setters
// ----------------------------------------------------------------------------

void wxBrush::SetColour( const wxColour& rColour )
{
    AllocExclusive();
    M_BRUSHDATA->m_vColour = rColour;
    RealizeResource();
}

void wxBrush::SetColour(unsigned char cRed, unsigned char cGreen, unsigned char cBlue)
{
    AllocExclusive();
    M_BRUSHDATA->m_vColour.Set( cRed, cGreen, cBlue );
    RealizeResource();
} // end of wxBrush::SetColour

void wxBrush::SetStyle(wxBrushStyle nStyle)
{
    AllocExclusive();
    M_BRUSHDATA->m_nStyle = nStyle;
    RealizeResource();
} // end of wxBrush::SetStyle

void wxBrush::SetStipple(
  const wxBitmap&                   rStipple
)
{
    AllocExclusive();
    M_BRUSHDATA->m_vStipple = rStipple;
    RealizeResource();
} // end of wxBrush::SetStipple

void wxBrush::SetPS(
  HPS                               hPS
)
{
    AllocExclusive();
    if (M_BRUSHDATA->m_hBrush)
        ::GpiDestroyPS(M_BRUSHDATA->m_hBrush);
    M_BRUSHDATA->m_hBrush = hPS;
    RealizeResource();
} // end of WxWinGdi_CPen::SetPS

// ----------------------------------------------------------------------------
// wxBrush house keeping stuff
// ----------------------------------------------------------------------------

bool wxBrush::operator == (
    const wxBrush& brush
) const
{
    if (m_refData == brush.m_refData) return true;

    if (!m_refData || !brush.m_refData) return false;

    return ( *(wxBrushRefData*)m_refData == *(wxBrushRefData*)brush.m_refData );
} // end of wxBrush::operator ==

wxGDIRefData *wxBrush::CreateGDIRefData() const
{
    return new wxBrushRefData;
}

wxGDIRefData *wxBrush::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxBrushRefData(*(const wxBrushRefData *)data);
}
