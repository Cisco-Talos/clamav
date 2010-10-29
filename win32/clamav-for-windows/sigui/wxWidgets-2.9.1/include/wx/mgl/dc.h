/////////////////////////////////////////////////////////////////////////////
// Name:        dc.h
// Purpose:     wxDC class
// Author:      Vaclav Slavik
// Created:     2001/03/09
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_DC_H_
#define _WX_DC_H_

#include "wx/defs.h"
#include "wx/region.h"

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxDC;

//-----------------------------------------------------------------------------
// constants
//-----------------------------------------------------------------------------

#ifndef MM_TEXT
#define MM_TEXT         0
#define MM_ISOTROPIC    1
#define MM_ANISOTROPIC  2
#define MM_LOMETRIC     3
#define MM_HIMETRIC     4
#define MM_TWIPS        5
#define MM_POINTS       6
#define MM_METRIC       7
#endif

//-----------------------------------------------------------------------------
// wxDC
//-----------------------------------------------------------------------------


// MGL fwd declarations:
class MGLDevCtx;
class MGLRegion;
struct font_t;

class WXDLLIMPEXP_CORE wxDC : public wxDCBase
{
    DECLARE_DYNAMIC_CLASS(wxDC)

public:
    wxDC();
    virtual ~wxDC();

    // implement base class pure virtuals
    // ----------------------------------

    virtual void Clear();

    virtual bool StartDoc(const wxString& message);
    virtual void EndDoc();

    virtual void StartPage();
    virtual void EndPage();

    virtual void SetFont(const wxFont& font);
    virtual void SetPen(const wxPen& pen);
    virtual void SetBrush(const wxBrush& brush);
    virtual void SetBackground(const wxBrush& brush);
    virtual void SetBackgroundMode(int mode);
    virtual void SetPalette(const wxPalette& palette);

    virtual void DestroyClippingRegion();

    virtual wxCoord GetCharHeight() const;
    virtual wxCoord GetCharWidth() const;
    virtual void DoGetTextExtent(const wxString& string,
                                 wxCoord *x, wxCoord *y,
                                 wxCoord *descent = NULL,
                                 wxCoord *externalLeading = NULL,
                                 const wxFont *theFont = NULL) const;

    virtual bool CanDrawBitmap() const;
    virtual bool CanGetTextExtent() const;
    virtual int GetDepth() const;
    virtual wxSize GetPPI() const;

    virtual void SetLogicalFunction(wxRasterOperationMode function);

    // implementation from now on
    // --------------------------

    virtual void ComputeScaleAndOrigin();

    wxCoord XDEV2LOG(wxCoord x) const       { return DeviceToLogicalX(x); }
    wxCoord XDEV2LOGREL(wxCoord x) const    { return DeviceToLogicalXRel(x); }
    wxCoord YDEV2LOG(wxCoord y) const       { return DeviceToLogicalY(y); }
    wxCoord YDEV2LOGREL(wxCoord y) const    { return DeviceToLogicalYRel(y); }
    wxCoord XLOG2DEV(wxCoord x) const       { return LogicalToDeviceX(x); }
    wxCoord XLOG2DEVREL(wxCoord x) const    { return LogicalToDeviceXRel(x); }
    wxCoord YLOG2DEV(wxCoord y) const       { return LogicalToDeviceY(y); }
    wxCoord YLOG2DEVREL(wxCoord y) const    { return LogicalToDeviceYRel(y); }

    MGLDevCtx *GetMGLDC() const { return m_MGLDC; }
    void SetMGLDC(MGLDevCtx *mgldc, bool OwnsMGLDC = false);

protected:
    virtual bool DoFloodFill(wxCoord x, wxCoord y, const wxColour& col,
                             wxFloodFillStyle style = wxFLOOD_SURFACE);

    virtual bool DoGetPixel(wxCoord x, wxCoord y, wxColour *col) const;

    virtual void DoDrawPoint(wxCoord x, wxCoord y);
    virtual void DoDrawLine(wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2);

    virtual void DoDrawArc(wxCoord x1, wxCoord y1,
                           wxCoord x2, wxCoord y2,
                           wxCoord xc, wxCoord yc);
    virtual void DoDrawEllipticArc(wxCoord x, wxCoord y, wxCoord w, wxCoord h,
                                   double sa, double ea);

    virtual void DoDrawRectangle(wxCoord x, wxCoord y, wxCoord width, wxCoord height);
    virtual void DoDrawRoundedRectangle(wxCoord x, wxCoord y,
                                        wxCoord width, wxCoord height,
                                        double radius);
    virtual void DoDrawEllipse(wxCoord x, wxCoord y, wxCoord width, wxCoord height);

    virtual void DoCrossHair(wxCoord x, wxCoord y);

    virtual void DoDrawIcon(const wxIcon& icon, wxCoord x, wxCoord y);
    virtual void DoDrawBitmap(const wxBitmap &bmp, wxCoord x, wxCoord y,
                              bool useMask = false);

    virtual void DoDrawText(const wxString& text, wxCoord x, wxCoord y);
    virtual void DoDrawRotatedText(const wxString& text, wxCoord x, wxCoord y,
                                   double angle);

    virtual bool DoBlit(wxCoord xdest, wxCoord ydest, wxCoord width, wxCoord height,
                        wxDC *source, wxCoord xsrc, wxCoord ysrc,
                        wxRasterOperationMode rop = wxCOPY, bool useMask = false,
                        wxCoord xsrcMask = -1, wxCoord ysrcMask = -1);

    virtual void DoSetClippingRegion(wxCoord x, wxCoord y,
                                     wxCoord width, wxCoord height);
    virtual void DoSetDeviceClippingRegion(const wxRegion& region);

    virtual void DoGetSize(int *width, int *height) const;
    virtual void DoGetSizeMM(int* width, int* height) const;

    virtual void DoDrawLines(int n, wxPoint points[],
                             wxCoord xoffset, wxCoord yoffset);
    virtual void DoDrawPolygon(int n, wxPoint points[],
                               wxCoord xoffset, wxCoord yoffset,
                               wxPolygonFillMode fillStyle = wxODDEVEN_RULE);

    // implementation from now on:

protected:
    // setup newly attached MGLDevCtx for wxDC's use
    // (does things like setting RGB blending mode for antialiased texts):
    void InitializeMGLDC();

    // common part of DoDrawText() and DoDrawRotatedText()
    void DrawAnyText(const wxString& text, wxCoord x, wxCoord y);

    // MGL uses pens as both wxPens and wxBrushes, so we have to
    // switch them as needed:
    void SelectPen();
    void SelectBrush();
    void SelectMGLStipplePen(int style);
    void SelectMGLFatPen(int style, int flag);

    // Select m_font into m_MGLDC:
    bool SelectMGLFont();

    // Convert wxWin logical function to MGL rop:
    int LogicalFunctionToMGLRop(int logFunc) const;

    // Unified implementation of DrawIcon, DrawBitmap and Blit:
    void DoDrawSubBitmap(const wxBitmap &bmp,
                         wxCoord x, wxCoord y, wxCoord w, wxCoord h,
                         wxCoord destx, wxCoord desty, int rop, bool useMask);

    // MGL DC class we use:
    MGLDevCtx        *m_MGLDC;
    bool              m_OwnsMGLDC:1;

    // helper variables for SelectXXXX():
    bool              m_penSelected;
    bool              m_brushSelected;
    bool              m_downloadedPatterns[2];

    // MGL does not render lines with width>1 with endings centered
    // at given coords but with top left corner of the pen at them,
    // these offsets are used to correct it. They are computed by
    // SelectPen.
    int               m_penOfsX, m_penOfsY;

    double            m_mm_to_pix_x, m_mm_to_pix_y;

    wxPalette         m_oldPalette;

    wxRegion          m_currentClippingRegion;
    wxRegion          m_globalClippingRegion;

    // wxDC::Blit handles memoryDCs as special cases :(
    bool              m_isMemDC;

    font_t            *m_mglFont;
};

#endif
    // _WX_DC_H_
