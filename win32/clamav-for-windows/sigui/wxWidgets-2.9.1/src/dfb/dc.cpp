/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/dc.cpp
// Purpose:     wxDFBDCImpl class
// Author:      Vaclav Slavik
// Created:     2006-08-07
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/dcmemory.h"
    #include "wx/log.h"
#endif

#include "wx/dfb/dc.h"
#include "wx/dfb/private.h"

// these values are used to initialize newly created DC
#define DEFAULT_FONT      (*wxNORMAL_FONT)
#define DEFAULT_PEN       (*wxBLACK_PEN)
#define DEFAULT_BRUSH     (*wxWHITE_BRUSH)

// ===========================================================================
// implementation
// ===========================================================================

//-----------------------------------------------------------------------------
// wxDFBDCImpl
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxDFBDCImpl, wxDCImpl)

void wxDFBDCImpl::DFBInit(const wxIDirectFBSurfacePtr& surface)
{
    m_surface = surface;

    wxCHECK_RET( surface != NULL, "invalid surface" );

    m_mm_to_pix_x = (double)wxGetDisplaySize().GetWidth() /
                    (double)wxGetDisplaySizeMM().GetWidth();
    m_mm_to_pix_y = (double)wxGetDisplaySize().GetHeight() /
                    (double)wxGetDisplaySizeMM().GetHeight();

    SetFont(DEFAULT_FONT);
    SetPen(DEFAULT_PEN);
    SetBrush(DEFAULT_BRUSH);
}


// ---------------------------------------------------------------------------
// clipping
// ---------------------------------------------------------------------------

void wxDFBDCImpl::DoSetClippingRegion(wxCoord cx, wxCoord cy, wxCoord cw, wxCoord ch)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxSize size(GetSize());

    wxASSERT_MSG( !m_clipping,
                  "narrowing clipping region not implemented yet" );

    // NB: We intersect the clipping rectangle with surface's area here because
    //     DirectFB will return an error if you try to set clipping rectangle
    //     that is partially outside of the surface.
    DFBRegion r;
    r.x1 = wxMax(0, XLOG2DEV(cx));
    r.y1 = wxMax(0, YLOG2DEV(cy));
    r.x2 = wxMin(r.x1 + XLOG2DEVREL(cw), size.x) - 1;
    r.y2 = wxMin(r.y1 + YLOG2DEVREL(ch), size.y) - 1;

    if ( !m_surface->SetClip(&r) )
        return;

    m_clipX1 = cx;
    m_clipY1 = cy;
    m_clipX2 = cx + cw - 1;
    m_clipY2 = cy + ch -1;
    m_clipping = true;
}

void wxDFBDCImpl::DoSetDeviceClippingRegion(const wxRegion& region)
{
    // NB: this can be done because wxDFB only supports rectangular regions
    wxRect rect = region.AsRect();

    // our parameter is in physical coordinates while DoSetClippingRegion()
    // takes logical ones
    rect.x = XDEV2LOG(rect.x);
    rect.y = YDEV2LOG(rect.y);
    rect.width = XDEV2LOG(rect.width);
    rect.height = YDEV2LOG(rect.height);

    DoSetClippingRegion(rect.x, rect.y, rect.width, rect.height);
}

void wxDFBDCImpl::DestroyClippingRegion()
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    m_surface->SetClip(NULL);

    ResetClipping();
}

// ---------------------------------------------------------------------------
// query capabilities
// ---------------------------------------------------------------------------

int wxDFBDCImpl::GetDepth() const
{
    return m_surface->GetDepth();
}

// ---------------------------------------------------------------------------
// drawing
// ---------------------------------------------------------------------------

void wxDFBDCImpl::Clear()
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    if ( m_backgroundBrush.GetStyle() == wxTRANSPARENT )
        return;

    wxColour clr = m_backgroundBrush.GetColour();
    m_surface->Clear(clr.Red(), clr.Green(), clr.Blue(), clr.Alpha());

    wxSize size(GetSize());
    CalcBoundingBox(XDEV2LOG(0), YDEV2LOG(0));
    CalcBoundingBox(XDEV2LOG(size.x), YDEV2LOG(size.y));
}

extern bool wxDoFloodFill(wxDC *dc, wxCoord x, wxCoord y,
                          const wxColour & col, wxFloodFillStyle style);

bool wxDFBDCImpl::DoFloodFill(wxCoord x, wxCoord y,
                       const wxColour& col, wxFloodFillStyle style)
{
    return wxDoFloodFill(GetOwner(), x, y, col, style);
}

bool wxDFBDCImpl::DoGetPixel(wxCoord x, wxCoord y, wxColour *col) const
{
    wxCHECK_MSG( col, false, "NULL colour parameter in wxDFBDCImpl::GetPixel");

    wxFAIL_MSG( "GetPixel not implemented" );

    wxUnusedVar(x);
    wxUnusedVar(y);

    return false;
}

void wxDFBDCImpl::DoCrossHair(wxCoord x, wxCoord y)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxFAIL_MSG( "CrossHair not implemented" );

    wxUnusedVar(x);
    wxUnusedVar(y);
}

void wxDFBDCImpl::DoDrawLine(wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    if ( m_pen.GetStyle() == wxTRANSPARENT )
        return;

    wxCoord xx1 = XLOG2DEV(x1);
    wxCoord yy1 = YLOG2DEV(y1);
    wxCoord xx2 = XLOG2DEV(x2);
    wxCoord yy2 = YLOG2DEV(y2);

    // FIXME: DrawLine() shouldn't draw the last pixel, but DFB's DrawLine()
    //        does draw it. We should undo any change to the last pixel by
    //        using GetPixel() and PutPixel(), but until they are implemented,
    //        handle at least the special case of vertical and horizontal
    //        lines correctly:
    if ( xx1 == xx2 )
    {
        if ( yy1 < yy2 )
            yy2--;
        else if ( yy1 > yy2 )
            yy2++;
    }
    if ( yy1 == yy2 )
    {
        if ( xx1 < xx2 )
            xx2--;
        else if ( xx1 > xx2 )
            xx2++;
    }

    m_surface->DrawLine(xx1, yy1, xx2, yy2);

    CalcBoundingBox(x1, y1);
    CalcBoundingBox(x2, y2);
}

// Draws an arc of a circle, centred on (xc, yc), with starting point (x1, y1)
// and ending at (x2, y2)
void wxDFBDCImpl::DoDrawArc(wxCoord WXUNUSED(x1), wxCoord WXUNUSED(y1),
                            wxCoord WXUNUSED(x2), wxCoord WXUNUSED(y2),
                            wxCoord WXUNUSED(xc), wxCoord WXUNUSED(yc))
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxFAIL_MSG( "DrawArc not implemented" );
}

void wxDFBDCImpl::DoDrawPoint(wxCoord x, wxCoord y)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    // NB: DirectFB API doesn't provide a function for drawing points, so
    //     implement it as 1px long line. This is inefficient, but then, so is
    //     using DrawPoint() for drawing more than a few points.
    DoDrawLine(x, y, x, y);

    // FIXME_DFB: implement special cases for common formats (RGB24,RGBA/RGB32)
}

void wxDFBDCImpl::DoDrawPolygon(int WXUNUSED(n), wxPoint WXUNUSED(points)[],
                                wxCoord WXUNUSED(xoffset), wxCoord WXUNUSED(yoffset),
                                wxPolygonFillMode WXUNUSED(fillStyle))
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxFAIL_MSG( "DrawPolygon not implemented" );
}

void wxDFBDCImpl::DoDrawLines(int WXUNUSED(n), wxPoint WXUNUSED(points)[],
                              wxCoord WXUNUSED(xoffset), wxCoord WXUNUSED(yoffset))
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    // TODO: impl. using DirectDB's DrawLines
    wxFAIL_MSG( "DrawLines not implemented" );
}

void wxDFBDCImpl::DoDrawRectangle(wxCoord x, wxCoord y, wxCoord width, wxCoord height)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxCoord xx = XLOG2DEV(x);
    wxCoord yy = YLOG2DEV(y);
    wxCoord ww = m_signX * XLOG2DEVREL(width);
    wxCoord hh = m_signY * YLOG2DEVREL(height);

    if ( ww == 0 || hh == 0 ) return;

    if ( ww < 0 )
    {
        ww = -ww;
        xx = xx - ww;
    }
    if ( hh < 0 )
    {
        hh = -hh;
        yy = yy - hh;
    }

    if ( m_brush.GetStyle() != wxTRANSPARENT )
    {
        SelectColour(m_brush.GetColour());
        m_surface->FillRectangle(xx, yy, ww, hh);
        // restore pen's colour, because other drawing functions expect the
        // colour to be set to the pen:
        SelectColour(m_pen.GetColour());
    }

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        m_surface->DrawRectangle(xx, yy, ww, hh);
    }

    CalcBoundingBox(x, y);
    CalcBoundingBox(x + width, y + height);
}

void wxDFBDCImpl::DoDrawRoundedRectangle(wxCoord WXUNUSED(x),
                                         wxCoord WXUNUSED(y),
                                         wxCoord WXUNUSED(width),
                                         wxCoord WXUNUSED(height),
                                         double WXUNUSED(radius))
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxFAIL_MSG( "DrawRoundedRectangle not implemented" );
}

void wxDFBDCImpl::DoDrawEllipse(wxCoord WXUNUSED(x),
                                wxCoord WXUNUSED(y),
                                wxCoord WXUNUSED(width),
                                wxCoord WXUNUSED(height))
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxFAIL_MSG( "DrawElipse not implemented" );
}

void wxDFBDCImpl::DoDrawEllipticArc(wxCoord WXUNUSED(x),
                                    wxCoord WXUNUSED(y),
                                    wxCoord WXUNUSED(w),
                                    wxCoord WXUNUSED(h),
                                    double WXUNUSED(sa),
                                    double WXUNUSED(ea))
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxFAIL_MSG( "DrawElipticArc not implemented" );
}

void wxDFBDCImpl::DoDrawText(const wxString& text, wxCoord x, wxCoord y)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxCoord xx = XLOG2DEV(x);
    wxCoord yy = YLOG2DEV(y);

    // update the bounding box
    wxCoord w, h;
    CalcBoundingBox(x, y);
    DoGetTextExtent(text, &w, &h);
    CalcBoundingBox(x + w, y + h);

    // if background mode is solid, DrawText must paint text's background:
    if ( m_backgroundMode == wxSOLID )
    {
        wxCHECK_RET( m_textBackgroundColour.Ok(),
                     wxT("invalid background color") );

        SelectColour(m_textBackgroundColour);
        m_surface->FillRectangle(xx, yy, XLOG2DEVREL(w), YLOG2DEVREL(h));
    }

    // finally draw the text itself:
    wxCHECK_RET( m_textForegroundColour.Ok(),
                 wxT("invalid foreground color") );
    SelectColour(m_textForegroundColour);
    m_surface->DrawString(text.utf8_str(), -1, xx, yy, DSTF_LEFT | DSTF_TOP);

    // restore pen's colour, because other drawing functions expect the colour
    // to be set to the pen:
    SelectColour(m_pen.GetColour());
}

void wxDFBDCImpl::DoDrawRotatedText(const wxString& WXUNUSED(text),
                                    wxCoord WXUNUSED(x), wxCoord WXUNUSED(y),
                                    double WXUNUSED(angle))
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxFAIL_MSG( "DrawRotatedText not implemented" );
}

// ---------------------------------------------------------------------------
// set GDI objects
// ---------------------------------------------------------------------------

void wxDFBDCImpl::SetPen(const wxPen& pen)
{
    m_pen = pen.Ok() ? pen : DEFAULT_PEN;

    SelectColour(m_pen.GetColour());
}

void wxDFBDCImpl::SetBrush(const wxBrush& brush)
{
    m_brush = brush.Ok() ? brush : DEFAULT_BRUSH;
}

void wxDFBDCImpl::SelectColour(const wxColour& clr)
{
    m_surface->SetColor(clr.Red(), clr.Green(), clr.Blue(), clr.Alpha());
    #warning "use SetColorIndex?"
}

#if wxUSE_PALETTE
void wxDFBDCImpl::SetPalette(const wxPalette& WXUNUSED(palette))
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxFAIL_MSG( "SetPalette not implemented" );
}
#endif // wxUSE_PALETTE

void wxDFBDCImpl::SetFont(const wxFont& font)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    wxFont f(font.Ok() ? font : DEFAULT_FONT);

    wxFont oldfont(m_font);

    m_font = f;

    if ( !m_surface->SetFont(GetCurrentFont()) )
    {
        m_font = oldfont;
        return;
    }
}

wxIDirectFBFontPtr wxDFBDCImpl::GetCurrentFont() const
{
    bool aa = (GetDepth() > 8);
    return m_font.GetDirectFBFont(aa);
}

void wxDFBDCImpl::SetBackground(const wxBrush& brush)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    if (!brush.Ok()) return;

    m_backgroundBrush = brush;
}

void wxDFBDCImpl::SetBackgroundMode(int mode)
{
    m_backgroundMode = mode;
}

void wxDFBDCImpl::SetLogicalFunction(wxRasterOperationMode function)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    // NB: we could also support XOR, but for blitting only (via DSBLIT_XOR);
    //     and possibly others via SetSrc/DstBlendFunction()
    wxASSERT_MSG( function == wxCOPY,
                  "only wxCOPY logical function supported" );

    m_logicalFunction = function;
}

bool wxDFBDCImpl::StartDoc(const wxString& WXUNUSED(message))
{
    // We might be previewing, so return true to let it continue.
    return true;
}

void wxDFBDCImpl::EndDoc()
{
}

void wxDFBDCImpl::StartPage()
{
}

void wxDFBDCImpl::EndPage()
{
}

// ---------------------------------------------------------------------------
// text metrics
// ---------------------------------------------------------------------------

wxCoord wxDFBDCImpl::GetCharHeight() const
{
    wxCHECK_MSG( IsOk(), -1, wxT("invalid dc") );
    wxCHECK_MSG( m_font.Ok(), -1, wxT("no font selected") );

    int h = -1;
    GetCurrentFont()->GetHeight(&h);
    return YDEV2LOGREL(h);
}

wxCoord wxDFBDCImpl::GetCharWidth() const
{
    wxCHECK_MSG( IsOk(), -1, wxT("invalid dc") );
    wxCHECK_MSG( m_font.Ok(), -1, wxT("no font selected") );

    int w = -1;
    GetCurrentFont()->GetStringWidth("H", 1, &w);
    // VS: YDEV is corrent, it should *not* be XDEV, because font's are only
    //     scaled according to m_scaleY
    return YDEV2LOGREL(w);
}

void wxDFBDCImpl::DoGetTextExtent(const wxString& string, wxCoord *x, wxCoord *y,
                           wxCoord *descent, wxCoord *externalLeading,
                           const wxFont *theFont) const
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );
    wxCHECK_RET( m_font.Ok(), wxT("no font selected") );
    wxCHECK_RET( !theFont || theFont->Ok(), wxT("invalid font") );

    wxFont oldFont;
    if ( theFont != NULL )
    {
        oldFont = m_font;
        wxConstCast(this, wxDFBDCImpl)->SetFont(*theFont);
    }

    wxCoord xx = 0, yy = 0;
    DFBRectangle rect;
    wxIDirectFBFontPtr f = GetCurrentFont();

    if ( f->GetStringExtents(string.utf8_str(), -1, &rect, NULL) )
    {
        // VS: YDEV is corrent, it should *not* be XDEV, because font's are
        //     only scaled according to m_scaleY
        xx = YDEV2LOGREL(rect.w);
        yy = YDEV2LOGREL(rect.h);

        if ( descent )
        {
            int d;
            if ( f->GetDescender(&d) )
                *descent = YDEV2LOGREL(-d);
            else
                *descent = 0;
        }
    }

    if ( x ) *x = xx;
    if ( y ) *y = yy;
    if ( externalLeading ) *externalLeading = 0;

    if ( theFont != NULL )
        wxConstCast(this, wxDFBDCImpl)->SetFont(oldFont);
}



// ---------------------------------------------------------------------------
// mapping modes
// ---------------------------------------------------------------------------

// FIXME_DFB: scaling affects pixel size of font, pens, brushes, which
//            is not currently implemented here; probably makes sense to
//            switch to Cairo instead of implementing everything for DFB

void wxDFBDCImpl::DoGetSize(int *w, int *h) const
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );

    m_surface->GetSize(w, h);
}

void wxDFBDCImpl::DoGetSizeMM(int *width, int *height) const
{
    #warning "move this to common code?"
    int w = 0;
    int h = 0;
    GetSize(&w, &h);
    if ( width ) *width = int(double(w) / (m_userScaleX*m_mm_to_pix_x));
    if ( height ) *height = int(double(h) / (m_userScaleY*m_mm_to_pix_y));
}

wxSize wxDFBDCImpl::GetPPI() const
{
    #warning "move this to common code?"
    return wxSize(int(double(m_mm_to_pix_x) * inches2mm),
                  int(double(m_mm_to_pix_y) * inches2mm));
}


// ---------------------------------------------------------------------------
// Blitting
// ---------------------------------------------------------------------------

bool wxDFBDCImpl::DoBlit(wxCoord xdest, wxCoord ydest,
                         wxCoord width, wxCoord height,
                         wxDC *source, wxCoord xsrc, wxCoord ysrc,
                         wxRasterOperationMode rop, bool useMask,
                         wxCoord xsrcMask, wxCoord ysrcMask)
{
    wxCHECK_MSG( IsOk(), false, "invalid dc" );
    wxCHECK_MSG( source, false, "invalid source dc" );

    // NB: we could also support XOR here (via DSBLIT_XOR)
    //     and possibly others via SetSrc/DstBlendFunction()
    wxCHECK_MSG( rop == wxCOPY, false, "only wxCOPY function supported" );

    // transform the source DC coords to the device ones
    xsrc = source->LogicalToDeviceX(xsrc);
    ysrc = source->LogicalToDeviceY(ysrc);

    // FIXME_DFB: use the mask origin when drawing transparently
    wxASSERT_MSG( xsrcMask == -1 && ysrcMask == -1,
                  "non-default source mask offset not implemented" );
#if 0
    if (xsrcMask == -1 && ysrcMask == -1)
    {
        xsrcMask = xsrc; ysrcMask = ysrc;
    }
    else
    {
        xsrcMask = source->LogicalToDeviceX(xsrcMask);
        ysrcMask = source->LogicalToDeviceY(ysrcMask);
    }
#endif

    wxMemoryDC *sourceAsMemDC = wxDynamicCast(source, wxMemoryDC);
    if ( sourceAsMemDC )
    {
        DoDrawSubBitmap(sourceAsMemDC->GetSelectedBitmap(),
                        xsrc, ysrc,
                        width, height,
                        xdest, ydest,
                        rop,
                        useMask);
    }
    else
    {
        return DoBlitFromSurface
               (
                 static_cast<wxDFBDCImpl *>(source->GetImpl())
                    ->GetDirectFBSurface(),
                 xsrc, ysrc,
                 width, height,
                 xdest, ydest
               );
    }

    return true;
}

void wxDFBDCImpl::DoDrawBitmap(const wxBitmap &bmp, wxCoord x, wxCoord y, bool useMask)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );
    wxCHECK_RET( bmp.Ok(), wxT("invalid bitmap") );

    DoDrawSubBitmap(bmp,
                    0, 0, bmp.GetWidth(), bmp.GetHeight(),
                    x, y,
                    m_logicalFunction, useMask);
}

void wxDFBDCImpl::DoDrawIcon(const wxIcon& icon, wxCoord x, wxCoord y)
{
    // VZ: egcs 1.0.3 refuses to compile this without cast, no idea why
    DoDrawBitmap((const wxBitmap&)icon, x, y, true);
}

void wxDFBDCImpl::DoDrawSubBitmap(const wxBitmap &bmp,
                           wxCoord x, wxCoord y, wxCoord w, wxCoord h,
                           wxCoord destx, wxCoord desty, int rop, bool useMask)
{
    wxCHECK_RET( IsOk(), wxT("invalid dc") );
    wxCHECK_RET( bmp.Ok(), wxT("invalid bitmap") );

    // NB: we could also support XOR here (via DSBLIT_XOR)
    //     and possibly others via SetSrc/DstBlendFunction()
    wxCHECK_RET( rop == wxCOPY, "only wxCOPY function supported" );

    if ( bmp.GetDepth() == 1 )
    {
        // Mono bitmaps are handled in special way -- all 1s are drawn in
        // foreground colours, all 0s in background colour.
        wxFAIL_MSG( "drawing mono bitmaps not implemented" );
        return;
    }

    if ( useMask && bmp.GetMask() )
    {
        // FIXME_DFB: see MGL sources for a way to do it, but it's not directly
        //            applicable because DirectFB doesn't implement ROPs; OTOH,
        //            it has blitting modes that can be useful; finally, see
        //            DFB's SetSrcBlendFunction() and SetSrcColorKey()
        wxFAIL_MSG( "drawing bitmaps with masks not implemented" );
        return;
    }

    DoBlitFromSurface(bmp.GetDirectFBSurface(),
                      x, y,
                      w, h,
                      destx, desty);
}

bool wxDFBDCImpl::DoBlitFromSurface(const wxIDirectFBSurfacePtr& src,
                                    wxCoord srcx, wxCoord srcy,
                                    wxCoord w, wxCoord h,
                                    wxCoord dstx, wxCoord dsty)
{
    // don't do anything if the source rectangle is outside of source surface,
    // DirectFB would assert in that case:
    wxSize srcsize;
    src->GetSize(&srcsize.x, &srcsize.y);
    if ( !wxRect(srcx, srcy, w, h).Intersects(wxRect(srcsize)) )
    {
        wxLogDebug("Blitting from area outside of the source surface, caller code needs fixing.");
        return false;
    }

    CalcBoundingBox(dstx, dsty);
    CalcBoundingBox(dstx + w, dsty + h);

    DFBRectangle srcRect = { srcx, srcy, w, h };
    DFBRectangle dstRect = { XLOG2DEV(dstx), YLOG2DEV(dsty),
                             XLOG2DEVREL(w), YLOG2DEVREL(h) };

    wxIDirectFBSurfacePtr dst(m_surface);

    // FIXME: this will have to be different in useMask case, see above
    DFBSurfaceBlittingFlags blitFlag = (src->GetPixelFormat() == DSPF_ARGB)
                                       ? DSBLIT_BLEND_ALPHACHANNEL
                                       : DSBLIT_NOFX;
    if ( !dst->SetBlittingFlags(blitFlag) )
        return false;

    if ( srcRect.w != dstRect.w || srcRect.h != dstRect.h )
    {
        // the bitmap is drawn stretched:
        dst->StretchBlit(src, &srcRect, &dstRect);
    }
    else
    {
        // no stretching, size is preserved:
        dst->Blit(src, &srcRect, dstRect.x, dstRect.y);
    }

    return true;
}
