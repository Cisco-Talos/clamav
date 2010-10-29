/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/wrapdfb.cpp
// Purpose:     wx wrappers for DirectFB interfaces
// Author:      Vaclav Slavik
// Created:     2006-09-04
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#include "wx/dfb/wrapdfb.h"

//-----------------------------------------------------------------------------
// wxDfbCheckReturn
//-----------------------------------------------------------------------------

bool wxDfbCheckReturn(DFBResult code)
{
    switch ( code )
    {
        case DFB_OK:
            return true;

        // these are programming errors, assert:
        #define DFB_ASSERT(code)                                        \
            case code:                                                  \
                wxFAIL_MSG( "DirectFB error: " wxT(#code) );         \
                return false                                            \

        DFB_ASSERT(DFB_DEAD);
        DFB_ASSERT(DFB_UNSUPPORTED);
        DFB_ASSERT(DFB_UNIMPLEMENTED);
        DFB_ASSERT(DFB_INVARG);
        DFB_ASSERT(DFB_NOIMPL);
        DFB_ASSERT(DFB_MISSINGFONT);
        DFB_ASSERT(DFB_THIZNULL);
        DFB_ASSERT(DFB_INVAREA);
        DFB_ASSERT(DFB_DESTROYED);
        DFB_ASSERT(DFB_NOSUCHMETHOD);
        DFB_ASSERT(DFB_NOSUCHINSTANCE);
        DFB_ASSERT(DFB_VERSIONMISMATCH);

        #undef  DFB_ASSERT

        // these are not errors, but valid return codes:
        case DFB_INTERRUPTED:
        case DFB_BUFFEREMPTY:
            return true;

        default:
            // FIXME: should handle the errors individually
            wxLogError(_("DirectFB error %d occured."), (int)code);
            return false;
    }
}

//-----------------------------------------------------------------------------
// wxDfbPtrBase
//-----------------------------------------------------------------------------

/* static */
void wxDfbPtrBase::DoAddRef(wxDfbWrapperBase *ptr)
{
    ptr->AddRef();
}

void wxDfbPtrBase::DoRelease(wxDfbWrapperBase *ptr)
{
    ptr->Release();
}

//-----------------------------------------------------------------------------
// wxIDirectFB
//-----------------------------------------------------------------------------

wxIDirectFBPtr wxIDirectFB::ms_ptr;

/* static */
void wxIDirectFB::CreateDirectFB()
{
    IDirectFB *dfb;
    if ( wxDfbCheckReturn(DirectFBCreate(&dfb)) )
        ms_ptr = new wxIDirectFB(dfb);
}

/* static */
void wxIDirectFB::CleanUp()
{
    ms_ptr.Reset();
}

wxIDirectFBSurfacePtr wxIDirectFB::GetPrimarySurface()
{
    DFBSurfaceDescription desc;
    desc.flags = DSDESC_CAPS;
    // NB: see dcscreen.cpp for why we request double-buffered surface
    //
    //     This assumes the cooperative level is DFSCL_NORMAL (that's the
    //     default and wx doesn't modify it anywhere); if we ever support
    //     other cooperative levels, DSCAPS_DOUBLE should *not* be used with
    //     them.
    desc.caps = DFBSurfaceCapabilities(DSCAPS_PRIMARY | DSCAPS_DOUBLE);
    return CreateSurface(&desc);
}

//-----------------------------------------------------------------------------
// wxIDirectFBSurface
//-----------------------------------------------------------------------------

DFBSurfacePixelFormat wxIDirectFBSurface::GetPixelFormat()
{
    DFBSurfacePixelFormat format = DSPF_UNKNOWN;
    GetPixelFormat(&format);
    return format;
}

int wxIDirectFBSurface::GetDepth()
{
    DFBSurfacePixelFormat format = DSPF_UNKNOWN;

    if ( !GetPixelFormat(&format) )
        return -1;

    return DFB_BITS_PER_PIXEL(format);
}

wxIDirectFBSurfacePtr
wxIDirectFBSurface::CreateCompatible(const wxSize& sz, int flags)
{
    wxSize size(sz);
    if ( size == wxDefaultSize )
    {
        if ( !GetSize(&size.x, &size.y) )
            return NULL;
    }

    wxCHECK_MSG( size.x > 0 && size.y > 0, NULL, "invalid size" );

    DFBSurfaceDescription desc;
    desc.flags = (DFBSurfaceDescriptionFlags)(
            DSDESC_CAPS | DSDESC_WIDTH | DSDESC_HEIGHT | DSDESC_PIXELFORMAT);
    GetCapabilities(&desc.caps);
    GetPixelFormat(&desc.pixelformat);
    desc.width = size.x;
    desc.height = size.y;

    // filter out caps that don't make sense for a new compatible surface:
    int caps = desc.caps;
    caps &= ~DSCAPS_PRIMARY;
    caps &= ~DSCAPS_SUBSURFACE;
    if ( flags & CreateCompatible_NoBackBuffer )
    {
        caps &= ~DSCAPS_DOUBLE;
        caps &= ~DSCAPS_TRIPLE;
    }
    desc.caps = (DFBSurfaceCapabilities)caps;

    wxIDirectFBSurfacePtr snew(wxIDirectFB::Get()->CreateSurface(&desc));
    if ( !snew )
        return NULL;

    if ( desc.pixelformat == DSPF_LUT8 )
    {
        wxIDirectFBPalettePtr pal(GetPalette());
        if ( pal )
        {
            if ( !snew->SetPalette(pal) )
                return NULL;
        }
    }

    return snew;
}

wxIDirectFBSurfacePtr wxIDirectFBSurface::Clone()
{
    wxIDirectFBSurfacePtr snew(CreateCompatible());
    if ( !snew )
        return NULL;

    if ( !snew->SetBlittingFlags(DSBLIT_NOFX) )
        return NULL;

    if ( !snew->Blit(GetRaw(), NULL, 0, 0) )
        return NULL;

    return snew;
}

bool wxIDirectFBSurface::Flip(const DFBRegion *region, int flags)
{
    return Check(m_ptr->Flip(m_ptr, region, (DFBSurfaceFlipFlags)flags));
}

bool wxIDirectFBSurface::FlipToFront(const DFBRegion *region)
{
    // Blit to the front buffer instead of exchanging front and back ones.
    // Always doing this ensures that back and front buffer have same content
    // and so painting to the back buffer will never lose any previous
    // drawings:
    return Flip(region, DSFLIP_BLIT);
}

//-----------------------------------------------------------------------------
// wxIDirectFBDisplayLayer
//-----------------------------------------------------------------------------

wxVideoMode wxIDirectFBDisplayLayer::GetVideoMode()
{
    DFBDisplayLayerConfig cfg;
    if ( !GetConfiguration(&cfg) )
        return wxVideoMode(); // invalid

    if ( !((cfg.flags & DLCONF_WIDTH) &&
           (cfg.flags & DLCONF_HEIGHT) &&
           (cfg.flags & DLCONF_PIXELFORMAT)) )
        return wxVideoMode(); // invalid

    return wxVideoMode
           (
             cfg.width,
             cfg.height,
             DFB_BITS_PER_PIXEL(cfg.pixelformat)
           );
}
