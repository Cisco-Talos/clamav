/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/overlay.cpp
// Purpose:     wxOverlay implementation for wxDFB
// Author:      Vaclav Slavik
// Created:     2006-10-20
// RCS-ID:      $Id$
// Copyright:   (c) wxWidgets team
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

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

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/dcclient.h"
#endif

#include "wx/private/overlay.h"
#include "wx/dfb/dcclient.h"
#include "wx/dfb/private.h"

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxOverlay
// ----------------------------------------------------------------------------

wxOverlayImpl::wxOverlayImpl()
{
    m_window = NULL;
    m_isEmpty = true;
}

wxOverlayImpl::~wxOverlayImpl()
{
    Reset();
}

bool wxOverlayImpl::IsOk()
{
    return m_window != NULL;
}

void wxOverlayImpl::Init(wxDC *dc, int x, int y, int width, int height)
{
    wxCHECK_RET( dc, "NULL dc pointer" );
    wxASSERT_MSG( !IsOk() , _("You cannot Init an overlay twice") );

    wxDFBDCImpl * const dcimpl = wxDynamicCast(dc->GetImpl(), wxDFBDCImpl);
    wxCHECK_RET( dcimpl, "must have a DFB wxDC" );

    m_window = dc->GetWindow();

    m_rect = wxRect(x, y, width, height);
    if ( wxDynamicCast(dc, wxClientDC) )
        m_rect.Offset(m_window->GetClientAreaOrigin());

    // FIXME: create surface with transparency or key color (?)
    m_surface = dcimpl->GetDirectFBSurface()->CreateCompatible
                (
                   m_rect.GetSize(),
                   wxIDirectFBSurface::CreateCompatible_NoBackBuffer
                );

    m_window->AddOverlay(this);
}

void wxOverlayImpl::BeginDrawing(wxDC *dc)
{
    wxCHECK_RET( dc, "NULL dc pointer" );

    wxWindowDCImpl * const
        dcimpl = static_cast<wxWindowDCImpl *>(dc->GetImpl());

    wxPoint origin(m_rect.GetPosition());
    if ( wxDynamicCast(dc, wxClientDC) )
        origin -= m_window->GetClientAreaOrigin();

    // drawing on overlay "hijacks" existing wxWindowDC rather then using
    // another DC, so we have to change the DC to draw on the overlay's surface.
    // Setting m_shouldFlip is done to avoid flipping and drawing of overlays
    // in ~wxWindowDC (we do it EndDrawing).
    dcimpl->DFBInit(m_surface);
    dcimpl->m_shouldFlip = false;
    dc->SetDeviceOrigin(-origin.x, -origin.y);

    m_isEmpty = false;
}

void wxOverlayImpl::EndDrawing(wxDC *WXUNUSED(dc))
{
    m_window->RefreshWindowRect(m_rect);
}

void wxOverlayImpl::Clear(wxDC *WXUNUSED(dc))
{
    wxASSERT_MSG( IsOk(),
                  "You cannot Clear an overlay that is not initialized" );

    m_isEmpty = true;
}

void wxOverlayImpl::Reset()
{
    if ( m_window )
    {
        m_window->RemoveOverlay(this);
        m_window = NULL;
        m_surface.Reset();
    }
}
