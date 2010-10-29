///////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/glcanvas.cpp
// Purpose:     wxGLCanvas, for using OpenGL with wxWidgets
//              Uses the GLX extension.
// Author:      Julian Smart and Wolfram Gloger
// Modified by: Vadim Zeitlin to update to new API
// Created:     1995, 1999
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart, Wolfram Gloger
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// TODO: merge this with wxGTK version in some src/unix/glcanvasx11.cpp

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if defined(__BORLANDC__)
    #pragma hdrstop
#endif

#if wxUSE_GLCANVAS

#include "wx/glcanvas.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/utils.h"
#endif

// ============================================================================
// implementation
// ============================================================================

IMPLEMENT_CLASS(wxGLCanvas, wxWindow)

wxGLCanvas::wxGLCanvas(wxWindow *parent,
                       wxWindowID id,
                       const int *attribList,
                       const wxPoint& pos,
                       const wxSize& size,
                       long style,
                       const wxString& name,
                       const wxPalette& palette)
{
    Create(parent, id, pos, size, style, name, attribList, palette);
}

bool wxGLCanvas::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxPoint& pos,
                        const wxSize& size,
                        long style,
                        const wxString& name,
                        const int *attribList,
                        const wxPalette& WXUNUSED(palette))
{
    if ( !wxWindow::Create(parent, id, pos, size, style, name) )
        return false;

    if ( !InitVisual(attribList) )
        return false;

    return true;
}

Window wxGLCanvas::GetXWindow() const
{
    return (Window)
#ifdef __WXMOTIF__
        GetClientXWindow();
#else
        GetClientAreaWindow();
#endif
}

int wxGLCanvas::GetColourIndex(const wxColour& col_)
{
    wxColour& col = const_cast<wxColour&>(col_);

#ifdef __WXMOTIF__
    col.AllocColour(GetXDisplay());
#else
    col.CalcPixel(wxTheApp->GetMainColormap(wxGetDisplay()));
#endif

    return col.GetPixel();
}

#endif // wxUSE_GLCANVAS
