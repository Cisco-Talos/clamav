/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/statbmp.cpp
// Purpose:     wxStaticBitmap
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
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

#if wxUSE_STATBMP

#include "wx/statbmp.h"

#ifndef WX_PRECOMP
    #include "wx/icon.h"
    #include "wx/window.h"
#endif

#include "wx/palmos/private.h"

// ---------------------------------------------------------------------------
// macors
// ---------------------------------------------------------------------------

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxStaticBitmapStyle )

wxBEGIN_FLAGS( wxStaticBitmapStyle )
    // new style border flags, we put them first to
    // use them for streaming out
    wxFLAGS_MEMBER(wxBORDER_SIMPLE)
    wxFLAGS_MEMBER(wxBORDER_SUNKEN)
    wxFLAGS_MEMBER(wxBORDER_DOUBLE)
    wxFLAGS_MEMBER(wxBORDER_RAISED)
    wxFLAGS_MEMBER(wxBORDER_STATIC)
    wxFLAGS_MEMBER(wxBORDER_NONE)

    // old style border flags
    wxFLAGS_MEMBER(wxSIMPLE_BORDER)
    wxFLAGS_MEMBER(wxSUNKEN_BORDER)
    wxFLAGS_MEMBER(wxDOUBLE_BORDER)
    wxFLAGS_MEMBER(wxRAISED_BORDER)
    wxFLAGS_MEMBER(wxSTATIC_BORDER)
    wxFLAGS_MEMBER(wxBORDER)

    // standard window styles
    wxFLAGS_MEMBER(wxTAB_TRAVERSAL)
    wxFLAGS_MEMBER(wxCLIP_CHILDREN)
    wxFLAGS_MEMBER(wxTRANSPARENT_WINDOW)
    wxFLAGS_MEMBER(wxWANTS_CHARS)
    wxFLAGS_MEMBER(wxFULL_REPAINT_ON_RESIZE)
    wxFLAGS_MEMBER(wxALWAYS_SHOW_SB )
    wxFLAGS_MEMBER(wxVSCROLL)
    wxFLAGS_MEMBER(wxHSCROLL)

wxEND_FLAGS( wxStaticBitmapStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxStaticBitmap, wxControl,"wx/statbmp.h")

wxBEGIN_PROPERTIES_TABLE(wxStaticBitmap)
    wxPROPERTY_FLAGS( WindowStyle , wxStaticBitmapStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE, 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxStaticBitmap)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_5( wxStaticBitmap, wxWindow* , Parent , wxWindowID , Id , wxBitmap, Bitmap, wxPoint , Position , wxSize , Size )

#else
IMPLEMENT_DYNAMIC_CLASS(wxStaticBitmap, wxControl)
#endif

/*
    TODO PROPERTIES :
        bitmap
*/

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// wxStaticBitmap
// ---------------------------------------------------------------------------

static wxGDIImage* ConvertImage( const wxGDIImage& bitmap )
{
    return NULL;
}

bool wxStaticBitmap::Create(wxWindow *parent,
                            wxWindowID id,
                            const wxGDIImage& bitmap,
                            const wxPoint& pos,
                            const wxSize& size,
                            long style,
                            const wxString& name)
{
    return false;
}

wxBorder wxStaticBitmap::GetDefaultBorder() const
{
    return wxBORDER_NONE;
}

WXDWORD wxStaticBitmap::MSWGetStyle(long style, WXDWORD *exstyle) const
{
    return 0;
}

bool wxStaticBitmap::ImageIsOk() const
{
    return false;
}

void wxStaticBitmap::Free()
{
}

wxSize wxStaticBitmap::DoGetBestSize() const
{
    return wxSize(0,0);
}

void wxStaticBitmap::SetImage( const wxGDIImage* image )
{
}

void wxStaticBitmap::SetImageNoCopy( wxGDIImage* image)
{
}

// We need this or the control can never be moved e.g. in Dialog Editor.
WXLRESULT wxStaticBitmap::MSWWindowProc(WXUINT nMsg,
                                   WXWPARAM wParam,
                                   WXLPARAM lParam)
{
    return false;
}

#endif // wxUSE_STATBMP
