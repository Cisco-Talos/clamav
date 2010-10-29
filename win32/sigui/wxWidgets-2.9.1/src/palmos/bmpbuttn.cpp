/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/bmpbuttn.cpp
// Purpose:     wxBitmapButton
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_BMPBUTTON

#include "wx/bmpbuttn.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/dcmemory.h"
#endif

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

#if wxUSE_EXTENDED_RTTI

WX_DEFINE_FLAGS( wxBitmapButtonStyle )

wxBEGIN_FLAGS( wxBitmapButtonStyle )
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

    wxFLAGS_MEMBER(wxBU_AUTODRAW)
    wxFLAGS_MEMBER(wxBU_LEFT)
    wxFLAGS_MEMBER(wxBU_RIGHT)
    wxFLAGS_MEMBER(wxBU_TOP)
    wxFLAGS_MEMBER(wxBU_BOTTOM)
wxEND_FLAGS( wxBitmapButtonStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxBitmapButton, wxButton,"wx/bmpbuttn.h")

wxBEGIN_PROPERTIES_TABLE(wxBitmapButton)
    wxPROPERTY_FLAGS( WindowStyle , wxBitmapButtonStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE, 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxBitmapButton)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_5( wxBitmapButton , wxWindow* , Parent , wxWindowID , Id , wxBitmap , Bitmap , wxPoint , Position , wxSize , Size )

#else
IMPLEMENT_DYNAMIC_CLASS(wxBitmapButton, wxButton)
#endif

#define BUTTON_HEIGHT_FACTOR (EDIT_CONTROL_FACTOR * 1.1)

bool wxBitmapButton::Create(wxWindow *parent, wxWindowID id,
    const wxBitmap& bitmap,
    const wxPoint& pos,
    const wxSize& size, long style,
    const wxValidator& wxVALIDATOR_PARAM(validator),
    const wxString& name)
{
    return false;
}

#define FOCUS_MARGIN 3

void wxBitmapButton::DrawFace( WXHDC dc, int left, int top,
    int right, int bottom, bool sel )
{
}

void wxBitmapButton::DrawButtonFocus( WXHDC dc, int left, int top, int right,
    int bottom, bool WXUNUSED(sel) )
{
}

void wxBitmapButton::DrawButtonDisable( WXHDC dc, int left, int top, int right,
    int bottom, bool with_marg )
{
}

wxSize wxBitmapButton::DoGetBestSize() const
{
    wxSize best;
    best.x = 0;
    best.y = 0;

    return best;
}

#endif // wxUSE_BMPBUTTON
