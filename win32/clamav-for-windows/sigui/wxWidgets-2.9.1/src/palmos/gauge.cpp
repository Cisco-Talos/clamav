/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/gauge.cpp
// Purpose:     wxGauge class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
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

#if wxUSE_GAUGE

#include "wx/gauge.h"

#ifndef WX_PRECOMP
#endif

#include "wx/palmos/private.h"

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

#ifndef PBS_SMOOTH
    #define PBS_SMOOTH 0x01
#endif

#ifndef PBS_VERTICAL
    #define PBS_VERTICAL 0x04
#endif

#ifndef PBM_SETBARCOLOR
    #define PBM_SETBARCOLOR         (WM_USER+9)
#endif

#ifndef PBM_SETBKCOLOR
    #define PBM_SETBKCOLOR          0x2001
#endif

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxGaugeStyle )

wxBEGIN_FLAGS( wxGaugeStyle )
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

    wxFLAGS_MEMBER(wxGA_HORIZONTAL)
    wxFLAGS_MEMBER(wxGA_VERTICAL)
    wxFLAGS_MEMBER(wxGA_SMOOTH)

wxEND_FLAGS( wxGaugeStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxGauge, wxControl,"wx/gauge.h")

wxBEGIN_PROPERTIES_TABLE(wxGauge)
    wxPROPERTY( Value , int , SetValue, GetValue, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Range , int , SetRange, GetRange, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( ShadowWidth , int , SetShadowWidth, GetShadowWidth, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( BezelFace , int , SetBezelFace, GetBezelFace, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxGaugeStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxGauge)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_6( wxGauge , wxWindow* , Parent , wxWindowID , Id , int , Range , wxPoint , Position , wxSize , Size , long , WindowStyle )
#else
IMPLEMENT_DYNAMIC_CLASS(wxGauge, wxControl)
#endif

// ============================================================================
// wxGauge implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxGauge creation
// ----------------------------------------------------------------------------

bool wxGauge::Create(wxWindow *parent,
                       wxWindowID id,
                       int range,
                       const wxPoint& pos,
                       const wxSize& size,
                       long style,
                       const wxValidator& validator,
                       const wxString& name)
{
    return false;
}

WXDWORD wxGauge::MSWGetStyle(long style, WXDWORD *exstyle) const
{
    return 0;
}

// ----------------------------------------------------------------------------
// wxGauge geometry
// ----------------------------------------------------------------------------

wxSize wxGauge::DoGetBestSize() const
{
    return wxSize(0,0);
}

// ----------------------------------------------------------------------------
// wxGauge setters
// ----------------------------------------------------------------------------

void wxGauge::SetRange(int r)
{
}

void wxGauge::SetValue(int pos)
{
}

bool wxGauge::SetForegroundColour(const wxColour& col)
{
    return false;
}

bool wxGauge::SetBackgroundColour(const wxColour& col)
{
    return false;
}

#endif // wxUSE_GAUGE
