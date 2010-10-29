/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/statline.cpp
// Purpose:     wxStaticLine class
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

#if wxUSE_STATLINE

#include "wx/statline.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif

#include "wx/palmos/private.h"

#ifndef SS_SUNKEN
    #define SS_SUNKEN 0x00001000L
#endif

#ifndef SS_NOTIFY
    #define SS_NOTIFY 0x00000100L
#endif

// ============================================================================
// implementation
// ============================================================================

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxStaticLineStyle )

wxBEGIN_FLAGS( wxStaticLineStyle )
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

    wxFLAGS_MEMBER(wxLI_HORIZONTAL)
    wxFLAGS_MEMBER(wxLI_VERTICAL)

wxEND_FLAGS( wxStaticLineStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxStaticLine, wxControl,"wx/statline.h")

wxBEGIN_PROPERTIES_TABLE(wxStaticLine)
    wxPROPERTY_FLAGS( WindowStyle , wxStaticLineStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE, 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxStaticLine)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_5( wxStaticLine, wxWindow* , Parent , wxWindowID , Id , wxPoint , Position , wxSize , Size , long , WindowStyle)

#else
IMPLEMENT_DYNAMIC_CLASS(wxStaticLine, wxControl)
#endif

/*
    TODO PROPERTIES :
        style (wxLI_HORIZONTAL)
*/

// ----------------------------------------------------------------------------
// wxStaticLine
// ----------------------------------------------------------------------------

bool wxStaticLine::Create(wxWindow *parent,
                          wxWindowID id,
                          const wxPoint& pos,
                          const wxSize& sizeOrig,
                          long style,
                          const wxString &name)
{
    return false;
}

WXDWORD wxStaticLine::MSWGetStyle(long style, WXDWORD *exstyle) const
{
    return 0;
}

#endif // wxUSE_STATLINE
