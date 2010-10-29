/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/spinbutt.cpp
// Purpose:     wxSpinButton
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

#if wxUSE_SPINBTN

#include "wx/spinbutt.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif

IMPLEMENT_DYNAMIC_CLASS(wxSpinEvent, wxNotifyEvent)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------


#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxSpinButtonStyle )

wxBEGIN_FLAGS( wxSpinButtonStyle )
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

    wxFLAGS_MEMBER(wxSP_HORIZONTAL)
    wxFLAGS_MEMBER(wxSP_VERTICAL)
    wxFLAGS_MEMBER(wxSP_ARROW_KEYS)
    wxFLAGS_MEMBER(wxSP_WRAP)

wxEND_FLAGS( wxSpinButtonStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxSpinButton, wxControl,"wx/spinbut.h")

wxBEGIN_PROPERTIES_TABLE(wxSpinButton)
    wxEVENT_RANGE_PROPERTY( Spin , wxEVT_SCROLL_TOP , wxEVT_SCROLL_ENDSCROLL , wxSpinEvent )

    wxPROPERTY( Value , int , SetValue, GetValue, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Min , int , SetMin, GetMin, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Max , int , SetMax, GetMax, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxSpinButtonStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxSpinButton)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_5( wxSpinButton , wxWindow* , Parent , wxWindowID , Id , wxPoint , Position , wxSize , Size , long , WindowStyle )
#else
IMPLEMENT_DYNAMIC_CLASS(wxSpinButton, wxControl)
#endif



// ----------------------------------------------------------------------------
// wxSpinButton
// ----------------------------------------------------------------------------

bool wxSpinButton::Create(wxWindow *parent,
                          wxWindowID id,
                          const wxPoint& pos,
                          const wxSize& size,
                          long style,
                          const wxString& name)
{
    return false;
}

wxSpinButton::~wxSpinButton()
{
}

// ----------------------------------------------------------------------------
// size calculation
// ----------------------------------------------------------------------------

wxSize wxSpinButton::DoGetBestSize() const
{
    return wxSize(0,0),
}

// ----------------------------------------------------------------------------
// Attributes
// ----------------------------------------------------------------------------

int wxSpinButton::GetValue() const
{
    return 0;
}

void wxSpinButton::SetValue(int val)
{
}

void wxSpinButton::SetRange(int minVal, int maxVal)
{
}

#endif
    // wxUSE_SPINBTN
