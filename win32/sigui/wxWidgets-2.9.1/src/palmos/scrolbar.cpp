/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/scrolbar.cpp
// Purpose:     wxScrollBar
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

#if wxUSE_SCROLLBAR

#include "wx/scrolbar.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/settings.h"
#endif

#include "wx/palmos/private.h"

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxScrollBarStyle )

wxBEGIN_FLAGS( wxScrollBarStyle )
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

    wxFLAGS_MEMBER(wxSB_HORIZONTAL)
    wxFLAGS_MEMBER(wxSB_VERTICAL)

wxEND_FLAGS( wxScrollBarStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxScrollBar, wxControl,"wx/scrolbar.h")

wxBEGIN_PROPERTIES_TABLE(wxScrollBar)
    wxEVENT_RANGE_PROPERTY( Scroll , wxEVT_SCROLL_TOP , wxEVT_SCROLL_ENDSCROLL , wxScrollEvent )

    wxPROPERTY( ThumbPosition , int , SetThumbPosition, GetThumbPosition, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Range , int , SetRange, GetRange, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( ThumbSize , int , SetThumbSize, GetThumbSize, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( PageSize , int , SetPageSize, GetPageSize, 0 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxScrollBarStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxScrollBar)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_5( wxScrollBar , wxWindow* , Parent , wxWindowID , Id , wxPoint , Position , wxSize , Size , long , WindowStyle )
#else
IMPLEMENT_DYNAMIC_CLASS(wxScrollBar, wxControl)
#endif

// Scrollbar
bool wxScrollBar::Create(wxWindow *parent, wxWindowID id,
           const wxPoint& pos,
           const wxSize& size, long style,
           const wxValidator& wxVALIDATOR_PARAM(validator),
           const wxString& name)
{
    return false;
}

wxScrollBar::~wxScrollBar(void)
{
}

bool wxScrollBar::MSWOnScroll(int WXUNUSED(orientation), WXWORD wParam,
                              WXWORD pos, WXHWND WXUNUSED(control))
{
    return false;
}

void wxScrollBar::SetThumbPosition(int viewStart)
{
}

int wxScrollBar::GetThumbPosition(void) const
{
}

void wxScrollBar::SetScrollbar(int position, int thumbSize, int range, int pageSize,
    bool refresh)
{
}


void wxScrollBar::Command(wxCommandEvent& event)
{
}

wxSize wxScrollBar::DoGetBestSize() const
{
    return wxSize(0,0);
}

#endif // wxUSE_SCROLLBAR
