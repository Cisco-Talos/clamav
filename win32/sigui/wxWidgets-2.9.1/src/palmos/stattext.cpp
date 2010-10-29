/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/stattext.cpp
// Purpose:     wxStaticText
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native wxStaticText implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_STATTEXT

#include "wx/stattext.h"

#ifndef WX_PRECOMP
    #include "wx/event.h"
    #include "wx/app.h"
    #include "wx/brush.h"
#endif

#include <Field.h>

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxStaticTextStyle )

wxBEGIN_FLAGS( wxStaticTextStyle )
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

    wxFLAGS_MEMBER(wxST_NO_AUTORESIZE)
    wxFLAGS_MEMBER(wxALIGN_LEFT)
    wxFLAGS_MEMBER(wxALIGN_RIGHT)
    wxFLAGS_MEMBER(wxALIGN_CENTRE)

wxEND_FLAGS( wxStaticTextStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxStaticText, wxControl,"wx/stattext.h")

wxBEGIN_PROPERTIES_TABLE(wxStaticText)
    wxPROPERTY( Label,wxString, SetLabel, GetLabel, wxString() , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxStaticTextStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE, 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxStaticText)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_6( wxStaticText , wxWindow* , Parent , wxWindowID , Id , wxString , Label , wxPoint , Position , wxSize , Size , long , WindowStyle )
#else
IMPLEMENT_DYNAMIC_CLASS(wxStaticText, wxControl)
#endif

bool wxStaticText::Create(wxWindow *parent,
                          wxWindowID id,
                          const wxString& label,
                          const wxPoint& pos,
                          const wxSize& size,
                          long style,
                          const wxString& name)
{
    if(!wxControl::Create(parent, id, pos, size, style, wxDefaultValidator, name))
        return false;

    // note that wxALIGN_LEFT is equal to 0 so we shouldn't
    // test for it using & operator

    JustificationType align = leftAlign;

    if ( style & wxALIGN_CENTRE )
        align = centerAlign ;
    else if ( style & wxALIGN_RIGHT )
        align = rightAlign;

    return wxControl::PalmCreateField(label, pos, size, false, false, align);
}

wxBorder wxStaticText::GetDefaultBorder() const
{
    return wxBORDER_NONE;
}

wxSize wxStaticText::DoGetBestSize() const
{
    return wxSize(0,0);
}

bool wxStaticText::SetFont(const wxFont& font)
{
    return false;
}

#endif // wxUSE_STATTEXT
