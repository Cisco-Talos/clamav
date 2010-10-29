/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/button.cpp
// Purpose:     wxButton
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native wxButton implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
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

#if wxUSE_BUTTON

#include "wx/button.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/brush.h"
    #include "wx/panel.h"
    #include "wx/bmpbuttn.h"
    #include "wx/settings.h"
    #include "wx/dcscreen.h"
    #include "wx/frame.h"
    #include "wx/dialog.h"
#endif

#include "wx/stockitem.h"

#include <Control.h>
#include <Form.h>

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

#if wxUSE_EXTENDED_RTTI

WX_DEFINE_FLAGS( wxButtonStyle )

wxBEGIN_FLAGS( wxButtonStyle )
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

    wxFLAGS_MEMBER(wxBU_LEFT)
    wxFLAGS_MEMBER(wxBU_RIGHT)
    wxFLAGS_MEMBER(wxBU_TOP)
    wxFLAGS_MEMBER(wxBU_BOTTOM)
    wxFLAGS_MEMBER(wxBU_EXACTFIT)
wxEND_FLAGS( wxButtonStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxButton, wxControl,"wx/button.h")

wxBEGIN_PROPERTIES_TABLE(wxButton)
    wxEVENT_PROPERTY( Click , wxEVT_COMMAND_BUTTON_CLICKED , wxCommandEvent)

    wxPROPERTY( Font , wxFont , SetFont , GetFont  , EMPTY_MACROVALUE, 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Label, wxString , SetLabel, GetLabel, wxString(), 0 /*flags*/ , wxT("Helpstring") , wxT("group") )

    wxPROPERTY_FLAGS( WindowStyle , wxButtonStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style

wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxButton)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_6( wxButton , wxWindow* , Parent , wxWindowID , Id , wxString , Label , wxPoint , Position , wxSize , Size , long , WindowStyle  )


#else
IMPLEMENT_DYNAMIC_CLASS(wxButton, wxControl)
#endif

// this macro tries to adjust the default button height to a reasonable value
// using the char height as the base
#define BUTTON_HEIGHT_FROM_CHAR_HEIGHT(cy) (11*EDIT_HEIGHT_FROM_CHAR_HEIGHT(cy)/10)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// creation/destruction
// ----------------------------------------------------------------------------

bool wxButton::Create(wxWindow *parent,
                      wxWindowID id,
                      const wxString& label,
                      const wxPoint& pos,
                      const wxSize& size,
                      long style,
                      const wxValidator& validator,
                      const wxString& name)
{
    // Default coordinates based on the knowledgebase recipe "Buttons"
    wxSize palmSize(size.x==wxDefaultCoord?36:size.x,
                    size.y==wxDefaultCoord?12:size.y);

    // Default placement depends on dialog vs. frame type of parent
    wxPoint palmPos(pos);
    if((palmPos.x==wxDefaultCoord)||(palmPos.y==wxDefaultCoord))
    {
        wxSize parentSize(parent->GetClientSize());
        wxWindow* parentTLW = parent;
        while ( parentTLW && !parentTLW->IsTopLevel() )
        {
            parentTLW = parentTLW->GetParent();
        }

        if(wxDynamicCast(parentTLW, wxFrame)!=NULL)
        {
            if(palmPos.x==wxDefaultCoord)
                palmPos.x = 0;
            if(palmPos.y==wxDefaultCoord)
                palmPos.y = parentSize.y-palmSize.y;
        }
        else if(wxDynamicCast(parentTLW, wxDialog)!=NULL)
        {
            if(palmPos.x==wxDefaultCoord)
                palmPos.x = 4;
            if(palmPos.y==wxDefaultCoord)
                palmPos.y = parentSize.y-palmSize.y-5;
        }
        else
        {
            // something seriously broken
            return false;
        }
    }

    // take the stock label
    wxString palmLabel = label;
    if( palmLabel.empty() && wxIsStockID(id) )
        palmLabel = wxGetStockLabel(id, wxSTOCK_NOFLAGS);

    if(!wxControl::Create(parent, id, palmPos, palmSize, style, validator, name))
        return false;

    return wxControl::PalmCreateControl(buttonCtl, palmLabel, palmPos, palmSize);
}

wxButton::~wxButton()
{
}

// ----------------------------------------------------------------------------
// size management including autosizing
// ----------------------------------------------------------------------------

wxSize wxButton::DoGetBestSize() const
{
    return wxSize(36,12);
}

/* static */
wxSize wxButtonBase::GetDefaultSize()
{
    return wxSize(36,12);
}

wxWindow *wxButton::SetDefault()
{
    FormType* form = (FormType* )GetParentForm();
    if(form==NULL)
        return NULL;
#ifdef __WXPALMOS6__
    FrmSetDefaultButtonID(form,GetId());
#endif // __WXPALMOS6__

    return wxButtonBase::SetDefault();
}

void wxButton::SetTmpDefault()
{
}

void wxButton::UnsetTmpDefault()
{
}

/* static */
void
wxButton::SetDefaultStyle(wxButton *btn, bool on)
{
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

bool wxButton::SendClickEvent()
{
    wxCommandEvent event(wxEVT_COMMAND_BUTTON_CLICKED, GetId());
    event.SetEventObject(this);
    return ProcessCommand(event);
}

void wxButton::Command(wxCommandEvent &event)
{
    ProcessCommand(event);
}

#endif // wxUSE_BUTTON
