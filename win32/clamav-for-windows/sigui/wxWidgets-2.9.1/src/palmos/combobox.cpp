/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/combobox.cpp
// Purpose:     wxComboBox class
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

#if wxUSE_COMBOBOX

#include "wx/combobox.h"

#ifndef WX_PRECOMP
    #include "wx/settings.h"
    #include "wx/log.h"
    // for wxEVT_COMMAND_TEXT_ENTER
    #include "wx/textctrl.h"
    #include "wx/brush.h"
#endif

#include "wx/clipbrd.h"
#include "wx/palmos/private.h"

#if wxUSE_TOOLTIPS
    #include "wx/tooltip.h"
#endif // wxUSE_TOOLTIPS

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxComboBoxStyle )

wxBEGIN_FLAGS( wxComboBoxStyle )
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

    wxFLAGS_MEMBER(wxCB_SIMPLE)
    wxFLAGS_MEMBER(wxCB_SORT)
    wxFLAGS_MEMBER(wxCB_READONLY)
    wxFLAGS_MEMBER(wxCB_DROPDOWN)

wxEND_FLAGS( wxComboBoxStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxComboBox, wxControl,"wx/combobox.h")

wxBEGIN_PROPERTIES_TABLE(wxComboBox)
    wxEVENT_PROPERTY( Select , wxEVT_COMMAND_COMBOBOX_SELECTED , wxCommandEvent )
    wxEVENT_PROPERTY( TextEnter , wxEVT_COMMAND_TEXT_ENTER , wxCommandEvent )

    // TODO DELEGATES
    wxPROPERTY( Font , wxFont , SetFont , GetFont  , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_COLLECTION( Choices , wxArrayString , wxString , AppendString , GetStrings , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Value ,wxString, SetValue, GetValue, EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Selection ,int, SetSelection, GetSelection, EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxComboBoxStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxComboBox)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_5( wxComboBox , wxWindow* , Parent , wxWindowID , Id , wxString , Value , wxPoint , Position , wxSize , Size )
#else
IMPLEMENT_DYNAMIC_CLASS(wxComboBox, wxControl)
#endif

// ----------------------------------------------------------------------------
// function prototypes
// ----------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// global vars
// ---------------------------------------------------------------------------

// the pointer to standard radio button wnd proc
static WNDPROC gs_wndprocEdit = (WNDPROC)NULL;

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxComboBox callbacks
// ----------------------------------------------------------------------------

WXLRESULT wxComboBox::MSWWindowProc(WXUINT nMsg, WXWPARAM wParam, WXLPARAM lParam)
{
    return 0;
}

bool wxComboBox::MSWProcessEditMsg(WXUINT msg, WXWPARAM wParam, WXLPARAM lParam)
{
    return false;
}

bool wxComboBox::MSWCommand(WXUINT param, WXWORD WXUNUSED(id))
{
    return false;
}

WXHWND wxComboBox::GetEditHWND() const
{
    return (WXHWND)0;
}

// ----------------------------------------------------------------------------
// wxComboBox creation
// ----------------------------------------------------------------------------

bool wxComboBox::Create(wxWindow *parent, wxWindowID id,
                        const wxString& value,
                        const wxPoint& pos,
                        const wxSize& size,
                        int n, const wxString choices[],
                        long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    return false;
}

bool wxComboBox::Create(wxWindow *parent, wxWindowID id,
                        const wxString& value,
                        const wxPoint& pos,
                        const wxSize& size,
                        const wxArrayString& choices,
                        long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    return false;
}

WXDWORD wxComboBox::MSWGetStyle(long style, WXDWORD *exstyle) const
{
    return 0;
}

// ----------------------------------------------------------------------------
// wxComboBox text control-like methods
// ----------------------------------------------------------------------------

void wxComboBox::SetValue(const wxString& value)
{
}

// Clipboard operations
void wxComboBox::Copy()
{
}

void wxComboBox::Cut()
{
}

void wxComboBox::Paste()
{
}

void wxComboBox::SetEditable(bool WXUNUSED(editable))
{
}

void wxComboBox::SetInsertionPoint(long pos)
{
}

void wxComboBox::SetInsertionPointEnd()
{
}

long wxComboBox::GetInsertionPoint() const
{
    return 0;
}

wxTextPos wxComboBox::GetLastPosition() const
{
    return 0;
}

void wxComboBox::Replace(long from, long to, const wxString& value)
{
}

void wxComboBox::Remove(long from, long to)
{
}

void wxComboBox::SetSelection(long from, long to)
{
}

bool wxComboBox::IsEditable() const
{
    return false;
}

void wxComboBox::Undo()
{
}

void wxComboBox::Redo()
{
}

void wxComboBox::SelectAll()
{
}

bool wxComboBox::CanCopy() const
{
    return false;
}

bool wxComboBox::CanCut() const
{
    return false;
}

bool wxComboBox::CanPaste() const
{
    return false;
}

bool wxComboBox::CanUndo() const
{
    return false;
}

bool wxComboBox::CanRedo() const
{
    return false;
}


#endif // wxUSE_COMBOBOX
