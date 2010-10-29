///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/checklst.cpp
// Purpose:     implementation of wxCheckListBox class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10.13.04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

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

#if wxUSE_CHECKLISTBOX && wxUSE_OWNER_DRAWN

#include "wx/checklst.h"

#ifndef WX_PRECOMP
    #include "wx/object.h"
    #include "wx/colour.h"
    #include "wx/font.h"
    #include "wx/bitmap.h"
    #include "wx/window.h"
    #include "wx/listbox.h"
    #include "wx/dcmemory.h"

    #include "wx/settings.h"

    #include "wx/log.h"
#endif

#include "wx/ownerdrw.h"

#include "wx/palmos/wrapwin.h"

#include "wx/palmos/private.h"

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// get item (converted to right type)
#define GetItem(n)    ((wxCheckListBoxItem *)(GetItem(n)))

// ============================================================================
// implementation
// ============================================================================


#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxCheckListBoxStyle )

wxBEGIN_FLAGS( wxCheckListBoxStyle )
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

    wxFLAGS_MEMBER(wxLB_SINGLE)
    wxFLAGS_MEMBER(wxLB_MULTIPLE)
    wxFLAGS_MEMBER(wxLB_EXTENDED)
    wxFLAGS_MEMBER(wxLB_HSCROLL)
    wxFLAGS_MEMBER(wxLB_ALWAYS_SB)
    wxFLAGS_MEMBER(wxLB_NEEDED_SB)
    wxFLAGS_MEMBER(wxLB_SORT)
    wxFLAGS_MEMBER(wxLB_OWNERDRAW)

wxEND_FLAGS( wxCheckListBoxStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxCheckListBox, wxListBox,"wx/checklst.h")

wxBEGIN_PROPERTIES_TABLE(wxCheckListBox)
    wxEVENT_PROPERTY( Toggle , wxEVT_COMMAND_CHECKLISTBOX_TOGGLED , wxCommandEvent )
    wxPROPERTY_FLAGS( WindowStyle , wxCheckListBoxStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , wxLB_OWNERDRAW /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxCheckListBox)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_4( wxCheckListBox , wxWindow* , Parent , wxWindowID , Id , wxPoint , Position , wxSize , Size )

#else
IMPLEMENT_DYNAMIC_CLASS(wxCheckListBox, wxListBox)
#endif

// ----------------------------------------------------------------------------
// declaration and implementation of wxCheckListBoxItem class
// ----------------------------------------------------------------------------

class wxCheckListBoxItem : public wxOwnerDrawn
{
friend class WXDLLEXPORT wxCheckListBox;
public:
  // ctor
  wxCheckListBoxItem(wxCheckListBox *pParent, size_t nIndex);

  // drawing functions
  virtual bool OnDrawItem(wxDC& dc, const wxRect& rc, wxODAction act, wxODStatus stat);

  // simple accessors and operations
  bool IsChecked() const { return m_bChecked; }

  void Check(bool bCheck);
  void Toggle() { Check(!IsChecked()); }

  void SendEvent();

private:

    wxDECLARE_NO_COPY_CLASS(wxCheckListBoxItem);
  bool            m_bChecked;
  wxCheckListBox *m_pParent;
  size_t          m_nIndex;
};

wxCheckListBoxItem::wxCheckListBoxItem(wxCheckListBox *pParent, size_t nIndex)
                  : wxOwnerDrawn(wxEmptyString, true)   // checkable
{
}

bool wxCheckListBoxItem::OnDrawItem(wxDC& dc, const wxRect& rc,
                                    wxODAction act, wxODStatus stat)
{
    return false;
}

// change the state of the item and redraw it
void wxCheckListBoxItem::Check(bool check)
{
}

// send an "item checked" event
void wxCheckListBoxItem::SendEvent()
{
}

// ----------------------------------------------------------------------------
// implementation of wxCheckListBox class
// ----------------------------------------------------------------------------

// define event table
// ------------------
BEGIN_EVENT_TABLE(wxCheckListBox, wxListBox)
  EVT_KEY_DOWN(wxCheckListBox::OnKeyDown)
  EVT_LEFT_DOWN(wxCheckListBox::OnLeftClick)
END_EVENT_TABLE()

// control creation
// ----------------

// def ctor: use Create() to really create the control
wxCheckListBox::wxCheckListBox()
{
}

// ctor which creates the associated control
wxCheckListBox::wxCheckListBox(wxWindow *parent, wxWindowID id,
                               const wxPoint& pos, const wxSize& size,
                               int nStrings, const wxString choices[],
                               long style, const wxValidator& val,
                               const wxString& name)
{
    Create(parent, id, pos, size, nStrings, choices, style, val, name);
}

wxCheckListBox::wxCheckListBox(wxWindow *parent, wxWindowID id,
                               const wxPoint& pos, const wxSize& size,
                               const wxArrayString& choices,
                               long style, const wxValidator& val,
                               const wxString& name)
{
    Create(parent, id, pos, size, choices, style, val, name);
}

bool wxCheckListBox::Create(wxWindow *parent, wxWindowID id,
                            const wxPoint& pos, const wxSize& size,
                            int n, const wxString choices[],
                            long style,
                            const wxValidator& validator, const wxString& name)
{
    return wxListBox::Create(parent, id, pos, size, n, choices,
                             style | wxLB_OWNERDRAW, validator, name);
}

bool wxCheckListBox::Create(wxWindow *parent, wxWindowID id,
                            const wxPoint& pos, const wxSize& size,
                            const wxArrayString& choices,
                            long style,
                            const wxValidator& validator, const wxString& name)
{
    return wxListBox::Create(parent, id, pos, size, choices,
                             style | wxLB_OWNERDRAW, validator, name);
}

// misc overloaded methods
// -----------------------

void wxCheckListBox::Delete(unsigned int n)
{
}

bool wxCheckListBox::SetFont( const wxFont &font )
{
    return false;
}

// create/retrieve item
// --------------------

// create a check list box item
wxOwnerDrawn *wxCheckListBox::CreateLboxItem(size_t nIndex)
{
  wxCheckListBoxItem *pItem = new wxCheckListBoxItem(this, nIndex);
  return pItem;
}

// return item size
// ----------------
bool wxCheckListBox::MSWOnMeasure(WXMEASUREITEMSTRUCT *item)
{
  return false;
}

// check items
// -----------

bool wxCheckListBox::IsChecked(unsigned int uiIndex) const
{
    return false;
}

void wxCheckListBox::Check(unsigned int uiIndex, bool bCheck)
{
}

// process events
// --------------

void wxCheckListBox::OnKeyDown(wxKeyEvent& event)
{
}

void wxCheckListBox::OnLeftClick(wxMouseEvent& event)
{
}

int wxCheckListBox::DoHitTestItem(wxCoord x, wxCoord y) const
{
    return wxNOT_FOUND;
}

#endif // wxUSE_CHECKLISTBOX && wxUSE_OWNER_DRAWN
