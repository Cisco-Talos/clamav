/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/radiobox.cpp
// Purpose:     wxRadioBox implementation
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native wxRadioBox implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
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

#if wxUSE_RADIOBOX

#include "wx/radiobox.h"

#ifndef WX_PRECOMP
    #include "wx/bitmap.h"
    #include "wx/brush.h"
    #include "wx/settings.h"
    #include "wx/log.h"
    #include "wx/radiobut.h"
#endif

#if wxUSE_TOOLTIPS
    #include "wx/tooltip.h"
#endif // wxUSE_TOOLTIPS

// TODO: wxCONSTRUCTOR
#if 0 // wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxRadioBoxStyle )

wxBEGIN_FLAGS( wxRadioBoxStyle )
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

    wxFLAGS_MEMBER(wxRA_SPECIFY_COLS)
    wxFLAGS_MEMBER(wxRA_SPECIFY_ROWS)
wxEND_FLAGS( wxRadioBoxStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxRadioBox, wxControl,"wx/radiobox.h")

wxBEGIN_PROPERTIES_TABLE(wxRadioBox)
    wxEVENT_PROPERTY( Select , wxEVT_COMMAND_RADIOBOX_SELECTED , wxCommandEvent )
    wxPROPERTY_FLAGS( WindowStyle , wxRadioBoxStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

#else
IMPLEMENT_DYNAMIC_CLASS(wxRadioBox, wxControl)
#endif

/*
    selection
    content
        label
        dimension
        item
*/

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// wxRadioBox
// ---------------------------------------------------------------------------

void wxRadioBox::Init()
{
    m_pos = wxPoint(0,0);
    m_size = wxSize(0,0);
}

unsigned int wxRadioBox::GetCount() const
{
    return m_radios.GetCount();
}

bool wxRadioBox::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxString& title,
                        const wxPoint& pos,
                        const wxSize& size,
                        int n,
                        const wxString choices[],
                        int majorDim,
                        long style,
                        const wxValidator& val,
                        const wxString& name)
{
    // initialize members
    SetMajorDim(majorDim == 0 ? n : majorDim, style);

    if ( GetMajorDim() == 0 || n == 0 )
        return false;

    // subtype of the native palmOS radio: checkbox or push button?
    const bool use_checkbox = style & wxRA_USE_CHECKBOX;
    const bool use_cols = style & wxRA_SPECIFY_COLS;

    // get default size and position for the initial placement
    m_size = size;
    m_pos = pos;
    int minor = n / GetMajorDim();
    if(n % GetMajorDim() > 0)
        minor++;
    if(m_size.x==wxDefaultCoord)
        m_size.x=36*(use_cols?GetMajorDim():minor);
    if(m_size.y==wxDefaultCoord)
        m_size.y=12*(use_cols?minor:GetMajorDim());
    if(m_pos.x==wxDefaultCoord)
        m_pos.x=0;
    if(m_pos.y==wxDefaultCoord)
        m_pos.y=0;

    m_label = title;

    if(!wxControl::Create(parent, id, m_pos, m_size, style, val, name))
        return false;

    int i = 0;
    for ( unsigned int j = 0; j < minor; j++ )
    {
        for ( unsigned int k = 0; k < GetMajorDim(); k++ )
        {
            if(i<n)
            {
                wxPoint start, end;
                start.x = (use_cols ? (k*m_size.x)/GetMajorDim() : (j*m_size.x)/minor);
                start.y = (use_cols ? (j*m_size.y)/minor : (k*m_size.y)/GetMajorDim());
                end.x = (use_cols ? ((k+1)*m_size.x)/GetMajorDim() : ((j+1)*m_size.x)/minor);
                end.y = (use_cols ? ((j+1)*m_size.y)/minor : ((k+1)*m_size.y)/GetMajorDim());
                wxRadioButton* rb = new wxRadioButton();
                rb->SetGroup( id );
                rb->Create(
                    this,
                    wxID_ANY,
                    choices[i],
                    start,
                    wxSize(end.x-start.x-1,end.y-start.y-1),
                    ( n == 0 ? wxRB_GROUP : 0 ) |
                    use_checkbox ? wxRB_USE_CHECKBOX : 0
                );
                m_radios.Put(i,rb);
                i++;
            }
        }
    }
}

bool wxRadioBox::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxString& title,
                        const wxPoint& pos,
                        const wxSize& size,
                        const wxArrayString& choices,
                        int majorDim,
                        long style,
                        const wxValidator& val,
                        const wxString& name)
{
    wxCArrayString chs(choices);

    return Create( parent, id, title, pos, size, chs.GetCount(),
                   chs.GetStrings(), majorDim, style, val, name );
}

wxRadioBox::~wxRadioBox()
{
}

wxRadioButton *wxRadioBox::GetRadioButton(int i) const
{
    return (wxRadioButton *)m_radios.Get(i);
}

void wxRadioBox::DoGetPosition( int *x, int *y ) const
{
    *x = m_pos.x;
    *y = m_pos.y;
}

void wxRadioBox::DoGetSize( int *width, int *height ) const
{
    *width = m_size.x;
    *height = m_size.y;
}

void wxRadioBox::DoMoveWindow(int x, int y, int width, int height)
{
    wxRect oldRect = GetRect();

    m_pos.x = x;
    m_pos.y = y;
    m_size.x = width;
    m_size.y = height;

    const bool use_cols = HasFlag(wxRA_SPECIFY_COLS);

    const unsigned int n = GetCount();
    unsigned int minor = n / GetMajorDim();
    if(n % GetMajorDim() > 0)
        minor++;

    unsigned int i = 0;
    for ( unsigned int j = 0; j < minor; j++ )
    {
        for ( unsigned int k = 0; k < GetMajorDim(); k++ )
        {
            if(i<n)
            {
                wxPoint start, end;
                start.x = (use_cols ? (k*m_size.x)/GetMajorDim() : (j*m_size.x)/minor);
                start.y = (use_cols ? (j*m_size.y)/minor : (k*m_size.y)/GetMajorDim());
                end.x = (use_cols ? ((k+1)*m_size.x)/GetMajorDim() : ((j+1)*m_size.x)/minor);
                end.y = (use_cols ? ((j+1)*m_size.y)/minor : ((k+1)*m_size.y)/GetMajorDim());
                wxRadioButton* rb = GetRadioButton(i);
                if(rb)
                {
                    rb->SetSize(start.x,start.y,end.x-start.x-1,end.y-start.y-1);
                }
                i++;
            }
        }
    }

    // refresh old and new area
    GetParent()->RefreshRect(oldRect.Union(GetRect()));
}

// get the origin of the client area in the client coordinates
wxPoint wxRadioBox::GetClientAreaOrigin() const
{
    return GetPosition();
}

void wxRadioBox::SetString(unsigned int item, const wxString& label)
{
    wxRadioButton *btn = GetRadioButton(item);
    if(btn)
        btn->SetLabel(label);
}

void wxRadioBox::SetSelection(int N)
{
}

// Get single selection, for single choice list items
int wxRadioBox::GetSelection() const
{
    return 0;
}

// Find string for position
wxString wxRadioBox::GetString(unsigned int item) const
{
    wxRadioButton *btn = GetRadioButton(item);
    if(btn)
        return btn->GetLabel();
    return wxEmptyString;
}

// ----------------------------------------------------------------------------
// size calculations
// ----------------------------------------------------------------------------

wxSize wxRadioBox::GetMaxButtonSize() const
{
    return wxSize(0,0);
}

wxSize wxRadioBox::GetTotalButtonSize(const wxSize& sizeBtn) const
{
    return wxSize(0,0);
}

wxSize wxRadioBox::DoGetBestSize() const
{
    return wxSize(0,0);
}

void wxRadioBox::SetFocus()
{
}

// Enable all subcontrols
bool wxRadioBox::Enable(bool enable)
{
    for(unsigned int i=0; i<GetCount(); i++)
        Enable(i, enable);
    return true;
}

// Enable a specific button
bool wxRadioBox::Enable(unsigned int item, bool enable)
{
    wxRadioButton *btn = GetRadioButton(item);
    if(btn)
        return btn->Enable(enable);
    return false;
}

bool wxRadioBox::Show(bool show)
{
    for(unsigned int i=0; i<GetCount(); i++)
        Show(i, show);
    return true;
}

// Show a specific button
bool wxRadioBox::Show(unsigned int item, bool show)
{
    wxRadioButton *btn = GetRadioButton(item);
    if(btn)
    {
        bool ret = btn->Show(show);
        RefreshRect(btn->GetRect());
        return ret;
    }
    return false;
}

wxString wxRadioBox::GetLabel()
{
    return m_label;
}

void wxRadioBox::SetLabel(const wxString& label)
{
    m_label = label;
}

void wxRadioBox::Refresh(bool eraseBack, const wxRect *rect)
{
    wxRect area = GetRect();

    if(rect)
    {
        area.Offset(rect->GetPosition());
        area.SetSize(rect->GetSize());
    }

    GetParent()->RefreshRect(area);
}

void wxRadioBox::Command(wxCommandEvent & event)
{
}

void wxRadioBox::SendNotificationEvent()
{
}

bool wxRadioBox::SetFont(const wxFont& font)
{
    return false;
}

#endif // wxUSE_RADIOBOX
