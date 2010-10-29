/////////////////////////////////////////////////////////////////////////////
// Name:        src/univ/radiobox.cpp
// Purpose:     wxRadioBox implementation
// Author:      Vadim Zeitlin
// Modified by:
// Created:     11.09.00
// RCS-ID:      $Id$
// Copyright:   (c) 2000 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_RADIOBOX

#include "wx/radiobox.h"

#ifndef WX_PRECOMP
    #include "wx/dcclient.h"
    #include "wx/radiobut.h"
    #include "wx/validate.h"
    #include "wx/arrstr.h"
#endif

#include "wx/tooltip.h"

#include "wx/univ/theme.h"
#include "wx/univ/renderer.h"
#include "wx/univ/inphand.h"
#include "wx/univ/colschem.h"

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

static const int BUTTON_BORDER_X = 2;
static const int BUTTON_BORDER_Y = 4;

static const int BOX_BORDER_X = 2;
static const int BOX_BORDER_Y = 2;

// ----------------------------------------------------------------------------
// wxRadioBox event handler
// ----------------------------------------------------------------------------

class wxRadioHookHandler : public wxEvtHandler
{
public:
    wxRadioHookHandler(wxRadioBox *radio) { m_radio = radio; }

    virtual bool ProcessEvent(wxEvent& event)
    {
        // we intercept the command events from radio buttons
        if ( event.GetEventType() == wxEVT_COMMAND_RADIOBUTTON_SELECTED )
        {
            m_radio->OnRadioButton(event);
        }
        else if ( event.GetEventType() == wxEVT_KEY_DOWN )
        {
            if ( m_radio->OnKeyDown((wxKeyEvent &)event) )
            {
                return true;
            }
        }

        // just pass it on
        return GetNextHandler()->ProcessEvent(event);
    }

private:
    wxRadioBox *m_radio;
};

// ============================================================================
// implementation
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxRadioBox, wxControl)

// ----------------------------------------------------------------------------
// wxRadioBox creation
// ----------------------------------------------------------------------------

void wxRadioBox::Init()
{
    m_selection = -1;
}

wxRadioBox::wxRadioBox(wxWindow *parent, wxWindowID id, const wxString& title,
                       const wxPoint& pos, const wxSize& size,
                       const wxArrayString& choices,
                       int majorDim, long style,
                       const wxValidator& val, const wxString& name)
{
    wxCArrayString chs(choices);

    Init();

    (void)Create(parent, id, title, pos, size, chs.GetCount(),
                 chs.GetStrings(), majorDim, style, val, name);
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

    return Create(parent, id, title, pos, size, chs.GetCount(),
                  chs.GetStrings(), majorDim, style, val, name);
}

bool wxRadioBox::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxString& title,
                        const wxPoint& pos,
                        const wxSize& size,
                        int n,
                        const wxString *choices,
                        int majorDim,
                        long style,
                        const wxValidator& wxVALIDATOR_PARAM(val),
                        const wxString& name)
{
    // for compatibility with the other ports which don't handle (yet?)
    // wxRA_LEFTTORIGHT and wxRA_TOPTOBOTTOM flags, we add them ourselves if
    // not specified
    if ( !(style & (wxRA_LEFTTORIGHT | wxRA_TOPTOBOTTOM)) )
    {
        // horizontal radiobox use left to right layout
        if ( style & wxRA_SPECIFY_COLS )
        {
            style |= wxRA_LEFTTORIGHT;
        }
        else if ( style & wxRA_SPECIFY_ROWS )
        {
            style |= wxRA_TOPTOBOTTOM;
        }
        else
        {
            wxFAIL_MSG( wxT("you must specify wxRA_XXX style!") );

            // use default
            style = wxRA_SPECIFY_COLS | wxRA_LEFTTORIGHT;
        }
    }

    if ( !wxStaticBox::Create(parent, id, title, pos, size, style, name) )
        return false;

#if wxUSE_VALIDATORS
    SetValidator(val);
#endif // wxUSE_VALIDATORS

    Append(n, choices);

    // majorDim default value is 0 which means make one row/column
    SetMajorDim(majorDim == 0 ? n : majorDim, style);

    if ( size == wxDefaultSize )
    {
        SetClientSize(DoGetBestClientSize());
    }

    // Need to move the radiobox in order to move the radio buttons
    wxPoint actualPos = GetPosition();
    wxSize actualSize = GetSize();
    DoMoveWindow(actualPos.x, actualPos.y, actualSize.x, actualSize.y);

    // radiobox should already have selection so select at least one item
    SetSelection(0);

    return true;
}

wxRadioBox::~wxRadioBox()
{
    // remove the event handlers we pushed on them from all buttons and delete
    // the buttons themselves: this must be done as the user code expects them
    // to disappear now and not some time later when they will be deleted by
    // our (common) parent
    unsigned int count = m_buttons.GetCount();
    for ( unsigned int n = 0; n < count; n++ )
    {
        m_buttons[n]->PopEventHandler(true /* delete it */);

        delete m_buttons[n];
    }
}

// ----------------------------------------------------------------------------
// wxRadioBox init
// ----------------------------------------------------------------------------

void wxRadioBox::Append(int count, const wxString *choices)
{
    if ( !count )
        return;

    wxWindow *parent = GetParent();
    m_buttons.Alloc(count);
    for ( int n = 0; n < count; n++ )
    {
        // make the first button in the box the start of new group by giving it
        // wxRB_GROUP style
        wxRadioButton *btn = new wxRadioButton(parent, wxID_ANY, choices[n],
                                               wxDefaultPosition,
                                               wxDefaultSize,
                                               n == 0 ? wxRB_GROUP : 0);

        // we want to get the events from the buttons to translate it into
        btn->PushEventHandler(new wxRadioHookHandler(this));
        m_buttons.Add(btn);
    }
}

// ----------------------------------------------------------------------------
// selection
// ----------------------------------------------------------------------------

void wxRadioBox::SetSelection(int n)
{
    wxCHECK_RET( IsValid(n), wxT("invalid index in wxRadioBox::SetSelection") );

    m_selection = n;

    wxRadioButton *btn = m_buttons[n];

    // the selected button is always focused in the radiobox
    btn->SetFocus();

    // this will also unselect the previously selected button in our group
    btn->SetValue(true);
}

int wxRadioBox::GetSelection() const
{
    return m_selection;
}

void wxRadioBox::SendRadioEvent()
{
    wxCHECK_RET( m_selection != -1, wxT("no active radio button") );

    wxCommandEvent event(wxEVT_COMMAND_RADIOBOX_SELECTED, GetId());
    InitCommandEvent(event);
    event.SetInt(m_selection);
    event.SetString(GetString(m_selection));

    Command(event);
}

void wxRadioBox::OnRadioButton(wxEvent& event)
{
    int n = m_buttons.Index((wxRadioButton *)event.GetEventObject());
    wxCHECK_RET( n != wxNOT_FOUND, wxT("click from alien radio button") );

    m_selection = n;

    SendRadioEvent();
}

// ----------------------------------------------------------------------------
// methods forwarded to the buttons
// ----------------------------------------------------------------------------

wxString wxRadioBox::GetString(unsigned int n) const
{
    wxCHECK_MSG( IsValid(n), wxEmptyString,
                 wxT("invalid index in wxRadioBox::GetString") );

    return m_buttons[n]->GetLabel();
}

void wxRadioBox::SetString(unsigned int n, const wxString& label)
{
    wxCHECK_RET( IsValid(n), wxT("invalid index in wxRadioBox::SetString") );

    m_buttons[n]->SetLabel(label);
}

bool wxRadioBox::Enable(unsigned int n, bool enable)
{
    wxCHECK_MSG( IsValid(n), false, wxT("invalid index in wxRadioBox::Enable") );

    return m_buttons[n]->Enable(enable);
}

bool wxRadioBox::IsItemEnabled(unsigned int n) const
{
    wxCHECK_MSG( IsValid(n), false, wxT("invalid index in wxRadioBox::IsItemEnabled") );

    return m_buttons[n]->IsEnabled();
}

bool wxRadioBox::Show(unsigned int n, bool show)
{
    wxCHECK_MSG( IsValid(n), false, wxT("invalid index in wxRadioBox::Show") );

    return m_buttons[n]->Show(show);
}

bool wxRadioBox::IsItemShown(unsigned int n) const
{
    wxCHECK_MSG( IsValid(n), false, wxT("invalid index in wxRadioBox::IsItemShown") );

    return m_buttons[n]->IsShown();
}

// ----------------------------------------------------------------------------
// methods forwarded to the static box
// ----------------------------------------------------------------------------

bool wxRadioBox::Enable(bool enable)
{
    if ( !wxStaticBox::Enable(enable) )
        return false;

    // also enable/disable the buttons
    const unsigned int count = m_buttons.GetCount();
    for ( unsigned int n = 0; n < count; n++ )
    {
        Enable(n, enable);
    }

    return true;
}

bool wxRadioBox::Show(bool show)
{
    if ( !wxStaticBox::Show(show) )
        return false;

    // also show/hide the buttons
    const unsigned int count = m_buttons.GetCount();
    for ( unsigned int n = 0; n < count; n++ )
    {
        Show(n, show);
    }

    return true;
}

wxString wxRadioBox::GetLabel() const
{
    return wxStaticBox::GetLabel();
}

void wxRadioBox::SetLabel(const wxString& label)
{
    wxStaticBox::SetLabel(label);
}

#if wxUSE_TOOLTIPS
void wxRadioBox::DoSetToolTip(wxToolTip *tooltip)
{
    wxControl::DoSetToolTip(tooltip);

    // Also set them for all Radio Buttons
    const unsigned int count = m_buttons.GetCount();
    for ( unsigned int n = 0; n < count; n++ )
    {
        if (tooltip)
            m_buttons[n]->SetToolTip(tooltip->GetTip());
        else
            m_buttons[n]->SetToolTip(NULL);
    }
}
#endif // wxUSE_TOOLTIPS

// ----------------------------------------------------------------------------
// buttons positioning
// ----------------------------------------------------------------------------

wxSize wxRadioBox::GetMaxButtonSize() const
{
    int widthMax, heightMax, width = 0, height = 0;
    widthMax = heightMax = 0;

    const unsigned int count = GetCount();
    for ( unsigned int n = 0; n < count; n++ )
    {
        m_buttons[n]->GetBestSize(&width, &height);

        if ( width > widthMax )
            widthMax = width;
        if ( height > heightMax )
            heightMax = height;
    }

    return wxSize(widthMax + BUTTON_BORDER_X, heightMax + BUTTON_BORDER_Y);
}

wxSize wxRadioBox::DoGetBestClientSize() const
{
    wxSize sizeBtn = GetMaxButtonSize();

    sizeBtn.x *= GetColumnCount();
    sizeBtn.y *= GetRowCount();

    // add a border around all buttons
    sizeBtn.x += 2*BOX_BORDER_X;
    sizeBtn.y += 2*BOX_BORDER_Y;

    // account for the area taken by static box
    wxRect rect = GetBorderGeometry();
    sizeBtn.x += rect.x + rect.width;
    sizeBtn.y += rect.y + rect.height;

    return sizeBtn;
}

void wxRadioBox::DoMoveWindow(int x0, int y0, int width, int height)
{
    wxStaticBox::DoMoveWindow(x0, y0, width, height);

    wxSize sizeBtn = GetMaxButtonSize();
    wxPoint ptOrigin = GetBoxAreaOrigin();
    wxPoint clientOrigin = GetParent() ? GetParent()->GetClientAreaOrigin() : wxPoint(0,0);

    x0 += ptOrigin.x + BOX_BORDER_X - clientOrigin.x;
    y0 += ptOrigin.y + BOX_BORDER_Y - clientOrigin.y;

    int x = x0,
        y = y0;

    const unsigned int count = GetCount();
    for ( unsigned int n = 0; n < count; n++ )
    {
        m_buttons[n]->SetSize(x, y, sizeBtn.x, sizeBtn.y);

        if ( GetWindowStyle() & wxRA_TOPTOBOTTOM )
        {
            // from top to bottom
            if ( (n + 1) % GetRowCount() )
            {
                // continue in this column
                y += sizeBtn.y;
            }
            else
            {
                // start a new column
                x += sizeBtn.x;
                y = y0;
            }
        }
        else // wxRA_LEFTTORIGHT: mirror the code above
        {
            // from left to right
            if ( (n + 1) % GetColumnCount() )
            {
                // continue in this row
                x += sizeBtn.x;
            }
            else
            {
                // start a new row
                y += sizeBtn.y;
                x = x0;
            }
        }
    }
}

// ----------------------------------------------------------------------------
// keyboard navigation
// ----------------------------------------------------------------------------

bool wxRadioBox::OnKeyDown(wxKeyEvent& event)
{
    wxDirection dir;
    switch ( event.GetKeyCode() )
    {
        case WXK_UP:
            dir = wxUP;
            break;

        case WXK_LEFT:
            dir = wxLEFT;
            break;

        case WXK_DOWN:
            dir = wxDOWN;
            break;

        case WXK_RIGHT:
            dir = wxRIGHT;
            break;

        default:
            return false;
    }

    int selOld = GetSelection();
    int selNew = GetNextItem(selOld, dir, GetWindowStyle());
    if ( selNew != selOld )
    {
        SetSelection(selNew);

        // emulate the button click
        SendRadioEvent();
    }

    return true;
}

#endif // wxUSE_RADIOBOX
