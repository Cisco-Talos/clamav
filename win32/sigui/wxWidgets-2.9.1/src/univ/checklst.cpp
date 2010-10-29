/////////////////////////////////////////////////////////////////////////////
// Name:        src/univ/checklst.cpp
// Purpose:     wxCheckListBox implementation
// Author:      Vadim Zeitlin
// Modified by:
// Created:     12.09.00
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

#if wxUSE_CHECKLISTBOX

#include "wx/checklst.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/dcclient.h"
    #include "wx/validate.h"
#endif

#include "wx/univ/renderer.h"
#include "wx/univ/inphand.h"
#include "wx/univ/theme.h"

// ----------------------------------------------------------------------------
// wxStdCheckListBoxInputHandler
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxStdCheckListboxInputHandler : public wxStdInputHandler
{
public:
    wxStdCheckListboxInputHandler(wxInputHandler *inphand);

    virtual bool HandleKey(wxInputConsumer *consumer,
                           const wxKeyEvent& event,
                           bool pressed);
    virtual bool HandleMouse(wxInputConsumer *consumer,
                             const wxMouseEvent& event);
};

// ============================================================================
// implementation of wxCheckListBox
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxCheckListBox, wxListBox)

// ----------------------------------------------------------------------------
// creation
// ----------------------------------------------------------------------------

void wxCheckListBox::Init()
{
}

wxCheckListBox::wxCheckListBox(wxWindow *parent,
                               wxWindowID id,
                               const wxPoint &pos,
                               const wxSize &size,
                               const wxArrayString& choices,
                               long style,
                               const wxValidator& validator,
                               const wxString &name)
{
    Init();

    Create(parent, id, pos, size, choices, style, validator, name);
}

bool wxCheckListBox::Create(wxWindow *parent,
                            wxWindowID id,
                            const wxPoint &pos,
                            const wxSize &size,
                            const wxArrayString& choices,
                            long style,
                            const wxValidator& validator,
                            const wxString &name)
{
    wxCArrayString chs(choices);

    return Create(parent, id, pos, size, chs.GetCount(), chs.GetStrings(),
                  style, validator, name);
}

bool wxCheckListBox::Create(wxWindow *parent,
                            wxWindowID id,
                            const wxPoint &pos,
                            const wxSize &size,
                            int n,
                            const wxString choices[],
                            long style,
                            const wxValidator& validator,
                            const wxString &name)
{
    if ( !wxListBox::Create(parent, id, pos, size,
                            n, choices, style, validator, name) )
        return false;

    CreateInputHandler(wxINP_HANDLER_CHECKLISTBOX);

    return true;
}

// ----------------------------------------------------------------------------
// wxCheckListBox functions
// ----------------------------------------------------------------------------

bool wxCheckListBox::IsChecked(unsigned int item) const
{
    wxCHECK_MSG( IsValid(item), false,
                 wxT("invalid index in wxCheckListBox::IsChecked") );

    return m_checks[item] != 0;
}

void wxCheckListBox::Check(unsigned int item, bool check)
{
    wxCHECK_RET( IsValid(item),
                 wxT("invalid index in wxCheckListBox::Check") );

    // intermediate var is needed to avoid compiler warning with VC++
    bool isChecked = m_checks[item] != 0;
    if ( check != isChecked )
    {
        m_checks[item] = check;

        RefreshItem(item);
    }
}

// ----------------------------------------------------------------------------
// methods forwarded to wxListBox
// ----------------------------------------------------------------------------

void wxCheckListBox::DoDeleteOneItem(unsigned int n)
{
    wxListBox::DoDeleteOneItem(n);

    m_checks.RemoveAt(n);
}

void wxCheckListBox::OnItemInserted(unsigned int pos)
{
    m_checks.Insert(false, pos);
}

void wxCheckListBox::DoClear()
{
    m_checks.Empty();
}

// ----------------------------------------------------------------------------
// drawing
// ----------------------------------------------------------------------------

wxSize wxCheckListBox::DoGetBestClientSize() const
{
    wxSize size = wxListBox::DoGetBestClientSize();
    size.x += GetRenderer()->GetCheckBitmapSize().x;

    return size;
}

void wxCheckListBox::DoDrawRange(wxControlRenderer *renderer,
                                 int itemFirst, int itemLast)
{
    renderer->DrawCheckItems(this, itemFirst, itemLast);
}

// ----------------------------------------------------------------------------
// actions
// ----------------------------------------------------------------------------

bool wxCheckListBox::PerformAction(const wxControlAction& action,
                                   long numArg,
                                   const wxString& strArg)
{
    if ( action == wxACTION_CHECKLISTBOX_TOGGLE )
    {
        int sel = (int)numArg;
        if ( sel == -1 )
        {
            sel = GetSelection();
        }

        if ( sel != -1 )
        {
            Check(sel, !IsChecked(sel));

            SendEvent(wxEVT_COMMAND_CHECKLISTBOX_TOGGLED, sel);
        }
    }
    else
    {
        return wxListBox::PerformAction(action, numArg, strArg);
    }

    return true;
}

/* static */
wxInputHandler *wxCheckListBox::GetStdInputHandler(wxInputHandler *handlerDef)
{
    static wxStdCheckListboxInputHandler s_handler(handlerDef);

    return &s_handler;
}

// ----------------------------------------------------------------------------
// wxStdCheckListboxInputHandler
// ----------------------------------------------------------------------------

wxStdCheckListboxInputHandler::
wxStdCheckListboxInputHandler(wxInputHandler *inphand)
    : wxStdInputHandler(wxListBox::GetStdInputHandler(inphand))
{
}

bool wxStdCheckListboxInputHandler::HandleKey(wxInputConsumer *consumer,
                                              const wxKeyEvent& event,
                                              bool pressed)
{
    if ( pressed && (event.GetKeyCode() == WXK_SPACE) )
        consumer->PerformAction(wxACTION_CHECKLISTBOX_TOGGLE);

    return wxStdInputHandler::HandleKey(consumer, event, pressed);
}

bool wxStdCheckListboxInputHandler::HandleMouse(wxInputConsumer *consumer,
                                                const wxMouseEvent& event)
{
    if ( event.LeftDown() || event.LeftDClick() )
    {
        wxCheckListBox *lbox = wxStaticCast(consumer->GetInputWindow(), wxCheckListBox);
        int x, y;

        wxPoint pt = event.GetPosition();
        pt -= consumer->GetInputWindow()->GetClientAreaOrigin();
        lbox->CalcUnscrolledPosition(pt.x, pt.y, &x, &y);

        wxRenderer *renderer = lbox->GetRenderer();
        x -= renderer->GetCheckItemMargin();

        int item = y / lbox->GetLineHeight();
        if ( x >= 0 &&
             x < renderer->GetCheckBitmapSize().x &&
             item >= 0 &&
             (unsigned int)item < lbox->GetCount() )
        {
            lbox->PerformAction(wxACTION_CHECKLISTBOX_TOGGLE, item);

            return true;
        }
    }

    return wxStdInputHandler::HandleMouse(consumer, event);
}

#endif // wxUSE_CHECKLISTBOX
