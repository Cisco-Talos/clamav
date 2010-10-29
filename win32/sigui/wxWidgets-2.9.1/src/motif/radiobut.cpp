/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/radiobut.cpp
// Purpose:     wxRadioButton
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/radiobut.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/ToggleB.h>
#include <Xm/ToggleBG.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

void wxRadioButtonCallback (Widget w, XtPointer clientData,
                            XmToggleButtonCallbackStruct * cbs);

IMPLEMENT_DYNAMIC_CLASS(wxRadioButton, wxControl)

wxRadioButton::wxRadioButton()
{
}

bool wxRadioButton::Create(wxWindow *parent, wxWindowID id,
                           const wxString& label,
                           const wxPoint& pos,
                           const wxSize& size, long style,
                           const wxValidator& validator,
                           const wxString& name)
{
    if( !CreateControl( parent, id, pos, size, style, validator, name ) )
        return false;
    PreCreation();

    Widget parentWidget = (Widget) parent->GetClientWidget();
    Display* dpy = XtDisplay(parentWidget);

    wxString label1(GetLabelText(label));

    wxXmString text( label1 );

    Widget radioButtonWidget = XtVaCreateManagedWidget ("toggle",
#if wxUSE_GADGETS
        xmToggleButtonGadgetClass, parentWidget,
#else
        xmToggleButtonWidgetClass, parentWidget,
#endif
        wxFont::GetFontTag(), m_font.GetFontTypeC(dpy),
        XmNlabelString, text(),
        XmNfillOnSelect, True,
        XmNindicatorType, XmONE_OF_MANY, // diamond-shape
        NULL);

    XtAddCallback (radioButtonWidget,
                   XmNvalueChangedCallback,
                   (XtCallbackProc)wxRadioButtonCallback,
                   (XtPointer)this);

    m_mainWidget = (WXWidget) radioButtonWidget;

    XtManageChild (radioButtonWidget);

    PostCreation();
    AttachWidget (parent, m_mainWidget, (WXWidget) NULL,
                  pos.x, pos.y, size.x, size.y);

    //copied from mac/radiobut.cpp (from here till "return true;")
    m_cycle = this ;

    if (HasFlag(wxRB_GROUP))
    {
        AddInCycle( NULL ) ;
    }
    else
    {
        /* search backward for last group start */
        wxRadioButton *chief = NULL;
        wxWindowList::compatibility_iterator node = parent->GetChildren().GetLast();
        while (node)
        {
            wxWindow *child = node->GetData();
            if (child->IsKindOf( CLASSINFO( wxRadioButton ) ) )
            {
                chief = (wxRadioButton*) child;
                if (child->HasFlag(wxRB_GROUP)) break;
            }
            node = node->GetPrevious();
        }
        AddInCycle( chief ) ;
    }
    return true;
}

void wxRadioButton::SetValue(bool value)
{
    if (GetValue() == value)
        return;

    m_inSetValue = true;
    XmToggleButtonSetState ((Widget) m_mainWidget, (Boolean) value, False);
    m_inSetValue = false;

    ClearSelections();
}

// Get single selection, for single choice list items
bool wxRadioButton::GetValue() const
{
    return (XmToggleButtonGetState ((Widget) m_mainWidget) != 0);
}

void wxRadioButton::Command (wxCommandEvent & event)
{
    SetValue ( (event.GetInt() != 0) );
    ProcessCommand (event);
}

void wxRadioButton::ChangeBackgroundColour()
{
    wxWindow::ChangeBackgroundColour();

    // What colour should this be?
    wxColour colour = *wxBLACK;
    WXPixel selectPixel = colour.AllocColour(XtDisplay((Widget)m_mainWidget));

    XtVaSetValues ((Widget) GetMainWidget(),
          XmNselectColor, selectPixel,
          NULL);
}

void wxRadioButtonCallback (Widget WXUNUSED(w), XtPointer clientData,
                            XmToggleButtonCallbackStruct * cbs)
{
    if (!cbs->set)
        return;

    wxRadioButton *item = (wxRadioButton *) clientData;
    if (item->InSetValue())
        return;

    //based on mac/radiobut.cpp
    wxRadioButton* old = item->ClearSelections();
    item->SetValue(true);

    if ( old )
    {
        wxCommandEvent event(wxEVT_COMMAND_RADIOBUTTON_SELECTED,
                             old->GetId() );
        event.SetEventObject(old);
        event.SetInt( false );
        old->ProcessCommand(event);
    }
    wxCommandEvent event2(wxEVT_COMMAND_RADIOBUTTON_SELECTED, item->GetId() );
    event2.SetEventObject(item);
    event2.SetInt( true );
    item->ProcessCommand(event2);
}

wxRadioButton* wxRadioButton::AddInCycle(wxRadioButton *cycle)
{
    if (cycle == NULL)
    {
        m_cycle = this;
    }
    else
    {
        wxRadioButton* current = cycle;
        while ( current->m_cycle != cycle )
            current = current->m_cycle;
        m_cycle = cycle;
        current->m_cycle = this;
    }

    return cycle;
}

wxRadioButton* wxRadioButton::ClearSelections()
{
    wxRadioButton* cycle = NextInCycle();
    wxRadioButton* old = 0;

    if (cycle)
    {
        while (cycle != this)
        {
            if ( cycle->GetValue() )
            {
                old = cycle;
                cycle->SetValue(false);
            }
            cycle = cycle->NextInCycle();
        }
    }

    return old;
}

void wxRadioButton::RemoveFromCycle()
{
    wxRadioButton* curr = NextInCycle();

    while( curr )
    {
        if( curr->NextInCycle() == this )
        {
            curr->m_cycle = this->m_cycle;
            return;
        }

        curr = curr->NextInCycle();
    }
}
