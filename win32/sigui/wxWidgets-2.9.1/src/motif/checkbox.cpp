/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/checkbox.cpp
// Purpose:     wxCheckBox
// Author:      Julian Smart
// Modified by:
// Created:     04/01/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/checkbox.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
#endif

#include "wx/tglbtn.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Label.h>
#include <Xm/LabelG.h>
#include <Xm/ToggleB.h>
#include <Xm/ToggleBG.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

// define symbols that are missing in old versions of Motif.
#if wxCHECK_MOTIF_VERSION( 2, 0 )
    #define wxHAS_3STATE 1
#else
    #define wxHAS_3STATE 0
#endif

#include "wx/motif/private.h"

void wxCheckBoxCallback (Widget w, XtPointer clientData,
                         XtPointer ptr);

IMPLEMENT_DYNAMIC_CLASS(wxCheckBox, wxControl)

// Single check box item
bool wxCheckBox::Create(wxWindow *parent, wxWindowID id, const wxString& label,
                        const wxPoint& pos,
                        const wxSize& size, long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    if( !wxControl::CreateControl( parent, id, pos, size, style, validator,
                                   name ) )
        return false;
    PreCreation();

    wxXmString text( GetLabelText(label) );

    Widget parentWidget = (Widget) parent->GetClientWidget();

    m_mainWidget = (WXWidget) XtVaCreateManagedWidget ("toggle",
        xmToggleButtonWidgetClass, parentWidget,
        wxFont::GetFontTag(), m_font.GetFontTypeC(XtDisplay(parentWidget)),
        XmNlabelString, text(),
        XmNrecomputeSize, False,
        // XmNindicatorOn, XmINDICATOR_CHECK_BOX,
        // XmNfillOnSelect, False,
#if wxHAS_3STATE
        XmNtoggleMode, Is3State() ? XmTOGGLE_INDETERMINATE : XmTOGGLE_BOOLEAN,
#endif
        NULL);

    XtAddCallback( (Widget)m_mainWidget,
                   XmNvalueChangedCallback, (XtCallbackProc)wxCheckBoxCallback,
                   (XtPointer)this );

    XmToggleButtonSetState ((Widget) m_mainWidget, False, True);

    PostCreation();
    AttachWidget( parent, m_mainWidget, (WXWidget)NULL,
                  pos.x, pos.y, size.x, size.y );

    return true;
}

void wxCheckBox::SetValue(bool val)
{
    if (val)
    {
        Set3StateValue(wxCHK_CHECKED);
    }
    else
    {
        Set3StateValue(wxCHK_UNCHECKED);
    }
}

bool wxCheckBox::GetValue() const
{
    return (Get3StateValue() != 0);
}

void wxCheckBox::Command (wxCommandEvent & event)
{
    int state = event.GetInt();
    wxCHECK_RET( (state == wxCHK_UNCHECKED) || (state == wxCHK_CHECKED)
        || (state == wxCHK_UNDETERMINED),
        wxT("event.GetInt() returned an invalid checkbox state") );

    Set3StateValue((wxCheckBoxState) state);
    ProcessCommand(event);
}

void wxCheckBoxCallback (Widget WXUNUSED(w), XtPointer clientData,
                         XtPointer WXUNUSED(ptr))
{
    wxCheckBox *item = (wxCheckBox *) clientData;

    if (item->InSetValue())
        return;

    wxCheckBoxState state = item->Get3StateValue();

    if( !item->Is3rdStateAllowedForUser() && state == wxCHK_UNDETERMINED )
    {
        state = wxCHK_UNCHECKED;
        item->Set3StateValue( state );
    }

    wxCommandEvent event( item->m_evtType, item->GetId() );
    event.SetInt( (int)state );
    event.SetEventObject( item );
    item->ProcessCommand( event );
}

void wxCheckBox::ChangeBackgroundColour()
{
    if (!m_backgroundColour.Ok())
        return;

    wxComputeColours (XtDisplay((Widget) m_mainWidget), & m_backgroundColour,
        NULL);

    XtVaSetValues ((Widget) m_mainWidget,
        XmNbackground, g_itemColors[wxBACK_INDEX].pixel,
        XmNtopShadowColor, g_itemColors[wxTOPS_INDEX].pixel,
        XmNbottomShadowColor, g_itemColors[wxBOTS_INDEX].pixel,
        XmNforeground, g_itemColors[wxFORE_INDEX].pixel,
        NULL);

    wxColour colour = *wxBLACK;
    WXPixel selectPixel = colour.AllocColour(XtDisplay((Widget)m_mainWidget));

    // Better to have the checkbox selection in black, or it's
    // hard to determine what state it is in.
    XtVaSetValues ((Widget) m_mainWidget,
           XmNselectColor, selectPixel,
           NULL);
}

void wxCheckBox::DoSet3StateValue(wxCheckBoxState state)
{
    m_inSetValue = true;

#if wxHAS_3STATE
    unsigned char value;

    switch (state)
    {
    case wxCHK_UNCHECKED: value = XmUNSET; break;
    case wxCHK_CHECKED: value = XmSET; break;
    case wxCHK_UNDETERMINED: value = XmINDETERMINATE; break;
    default: wxASSERT(0); return;
    }

    XtVaSetValues( (Widget) m_mainWidget,
                   XmNset, value,
                   NULL );
#else
    XmToggleButtonSetState ((Widget) m_mainWidget,
                            state == wxCHK_CHECKED, True);
#endif

    m_inSetValue = false;
}

wxCheckBoxState wxCheckBox::DoGet3StateValue() const
{
#if wxHAS_3STATE
    unsigned char value = 0;

    XtVaGetValues( (Widget) m_mainWidget,
                   XmNset, &value,
                   NULL );

    switch (value)
    {
    case XmUNSET: return wxCHK_UNCHECKED;
    case XmSET: return wxCHK_CHECKED;
    case XmINDETERMINATE: return wxCHK_UNDETERMINED;
    }

    // impossible...
    return wxCHK_UNDETERMINED;
#else
    return wxCheckBoxState(XmToggleButtonGetState ((Widget) m_mainWidget));
#endif
}

///////////////////////////////////////////////////////////////////////////////
// wxToggleButton
///////////////////////////////////////////////////////////////////////////////

#if wxUSE_TOGGLEBTN

wxDEFINE_EVENT( wxEVT_COMMAND_TOGGLEBUTTON_CLICKED, wxCommandEvent );
IMPLEMENT_DYNAMIC_CLASS(wxToggleButton, wxControl)

bool wxToggleButton::Create( wxWindow* parent, wxWindowID id,
                             const wxString& label,
                             const wxPoint& pos,
                             const wxSize& size,
                             long style,
                             const wxValidator& val,
                             const wxString &name )
{
    if( !wxCheckBox::Create( parent, id, label, pos, size, style, val, name ) )
        return false;

    XtVaSetValues( (Widget)m_mainWidget,
                   XmNindicatorSize, 0,
#if XmVersion >= 2000
                   XmNindicatorOn, XmINDICATOR_NONE,
#else
                   XmNindicatorOn, False,
#endif
                   XmNfillOnSelect, False,
                   XmNshadowThickness, 2,
                   XmNalignment, XmALIGNMENT_CENTER,
                   XmNmarginLeft, 0,
                   XmNmarginRight, 0,
                   NULL );

    // set it again, because the XtVaSetValue above resets it
    if( size.x != -1 || size.y != -1 )
        SetSize( size );

    return true;
}

#endif // wxUSE_TOGGLEBTN
