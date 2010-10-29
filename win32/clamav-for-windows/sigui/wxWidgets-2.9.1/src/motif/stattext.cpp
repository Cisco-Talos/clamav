/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/stattext.cpp
// Purpose:     wxStaticText
// Author:      Julian Smart
// Modified by:
// Created:     04/01/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_STATTEXT

#include "wx/stattext.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Label.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxStaticText, wxControl)

bool wxStaticText::Create(wxWindow *parent, wxWindowID id,
           const wxString& label,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxString& name)
{
    if( !CreateControl( parent, id, pos, size, style,
                        wxDefaultValidator, name ) )
        return false;
    m_labelWidget = (WXWidget) 0;
    PreCreation();

    Widget parentWidget = (Widget) parent->GetClientWidget();

    Widget borderWidget =
        (Widget) wxCreateBorderWidget( (WXWidget)parentWidget, style );

    m_labelWidget =
        XtVaCreateManagedWidget (name.mb_str(),
            xmLabelWidgetClass,
            borderWidget ? borderWidget : parentWidget,
            wxFont::GetFontTag(), m_font.GetFontTypeC(XtDisplay(parentWidget)),
            XmNalignment, ((style & wxALIGN_RIGHT)  ? XmALIGNMENT_END :
                          ((style & wxALIGN_CENTRE) ? XmALIGNMENT_CENTER :
                                                      XmALIGNMENT_BEGINNING)),
            XmNrecomputeSize, ((style & wxST_NO_AUTORESIZE) ? TRUE : FALSE),
            NULL);

    m_mainWidget = borderWidget ? borderWidget : m_labelWidget;

    SetLabel(label);

    wxSize best = GetBestSize();
    if( size.x != -1 ) best.x = size.x;
    if( size.y != -1 ) best.y = size.y;

    PostCreation();
    AttachWidget (parent, m_mainWidget, (WXWidget) NULL,
                  pos.x, pos.y, best.x, best.y);

    return true;
}

void wxStaticText::SetLabel(const wxString& label)
{
    m_labelOrig = label;       // save original label

    // Motif does not support neither ellipsize nor markup in static text:
    DoSetLabel(GetEllipsizedLabelWithoutMarkup());
}

// for wxST_ELLIPSIZE_* support:

wxString wxStaticText::DoGetLabel() const
{
    XmString label = NULL;
    XtVaGetValues((Widget)m_labelWidget, XmNlabelString, &label, NULL);

    return wxXmStringToString(label);
}

void wxStaticText::DoSetLabel(const wxString& str)
{
    // build our own cleaned label
    wxXmString label_str(RemoveMnemonics(str));

    // This variable means we don't need so many casts later.
    Widget widget = (Widget) m_labelWidget;

        XtVaSetValues(widget,
            XmNlabelString, label_str(),
            XmNlabelType, XmSTRING,
            NULL);
}

/*
   FIXME: UpdateLabel() should be called on size events to allow correct
          dynamic ellipsizing of the label
*/

wxSize wxStaticText::DoGetBestSize() const
{
    int w, h;
    GetTextExtent(GetLabelText(), &w, &h, NULL, NULL, NULL);

    return wxSize(w, h);
}

#endif // wxUSE_STATTEXT
