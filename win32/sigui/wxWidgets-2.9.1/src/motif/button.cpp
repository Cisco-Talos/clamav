/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/button.cpp
// Purpose:     wxButton
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/button.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/PushBG.h>
#include <Xm/PushB.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif


#ifndef WX_PRECOMP
    #include "wx/toplevel.h"
#endif

#include "wx/stockitem.h"
#include "wx/motif/private.h"
#include "wx/sysopt.h"

void wxButtonCallback (Widget w, XtPointer clientData, XtPointer ptr);

IMPLEMENT_DYNAMIC_CLASS(wxButton, wxControl)

#define MIN_WIDTH 78
#define MIN_LARGE_HEIGHT 30

// Button

bool wxButton::Create(wxWindow *parent, wxWindowID id, const wxString& lbl,
                      const wxPoint& pos,
                      const wxSize& size, long style,
                      const wxValidator& validator,
                      const wxString& name)
{
    wxString label(lbl);
    if (label.empty() && wxIsStockID(id))
        label = wxGetStockLabel(id);

    if( !CreateControl( parent, id, pos, size, style, validator, name ) )
        return false;
    PreCreation();

    wxXmString text( GetLabelText(label) );

    Widget parentWidget = (Widget) parent->GetClientWidget();

    /*
    * Patch Note (important)
    * There is no major reason to put a defaultButtonThickness here.
    * Not requesting it give the ability to put wxButton with a spacing
    * as small as requested. However, if some button become a DefaultButton,
    * other buttons are no more aligned -- This is why we set
    * defaultButtonThickness of ALL buttons belonging to the same wxPanel,
    * in the ::SetDefaultButton method.
    */
    m_mainWidget = (WXWidget) XtVaCreateManagedWidget ("button",
        xmPushButtonWidgetClass,
        parentWidget,
        wxFont::GetFontTag(), m_font.GetFontTypeC(XtDisplay(parentWidget)),
        XmNlabelString, text(),
        XmNrecomputeSize, False,
        // See comment for wxButton::SetDefault
        // XmNdefaultButtonShadowThickness, 1,
        NULL);

    XtAddCallback ((Widget) m_mainWidget,
                   XmNactivateCallback, (XtCallbackProc) wxButtonCallback,
                   (XtPointer) this);

    wxSize best = GetBestSize();
    if( size.x != -1 ) best.x = size.x;
    if( size.y != -1 ) best.y = size.y;

    PostCreation();
    AttachWidget (parent, m_mainWidget, (WXWidget) NULL,
                  pos.x, pos.y, best.x, best.y);

    return true;
}

void wxButton::SetDefaultShadowThicknessAndResize()
{
    Widget buttonWidget = (Widget)GetMainWidget();
    bool managed = XtIsManaged( buttonWidget );
    if( managed )
        XtUnmanageChild( buttonWidget );

    XtVaSetValues( buttonWidget,
                   XmNdefaultButtonShadowThickness, 1,
                   NULL );

    if( managed )
        XtManageChild( buttonWidget );

    // this can't currently be done, because user code that calls SetDefault
    // will break otherwise
#if 0
    wxSize best = GetBestSize(), actual = GetSize();
    if( best.x < actual.x ) best.x = actual.x;
    if( best.y < actual.y ) best.y = actual.y;

    if( best != actual )
        SetSize( best );
#endif
    InvalidateBestSize();
}


wxWindow *wxButton::SetDefault()
{
    wxWindow *oldDefault = wxButtonBase::SetDefault();

    // We initially do not set XmNdefaultShadowThickness, to have
    // small buttons.  Unfortunately, buttons are now mis-aligned. We
    // try to correct this now -- setting this ressource to 1 for each
    // button in the same row.  Because it's very hard to find
    // wxButton in the same row, correction is straighforward: we set
    // resource for all wxButton in this parent (but not sub panels)

    wxWindow *parent = GetParent();
    for (wxWindowList::compatibility_iterator node = parent->GetChildren().GetFirst ();
         node; node = node->GetNext ())
    {
        wxWindow *win = node->GetData ();
        wxButton *item = wxDynamicCast(win, wxButton);
        if (item)
            item->SetDefaultShadowThicknessAndResize();
    }

    XtVaSetValues ((Widget) parent->GetMainWidget(),
                   XmNdefaultButton, (Widget) GetMainWidget(),
                   NULL);

    return oldDefault;
}

static inline bool wxMotifLargeButtons()
{
    return wxSystemOptions::HasOption("motif.largebuttons")
        && wxSystemOptions::GetOptionInt("motif.largebuttons") != 0;
}

/* static */
wxSize wxButton::GetDefaultSize()
{
    // TODO: check font size as in wxMSW ?  MB
    // Note: this is the button size (text + margin + shadow + defaultBorder)
    return wxSize( MIN_WIDTH, MIN_LARGE_HEIGHT );
}

wxSize wxButton::DoGetBestSize() const
{
    if( wxMotifLargeButtons() )
        return OldGetBestSize();

    wxSize best = wxControl::DoGetBestSize();

    if( HasFlag( wxBU_EXACTFIT ) )
        return best;
    else if( best.x < MIN_WIDTH )
        best.x = MIN_WIDTH;

    return best;
}

wxSize wxButton::GetMinSize() const
{
    if( wxMotifLargeButtons() )
        return OldGetMinSize();

    return DoGetBestSize();
}

wxSize wxButton::OldGetMinSize() const
{
    return OldGetBestSize();
}

wxSize wxButton::OldGetBestSize() const
{
    Dimension xmargin, ymargin, highlight, shadow, defThickness;

    XtVaGetValues( (Widget)m_mainWidget,
                   XmNmarginWidth, &xmargin,
                   XmNmarginHeight, &ymargin,
                   XmNhighlightThickness, &highlight,
                   XmNshadowThickness, &shadow,
                   XmNdefaultButtonShadowThickness, &defThickness,
                   NULL );

    int x = 0;  int y = 0;
    GetTextExtent( GetLabel(), &x, &y );

    int margin = highlight * 2 +
        ( defThickness ? ( ( shadow + defThickness ) * 4 ) : ( shadow * 2 ) );

    wxSize best( x + xmargin * 2 + margin,
                 y + ymargin * 2 + margin );

    // all buttons have at least the standard size unless the user explicitly
    // wants them to be of smaller size and used wxBU_EXACTFIT style when
    // creating the button
    if( !HasFlag( wxBU_EXACTFIT ) )
    {
        wxSize def = GetDefaultSize();
        int margin =  highlight * 2 +
            ( defThickness ? ( shadow * 4 + defThickness * 4 ) : 0 );
        def.x += margin;
        def.y += margin;

        if( def.x > best.x )
            best.x = def.x;
        if( def.y > best.y )
            best.y = def.y;
    }

    return best;
}

void wxButton::Command (wxCommandEvent & event)
{
    ProcessCommand (event);
}

void wxButtonCallback (Widget w, XtPointer clientData, XtPointer WXUNUSED(ptr))
{
    if (!wxGetWindowFromTable(w))
        // Widget has been deleted!
        return;

    wxButton *item = (wxButton *) clientData;
    wxCommandEvent event (wxEVT_COMMAND_BUTTON_CLICKED, item->GetId());
    event.SetEventObject(item);
    item->ProcessCommand (event);
}
