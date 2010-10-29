/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/statbox.cpp
// Purpose:     wxStaticBox
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/statbox.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Frame.h>
#include <Xm/Label.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxStaticBox, wxControl)

BEGIN_EVENT_TABLE(wxStaticBox, wxControl)
//EVT_ERASE_BACKGROUND(wxStaticBox::OnEraseBackground)
END_EVENT_TABLE()

// ----------------------------------------------------------------------------
// wxXmSizeKeeper
// ----------------------------------------------------------------------------

// helper class to reduce code duplication
class wxXmSizeKeeper
{
    Dimension m_x, m_y;
    Widget m_widget;
public:
    wxXmSizeKeeper( Widget w )
        : m_widget( w )
    {
        XtVaGetValues( m_widget,
                       XmNwidth, &m_x,
                       XmNheight, &m_y,
                       NULL );
    }

    void Restore()
    {
        int x, y;

        XtVaGetValues( m_widget,
                       XmNwidth, &x,
                       XmNheight, &y,
                       NULL );
        if( x != m_x || y != m_y )
            XtVaSetValues( m_widget,
                           XmNwidth, m_x,
                           XmNheight, m_y,
                           NULL );
    }
};

/*
 * Static box
 */

wxStaticBox::wxStaticBox()
{
    m_labelWidget = (WXWidget) 0;
}

bool wxStaticBox::Create(wxWindow *parent, wxWindowID id,
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

    m_mainWidget = XtVaCreateManagedWidget ("staticboxframe",
            xmFrameWidgetClass, parentWidget,
            // MBN: why override default?
            // XmNshadowType, XmSHADOW_IN,
            NULL);

    if (!label.empty())
    {
        wxString label1(GetLabelText(label));
        wxXmString text(label1);
        Display* dpy = XtDisplay( parentWidget );

        m_labelWidget = (WXWidget) XtVaCreateManagedWidget ("staticboxlabel",
                xmLabelWidgetClass, (Widget)m_mainWidget,
                wxFont::GetFontTag(), m_font.GetFontTypeC(dpy),
                XmNlabelString, text(),
#if wxCHECK_MOTIF_VERSION( 2, 0 )
                XmNframeChildType, XmFRAME_TITLE_CHILD,
#else
                XmNchildType, XmFRAME_TITLE_CHILD,
#endif
                NULL);
    }

    PostCreation();
    AttachWidget (parent, m_mainWidget, NULL, pos.x, pos.y, size.x, size.y);

    return true;
}

wxStaticBox::~wxStaticBox()
{
   DetachWidget(m_mainWidget);
   XtDestroyWidget((Widget) m_mainWidget);

   m_mainWidget = (WXWidget) 0;
   m_labelWidget = (WXWidget) 0;
}

void wxStaticBox::SetLabel( const wxString& label )
{
    wxXmSizeKeeper sk( (Widget)GetMainWidget() );

    wxStaticBoxBase::SetLabel( label );

    sk.Restore();
}

void wxStaticBox::GetBordersForSizer(int *borderTop, int *borderOther) const
{
    Dimension shadow, border;

    XtVaGetValues( (Widget) GetMainWidget(),
                   XmNshadowThickness, &shadow,
                   XmNborderWidth, &border,
                   NULL);

    *borderOther = shadow + border;

    if( GetLabelWidget() )
    {
        XtWidgetGeometry preferred;
        XtQueryGeometry( (Widget) GetLabelWidget(), NULL, &preferred );

        *borderTop = preferred.height;
    }
    else
    {
        *borderTop = shadow;
    }
}
