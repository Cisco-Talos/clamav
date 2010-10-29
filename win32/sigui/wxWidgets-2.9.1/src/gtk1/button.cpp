/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/button.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_BUTTON

#ifndef WX_PRECOMP
    #include "wx/button.h"
#endif

#include "wx/stockitem.h"

#include "wx/gtk1/private.h"
#include "wx/gtk1/win_gtk.h"

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class wxButton;

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

extern bool   g_blockEventsOnDrag;

//-----------------------------------------------------------------------------
// "clicked"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_button_clicked_callback( GtkWidget *WXUNUSED(widget), wxButton *button )
{
    if (g_isIdle)
       wxapp_install_idle_handler();

    if (!button->m_hasVMT) return;
    if (g_blockEventsOnDrag) return;

    wxCommandEvent event(wxEVT_COMMAND_BUTTON_CLICKED, button->GetId());
    event.SetEventObject(button);
    button->HandleWindowEvent(event);
}
}

//-----------------------------------------------------------------------------
// "style_set" from m_widget
//-----------------------------------------------------------------------------

static gint
gtk_button_style_set_callback( GtkWidget *m_widget, GtkStyle *WXUNUSED(style), wxButton *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    int left_border = 0;
    int right_border = 0;
    int top_border = 0;
    int bottom_border = 0;

    /* the default button has a border around it */
    if (GTK_WIDGET_CAN_DEFAULT(m_widget))
    {
        left_border = 6;
        right_border = 6;
        top_border = 6;
        bottom_border = 5;
        win->DoMoveWindow( win->m_x-top_border,
                           win->m_y-left_border,
                           win->m_width+left_border+right_border,
                           win->m_height+top_border+bottom_border );
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// wxButton
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxButton,wxControl)

wxButton::wxButton()
{
}

wxButton::~wxButton()
{
}

bool wxButton::Create(  wxWindow *parent, wxWindowID id, const wxString &label,
      const wxPoint &pos, const wxSize &size,
      long style, const wxValidator& validator, const wxString &name )
{
    m_needParent = true;
    m_acceptsFocus = true;

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, validator, name ))
    {
        wxFAIL_MSG( wxT("wxButton creation failed") );
        return false;
    }

    m_widget = gtk_button_new_with_label("");

    float x_alignment = 0.5;
    if (HasFlag(wxBU_LEFT))
        x_alignment = 0.0;
    else if (HasFlag(wxBU_RIGHT))
        x_alignment = 1.0;

    float y_alignment = 0.5;
    if (HasFlag(wxBU_TOP))
        y_alignment = 0.0;
    else if (HasFlag(wxBU_BOTTOM))
        y_alignment = 1.0;

    if (GTK_IS_MISC(BUTTON_CHILD(m_widget)))
        gtk_misc_set_alignment (GTK_MISC (BUTTON_CHILD (m_widget)),
                                x_alignment, y_alignment);

    SetLabel(label);

    if (style & wxNO_BORDER)
       gtk_button_set_relief( GTK_BUTTON(m_widget), GTK_RELIEF_NONE );

    gtk_signal_connect_after( GTK_OBJECT(m_widget), "clicked",
      GTK_SIGNAL_FUNC(gtk_button_clicked_callback), (gpointer*)this );

    gtk_signal_connect_after( GTK_OBJECT(m_widget), "style_set",
      GTK_SIGNAL_FUNC(gtk_button_style_set_callback), (gpointer*) this );

    m_parent->DoAddChild( this );

    PostCreation(size);

    return true;
}


wxWindow *wxButton::SetDefault()
{
    wxWindow *oldDefault = wxButtonBase::SetDefault();

    GTK_WIDGET_SET_FLAGS( m_widget, GTK_CAN_DEFAULT );
    gtk_widget_grab_default( m_widget );

    // resize for default border
    gtk_button_style_set_callback( m_widget, NULL, this );

    return oldDefault;
}

/* static */
wxSize wxButtonBase::GetDefaultSize()
{
    return wxSize(80,26);
}

void wxButton::SetLabel( const wxString &lbl )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid button") );

    wxString label(lbl);

    if (label.empty() && wxIsStockID(m_windowId))
        label = wxGetStockLabel(m_windowId);

    wxControl::SetLabel(label);

    const wxString labelGTK = GTKRemoveMnemonics(label);

    gtk_label_set(GTK_LABEL(BUTTON_CHILD(m_widget)), wxGTK_CONV(labelGTK));
}

bool wxButton::Enable( bool enable )
{
    if ( !wxControl::Enable( enable ) )
        return false;

    gtk_widget_set_sensitive( BUTTON_CHILD(m_widget), enable );

    return true;
}

bool wxButton::IsOwnGtkWindow( GdkWindow *window )
{
    return (window == m_widget->window);
}

void wxButton::DoApplyWidgetStyle(GtkRcStyle *style)
{
    gtk_widget_modify_style(m_widget, style);
    gtk_widget_modify_style(BUTTON_CHILD(m_widget), style);
}

wxSize wxButton::DoGetBestSize() const
{
    // the default button in wxGTK is bigger than the other ones because of an
    // extra border around it, but we don't want to take it into account in
    // our size calculations (otherwsie the result is visually ugly), so
    // always return the size of non default button from here
    const bool isDefault = GTK_WIDGET_HAS_DEFAULT(m_widget);
    if ( isDefault )
    {
        // temporarily unset default flag
        GTK_WIDGET_UNSET_FLAGS( m_widget, GTK_CAN_DEFAULT );
    }

    wxSize ret( wxControl::DoGetBestSize() );

    if ( isDefault )
    {
        // set it back again
        GTK_WIDGET_SET_FLAGS( m_widget, GTK_CAN_DEFAULT );
    }

    ret.x += 10;  // add a few pixels for sloppy (but common) themes

    if (!HasFlag(wxBU_EXACTFIT))
    {
        wxSize defaultSize = GetDefaultSize();
        if (ret.x < defaultSize.x) ret.x = defaultSize.x;
        if (ret.y < defaultSize.y) ret.y = defaultSize.y;
    }

    CacheBestSize(ret);
    return ret;
}

// static
wxVisualAttributes
wxButton::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    return GetDefaultAttributesFromGTKWidget(gtk_button_new);
}

#endif // wxUSE_BUTTON
