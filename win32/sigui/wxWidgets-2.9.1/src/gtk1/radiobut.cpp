/////////////////////////////////////////////////////////////////////////////
// Name:        radiobut.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_RADIOBOX

#include "wx/radiobut.h"

#include "wx/gtk1/private.h"

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

extern bool           g_blockEventsOnDrag;
extern wxCursor       g_globalCursor;
extern wxWindowGTK   *g_delayedFocus;

//-----------------------------------------------------------------------------
// "clicked"
//-----------------------------------------------------------------------------

extern "C" {
static
void gtk_radiobutton_clicked_callback( GtkToggleButton *button, wxRadioButton *rb )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (!rb->m_hasVMT) return;

    if (g_blockEventsOnDrag) return;

    if (!button->active) return;

    if (rb->m_blockEvent) return;

    wxCommandEvent event( wxEVT_COMMAND_RADIOBUTTON_SELECTED, rb->GetId());
    event.SetInt( rb->GetValue() );
    event.SetEventObject( rb );
    rb->HandleWindowEvent( event );
}
}

//-----------------------------------------------------------------------------
// wxRadioButton
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxRadioButton,wxControl)

bool wxRadioButton::Create( wxWindow *parent,
                            wxWindowID id,
                            const wxString& label,
                            const wxPoint& pos,
                            const wxSize& size,
                            long style,
                            const wxValidator& validator,
                            const wxString& name )
{
    m_acceptsFocus = TRUE;
    m_needParent = TRUE;

    m_blockEvent = FALSE;

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, validator, name ))
    {
        wxFAIL_MSG( wxT("wxRadioButton creation failed") );
        return FALSE;
    }

    GSList* radioButtonGroup = NULL;
    if (!HasFlag(wxRB_GROUP))
    {
        // search backward for last group start
        wxRadioButton *chief = NULL;
        wxWindowList::compatibility_iterator node = parent->GetChildren().GetLast();
        while (node)
        {
            wxWindow *child = node->GetData();
            if (child->IsRadioButton())
            {
                chief = (wxRadioButton*) child;
                if (child->HasFlag(wxRB_GROUP))
                    break;
            }
            node = node->GetPrevious();
        }
        if (chief)
        {
            // we are part of the group started by chief
            radioButtonGroup = gtk_radio_button_group( GTK_RADIO_BUTTON(chief->m_widget) );
        }
    }

    m_widget = gtk_radio_button_new_with_label( radioButtonGroup, wxGTK_CONV( label ) );

    SetLabel(label);

    gtk_signal_connect( GTK_OBJECT(m_widget), "clicked",
      GTK_SIGNAL_FUNC(gtk_radiobutton_clicked_callback), (gpointer*)this );

    m_parent->DoAddChild( this );

    PostCreation(size);

    return TRUE;
}

void wxRadioButton::SetLabel( const wxString& label )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid radiobutton") );

    GTKSetLabelForLabel(GTK_LABEL(BUTTON_CHILD(m_widget)), label);
}

void wxRadioButton::SetValue( bool val )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid radiobutton") );

    if (val == GetValue())
        return;

    m_blockEvent = TRUE;

    if (val)
    {
        gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON(m_widget), TRUE );
    }
    else
    {
        // should give an assert
        // RL - No it shouldn't.  A wxGenericValidator might try to set it
        //      as FALSE.  Failing silently is probably TRTTD here.
    }

    m_blockEvent = FALSE;
}

bool wxRadioButton::GetValue() const
{
    wxCHECK_MSG( m_widget != NULL, FALSE, wxT("invalid radiobutton") );

    return GTK_TOGGLE_BUTTON(m_widget)->active;
}

bool wxRadioButton::Enable( bool enable )
{
    if ( !wxControl::Enable( enable ) )
        return FALSE;

    gtk_widget_set_sensitive( BUTTON_CHILD(m_widget), enable );

    return TRUE;
}

void wxRadioButton::DoApplyWidgetStyle(GtkRcStyle *style)
{
    gtk_widget_modify_style(m_widget, style);
    gtk_widget_modify_style(BUTTON_CHILD(m_widget), style);
}

bool wxRadioButton::IsOwnGtkWindow( GdkWindow *window )
{
    return window == TOGGLE_BUTTON_EVENT_WIN(m_widget);
}

void wxRadioButton::OnInternalIdle()
{
    wxCursor cursor = m_cursor;
    if (g_globalCursor.Ok()) cursor = g_globalCursor;

    GdkWindow *win = TOGGLE_BUTTON_EVENT_WIN(m_widget);
    if ( win && cursor.Ok())
    {
        /* I now set the cursor the anew in every OnInternalIdle call
       as setting the cursor in a parent window also effects the
       windows above so that checking for the current cursor is
       not possible. */

       gdk_window_set_cursor( win, cursor.GetCursor() );
    }

    if (g_delayedFocus == this)
    {
        if (GTK_WIDGET_REALIZED(m_widget))
        {
            gtk_widget_grab_focus( m_widget );
            g_delayedFocus = NULL;
        }
    }

    if (wxUpdateUIEvent::CanUpdate(this))
        UpdateWindowUI(wxUPDATE_UI_FROMIDLE);
}

wxSize wxRadioButton::DoGetBestSize() const
{
    return wxControl::DoGetBestSize();
}

// static
wxVisualAttributes
wxRadioButton::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    wxVisualAttributes attr;
    // NB: we need toplevel window so that GTK+ can find the right style
    GtkWidget *wnd = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    GtkWidget* widget = gtk_radio_button_new_with_label(NULL, "");
    gtk_container_add(GTK_CONTAINER(wnd), widget);
    attr = GetDefaultAttributesFromGTKWidget(widget);
    gtk_widget_destroy(wnd);
    return attr;
}


#endif
