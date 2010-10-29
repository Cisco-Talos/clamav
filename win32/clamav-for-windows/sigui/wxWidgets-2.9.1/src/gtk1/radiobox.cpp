/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/radiobox.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_RADIOBOX

#include "wx/radiobox.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/frame.h"
    #include "wx/dialog.h"
#endif

#include "wx/gtk1/private.h"
#include <gdk/gdkkeysyms.h>

#include "wx/gtk1/win_gtk.h"

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

extern bool          g_blockEventsOnDrag;
extern wxWindowGTK  *g_delayedFocus;

//-----------------------------------------------------------------------------
// "clicked"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_radiobutton_clicked_callback( GtkToggleButton *button, wxRadioBox *rb )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (!rb->m_hasVMT) return;
    if (g_blockEventsOnDrag) return;

    if (!button->active) return;

    wxCommandEvent event( wxEVT_COMMAND_RADIOBOX_SELECTED, rb->GetId() );
    event.SetInt( rb->GetSelection() );
    event.SetString( rb->GetStringSelection() );
    event.SetEventObject( rb );
    rb->HandleWindowEvent(event);
}
}

//-----------------------------------------------------------------------------
// "key_press_event"
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_radiobox_keypress_callback( GtkWidget *widget, GdkEventKey *gdk_event, wxRadioBox *rb )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (!rb->m_hasVMT) return FALSE;
    if (g_blockEventsOnDrag) return FALSE;

    if ((gdk_event->keyval != GDK_Up) &&
        (gdk_event->keyval != GDK_Down) &&
        (gdk_event->keyval != GDK_Left) &&
        (gdk_event->keyval != GDK_Right))
    {
        return FALSE;
    }

    wxList::compatibility_iterator node = rb->m_boxes.Find( (wxObject*) widget );
    if (!node)
    {
        return FALSE;
    }

    gtk_signal_emit_stop_by_name( GTK_OBJECT(widget), "key_press_event" );

    if ((gdk_event->keyval == GDK_Up) ||
        (gdk_event->keyval == GDK_Left))
    {
        if (node == rb->m_boxes.GetFirst())
            node = rb->m_boxes.GetLast();
        else
            node = node->GetPrevious();
    }
    else
    {
        if (node == rb->m_boxes.GetLast())
            node = rb->m_boxes.GetFirst();
        else
            node = node->GetNext();
    }

    GtkWidget *button = (GtkWidget*) node->GetData();

    gtk_widget_grab_focus( button );

    return TRUE;
}
}

extern "C" {
static gint gtk_radiobutton_focus_in( GtkWidget *WXUNUSED(widget),
                                      GdkEvent *WXUNUSED(event),
                                      wxRadioBox *win )
{
    if ( win->m_lostFocus )
    {
        // no, we didn't really lose it
        win->m_lostFocus = FALSE;
    }
    else if ( !win->m_hasFocus )
    {
        win->m_hasFocus = true;

        wxFocusEvent event( wxEVT_SET_FOCUS, win->GetId() );
        event.SetEventObject( win );

        // never stop the signal emission, it seems to break the kbd handling
        // inside the radiobox
        (void)win->HandleWindowEvent( event );
    }

    return FALSE;
}
}

extern "C" {
static gint gtk_radiobutton_focus_out( GtkWidget *WXUNUSED(widget),
                                       GdkEvent *WXUNUSED(event),
                                       wxRadioBox *win )
{
  //    wxASSERT_MSG( win->m_hasFocus, wxT("got focus out without any focus in?") );
  // Replace with a warning, else we dump core a lot!
  //  if (!win->m_hasFocus)
  //      wxLogWarning(wxT("Radiobox got focus out without any focus in.") );

    // we might have lost the focus, but may be not - it may have just gone to
    // another button in the same radiobox, so we'll check for it in the next
    // idle iteration (leave m_hasFocus == true for now)
    win->m_lostFocus = true;

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// wxRadioBox
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxRadioBox,wxControl)

void wxRadioBox::Init()
{
    m_needParent = true;
    m_acceptsFocus = true;

    m_hasFocus =
    m_lostFocus = false;
}

bool wxRadioBox::Create( wxWindow *parent, wxWindowID id,
                         const wxString& title,
                         const wxPoint &pos, const wxSize &size,
                         const wxArrayString& choices, int majorDim,
                         long style, const wxValidator& validator,
                         const wxString &name )
{
    wxCArrayString chs(choices);

    return Create( parent, id, title, pos, size, chs.GetCount(),
                   chs.GetStrings(), majorDim, style, validator, name );
}

bool wxRadioBox::Create( wxWindow *parent, wxWindowID id, const wxString& title,
                         const wxPoint &pos, const wxSize &size,
                         int n, const wxString choices[], int majorDim,
                         long style, const wxValidator& validator,
                         const wxString &name )
{
    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, validator, name ))
    {
        wxFAIL_MSG( wxT("wxRadioBox creation failed") );
        return false;
    }

    m_widget = gtk_frame_new(NULL);
    SetLabel(title);
    if ( HasFlag(wxNO_BORDER) )
    {
        // If we don't do this here, the wxNO_BORDER style is ignored in Show()
        gtk_frame_set_shadow_type(GTK_FRAME(m_widget), GTK_SHADOW_NONE);
    }

    // majorDim may be 0 if all trailing parameters were omitted, so don't
    // assert here but just use the correct value for it
    SetMajorDim(majorDim == 0 ? n : majorDim, style);


    unsigned int num_of_cols = GetColumnCount();
    unsigned int num_of_rows = GetRowCount();

    GtkRadioButton *m_radio = NULL;

    GtkWidget *table = gtk_table_new( num_of_rows, num_of_cols, FALSE );
    gtk_table_set_col_spacings( GTK_TABLE(table), 1 );
    gtk_table_set_row_spacings( GTK_TABLE(table), 1 );
    gtk_widget_show( table );
    gtk_container_add( GTK_CONTAINER(m_widget), table );

    wxString label;
    GSList *radio_button_group = NULL;
    for (int i = 0; i < n; i++)
    {
        if ( i != 0 )
            radio_button_group = gtk_radio_button_group( GTK_RADIO_BUTTON(m_radio) );

        label.Empty();
        for ( const wxChar *pc = choices[i]; *pc; pc++ )
        {
            if ( *pc != wxT('&') )
                label += *pc;
        }

        m_radio = GTK_RADIO_BUTTON( gtk_radio_button_new_with_label( radio_button_group, wxGTK_CONV( label ) ) );
        gtk_widget_show( GTK_WIDGET(m_radio) );

        gtk_signal_connect( GTK_OBJECT(m_radio), "key_press_event",
           GTK_SIGNAL_FUNC(gtk_radiobox_keypress_callback), (gpointer)this );

        m_boxes.Append( (wxObject*) m_radio );

        if (HasFlag(wxRA_SPECIFY_COLS))
        {
            int left = i%num_of_cols;
            int right = (i%num_of_cols) + 1;
            int top = i/num_of_cols;
            int bottom = (i/num_of_cols)+1;
            gtk_table_attach( GTK_TABLE(table), GTK_WIDGET(m_radio), left, right, top, bottom,
                  GTK_FILL, GTK_FILL, 1, 1 );
        }
        else
        {
            int left = i/num_of_rows;
            int right = (i/num_of_rows) + 1;
            int top = i%num_of_rows;
            int bottom = (i%num_of_rows)+1;
            gtk_table_attach( GTK_TABLE(table), GTK_WIDGET(m_radio), left, right, top, bottom,
                  GTK_FILL, GTK_FILL, 1, 1 );
        }

        ConnectWidget( GTK_WIDGET(m_radio) );

        if (!i) gtk_toggle_button_set_state( GTK_TOGGLE_BUTTON(m_radio), TRUE );

        gtk_signal_connect( GTK_OBJECT(m_radio), "clicked",
            GTK_SIGNAL_FUNC(gtk_radiobutton_clicked_callback), (gpointer*)this );

        gtk_signal_connect( GTK_OBJECT(m_radio), "focus_in_event",
            GTK_SIGNAL_FUNC(gtk_radiobutton_focus_in), (gpointer)this );

        gtk_signal_connect( GTK_OBJECT(m_radio), "focus_out_event",
            GTK_SIGNAL_FUNC(gtk_radiobutton_focus_out), (gpointer)this );
    }

    m_parent->DoAddChild( this );

    PostCreation(size);

    return true;
}

wxRadioBox::~wxRadioBox()
{
    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        GtkWidget *button = GTK_WIDGET( node->GetData() );
        gtk_widget_destroy( button );
        node = node->GetNext();
    }
}

bool wxRadioBox::Show(bool show)
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid radiobox") );

    if (!wxControl::Show(show))
    {
        // nothing to do
        return false;
    }

    if ( HasFlag(wxNO_BORDER) )
        gtk_widget_hide( m_widget );

    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        GtkWidget *button = GTK_WIDGET( node->GetData() );

        if (show)
            gtk_widget_show( button );
        else
            gtk_widget_hide( button );

        node = node->GetNext();
    }

    return true;
}

void wxRadioBox::SetFocus()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid radiobox") );

    if (m_boxes.GetCount() == 0) return;

    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        GtkToggleButton *button = GTK_TOGGLE_BUTTON( node->GetData() );
        if (button->active)
        {
            gtk_widget_grab_focus( GTK_WIDGET(button) );
            return;
        }
        node = node->GetNext();
    }
}

void wxRadioBox::SetSelection( int n )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid radiobox") );

    wxList::compatibility_iterator node = m_boxes.Item( n );

    wxCHECK_RET( node, wxT("radiobox wrong index") );

    GtkToggleButton *button = GTK_TOGGLE_BUTTON( node->GetData() );

    GtkDisableEvents();

    gtk_toggle_button_set_active( button, 1 );

    GtkEnableEvents();
}

int wxRadioBox::GetSelection(void) const
{
    wxCHECK_MSG( m_widget != NULL, wxNOT_FOUND, wxT("invalid radiobox") );

    int count = 0;

    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        GtkToggleButton *button = GTK_TOGGLE_BUTTON( node->GetData() );
        if (button->active) return count;
        count++;
        node = node->GetNext();
    }

    wxFAIL_MSG( wxT("wxRadioBox none selected") );

    return wxNOT_FOUND;
}

wxString wxRadioBox::GetString(unsigned int n) const
{
    wxCHECK_MSG( m_widget != NULL, wxEmptyString, wxT("invalid radiobox") );

    wxList::compatibility_iterator node = m_boxes.Item( n );

    wxCHECK_MSG( node, wxEmptyString, wxT("radiobox wrong index") );

    GtkLabel *label = GTK_LABEL( BUTTON_CHILD(node->GetData()) );

    wxString str( label->label );

    return str;
}

void wxRadioBox::SetLabel( const wxString& label )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid radiobox") );

    GTKSetLabelForFrame(GTK_FRAME(m_widget), label);
}

void wxRadioBox::SetString(unsigned int item, const wxString& label)
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid radiobox") );

    wxList::compatibility_iterator node = m_boxes.Item( item );

    wxCHECK_RET( node, wxT("radiobox wrong index") );

    GtkLabel *g_label = GTK_LABEL( BUTTON_CHILD(node->GetData()) );

    gtk_label_set( g_label, wxGTK_CONV( label ) );
}

bool wxRadioBox::Enable( bool enable )
{
    if ( !wxControl::Enable( enable ) )
        return false;

    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        GtkButton *button = GTK_BUTTON( node->GetData() );
        GtkLabel *label = GTK_LABEL( BUTTON_CHILD(button) );

        gtk_widget_set_sensitive( GTK_WIDGET(button), enable );
        gtk_widget_set_sensitive( GTK_WIDGET(label), enable );
        node = node->GetNext();
    }

    return true;
}

bool wxRadioBox::Enable(unsigned int item, bool enable)
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid radiobox") );

    wxList::compatibility_iterator node = m_boxes.Item( item );

    wxCHECK_MSG( node, false, wxT("radiobox wrong index") );

    GtkButton *button = GTK_BUTTON( node->GetData() );
    GtkLabel *label = GTK_LABEL( BUTTON_CHILD(button) );

    gtk_widget_set_sensitive( GTK_WIDGET(button), enable );
    gtk_widget_set_sensitive( GTK_WIDGET(label), enable );

    return true;
}

bool wxRadioBox::IsItemEnabled(unsigned int item) const
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid radiobox") );

    wxList::compatibility_iterator node = m_boxes.Item( item );

    wxCHECK_MSG( node, false, wxT("radiobox wrong index") );

    GtkButton *button = GTK_BUTTON( node->GetData() );

    // don't use GTK_WIDGET_IS_SENSITIVE() here, we want to return true even if
    // the parent radiobox is disabled
    return GTK_WIDGET_SENSITIVE(GTK_WIDGET(button));
}

bool wxRadioBox::Show(unsigned int item, bool show)
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid radiobox") );

    wxList::compatibility_iterator node = m_boxes.Item( item );

    wxCHECK_MSG( node, false, wxT("radiobox wrong index") );

    GtkWidget *button = GTK_WIDGET( node->GetData() );

    if (show)
        gtk_widget_show( button );
    else
        gtk_widget_hide( button );

    return true;
}

bool wxRadioBox::IsItemShown(unsigned int item) const
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid radiobox") );

    wxList::compatibility_iterator node = m_boxes.Item( item );

    wxCHECK_MSG( node, false, wxT("radiobox wrong index") );

    GtkButton *button = GTK_BUTTON( node->GetData() );

    return GTK_WIDGET_VISIBLE(GTK_WIDGET(button));
}

unsigned int wxRadioBox::GetCount() const
{
    return m_boxes.GetCount();
}

void wxRadioBox::GtkDisableEvents()
{
    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        gtk_signal_disconnect_by_func( GTK_OBJECT(node->GetData()),
           GTK_SIGNAL_FUNC(gtk_radiobutton_clicked_callback), (gpointer*)this );

        node = node->GetNext();
    }
}

void wxRadioBox::GtkEnableEvents()
{
    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        gtk_signal_connect( GTK_OBJECT(node->GetData()), "clicked",
           GTK_SIGNAL_FUNC(gtk_radiobutton_clicked_callback), (gpointer*)this );

        node = node->GetNext();
    }
}

void wxRadioBox::DoApplyWidgetStyle(GtkRcStyle *style)
{
    gtk_widget_modify_style( m_widget, style );

    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        GtkWidget *widget = GTK_WIDGET( node->GetData() );

        gtk_widget_modify_style( widget, style );
        gtk_widget_modify_style( BUTTON_CHILD(node->GetData()), style );

        node = node->GetNext();
    }
}

#if wxUSE_TOOLTIPS
void wxRadioBox::ApplyToolTip( GtkTooltips *tips, const wxChar *tip )
{
    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        GtkWidget *widget = GTK_WIDGET( node->GetData() );
        gtk_tooltips_set_tip( tips, widget, wxConvCurrent->cWX2MB(tip), NULL );
        node = node->GetNext();
    }
}
#endif // wxUSE_TOOLTIPS

bool wxRadioBox::IsOwnGtkWindow( GdkWindow *window )
{
    if (window == m_widget->window)
        return true;

    wxList::compatibility_iterator node = m_boxes.GetFirst();
    while (node)
    {
        GtkWidget *button = GTK_WIDGET( node->GetData() );

        if (window == button->window)
            return true;

        node = node->GetNext();
    }

    return false;
}

void wxRadioBox::OnInternalIdle()
{
    if ( m_lostFocus )
    {
        m_hasFocus = false;
        m_lostFocus = false;

        wxFocusEvent event( wxEVT_KILL_FOCUS, GetId() );
        event.SetEventObject( this );

        (void)HandleWindowEvent( event );
    }

    if (g_delayedFocus == this)
    {
        if (GTK_WIDGET_REALIZED(m_widget))
        {
            g_delayedFocus = NULL;
            SetFocus();
        }
    }
}

// static
wxVisualAttributes
wxRadioBox::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
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

#endif // wxUSE_RADIOBOX
