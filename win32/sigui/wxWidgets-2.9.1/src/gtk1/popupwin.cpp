/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/popupwin.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_POPUPWIN

#include "wx/popupwin.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/frame.h"
    #include "wx/cursor.h"
#endif // WX_PRECOMP

#include <gdk/gdk.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include "wx/gtk1/win_gtk.h"

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

//-----------------------------------------------------------------------------
// "button_press"
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_popup_button_press (GtkWidget *widget, GdkEvent *gdk_event, wxPopupWindow* win )
{
    GtkWidget *child = gtk_get_event_widget (gdk_event);

  /* We don't ask for button press events on the grab widget, so
   *  if an event is reported directly to the grab widget, it must
   *  be on a window outside the application (and thus we remove
   *  the popup window). Otherwise, we check if the widget is a child
   *  of the grab widget, and only remove the popup window if it
   *  is not.
   */
    if (child != widget)
    {
        while (child)
        {
            if (child == widget)
                return FALSE;
            child = child->parent;
        }
    }

    wxFocusEvent event( wxEVT_KILL_FOCUS, win->GetId() );
    event.SetEventObject( win );

    (void)win->HandleWindowEvent( event );

    return TRUE;
}
}

//-----------------------------------------------------------------------------
// "focus" from m_window
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_dialog_focus_callback( GtkWidget *widget, GtkDirectionType WXUNUSED(d), wxWindow *WXUNUSED(win) )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    // This disables GTK's tab traversal
    gtk_signal_emit_stop_by_name( GTK_OBJECT(widget), "focus" );
    return TRUE;
}
}

//-----------------------------------------------------------------------------
// "delete_event"
//-----------------------------------------------------------------------------

extern "C" {
bool gtk_dialog_delete_callback( GtkWidget *WXUNUSED(widget), GdkEvent *WXUNUSED(event), wxPopupWindow *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (win->IsEnabled())
        win->Close();

    return TRUE;
}
}

//-----------------------------------------------------------------------------
// "realize" from m_widget
//-----------------------------------------------------------------------------

/* we cannot MWM hints and icons before the widget has been realized,
   so we do this directly after realization */

extern "C" {
static gint
gtk_dialog_realized_callback( GtkWidget * WXUNUSED(widget), wxPopupWindow *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    /* all this is for Motif Window Manager "hints" and is supposed to be
       recognized by other WM as well. not tested. */
    long decor = (long) GDK_DECOR_BORDER;
    long func = (long) GDK_FUNC_MOVE ;

    gdk_window_set_decorations( win->m_widget->window, (GdkWMDecoration)decor);
    gdk_window_set_functions( win->m_widget->window, (GdkWMFunction)func);

    gtk_window_set_policy(GTK_WINDOW(win->m_widget), 0, 0, 1);

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// InsertChild for wxPopupWindow
//-----------------------------------------------------------------------------

/* Callback for wxFrame. This very strange beast has to be used because
 * C++ has no virtual methods in a constructor. We have to emulate a
 * virtual function here as wxWidgets requires different ways to insert
 * a child in container classes. */

static void wxInsertChildInDialog( wxPopupWindow* parent, wxWindow* child )
{
    gtk_pizza_put( GTK_PIZZA(parent->m_wxwindow),
                   GTK_WIDGET(child->m_widget),
                   child->m_x,
                   child->m_y,
                   child->m_width,
                   child->m_height );

    if (parent->HasFlag(wxTAB_TRAVERSAL))
    {
        /* we now allow a window to get the focus as long as it
           doesn't have any children. */
        GTK_WIDGET_UNSET_FLAGS( parent->m_wxwindow, GTK_CAN_FOCUS );
    }
}

//-----------------------------------------------------------------------------
// wxPopupWindow
//-----------------------------------------------------------------------------

BEGIN_EVENT_TABLE(wxPopupWindow,wxPopupWindowBase)
#ifdef __WXUNIVERSAL__
    EVT_SIZE(wxPopupWindow::OnSize)
#endif
END_EVENT_TABLE()

wxPopupWindow::~wxPopupWindow()
{
}

bool wxPopupWindow::Create( wxWindow *parent, int style )
{
    m_needParent = false;

    if (!PreCreation( parent, wxDefaultPosition, wxDefaultSize ) ||
        !CreateBase( parent, -1, wxDefaultPosition, wxDefaultSize, style, wxDefaultValidator, wxT("popup") ))
    {
        wxFAIL_MSG( wxT("wxPopupWindow creation failed") );
        return false;
    }

    // Unlike windows, top level windows are created hidden by default.
    m_isShown = false;

    // All dialogs should really have this style
    m_windowStyle |= wxTAB_TRAVERSAL;

    m_insertCallback = (wxInsertChildFunction) wxInsertChildInDialog;

    m_widget = gtk_window_new( GTK_WINDOW_POPUP );

    if ((m_parent) && (GTK_IS_WINDOW(m_parent->m_widget)))
        gtk_window_set_transient_for( GTK_WINDOW(m_widget), GTK_WINDOW(m_parent->m_widget) );

    GTK_WIDGET_UNSET_FLAGS( m_widget, GTK_CAN_FOCUS );

    gtk_signal_connect( GTK_OBJECT(m_widget), "delete_event",
        GTK_SIGNAL_FUNC(gtk_dialog_delete_callback), (gpointer)this );

    m_wxwindow = gtk_pizza_new();
    gtk_widget_show( m_wxwindow );
    GTK_WIDGET_UNSET_FLAGS( m_wxwindow, GTK_CAN_FOCUS );

    gtk_container_add( GTK_CONTAINER(m_widget), m_wxwindow );

    if (m_parent) m_parent->AddChild( this );

    PostCreation();

    /*  we cannot set MWM hints  before the widget has
        been realized, so we do this directly after realization */
    gtk_signal_connect( GTK_OBJECT(m_widget), "realize",
                        GTK_SIGNAL_FUNC(gtk_dialog_realized_callback), (gpointer) this );

    // disable native tab traversal
    gtk_signal_connect( GTK_OBJECT(m_widget), "focus",
        GTK_SIGNAL_FUNC(gtk_dialog_focus_callback), (gpointer)this );

    gtk_signal_connect (GTK_OBJECT(m_widget), "button_press_event",
        GTK_SIGNAL_FUNC(gtk_popup_button_press), (gpointer)this );

    return true;
}

void wxPopupWindow::DoMoveWindow(int WXUNUSED(x), int WXUNUSED(y), int WXUNUSED(width), int WXUNUSED(height) )
{
    wxFAIL_MSG( wxT("DoMoveWindow called for wxPopupWindow") );
}

void wxPopupWindow::DoSetSize( int x, int y, int width, int height, int sizeFlags )
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid dialog") );
    wxASSERT_MSG( (m_wxwindow != NULL), wxT("invalid dialog") );

    if (m_resizing) return; /* I don't like recursions */
    m_resizing = true;

    int old_x = m_x;
    int old_y = m_y;

    int old_width = m_width;
    int old_height = m_height;

    if ((sizeFlags & wxSIZE_ALLOW_MINUS_ONE) == 0)
    {
        if (x != -1) m_x = x;
        if (y != -1) m_y = y;
        if (width != -1) m_width = width;
        if (height != -1) m_height = height;
    }
    else
    {
        m_x = x;
        m_y = y;
        m_width = width;
        m_height = height;
    }

/*
    if ((sizeFlags & wxSIZE_AUTO_WIDTH) == wxSIZE_AUTO_WIDTH)
    {
        if (width == -1) m_width = 80;
    }

    if ((sizeFlags & wxSIZE_AUTO_HEIGHT) == wxSIZE_AUTO_HEIGHT)
    {
       if (height == -1) m_height = 26;
    }
*/

    int minWidth = GetMinWidth(),
        minHeight = GetMinHeight(),
        maxWidth = GetMaxWidth(),
        maxHeight = GetMaxHeight();

    if ((minWidth != -1) && (m_width < minWidth)) m_width = minWidth;
    if ((minHeight != -1) && (m_height < minHeight)) m_height = minHeight;
    if ((maxWidth != -1) && (m_width > maxWidth)) m_width = maxWidth;
    if ((maxHeight != -1) && (m_height > maxHeight)) m_height = maxHeight;

    if ((m_x != -1) || (m_y != -1))
    {
        if ((m_x != old_x) || (m_y != old_y))
        {
            /* we set the position here and when showing the dialog
               for the first time in idle time */
            gtk_widget_set_uposition( m_widget, m_x, m_y );
        }
    }

    if ((m_width != old_width) || (m_height != old_height))
    {
        gtk_widget_set_usize( m_widget, m_width, m_height );

        /* actual resizing is deferred to GtkOnSize in idle time and
           when showing the dialog */
        m_sizeSet = false;

    }

    m_resizing = false;
}

void wxPopupWindow::GtkOnSize( int WXUNUSED(x), int WXUNUSED(y), int width, int height )
{
    // due to a bug in gtk, x,y are always 0
    // m_x = x;
    // m_y = y;

    if ((m_height == height) && (m_width == width) && (m_sizeSet)) return;
    if (!m_wxwindow) return;

    m_width = width;
    m_height = height;

    /* FIXME: is this a hack? */
    /* Since for some reason GTK will revert to using maximum size ever set
       for this window, we have to set geometry hints maxsize to match size
       given. Also set the to that minsize since resizing isn't possible
       anyway. */

    /* set size hints */
    gint flag = GDK_HINT_MAX_SIZE | GDK_HINT_MIN_SIZE; // GDK_HINT_POS;
    GdkGeometry geom;
    geom.min_width = m_width;
    geom.min_height = m_height;
    geom.max_width = m_width;
    geom.max_height = m_height;
    gtk_window_set_geometry_hints( GTK_WINDOW(m_widget),
                                   NULL,
                                   &geom,
                                   (GdkWindowHints) flag );


    m_sizeSet = true;

    wxSizeEvent event( wxSize(m_width,m_height), GetId() );
    event.SetEventObject( this );
    HandleWindowEvent( event );
}

void wxPopupWindow::OnInternalIdle()
{
    if (!m_sizeSet && GTK_WIDGET_REALIZED(m_wxwindow))
        GtkOnSize( m_x, m_y, m_width, m_height );

    wxWindow::OnInternalIdle();
}

bool wxPopupWindow::Show( bool show )
{
    if (show && !m_sizeSet)
    {
        /* by calling GtkOnSize here, we don't have to call
           either after showing the frame, which would entail
           much ugly flicker nor from within the size_allocate
           handler, because GTK 1.1.X forbids that. */

        GtkOnSize( m_x, m_y, m_width, m_height );
    }

    bool ret = wxWindow::Show( show );

    return ret;
}

#endif // wxUSE_POPUPWIN
