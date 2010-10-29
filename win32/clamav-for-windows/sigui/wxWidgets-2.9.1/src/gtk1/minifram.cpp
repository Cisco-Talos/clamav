/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/minifram.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_MINIFRAME

#include "wx/minifram.h"

#ifndef WX_PRECOMP
    #include "wx/dcscreen.h"
#endif

#include "gtk/gtk.h"
#include "wx/dcclient.h"
#include "wx/gtk1/win_gtk.h"
#include "wx/gtk1/private.h"
#include "wx/gtk1/dcclient.h"

#include <gdk/gdk.h>
#include <gdk/gdkprivate.h>
#include <gdk/gdkx.h>

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

extern bool        g_blockEventsOnDrag;
extern bool        g_blockEventsOnScroll;
extern GtkWidget  *wxGetRootWindow();

//-----------------------------------------------------------------------------
// local functions
//-----------------------------------------------------------------------------

/* draw XOR rectangle when moving mine frame around */

static void DrawFrame( GtkWidget *widget, int x, int y, int w, int h )
{
    int org_x = 0;
    int org_y = 0;
    gdk_window_get_origin( widget->window, &org_x, &org_y );
    x += org_x;
    y += org_y;

    GdkGC *gc = gdk_gc_new( GDK_ROOT_PARENT() );
    gdk_gc_set_subwindow( gc, GDK_INCLUDE_INFERIORS );
    gdk_gc_set_function( gc, GDK_INVERT );

    gdk_draw_rectangle( GDK_ROOT_PARENT(), gc, FALSE, x, y, w, h );
    gdk_gc_unref( gc );
}

//-----------------------------------------------------------------------------
// "expose_event" of m_mainWidget
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_window_own_expose_callback( GtkWidget *widget, GdkEventExpose *gdk_event, wxFrame *win )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (!win->m_hasVMT) return;
    if (gdk_event->count > 0) return;

    GtkPizza *pizza = GTK_PIZZA(widget);

    gtk_draw_shadow( widget->style,
                     pizza->bin_window,
                     GTK_STATE_NORMAL,
                     GTK_SHADOW_OUT,
                     0, 0,
                     win->m_width, win->m_height );

    if (!win->GetTitle().empty() &&
        ((win->GetWindowStyle() & wxCAPTION) ||
         (win->GetWindowStyle() & wxTINY_CAPTION)))
    {
        wxClientDC dc(win);
        dc.SetFont( *wxSMALL_FONT );
        int height = dc.GetCharHeight();

        GdkGC *gc = gdk_gc_new( pizza->bin_window );
        gdk_gc_set_foreground( gc, &widget->style->bg[GTK_STATE_SELECTED] );
        gdk_draw_rectangle( pizza->bin_window, gc, TRUE,
                            3,
                            3,
                            win->m_width - 7,
                            height+1 );
        gdk_gc_unref( gc );

        // Hack alert
        static_cast<wxClientDCImpl *>(dc.GetImpl())->m_window = pizza->bin_window;
        dc.SetTextForeground( *wxWHITE );
        dc.DrawText( win->GetTitle(), 6, 3 );
    }
}
}

//-----------------------------------------------------------------------------
// "draw" of m_mainWidget
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_window_own_draw_callback( GtkWidget *widget, GdkRectangle *WXUNUSED(rect), wxFrame *win )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (!win->m_hasVMT) return;

    GtkPizza *pizza = GTK_PIZZA(widget);

    gtk_draw_shadow( widget->style,
                     pizza->bin_window,
                     GTK_STATE_NORMAL,
                     GTK_SHADOW_OUT,
                     0, 0,
                     win->m_width, win->m_height );

    if (!win->GetTitle().empty() &&
        ((win->GetWindowStyle() & wxCAPTION) ||
         (win->GetWindowStyle() & wxTINY_CAPTION)))
    {
        wxClientDC dc(win);
        dc.SetFont( *wxSMALL_FONT );
        int height = dc.GetCharHeight();

        GdkGC *gc = gdk_gc_new( pizza->bin_window );
        gdk_gc_set_foreground( gc, &widget->style->bg[GTK_STATE_SELECTED] );
        gdk_draw_rectangle( pizza->bin_window, gc, TRUE,
                            3,
                            3,
                            win->m_width - 7,
                            height+1 );
        gdk_gc_unref( gc );

        // Hack alert
        static_cast<wxClientDCImpl *>(dc.GetImpl())->m_window = pizza->bin_window;
        dc.SetTextForeground( *wxWHITE );
        dc.DrawText( win->GetTitle(), 6, 3 );
    }
}
}

//-----------------------------------------------------------------------------
// "button_press_event" of m_mainWidget
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_window_button_press_callback( GtkWidget *widget, GdkEventButton *gdk_event, wxMiniFrame *win )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (!win->m_hasVMT) return FALSE;
    if (g_blockEventsOnDrag) return TRUE;
    if (g_blockEventsOnScroll) return TRUE;

    if (win->m_isDragging) return TRUE;

    GtkPizza *pizza = GTK_PIZZA(widget);
    if (gdk_event->window != pizza->bin_window) return TRUE;

    wxClientDC dc(win);
    dc.SetFont( *wxSMALL_FONT );
    int height = dc.GetCharHeight() + 1;

    if (gdk_event->y > height) return TRUE;

    gdk_window_raise( win->m_widget->window );

    gdk_pointer_grab( widget->window, FALSE,
                      (GdkEventMask)
                         (GDK_BUTTON_PRESS_MASK |
                          GDK_BUTTON_RELEASE_MASK |
                          GDK_POINTER_MOTION_MASK        |
                          GDK_POINTER_MOTION_HINT_MASK  |
                          GDK_BUTTON_MOTION_MASK        |
                          GDK_BUTTON1_MOTION_MASK),
                      NULL,
                      NULL,
                      (unsigned int) GDK_CURRENT_TIME );

    win->m_diffX = (int)gdk_event->x;
    win->m_diffY = (int)gdk_event->y;
    DrawFrame( widget, 0, 0, win->m_width, win->m_height );
    win->m_oldX = 0;
    win->m_oldY = 0;

    win->m_isDragging = true;

    return TRUE;
}
}

//-----------------------------------------------------------------------------
// "button_release_event" of m_mainWidget
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_window_button_release_callback( GtkWidget *widget, GdkEventButton *gdk_event, wxMiniFrame *win )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (!win->m_hasVMT) return FALSE;
    if (g_blockEventsOnDrag) return TRUE;
    if (g_blockEventsOnScroll) return TRUE;

    if (!win->m_isDragging) return TRUE;

    win->m_isDragging = false;

    int x = (int)gdk_event->x;
    int y = (int)gdk_event->y;

    DrawFrame( widget, win->m_oldX, win->m_oldY, win->m_width, win->m_height );
    gdk_pointer_ungrab ( (guint32)GDK_CURRENT_TIME );
    int org_x = 0;
    int org_y = 0;
    gdk_window_get_origin( widget->window, &org_x, &org_y );
    x += org_x - win->m_diffX;
    y += org_y - win->m_diffY;
    win->m_x = x;
    win->m_y = y;
    gtk_widget_set_uposition( win->m_widget, x, y );

    return TRUE;
}
}

//-----------------------------------------------------------------------------
// "motion_notify_event" of m_mainWidget
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_window_motion_notify_callback( GtkWidget *widget, GdkEventMotion *gdk_event, wxMiniFrame *win )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (!win->m_hasVMT) return FALSE;
    if (g_blockEventsOnDrag) return TRUE;
    if (g_blockEventsOnScroll) return TRUE;

    if (!win->m_isDragging) return TRUE;

    if (gdk_event->is_hint)
    {
       int x = 0;
       int y = 0;
       GdkModifierType state;
       gdk_window_get_pointer(gdk_event->window, &x, &y, &state);
       gdk_event->x = x;
       gdk_event->y = y;
       gdk_event->state = state;
    }

    DrawFrame( widget, win->m_oldX, win->m_oldY, win->m_width, win->m_height );
    win->m_oldX = (int)gdk_event->x - win->m_diffX;
    win->m_oldY = (int)gdk_event->y - win->m_diffY;
    DrawFrame( widget, win->m_oldX, win->m_oldY, win->m_width, win->m_height );

    return TRUE;
}
}

//-----------------------------------------------------------------------------
// "clicked" of X system button
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_button_clicked_callback( GtkWidget *WXUNUSED(widget), wxMiniFrame *mf )
{
    if (g_isIdle) wxapp_install_idle_handler();

    mf->Close();
}
}

//-----------------------------------------------------------------------------
// wxMiniFrame
//-----------------------------------------------------------------------------

static const char *cross_xpm[] = {
/* columns rows colors chars-per-pixel */
"5 5 16 1",
"  c Gray0",
". c #bf0000",
"X c #00bf00",
"o c #bfbf00",
"O c #0000bf",
"+ c #bf00bf",
"@ c #00bfbf",
"# c None",
"$ c #808080",
"% c Red",
"& c Green",
"* c Yellow",
"= c Blue",
"- c Magenta",
"; c Cyan",
": c Gray100",
/* pixels */
" ### ",
"# # #",
"## ##",
"# # #",
" ### ",
};

IMPLEMENT_DYNAMIC_CLASS(wxMiniFrame,wxFrame)

bool wxMiniFrame::Create( wxWindow *parent, wxWindowID id, const wxString &title,
      const wxPoint &pos, const wxSize &size,
      long style, const wxString &name )
{
    style = style | wxCAPTION;

    if ((style & wxCAPTION) || (style & wxTINY_CAPTION))
        m_miniTitle = 13;

    m_miniEdge = 3;
    m_isDragging = false;
    m_oldX = -1;
    m_oldY = -1;
    m_diffX = 0;
    m_diffY = 0;

    wxFrame::Create( parent, id, title, pos, size, style, name );

    if (m_parent && (GTK_IS_WINDOW(m_parent->m_widget)))
    {
        gtk_window_set_transient_for( GTK_WINDOW(m_widget), GTK_WINDOW(m_parent->m_widget) );
    }

    if ((style & wxSYSTEM_MENU) &&
        ((style & wxCAPTION) || (style & wxTINY_CAPTION)))
    {
        GdkBitmap *mask = NULL;
        GdkPixmap *pixmap = gdk_pixmap_create_from_xpm_d
                            (
                                wxGetRootWindow()->window,
                                &mask,
                                NULL,
                                (char **)cross_xpm
                            );

        GtkWidget *pw = gtk_pixmap_new( pixmap, mask );
        gdk_bitmap_unref( mask );
        gdk_pixmap_unref( pixmap );
        gtk_widget_show( pw );

        GtkWidget *close_button = gtk_button_new();
        gtk_container_add( GTK_CONTAINER(close_button), pw );

        gtk_pizza_put( GTK_PIZZA(m_mainWidget),
                         close_button,
                         size.x-16, 4, 11, 11 );

        gtk_widget_show( close_button );

        gtk_signal_connect( GTK_OBJECT(close_button), "clicked",
          GTK_SIGNAL_FUNC(gtk_button_clicked_callback), (gpointer*)this );
    }

    /* these are called when the borders are drawn */
    gtk_signal_connect( GTK_OBJECT(m_mainWidget), "expose_event",
        GTK_SIGNAL_FUNC(gtk_window_own_expose_callback), (gpointer)this );

    gtk_signal_connect( GTK_OBJECT(m_mainWidget), "draw",
       GTK_SIGNAL_FUNC(gtk_window_own_draw_callback), (gpointer)this );

    /* these are required for dragging the mini frame around */
    gtk_signal_connect( GTK_OBJECT(m_mainWidget), "button_press_event",
      GTK_SIGNAL_FUNC(gtk_window_button_press_callback), (gpointer)this );

    gtk_signal_connect( GTK_OBJECT(m_mainWidget), "button_release_event",
      GTK_SIGNAL_FUNC(gtk_window_button_release_callback), (gpointer)this );

    gtk_signal_connect( GTK_OBJECT(m_mainWidget), "motion_notify_event",
      GTK_SIGNAL_FUNC(gtk_window_motion_notify_callback), (gpointer)this );

    return true;
}

void wxMiniFrame::SetTitle( const wxString &title )
{
    wxFrame::SetTitle( title );

    gtk_widget_draw( m_mainWidget, NULL );
}

#endif // wxUSE_MINIFRAME
