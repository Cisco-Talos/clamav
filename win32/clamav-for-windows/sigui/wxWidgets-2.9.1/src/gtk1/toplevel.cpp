/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/toplevel.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#ifdef __VMS
#define XIconifyWindow XICONIFYWINDOW
#endif

#include "wx/toplevel.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/dcclient.h"
    #include "wx/dialog.h"
    #include "wx/timer.h"
    #include "wx/settings.h"
    #include "wx/control.h"
#endif

#include "wx/gtk1/private.h"
#include "wx/evtloop.h"

#include <glib.h>
#include <gdk/gdk.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <gdk/gdkx.h>

#include "wx/gtk1/win_gtk.h"

#include "wx/unix/utilsx11.h"

// XA_CARDINAL
#include <X11/Xatom.h>

// ----------------------------------------------------------------------------
// idle system
// ----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

// ----------------------------------------------------------------------------
// data
// ----------------------------------------------------------------------------

extern int              g_openDialogs;
extern wxWindowGTK     *g_delayedFocus;

// the frame that is currently active (i.e. its child has focus). It is
// used to generate wxActivateEvents
static wxTopLevelWindowGTK *g_activeFrame = NULL;
static wxTopLevelWindowGTK *g_lastActiveFrame = NULL;

// if we detect that the app has got/lost the focus, we set this variable to
// either TRUE or FALSE and an activate event will be sent during the next
// OnIdle() call and it is reset to -1: this value means that we shouldn't
// send any activate events at all
static int g_sendActivateEvent = -1;

//-----------------------------------------------------------------------------
// RequestUserAttention related functions
//-----------------------------------------------------------------------------

extern "C" {
static void wxgtk_window_set_urgency_hint (GtkWindow *win,
                                           gboolean setting)
{
    wxASSERT_MSG( GTK_WIDGET_REALIZED(win), wxT("wxgtk_window_set_urgency_hint: GdkWindow not realized") );
    GdkWindow *window = GTK_WIDGET(win)->window;
    XWMHints *wm_hints;

    wm_hints = XGetWMHints(GDK_WINDOW_XDISPLAY(window), GDK_WINDOW_XWINDOW(window));

    if (!wm_hints)
        wm_hints = XAllocWMHints();

    if (setting)
        wm_hints->flags |= XUrgencyHint;
    else
        wm_hints->flags &= ~XUrgencyHint;

    XSetWMHints(GDK_WINDOW_XDISPLAY(window), GDK_WINDOW_XWINDOW(window), wm_hints);
    XFree(wm_hints);
}

static gint gtk_frame_urgency_timer_callback( wxTopLevelWindowGTK *win )
{
    wxgtk_window_set_urgency_hint(GTK_WINDOW( win->m_widget ), FALSE);

    win->m_urgency_hint = -2;
    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "focus_in_event"
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_frame_focus_in_callback( GtkWidget *widget,
                                         GdkEvent *WXUNUSED(event),
                                         wxTopLevelWindowGTK *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    switch ( g_sendActivateEvent )
    {
        case -1:
            // we've got focus from outside, synthetize wxActivateEvent
            g_sendActivateEvent = 1;
            break;

        case 0:
            // another our window just lost focus, it was already ours before
            // - don't send any wxActivateEvent
            g_sendActivateEvent = -1;
            break;
    }

    g_activeFrame = win;
    g_lastActiveFrame = g_activeFrame;

    // wxPrintf( wxT("active: %s\n"), win->GetTitle().c_str() );

    // MR: wxRequestUserAttention related block
    switch( win->m_urgency_hint )
    {
        default:
            gtk_timeout_remove( win->m_urgency_hint );
            // no break, fallthrough to remove hint too
        case -1:
            wxgtk_window_set_urgency_hint(GTK_WINDOW( widget ), FALSE);

            win->m_urgency_hint = -2;
            break;

        case -2: break;
    }

    wxLogTrace(wxT("activate"), wxT("Activating frame %p (from focus_in)"), g_activeFrame);
    wxActivateEvent event(wxEVT_ACTIVATE, true, g_activeFrame->GetId());
    event.SetEventObject(g_activeFrame);
    g_activeFrame->HandleWindowEvent(event);

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "focus_out_event"
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_frame_focus_out_callback( GtkWidget *WXUNUSED(widget),
                                          GdkEventFocus *WXUNUSED(gdk_event),
                                          wxTopLevelWindowGTK *WXUNUSED(win) )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    // if the focus goes out of our app alltogether, OnIdle() will send
    // wxActivateEvent, otherwise gtk_window_focus_in_callback() will reset
    // g_sendActivateEvent to -1
    g_sendActivateEvent = 0;

    // wxASSERT_MSG( (g_activeFrame == win), wxT("TLW deactivatd although it wasn't active") );

    // wxPrintf( wxT("inactive: %s\n"), win->GetTitle().c_str() );

    if (g_activeFrame)
    {
        wxLogTrace(wxT("activate"), wxT("Activating frame %p (from focus_in)"), g_activeFrame);
        wxActivateEvent event(wxEVT_ACTIVATE, false, g_activeFrame->GetId());
        event.SetEventObject(g_activeFrame);
        g_activeFrame->HandleWindowEvent(event);

        g_activeFrame = NULL;
    }

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "focus" from m_window
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_frame_focus_callback( GtkWidget *widget, GtkDirectionType WXUNUSED(d), wxWindow *WXUNUSED(win) )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    // This disables GTK's tab traversal
    gtk_signal_emit_stop_by_name( GTK_OBJECT(widget), "focus" );
    return TRUE;
}
}

//-----------------------------------------------------------------------------
// "size_allocate"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_frame_size_callback( GtkWidget *WXUNUSED(widget), GtkAllocation* alloc, wxTopLevelWindowGTK *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (!win->m_hasVMT)
        return;

    if ((win->m_width != alloc->width) || (win->m_height != alloc->height))
    {
/*
        wxPrintf( "OnSize from " );
        if (win->GetClassInfo() && win->GetClassInfo()->GetClassName())
           wxPrintf( win->GetClassInfo()->GetClassName() );
        wxPrintf( " %d %d %d %d\n", (int)alloc->x,
                                (int)alloc->y,
                                (int)alloc->width,
                                (int)alloc->height );
*/

        win->m_width = alloc->width;
        win->m_height = alloc->height;
        win->GtkUpdateSize();
    }
}
}

//-----------------------------------------------------------------------------
// "delete_event"
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_frame_delete_callback( GtkWidget *WXUNUSED(widget), GdkEvent *WXUNUSED(event), wxTopLevelWindowGTK *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (win->IsEnabled() &&
        (g_openDialogs == 0 || (win->GetExtraStyle() & wxTOPLEVEL_EX_DIALOG) ||
         win->IsGrabbed()))
        win->Close();

    return TRUE;
}
}


//-----------------------------------------------------------------------------
// "configure_event"
//-----------------------------------------------------------------------------

extern "C" {
static gint
gtk_frame_configure_callback( GtkWidget *WXUNUSED(widget), GdkEventConfigure *WXUNUSED(event), wxTopLevelWindowGTK *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (!win->m_hasVMT || !win->IsShown())
        return FALSE;


    int x = 0;
    int y = 0;
    gdk_window_get_root_origin( win->m_widget->window, &x, &y );
    win->m_x = x;
    win->m_y = y;

    wxMoveEvent mevent( wxPoint(win->m_x,win->m_y), win->GetId() );
    mevent.SetEventObject( win );
    win->HandleWindowEvent( mevent );

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "realize" from m_widget
//-----------------------------------------------------------------------------

// we cannot MWM hints and icons before the widget has been realized,
// so we do this directly after realization

extern "C" {
static void
gtk_frame_realized_callback( GtkWidget * WXUNUSED(widget),
                             wxTopLevelWindowGTK *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    // All this is for Motif Window Manager "hints" and is supposed to be
    // recognized by other WM as well. Not tested.
    gdk_window_set_decorations(win->m_widget->window,
                               (GdkWMDecoration)win->m_gdkDecor);
    gdk_window_set_functions(win->m_widget->window,
                               (GdkWMFunction)win->m_gdkFunc);

    // GTK's shrinking/growing policy
    if ((win->m_gdkFunc & GDK_FUNC_RESIZE) == 0)
        gtk_window_set_policy(GTK_WINDOW(win->m_widget), 0, 0, 1);
    else
        gtk_window_set_policy(GTK_WINDOW(win->m_widget), 1, 1, 1);

    // reset the icon
    wxIconBundle iconsOld = win->GetIcons();
    if ( !iconsOld.IsEmpty() )
    {
        win->SetIcon( wxNullIcon );
        win->SetIcons( iconsOld );
    }
}
}

//-----------------------------------------------------------------------------
// "map_event" from m_widget
//-----------------------------------------------------------------------------

extern "C" {
static void
gtk_frame_map_callback( GtkWidget * WXUNUSED(widget),
                        GdkEvent * WXUNUSED(event),
                        wxTopLevelWindow *win )
{
    win->SetIconizeState(false);
}
}

//-----------------------------------------------------------------------------
// "unmap_event" from m_widget
//-----------------------------------------------------------------------------

extern "C" {
static void
gtk_frame_unmap_callback( GtkWidget * WXUNUSED(widget),
                          GdkEvent * WXUNUSED(event),
                          wxTopLevelWindow *win )
{
    win->SetIconizeState(true);
}
}

//-----------------------------------------------------------------------------
// "expose_event" of m_client
//-----------------------------------------------------------------------------

extern "C" {
static int gtk_window_expose_callback( GtkWidget *widget, GdkEventExpose *gdk_event, wxWindow *win )
{
    GtkPizza *pizza = GTK_PIZZA(widget);

    gtk_paint_flat_box (win->m_widget->style,
                        pizza->bin_window, GTK_STATE_NORMAL,
                        GTK_SHADOW_NONE,
                        &gdk_event->area,
                        win->m_widget,
                        (char *)"base",
                        0, 0, -1, -1);

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "draw" of m_client
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_window_draw_callback( GtkWidget *widget, GdkRectangle *rect, wxWindow *win )
{
    GtkPizza *pizza = GTK_PIZZA(widget);

    gtk_paint_flat_box (win->m_widget->style,
                        pizza->bin_window, GTK_STATE_NORMAL,
                        GTK_SHADOW_NONE,
                        rect,
                        win->m_widget,
                        (char *)"base",
                        0, 0, -1, -1);
}
}

// ----------------------------------------------------------------------------
// wxTopLevelWindowGTK itself
// ----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// InsertChild for wxTopLevelWindowGTK
//-----------------------------------------------------------------------------

/* Callback for wxTopLevelWindowGTK. This very strange beast has to be used because
 * C++ has no virtual methods in a constructor. We have to emulate a
 * virtual function here as wxWidgets requires different ways to insert
 * a child in container classes. */

static void wxInsertChildInTopLevelWindow( wxTopLevelWindowGTK* parent, wxWindow* child )
{
    wxASSERT( GTK_IS_WIDGET(child->m_widget) );

    if (!parent->m_insertInClientArea)
    {
        // these are outside the client area
        wxTopLevelWindowGTK* frame = (wxTopLevelWindowGTK*) parent;
        gtk_pizza_put( GTK_PIZZA(frame->m_mainWidget),
                         GTK_WIDGET(child->m_widget),
                         child->m_x,
                         child->m_y,
                         child->m_width,
                         child->m_height );
    }
    else
    {
        // these are inside the client area
        gtk_pizza_put( GTK_PIZZA(parent->m_wxwindow),
                         GTK_WIDGET(child->m_widget),
                         child->m_x,
                         child->m_y,
                         child->m_width,
                         child->m_height );
    }

    // resize on OnInternalIdle
    parent->GtkUpdateSize();
}

// ----------------------------------------------------------------------------
// wxTopLevelWindowGTK creation
// ----------------------------------------------------------------------------

void wxTopLevelWindowGTK::Init()
{
    m_sizeSet = false;
    m_miniEdge = 0;
    m_miniTitle = 0;
    m_mainWidget = NULL;
    m_insertInClientArea = true;
    m_isIconized = false;
    m_fsIsShowing = false;
    m_themeEnabled = true;
    m_gdkDecor = m_gdkFunc = 0;
    m_grabbed = false;

    m_urgency_hint = -2;
}

bool wxTopLevelWindowGTK::Create( wxWindow *parent,
                                  wxWindowID id,
                                  const wxString& title,
                                  const wxPoint& pos,
                                  const wxSize& sizeOrig,
                                  long style,
                                  const wxString &name )
{
    // always create a frame of some reasonable, even if arbitrary, size (at
    // least for MSW compatibility)
    wxSize size = sizeOrig;
    size.x = WidthDefault(size.x);
    size.y = HeightDefault(size.y);

    wxTopLevelWindows.Append( this );

    m_needParent = false;

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, wxDefaultValidator, name ))
    {
        wxFAIL_MSG( wxT("wxTopLevelWindowGTK creation failed") );
        return false;
    }

    m_title = title;

    m_insertCallback = (wxInsertChildFunction) wxInsertChildInTopLevelWindow;

    // NB: m_widget may be !=NULL if it was created by derived class' Create,
    //     e.g. in wxTaskBarIconAreaGTK
    if (m_widget == NULL)
    {
        if (GetExtraStyle() & wxTOPLEVEL_EX_DIALOG)
        {
            m_widget = gtk_window_new(GTK_WINDOW_DIALOG);
        }
        else
        {
            m_widget = gtk_window_new(GTK_WINDOW_TOPLEVEL);
#if GTK_CHECK_VERSION(2,1,0)
            if (!gtk_check_version(2,1,0))
            {
                if (style & wxFRAME_TOOL_WINDOW)
                {
                    gtk_window_set_type_hint(GTK_WINDOW(m_widget),
                                             GDK_WINDOW_TYPE_HINT_UTILITY);

                    // On some WMs, like KDE, a TOOL_WINDOW will still show
                    // on the taskbar, but on Gnome a TOOL_WINDOW will not.
                    // For consistency between WMs and with Windows, we
                    // should set the NO_TASKBAR flag which will apply
                    // the set_skip_taskbar_hint if it is available,
                    // ensuring no taskbar entry will appear.
                    style |= wxFRAME_NO_TASKBAR;
                }
            }
#endif
        }
    }

    wxWindow *topParent = wxGetTopLevelParent(m_parent);
    if (topParent && (((GTK_IS_WINDOW(topParent->m_widget)) &&
                       (GetExtraStyle() & wxTOPLEVEL_EX_DIALOG)) ||
                       (style & wxFRAME_FLOAT_ON_PARENT)))
    {
        gtk_window_set_transient_for( GTK_WINDOW(m_widget),
                                      GTK_WINDOW(topParent->m_widget) );
    }

    if (!name.empty())
        gtk_window_set_wmclass( GTK_WINDOW(m_widget), wxGTK_CONV( name ), wxGTK_CONV( name ) );

    gtk_window_set_title( GTK_WINDOW(m_widget), wxGTK_CONV( title ) );
    GTK_WIDGET_UNSET_FLAGS( m_widget, GTK_CAN_FOCUS );

    gtk_signal_connect( GTK_OBJECT(m_widget), "delete_event",
        GTK_SIGNAL_FUNC(gtk_frame_delete_callback), (gpointer)this );

    // m_mainWidget holds the toolbar, the menubar and the client area
    m_mainWidget = gtk_pizza_new();
    gtk_widget_show( m_mainWidget );
    GTK_WIDGET_UNSET_FLAGS( m_mainWidget, GTK_CAN_FOCUS );
    gtk_container_add( GTK_CONTAINER(m_widget), m_mainWidget );

    if (m_miniEdge == 0) // wxMiniFrame has its own version.
    {
       // For m_mainWidget themes
       gtk_signal_connect( GTK_OBJECT(m_mainWidget), "expose_event",
                GTK_SIGNAL_FUNC(gtk_window_expose_callback), (gpointer)this );
       gtk_signal_connect( GTK_OBJECT(m_mainWidget), "draw",
                GTK_SIGNAL_FUNC(gtk_window_draw_callback), (gpointer)this );
    }

    // m_wxwindow only represents the client area without toolbar and menubar
    m_wxwindow = gtk_pizza_new();
    gtk_widget_show( m_wxwindow );
    gtk_container_add( GTK_CONTAINER(m_mainWidget), m_wxwindow );

    // we donm't allow the frame to get the focus as otherwise
    // the frame will grab it at arbitrary focus changes
    GTK_WIDGET_UNSET_FLAGS( m_wxwindow, GTK_CAN_FOCUS );

    if (m_parent) m_parent->AddChild( this );

    // the user resized the frame by dragging etc.
    gtk_signal_connect( GTK_OBJECT(m_widget), "size_allocate",
        GTK_SIGNAL_FUNC(gtk_frame_size_callback), (gpointer)this );

    PostCreation();

    if ((m_x != -1) || (m_y != -1))
        gtk_widget_set_uposition( m_widget, m_x, m_y );

    gtk_window_set_default_size( GTK_WINDOW(m_widget), m_width, m_height );

    //  we cannot set MWM hints and icons before the widget has
    //  been realized, so we do this directly after realization
    gtk_signal_connect( GTK_OBJECT(m_widget), "realize",
                        GTK_SIGNAL_FUNC(gtk_frame_realized_callback), (gpointer) this );

    // map and unmap for iconized state
    gtk_signal_connect( GTK_OBJECT(m_widget), "map_event",
        GTK_SIGNAL_FUNC(gtk_frame_map_callback), (gpointer)this );
    gtk_signal_connect( GTK_OBJECT(m_widget), "unmap_event",
        GTK_SIGNAL_FUNC(gtk_frame_unmap_callback), (gpointer)this );

    // the only way to get the window size is to connect to this event
    gtk_signal_connect( GTK_OBJECT(m_widget), "configure_event",
        GTK_SIGNAL_FUNC(gtk_frame_configure_callback), (gpointer)this );

    // disable native tab traversal
    gtk_signal_connect( GTK_OBJECT(m_widget), "focus",
        GTK_SIGNAL_FUNC(gtk_frame_focus_callback), (gpointer)this );

    // activation
    gtk_signal_connect( GTK_OBJECT(m_widget), "focus_in_event",
        GTK_SIGNAL_FUNC(gtk_frame_focus_in_callback), (gpointer)this );
    gtk_signal_connect( GTK_OBJECT(m_widget), "focus_out_event",
        GTK_SIGNAL_FUNC(gtk_frame_focus_out_callback), (gpointer)this );

    // decorations
    if ((m_miniEdge > 0) || (style & wxSIMPLE_BORDER) || (style & wxNO_BORDER))
    {
        m_gdkDecor = 0;
        m_gdkFunc = 0;
    }
    else
    {
        m_gdkDecor = (long) GDK_DECOR_BORDER;
        m_gdkFunc = (long) GDK_FUNC_MOVE;

        // All this is for Motif Window Manager "hints" and is supposed to be
        // recognized by other WMs as well.
        if ((style & wxCAPTION) != 0)
        {
            m_gdkDecor |= GDK_DECOR_TITLE;
        }
        if ((style & wxCLOSE_BOX) != 0)
        {
            m_gdkFunc |= GDK_FUNC_CLOSE;
        }
        if ((style & wxSYSTEM_MENU) != 0)
        {
            m_gdkDecor |= GDK_DECOR_MENU;
        }
        if ((style & wxMINIMIZE_BOX) != 0)
        {
            m_gdkFunc |= GDK_FUNC_MINIMIZE;
            m_gdkDecor |= GDK_DECOR_MINIMIZE;
        }
        if ((style & wxMAXIMIZE_BOX) != 0)
        {
            m_gdkFunc |= GDK_FUNC_MAXIMIZE;
            m_gdkDecor |= GDK_DECOR_MAXIMIZE;
        }
        if ((style & wxRESIZE_BORDER) != 0)
        {
           m_gdkFunc |= GDK_FUNC_RESIZE;
           m_gdkDecor |= GDK_DECOR_RESIZEH;
        }
    }

    return true;
}

wxTopLevelWindowGTK::~wxTopLevelWindowGTK()
{
    if (m_grabbed)
    {
        wxASSERT_MSG( false, wxT("Window still grabbed"));
        RemoveGrab();
    }

    SendDestroyEvent();

    // it may also be GtkScrolledWindow in the case of an MDI child
    if (GTK_IS_WINDOW(m_widget))
    {
        gtk_window_set_focus( GTK_WINDOW(m_widget), NULL );
    }

    if (g_activeFrame == this)
        g_activeFrame = NULL;
    if (g_lastActiveFrame == this)
        g_lastActiveFrame = NULL;
}



bool wxTopLevelWindowGTK::ShowFullScreen(bool show, long style )
{
    if (show == m_fsIsShowing)
        return false; // return what?

    m_fsIsShowing = show;

    wxX11FullScreenMethod method =
        wxGetFullScreenMethodX11((WXDisplay*)GDK_DISPLAY(),
                                 (WXWindow)GDK_ROOT_WINDOW());

#if GTK_CHECK_VERSION(2,2,0)
    // NB: gtk_window_fullscreen() uses freedesktop.org's WMspec extensions
    //     to switch to fullscreen, which is not always available. We must
    //     check if WM supports the spec and use legacy methods if it
    //     doesn't.
    if ( (method == wxX11_FS_WMSPEC) && !gtk_check_version(2,2,0) )
    {
        if (show)
            gtk_window_fullscreen( GTK_WINDOW( m_widget ) );
        else
            gtk_window_unfullscreen( GTK_WINDOW( m_widget ) );
    }
    else
#endif // GTK+ >= 2.2.0
    {
        GdkWindow *window = m_widget->window;

        if (show)
        {
            m_fsSaveFlag = style;
            GetPosition( &m_fsSaveFrame.x, &m_fsSaveFrame.y );
            GetSize( &m_fsSaveFrame.width, &m_fsSaveFrame.height );

            int screen_width,screen_height;
            wxDisplaySize( &screen_width, &screen_height );

            gint client_x, client_y, root_x, root_y;
            gint width, height;

            if (method != wxX11_FS_WMSPEC)
            {
                // don't do it always, Metacity hates it
                m_fsSaveGdkFunc = m_gdkFunc;
                m_fsSaveGdkDecor = m_gdkDecor;
                m_gdkFunc = m_gdkDecor = 0;
                gdk_window_set_decorations(window, (GdkWMDecoration)0);
                gdk_window_set_functions(window, (GdkWMFunction)0);
            }

            gdk_window_get_origin (m_widget->window, &root_x, &root_y);
            gdk_window_get_geometry (m_widget->window, &client_x, &client_y,
                         &width, &height, NULL);

            gdk_window_move_resize (m_widget->window, -client_x, -client_y,
                        screen_width + 1, screen_height + 1);

            wxSetFullScreenStateX11((WXDisplay*)GDK_DISPLAY(),
                                    (WXWindow)GDK_ROOT_WINDOW(),
                                    (WXWindow)GDK_WINDOW_XWINDOW(window),
                                    show, &m_fsSaveFrame, method);
        }
        else // hide
        {
            if (method != wxX11_FS_WMSPEC)
            {
                // don't do it always, Metacity hates it
                m_gdkFunc = m_fsSaveGdkFunc;
                m_gdkDecor = m_fsSaveGdkDecor;
                gdk_window_set_decorations(window, (GdkWMDecoration)m_gdkDecor);
                gdk_window_set_functions(window, (GdkWMFunction)m_gdkFunc);
            }

            wxSetFullScreenStateX11((WXDisplay*)GDK_DISPLAY(),
                                    (WXWindow)GDK_ROOT_WINDOW(),
                                    (WXWindow)GDK_WINDOW_XWINDOW(window),
                                    show, &m_fsSaveFrame, method);

            SetSize(m_fsSaveFrame.x, m_fsSaveFrame.y,
                    m_fsSaveFrame.width, m_fsSaveFrame.height);
        }
    }

    // documented behaviour is to show the window if it's still hidden when
    // showing it full screen
    if ( show && !IsShown() )
        Show();

    return true;
}

// ----------------------------------------------------------------------------
// overridden wxWindow methods
// ----------------------------------------------------------------------------

bool wxTopLevelWindowGTK::Show( bool show )
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

    if (show && !m_sizeSet)
    {
        /* by calling GtkOnSize here, we don't have to call
           either after showing the frame, which would entail
           much ugly flicker or from within the size_allocate
           handler, because GTK 1.1.X forbids that. */

        GtkOnSize( m_x, m_y, m_width, m_height );
    }

    if (show)
        gtk_widget_set_uposition( m_widget, m_x, m_y );

    return wxWindow::Show( show );
}

void wxTopLevelWindowGTK::Raise()
{
    wxWindow::Raise();
}

void wxTopLevelWindowGTK::DoMoveWindow(int WXUNUSED(x), int WXUNUSED(y), int WXUNUSED(width), int WXUNUSED(height) )
{
    wxFAIL_MSG( wxT("DoMoveWindow called for wxTopLevelWindowGTK") );
}

void wxTopLevelWindowGTK::DoSetSize( int x, int y, int width, int height, int sizeFlags )
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

    // this shouldn't happen: wxFrame, wxMDIParentFrame and wxMDIChildFrame have m_wxwindow
    wxASSERT_MSG( (m_wxwindow != NULL), wxT("invalid frame") );

    // avoid recursions
    if (m_resizing)
        return;
    m_resizing = true;

    int old_x = m_x;
    int old_y = m_y;

    int old_width = m_width;
    int old_height = m_height;

    if ((sizeFlags & wxSIZE_ALLOW_MINUS_ONE) == 0)
    {
        if (x != -1) m_x = x;
        if (y != -1) m_y = y;
    }
    else
    {
        m_x = x;
        m_y = y;
    }
    if (width != -1) m_width = width;
    if (height != -1) m_height = height;

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

#ifdef __WXGPE__
    // GPE's window manager doesn't like size hints
    // at all, esp. when the user has to use the
    // virtual keyboard.
    minWidth = -1;
    minHeight = -1;
    maxWidth = -1;
    maxHeight = -1;
#endif

    if ((minWidth != -1) && (m_width < minWidth)) m_width = minWidth;
    if ((minHeight != -1) && (m_height < minHeight)) m_height = minHeight;
    if ((maxWidth != -1) && (m_width > maxWidth)) m_width = maxWidth;
    if ((maxHeight != -1) && (m_height > maxHeight)) m_height = maxHeight;

    if ((m_x != -1) || (m_y != -1))
    {
        if ((m_x != old_x) || (m_y != old_y))
        {
            gtk_widget_set_uposition( m_widget, m_x, m_y );
        }
    }

    if ((m_width != old_width) || (m_height != old_height))
    {
        if (m_widget->window)
            gdk_window_resize( m_widget->window, m_width, m_height );
        else
            gtk_window_set_default_size( GTK_WINDOW(m_widget), m_width, m_height );

        /* we set the size in GtkOnSize, i.e. mostly the actual resizing is
           done either directly before the frame is shown or in idle time
           so that different calls to SetSize() don't lead to flicker. */
        m_sizeSet = false;
    }

    m_resizing = false;
}

void wxTopLevelWindowGTK::DoGetClientSize( int *width, int *height ) const
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

    wxWindow::DoGetClientSize( width, height );
    if (height)
    {
        // mini edge
        *height -= m_miniEdge*2 + m_miniTitle;
    }
    if (width)
    {
        *width -= m_miniEdge*2;
    }
}

void wxTopLevelWindowGTK::DoSetClientSize( int width, int height )
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

    DoSetSize(-1, -1,
              width + m_miniEdge*2, height  + m_miniEdge*2 + m_miniTitle, 0);
}

void wxTopLevelWindowGTK::GtkOnSize( int WXUNUSED(x), int WXUNUSED(y),
                                     int width, int height )
{
    // due to a bug in gtk, x,y are always 0
    // m_x = x;
    // m_y = y;

    // avoid recursions
    if (m_resizing) return;
    m_resizing = true;

    if ( m_wxwindow == NULL ) return;

    m_width = width;
    m_height = height;

    /* wxMDIChildFrame derives from wxFrame but it _is_ a wxWindow as it uses
       wxWindow::Create to create it's GTK equivalent. m_mainWidget is only
       set in wxFrame::Create so it is used to check what kind of frame we
       have here. if m_mainWidget is NULL it is a wxMDIChildFrame and so we
       skip the part which handles m_frameMenuBar, m_frameToolBar and (most
       importantly) m_mainWidget */

    int minWidth = GetMinWidth(),
        minHeight = GetMinHeight(),
        maxWidth = GetMaxWidth(),
        maxHeight = GetMaxHeight();

#ifdef __WXGPE__
    // GPE's window manager doesn't like size hints
    // at all, esp. when the user has to use the
    // virtual keyboard.
    minWidth = -1;
    minHeight = -1;
    maxWidth = -1;
    maxHeight = -1;
#endif

    if ((minWidth != -1) && (m_width < minWidth)) m_width = minWidth;
    if ((minHeight != -1) && (m_height < minHeight)) m_height = minHeight;
    if ((maxWidth != -1) && (m_width > maxWidth)) m_width = maxWidth;
    if ((maxHeight != -1) && (m_height > maxHeight)) m_height = maxHeight;

    if (m_mainWidget)
    {
        // set size hints
        gint            flag = 0; // GDK_HINT_POS;
        GdkGeometry     geom;

        if ((minWidth != -1) || (minHeight != -1)) flag |= GDK_HINT_MIN_SIZE;
        if ((maxWidth != -1) || (maxHeight != -1)) flag |= GDK_HINT_MAX_SIZE;

        geom.min_width = minWidth;
        geom.min_height = minHeight;

            // Because of the way we set GDK_HINT_MAX_SIZE above, if either of
            // maxHeight or maxWidth is set, we must set them both, else the
            // remaining -1 will be taken literally.

            // I'm certain this also happens elsewhere, and is the probable
            // cause of other such things as:
            // Gtk-WARNING **: gtk_widget_size_allocate():
            //       attempt to allocate widget with width 65535 and height 600
            // but I don't have time to track them all now..
            //
            // Really we need to encapulate all this height/width business and
            // stop any old method from ripping at the members directly and
            // scattering -1's without regard for who might resolve them later.

        geom.max_width = ( maxHeight == -1 ) ? maxWidth
                         : ( maxWidth == -1 ) ? wxGetDisplaySize().GetWidth()
                           : maxWidth ;

        geom.max_height = ( maxWidth == -1 ) ? maxHeight    // ( == -1 here )
                          : ( maxHeight == -1 ) ? wxGetDisplaySize().GetHeight()
                            : maxHeight ;

        gtk_window_set_geometry_hints( GTK_WINDOW(m_widget),
                                       NULL,
                                       &geom,
                                       (GdkWindowHints) flag );

        /* I revert back to wxGTK's original behaviour. m_mainWidget holds the
         * menubar, the toolbar and the client area, which is represented by
         * m_wxwindow.
         * this hurts in the eye, but I don't want to call SetSize()
         * because I don't want to call any non-native functions here. */

        int client_x = m_miniEdge;
        int client_y = m_miniEdge + m_miniTitle;
        int client_w = m_width - 2*m_miniEdge;
        int client_h = m_height - 2*m_miniEdge - m_miniTitle;

        gtk_pizza_set_size( GTK_PIZZA(m_mainWidget),
                              m_wxwindow,
                              client_x, client_y, client_w, client_h );
    }
    else
    {
        // If there is no m_mainWidget between m_widget and m_wxwindow there
        // is no need to set the size or position of m_wxwindow.
    }

    m_sizeSet = true;

    // send size event to frame
    wxSizeEvent event( wxSize(m_width,m_height), GetId() );
    event.SetEventObject( this );
    HandleWindowEvent( event );

    m_resizing = false;
}

void wxTopLevelWindowGTK::OnInternalIdle()
{
    if (!m_sizeSet && GTK_WIDGET_REALIZED(m_wxwindow))
    {
        GtkOnSize( m_x, m_y, m_width, m_height );

        // we'll come back later
        if (g_isIdle)
            wxapp_install_idle_handler();
        return;
    }

    // set the focus if not done yet and if we can already do it
    if ( GTK_WIDGET_REALIZED(m_wxwindow) )
    {
        if ( g_delayedFocus &&
             wxGetTopLevelParent((wxWindow*)g_delayedFocus) == this )
        {
            wxLogTrace(wxT("focus"),
                       wxT("Setting focus from wxTLW::OnIdle() to %s(%s)"),
                       g_delayedFocus->GetClassInfo()->GetClassName(),
                       g_delayedFocus->GetLabel().c_str());

            g_delayedFocus->SetFocus();
            g_delayedFocus = NULL;
        }
    }

    wxWindow::OnInternalIdle();

    // Synthetize activate events.
    if ( g_sendActivateEvent != -1 )
    {
        bool activate = g_sendActivateEvent != 0;

        // if (!activate) wxPrintf( wxT("de") );
        // wxPrintf( wxT("activate\n") );

        // do it only once
        g_sendActivateEvent = -1;

        wxTheApp->SetActive(activate, (wxWindow *)g_lastActiveFrame);
    }
}

// ----------------------------------------------------------------------------
// frame title/icon
// ----------------------------------------------------------------------------

void wxTopLevelWindowGTK::SetTitle( const wxString &title )
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

    if ( title == m_title )
        return;

    m_title = title;

    gtk_window_set_title( GTK_WINDOW(m_widget), wxGTK_CONV( title ) );
}

void wxTopLevelWindowGTK::SetIcons( const wxIconBundle &icons )
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

    wxTopLevelWindowBase::SetIcons( icons );

    if ( icons.IsEmpty() )
        return;

    GdkWindow* window = m_widget->window;
    if (!window)
        return;

    wxIcon icon = icons.GetIcon(-1);
    if (icon.Ok())
    {
        wxMask *mask = icon.GetMask();
        GdkBitmap *bm = NULL;
        if (mask) bm = mask->GetBitmap();

        gdk_window_set_icon( m_widget->window, NULL, icon.GetPixmap(), bm );
    }

    wxSetIconsX11( (WXDisplay*)GDK_WINDOW_XDISPLAY( window ),
                   (WXWindow)GDK_WINDOW_XWINDOW( window ), icons );
}

// ----------------------------------------------------------------------------
// frame state: maximized/iconized/normal
// ----------------------------------------------------------------------------

void wxTopLevelWindowGTK::Maximize(bool WXUNUSED(maximize))
{
    wxFAIL_MSG( wxT("not implemented") );
}

bool wxTopLevelWindowGTK::IsMaximized() const
{
  //    wxFAIL_MSG( wxT("not implemented") );

    // This is an approximation
    return false;
}

void wxTopLevelWindowGTK::Restore()
{
    wxFAIL_MSG( wxT("not implemented") );
}

void wxTopLevelWindowGTK::Iconize( bool iconize )
{
   if (iconize)
   {
       GdkWindow *window = m_widget->window;

       // you should do it later, for example from OnCreate() handler
       wxCHECK_RET( window, wxT("frame not created yet - can't iconize") );

       XIconifyWindow( GDK_WINDOW_XDISPLAY( window ),
                       GDK_WINDOW_XWINDOW( window ),
                       DefaultScreen( GDK_DISPLAY() ) );
   }
}

bool wxTopLevelWindowGTK::IsIconized() const
{
    return m_isIconized;
}

void wxTopLevelWindowGTK::SetIconizeState(bool iconize)
{
    if ( iconize != m_isIconized )
    {
        m_isIconized = iconize;
        (void)SendIconizeEvent(iconize);
    }
}

void wxTopLevelWindowGTK::AddGrab()
{
    if (!m_grabbed)
    {
        m_grabbed = true;
        gtk_grab_add( m_widget );
        wxEventLoop().Run();
        gtk_grab_remove( m_widget );
    }
}

void wxTopLevelWindowGTK::RemoveGrab()
{
    if (m_grabbed)
    {
        gtk_main_quit();
        m_grabbed = false;
    }
}


// helper
static bool do_shape_combine_region(GdkWindow* window, const wxRegion& region)
{
    if (window)
    {
        if (region.IsEmpty())
        {
            gdk_window_shape_combine_mask(window, NULL, 0, 0);
        }
        else
        {
            wxBitmap bmp = region.ConvertToBitmap();
            bmp.SetMask(new wxMask(bmp, *wxBLACK));
            GdkBitmap* mask = bmp.GetMask()->GetBitmap();
            gdk_window_shape_combine_mask(window, mask, 0, 0);
            return true;
        }
    }
    return false;
}


bool wxTopLevelWindowGTK::SetShape(const wxRegion& region)
{
    wxCHECK_MSG( HasFlag(wxFRAME_SHAPED), false,
                 wxT("Shaped windows must be created with the wxFRAME_SHAPED style."));

    GdkWindow *window = NULL;
    if (m_wxwindow)
    {
        window = GTK_PIZZA(m_wxwindow)->bin_window;
        do_shape_combine_region(window, region);
    }
    window = m_widget->window;
    return do_shape_combine_region(window, region);
}

bool wxTopLevelWindowGTK::IsActive()
{
    return (this == (wxTopLevelWindowGTK*)g_activeFrame);
}

void wxTopLevelWindowGTK::RequestUserAttention(int flags)
{
    bool new_hint_value = false;

    // FIXME: This is a workaround to focus handling problem
    // If RequestUserAttention is called for example right after a wxSleep, OnInternalIdle hasn't
    // yet been processed, and the internal focus system is not up to date yet.
    // wxYieldIfNeeded ensures the processing of it, but can have unwanted side effects - MR
    ::wxYieldIfNeeded();

    if(m_urgency_hint >= 0)
        gtk_timeout_remove(m_urgency_hint);

    m_urgency_hint = -2;

    if( GTK_WIDGET_REALIZED(m_widget) && !IsActive() )
    {
        new_hint_value = true;

        if (flags & wxUSER_ATTENTION_INFO)
        {
            m_urgency_hint = gtk_timeout_add(5000, (GtkFunction)gtk_frame_urgency_timer_callback, this);
        } else {
            m_urgency_hint = -1;
        }
    }

    wxgtk_window_set_urgency_hint(GTK_WINDOW( m_widget ), new_hint_value);
}

void wxTopLevelWindowGTK::SetWindowStyleFlag( long style )
{
    // Process wxWindow styles. This also updates the internal variable
    // Therefore m_windowStyle bits carry now the _new_ style values
    wxWindow::SetWindowStyleFlag(style);
}
