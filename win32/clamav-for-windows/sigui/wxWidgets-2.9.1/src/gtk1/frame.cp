/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/frame.cpp
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

#include "wx/frame.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/dcclient.h"
    #include "wx/menu.h"
    #include "wx/dialog.h"
    #include "wx/control.h"
    #include "wx/toolbar.h"
    #include "wx/statusbr.h"
#endif // WX_PRECOMP

#include <glib.h>
#include "wx/gtk1/private.h"

#include <gdk/gdkkeysyms.h>
#include <gdk/gdkx.h>

#include "wx/gtk1/win_gtk.h"

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

const int wxSTATUS_HEIGHT  = 25;
const int wxPLACE_HOLDER   = 0;

// ----------------------------------------------------------------------------
// idle system
// ----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

// ----------------------------------------------------------------------------
// event tables
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxFrame, wxTopLevelWindow)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// GTK callbacks
// ----------------------------------------------------------------------------

#if wxUSE_MENUS_NATIVE

//-----------------------------------------------------------------------------
// "child_attached" of menu bar
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_menu_attached_callback( GtkWidget *WXUNUSED(widget), GtkWidget *WXUNUSED(child), wxFrame *win )
{
    if (!win->m_hasVMT) return;

    win->m_menuBarDetached = false;
    win->GtkUpdateSize();
}
}

//-----------------------------------------------------------------------------
// "child_detached" of menu bar
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_menu_detached_callback( GtkWidget *WXUNUSED(widget), GtkWidget *WXUNUSED(child), wxFrame *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (!win->m_hasVMT) return;

    // Raise the client area area
    gdk_window_raise( win->m_wxwindow->window );

    win->m_menuBarDetached = true;
    win->GtkUpdateSize();
}
}

#endif // wxUSE_MENUS_NATIVE

#if wxUSE_TOOLBAR
//-----------------------------------------------------------------------------
// "child_attached" of tool bar
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_toolbar_attached_callback( GtkWidget *WXUNUSED(widget), GtkWidget *WXUNUSED(child), wxFrame *win )
{
    if (!win->m_hasVMT) return;

    win->m_toolBarDetached = false;
    win->GtkUpdateSize();
}
}

//-----------------------------------------------------------------------------
// "child_detached" of tool bar
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_toolbar_detached_callback( GtkWidget *WXUNUSED(widget), GtkWidget *WXUNUSED(child), wxFrame *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (!win->m_hasVMT) return;

    // Raise the client area area
    gdk_window_raise( win->m_wxwindow->window );

    win->m_toolBarDetached = true;
    win->GtkUpdateSize();
}
}
#endif // wxUSE_TOOLBAR


// ----------------------------------------------------------------------------
// wxFrame itself
// ----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// InsertChild for wxFrame
//-----------------------------------------------------------------------------

/* Callback for wxFrame. This very strange beast has to be used because
 * C++ has no virtual methods in a constructor. We have to emulate a
 * virtual function here as wxWidgets requires different ways to insert
 * a child in container classes. */

static void wxInsertChildInFrame( wxFrame* parent, wxWindow* child )
{
    wxASSERT( GTK_IS_WIDGET(child->m_widget) );

    if (!parent->m_insertInClientArea)
    {
        // These are outside the client area
        wxFrame* frame = (wxFrame*) parent;
        gtk_pizza_put( GTK_PIZZA(frame->m_mainWidget),
                         GTK_WIDGET(child->m_widget),
                         child->m_x,
                         child->m_y,
                         child->m_width,
                         child->m_height );

#if wxUSE_TOOLBAR_NATIVE
        // We connect to these events for recalculating the client area
        // space when the toolbar is floating
        if (wxIS_KIND_OF(child,wxToolBar))
        {
            wxToolBar *toolBar = (wxToolBar*) child;
            if (toolBar->GetWindowStyle() & wxTB_DOCKABLE)
            {
                gtk_signal_connect( GTK_OBJECT(toolBar->m_widget), "child_attached",
                    GTK_SIGNAL_FUNC(gtk_toolbar_attached_callback), (gpointer)parent );

                gtk_signal_connect( GTK_OBJECT(toolBar->m_widget), "child_detached",
                    GTK_SIGNAL_FUNC(gtk_toolbar_detached_callback), (gpointer)parent );
            }
        }
#endif // wxUSE_TOOLBAR
    }
    else
    {
        // These are inside the client area
        gtk_pizza_put( GTK_PIZZA(parent->m_wxwindow),
                         GTK_WIDGET(child->m_widget),
                         child->m_x,
                         child->m_y,
                         child->m_width,
                         child->m_height );
    }

    // Resize on OnInternalIdle
    parent->GtkUpdateSize();
}

// ----------------------------------------------------------------------------
// wxFrame creation
// ----------------------------------------------------------------------------

void wxFrame::Init()
{
    m_menuBarDetached = false;
    m_toolBarDetached = false;
    m_menuBarHeight = 2;
}

bool wxFrame::Create( wxWindow *parent,
                      wxWindowID id,
                      const wxString& title,
                      const wxPoint& pos,
                      const wxSize& sizeOrig,
                      long style,
                      const wxString &name )
{
    bool rt = wxTopLevelWindow::Create(parent, id, title, pos, sizeOrig,
                                       style, name);
    m_insertCallback = (wxInsertChildFunction) wxInsertChildInFrame;

    return rt;
}

wxFrame::~wxFrame()
{
    SendDestroyEvent();

    DeleteAllBars();
}

// ----------------------------------------------------------------------------
// overridden wxWindow methods
// ----------------------------------------------------------------------------

void wxFrame::DoGetClientSize( int *width, int *height ) const
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

    wxTopLevelWindow::DoGetClientSize( width, height );

    if (height)
    {
#if wxUSE_MENUS_NATIVE
        // menu bar
        if (m_frameMenuBar)
        {
            if (!m_menuBarDetached)
                (*height) -= m_menuBarHeight;
            else
                (*height) -= wxPLACE_HOLDER;
        }
#endif // wxUSE_MENUS_NATIVE

#if wxUSE_STATUSBAR
        // status bar
        if (m_frameStatusBar && m_frameStatusBar->IsShown())
            (*height) -= wxSTATUS_HEIGHT;
#endif // wxUSE_STATUSBAR

#if wxUSE_TOOLBAR
        // tool bar
        if (m_frameToolBar && m_frameToolBar->IsShown())
        {
            if (m_toolBarDetached)
            {
                *height -= wxPLACE_HOLDER;
            }
            else
            {
                int x, y;
                m_frameToolBar->GetSize( &x, &y );
                if ( m_frameToolBar->GetWindowStyle() & wxTB_VERTICAL )
                {
                    *width -= x;
                }
                else
                {
                    *height -= y;
                }
            }
        }
#endif // wxUSE_TOOLBAR
    }
}

void wxFrame::DoSetClientSize( int width, int height )
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

#if wxUSE_MENUS_NATIVE
        // menu bar
        if (m_frameMenuBar)
        {
            if (!m_menuBarDetached)
                height += m_menuBarHeight;
            else
                height += wxPLACE_HOLDER;
        }
#endif // wxUSE_MENUS_NATIVE

#if wxUSE_STATUSBAR
        // status bar
        if (m_frameStatusBar && m_frameStatusBar->IsShown()) height += wxSTATUS_HEIGHT;
#endif

#if wxUSE_TOOLBAR
        // tool bar
        if (m_frameToolBar && m_frameToolBar->IsShown())
        {
            if (m_toolBarDetached)
            {
                height += wxPLACE_HOLDER;
            }
            else
            {
                int x, y;
                m_frameToolBar->GetSize( &x, &y );
                if ( m_frameToolBar->GetWindowStyle() & wxTB_VERTICAL )
                {
                    width += x;
                }
                else
                {
                    height += y;
                }
            }
        }
#endif

    wxTopLevelWindow::DoSetClientSize( width, height );
}

void wxFrame::GtkOnSize( int WXUNUSED(x), int WXUNUSED(y),
                         int width, int height )
{
    // due to a bug in gtk, x,y are always 0
    // m_x = x;
    // m_y = y;

    // avoid recursions
    if (m_resizing) return;
    m_resizing = true;

    // this shouldn't happen: wxFrame, wxMDIParentFrame and wxMDIChildFrame have m_wxwindow
    wxASSERT_MSG( (m_wxwindow != NULL), wxT("invalid frame") );

    m_width = width;
    m_height = height;

    // space occupied by m_frameToolBar and m_frameMenuBar
    int client_area_x_offset = 0,
        client_area_y_offset = 0;

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

    if ((minWidth != -1) && (m_width < minWidth)) m_width = minWidth;
    if ((minHeight != -1) && (m_height < minHeight)) m_height = minHeight;
    if ((maxWidth != -1) && (m_width > maxWidth)) m_width = maxWidth;
    if ((maxHeight != -1) && (m_height > maxHeight)) m_height = maxHeight;

    if (m_mainWidget)
    {
        // set size hints
        gint flag = 0; // GDK_HINT_POS;
        if ((minWidth != -1) || (minHeight != -1)) flag |= GDK_HINT_MIN_SIZE;
        if ((maxWidth != -1) || (maxHeight != -1)) flag |= GDK_HINT_MAX_SIZE;
        GdkGeometry geom;
        geom.min_width = minWidth;
        geom.min_height = minHeight;
        geom.max_width = maxWidth;
        geom.max_height = maxHeight;
        gtk_window_set_geometry_hints( GTK_WINDOW(m_widget),
                                       NULL,
                                       &geom,
                                       (GdkWindowHints) flag );

        // I revert back to wxGTK's original behaviour. m_mainWidget holds
        // the menubar, the toolbar and the client area, which is represented
        // by m_wxwindow.
        // This hurts in the eye, but I don't want to call SetSize()
        // because I don't want to call any non-native functions here.

#if wxUSE_MENUS_NATIVE
        if (m_frameMenuBar)
        {
            int xx = m_miniEdge;
            int yy = m_miniEdge + m_miniTitle;
            int ww = m_width  - 2*m_miniEdge;
            int hh = m_menuBarHeight;
            if (m_menuBarDetached) hh = wxPLACE_HOLDER;
            m_frameMenuBar->m_x = xx;
            m_frameMenuBar->m_y = yy;
            m_frameMenuBar->m_width = ww;
            m_frameMenuBar->m_height = hh;
            gtk_pizza_set_size( GTK_PIZZA(m_mainWidget),
                                  m_frameMenuBar->m_widget,
                                  xx, yy, ww, hh );
            client_area_y_offset += hh;
        }
#endif // wxUSE_MENUS_NATIVE

#if wxUSE_TOOLBAR
        if ((m_frameToolBar) && m_frameToolBar->IsShown() &&
            (m_frameToolBar->m_widget->parent == m_mainWidget))
        {
            int xx = m_miniEdge;
            int yy = m_miniEdge + m_miniTitle;
#if wxUSE_MENUS_NATIVE
            if (m_frameMenuBar)
            {
                if (!m_menuBarDetached)
                    yy += m_menuBarHeight;
                else
                    yy += wxPLACE_HOLDER;
            }
#endif // wxUSE_MENUS_NATIVE

            m_frameToolBar->m_x = xx;
            m_frameToolBar->m_y = yy;

            // don't change the toolbar's reported height/width
            int ww, hh;
            if ( m_frameToolBar->GetWindowStyle() & wxTB_VERTICAL )
            {
                ww = m_toolBarDetached ? wxPLACE_HOLDER
                                       : m_frameToolBar->m_width;
                hh = m_height - 2*m_miniEdge;

                client_area_x_offset += ww;
            }
            else
            {
                ww = m_width - 2*m_miniEdge;
                hh = m_toolBarDetached ? wxPLACE_HOLDER
                                       : m_frameToolBar->m_height;

                client_area_y_offset += hh;
            }

            gtk_pizza_set_size( GTK_PIZZA(m_mainWidget),
                                  m_frameToolBar->m_widget,
                                  xx, yy, ww, hh );
        }
#endif // wxUSE_TOOLBAR

        int client_x = client_area_x_offset + m_miniEdge;
        int client_y = client_area_y_offset + m_miniEdge + m_miniTitle;
        int client_w = m_width - client_area_x_offset - 2*m_miniEdge;
        int client_h = m_height - client_area_y_offset- 2*m_miniEdge - m_miniTitle;
        gtk_pizza_set_size( GTK_PIZZA(m_mainWidget),
                              m_wxwindow,
                              client_x, client_y, client_w, client_h );
    }
    else
    {
        // If there is no m_mainWidget between m_widget and m_wxwindow there
        // is no need to set the size or position of m_wxwindow.
    }

#if wxUSE_STATUSBAR
    if (m_frameStatusBar && m_frameStatusBar->IsShown())
    {
        int xx = 0 + m_miniEdge;
        int yy = m_height - wxSTATUS_HEIGHT - m_miniEdge - client_area_y_offset;
        int ww = m_width - 2*m_miniEdge;
        int hh = wxSTATUS_HEIGHT;
        m_frameStatusBar->m_x = xx;
        m_frameStatusBar->m_y = yy;
        m_frameStatusBar->m_width = ww;
        m_frameStatusBar->m_height = hh;
        gtk_pizza_set_size( GTK_PIZZA(m_wxwindow),
                            m_frameStatusBar->m_widget,
                            xx, yy, ww, hh );
        gtk_widget_draw( m_frameStatusBar->m_widget, NULL );
    }
#endif // wxUSE_STATUSBAR

    m_sizeSet = true;

    // send size event to frame
    wxSizeEvent event( wxSize(m_width,m_height), GetId() );
    event.SetEventObject( this );
    HandleWindowEvent( event );

#if wxUSE_STATUSBAR
    // send size event to status bar
    if (m_frameStatusBar)
    {
        wxSizeEvent event2( wxSize(m_frameStatusBar->m_width,m_frameStatusBar->m_height), m_frameStatusBar->GetId() );
        event2.SetEventObject( m_frameStatusBar );
        m_frameStatusBar->HandleWindowEvent( event2 );
    }
#endif // wxUSE_STATUSBAR

    m_resizing = false;
}

void wxFrame::OnInternalIdle()
{
    wxFrameBase::OnInternalIdle();

#if wxUSE_MENUS_NATIVE
    if (m_frameMenuBar) m_frameMenuBar->OnInternalIdle();
#endif // wxUSE_MENUS_NATIVE
#if wxUSE_TOOLBAR
    if (m_frameToolBar) m_frameToolBar->OnInternalIdle();
#endif
#if wxUSE_STATUSBAR
    if (m_frameStatusBar)
    {
        m_frameStatusBar->OnInternalIdle();

        // There may be controls in the status bar that
        // need to be updated
        for ( wxWindowList::compatibility_iterator node = m_frameStatusBar->GetChildren().GetFirst();
          node;
          node = node->GetNext() )
        {
            wxWindow *child = node->GetData();
            child->OnInternalIdle();
        }
    }
#endif
}

// ----------------------------------------------------------------------------
// menu/tool/status bar stuff
// ----------------------------------------------------------------------------

#if wxUSE_MENUS_NATIVE

void wxFrame::DetachMenuBar()
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );
    wxASSERT_MSG( (m_wxwindow != NULL), wxT("invalid frame") );

    if ( m_frameMenuBar )
    {
        m_frameMenuBar->Attach( this );

        if (m_frameMenuBar->GetWindowStyle() & wxMB_DOCKABLE)
        {
            gtk_signal_disconnect_by_func( GTK_OBJECT(m_frameMenuBar->m_widget),
                GTK_SIGNAL_FUNC(gtk_menu_attached_callback), (gpointer)this );

            gtk_signal_disconnect_by_func( GTK_OBJECT(m_frameMenuBar->m_widget),
                GTK_SIGNAL_FUNC(gtk_menu_detached_callback), (gpointer)this );
        }

        gtk_widget_ref( m_frameMenuBar->m_widget );

        gtk_container_remove( GTK_CONTAINER(m_mainWidget), m_frameMenuBar->m_widget );
    }

    wxFrameBase::DetachMenuBar();
}

void wxFrame::AttachMenuBar( wxMenuBar *menuBar )
{
    wxFrameBase::AttachMenuBar(menuBar);

    if (m_frameMenuBar)
    {
        m_frameMenuBar->SetParent(this);
        gtk_pizza_put( GTK_PIZZA(m_mainWidget),
                m_frameMenuBar->m_widget,
                m_frameMenuBar->m_x,
                m_frameMenuBar->m_y,
                m_frameMenuBar->m_width,
                m_frameMenuBar->m_height );

        if (menuBar->GetWindowStyle() & wxMB_DOCKABLE)
        {
            gtk_signal_connect( GTK_OBJECT(menuBar->m_widget), "child_attached",
                GTK_SIGNAL_FUNC(gtk_menu_attached_callback), (gpointer)this );

            gtk_signal_connect( GTK_OBJECT(menuBar->m_widget), "child_detached",
                GTK_SIGNAL_FUNC(gtk_menu_detached_callback), (gpointer)this );
        }

        gtk_widget_show( m_frameMenuBar->m_widget );

        UpdateMenuBarSize();
    }
    else
    {
        m_menuBarHeight = 2;
        GtkUpdateSize();        // resize window in OnInternalIdle
    }
}

void wxFrame::UpdateMenuBarSize()
{
    GtkRequisition  req;

    req.width = 2;
    req.height = 2;

    // this is called after Remove with a NULL m_frameMenuBar
    if ( m_frameMenuBar )
        (* GTK_WIDGET_CLASS( GTK_OBJECT_GET_CLASS(m_frameMenuBar->m_widget) )->size_request )
            (m_frameMenuBar->m_widget, &req );

    m_menuBarHeight = req.height;

    // resize window in OnInternalIdle

    GtkUpdateSize();
}

#endif // wxUSE_MENUS_NATIVE

#if wxUSE_TOOLBAR

wxToolBar* wxFrame::CreateToolBar( long style, wxWindowID id, const wxString& name )
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

    m_insertInClientArea = false;

    m_frameToolBar = wxFrameBase::CreateToolBar( style, id, name );

    m_insertInClientArea = true;

    GtkUpdateSize();

    return m_frameToolBar;
}

void wxFrame::SetToolBar(wxToolBar *toolbar)
{
    bool hadTbar = m_frameToolBar != NULL;

    wxFrameBase::SetToolBar(toolbar);

    if ( m_frameToolBar )
    {
        // insert into toolbar area if not already there
        if ((m_frameToolBar->m_widget->parent) &&
            (m_frameToolBar->m_widget->parent != m_mainWidget))
        {
            GetChildren().DeleteObject( m_frameToolBar );

            gtk_widget_reparent( m_frameToolBar->m_widget, m_mainWidget );
            GtkUpdateSize();
        }
    }
    else // toolbar unset
    {
        // still need to update size if it had been there before
        if ( hadTbar )
        {
            GtkUpdateSize();
        }
    }
}

#endif // wxUSE_TOOLBAR

#if wxUSE_STATUSBAR

wxStatusBar* wxFrame::CreateStatusBar(int number,
                                      long style,
                                      wxWindowID id,
                                      const wxString& name)
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid frame") );

    // because it will change when toolbar is added
    GtkUpdateSize();

    return wxFrameBase::CreateStatusBar( number, style, id, name );
}

void wxFrame::SetStatusBar(wxStatusBar *statbar)
{
    bool hadStatBar = m_frameStatusBar != NULL;

    wxFrameBase::SetStatusBar(statbar);

    if (hadStatBar && !m_frameStatusBar)
        GtkUpdateSize();
}

void wxFrame::PositionStatusBar()
{
    if ( !m_frameStatusBar )
        return;

    GtkUpdateSize();
}
#endif // wxUSE_STATUSBAR
