/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/listbox.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_LISTBOX

#include "wx/listbox.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/intl.h"
    #include "wx/utils.h"
    #include "wx/settings.h"
    #include "wx/checklst.h"
    #include "wx/arrstr.h"
#endif

#include "wx/gtk1/private.h"

#if wxUSE_TOOLTIPS
    #include "wx/tooltip.h"
#endif

#include <gdk/gdk.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

extern bool           g_blockEventsOnDrag;
extern bool           g_blockEventsOnScroll;
extern wxCursor       g_globalCursor;
extern wxWindowGTK   *g_delayedFocus;
extern wxWindowGTK   *g_focusWindow;
extern wxWindowGTK   *g_focusWindowLast;

static bool       g_hasDoubleClicked = false;

//-----------------------------------------------------------------------------
// idle callback for SetFirstItem
//-----------------------------------------------------------------------------

struct wxlistbox_idle_struct
{
    wxListBox   *m_listbox;
    int          m_item;
    gint         m_tag;
};

extern "C" {
static gint wxlistbox_idle_callback( gpointer gdata )
{
    wxlistbox_idle_struct* data = (wxlistbox_idle_struct*) gdata;
    gdk_threads_enter();

    gtk_idle_remove( data->m_tag );

    // check that the items haven't been deleted from the listbox since we had
    // installed this callback
    wxListBox *lbox = data->m_listbox;
    if ( data->m_item < (int)lbox->GetCount() )
    {
        lbox->SetFirstItem( data->m_item );
    }

    delete data;

    gdk_threads_leave();

    return TRUE;
}
}

//-----------------------------------------------------------------------------
// "focus_in_event"
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_listitem_focus_in_callback( GtkWidget *WXUNUSED(widget),
                                            GdkEvent *WXUNUSED(event),
                                            wxWindow *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    g_focusWindowLast =
    g_focusWindow = win;

    // does the window itself think that it has the focus?
    if ( !win->m_hasFocus )
    {
        // not yet, notify it
        win->m_hasFocus = true;

        wxChildFocusEvent eventChildFocus(win);
        (void)win->HandleWindowEvent(eventChildFocus);

        wxFocusEvent eventFocus(wxEVT_SET_FOCUS, win->GetId());
        eventFocus.SetEventObject(win);

        (void)win->HandleWindowEvent(eventFocus);
    }

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "focus_out_event"
//-----------------------------------------------------------------------------

extern "C" {
static gint gtk_listitem_focus_out_callback( GtkWidget *WXUNUSED(widget),
                                             GdkEventFocus *WXUNUSED(gdk_event),
                                             wxWindowGTK *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    g_focusWindow = NULL;

    // don't send the window a kill focus event if it thinks that it doesn't
    // have focus already
    if ( win->m_hasFocus )
    {
        win->m_hasFocus = false;

        wxFocusEvent event( wxEVT_KILL_FOCUS, win->GetId() );
        event.SetEventObject( win );

        // even if we did process the event in wx code, still let GTK itself
        // process it too as otherwise bad things happen, especially in GTK2
        // where the text control simply aborts the program if it doesn't get
        // the matching focus out event
        (void)win->HandleWindowEvent( event );
    }

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "button_release_event"
//-----------------------------------------------------------------------------

/* we would normally emit a wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event once
   a GDK_2BUTTON_PRESS occurs, but this has the particular problem of the
   listbox keeping the focus until it receives a GDK_BUTTON_RELEASE event.
   this can lead to race conditions so that we emit the dclick event
   after the GDK_BUTTON_RELEASE event after the GDK_2BUTTON_PRESS event */

extern "C" {
static gint
gtk_listbox_button_release_callback( GtkWidget * WXUNUSED(widget),
                                     GdkEventButton * WXUNUSED(gdk_event),
                                     wxListBox *listbox )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (g_blockEventsOnDrag) return FALSE;
    if (g_blockEventsOnScroll) return FALSE;

    if (!listbox->m_hasVMT) return FALSE;

    if (!g_hasDoubleClicked) return FALSE;

    wxCommandEvent event( wxEVT_COMMAND_LISTBOX_DOUBLECLICKED, listbox->GetId() );
    event.SetEventObject( listbox );

    wxArrayInt aSelections;
    int n, count = listbox->GetSelections(aSelections);
    if ( count > 0 )
    {
        n = aSelections[0];
        if ( listbox->HasClientObjectData() )
            event.SetClientObject( listbox->GetClientObject(n) );
        else if ( listbox->HasClientUntypedData() )
            event.SetClientData( listbox->GetClientData(n) );
        event.SetString( listbox->GetString(n) );
    }
    else
    {
        n = -1;
    }

    event.SetInt(n);

    listbox->HandleWindowEvent( event );

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "button_press_event"
//-----------------------------------------------------------------------------

extern "C" {
static gint
gtk_listbox_button_press_callback( GtkWidget *widget,
                                   GdkEventButton *gdk_event,
                                   wxListBox *listbox )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (g_blockEventsOnDrag) return FALSE;
    if (g_blockEventsOnScroll) return FALSE;

    if (!listbox->m_hasVMT) return FALSE;

    int sel = listbox->GtkGetIndex( widget );

#if wxUSE_CHECKLISTBOX
    if ((listbox->m_hasCheckBoxes) && (gdk_event->x < 15) && (gdk_event->type != GDK_2BUTTON_PRESS))
    {
        wxCheckListBox *clb = (wxCheckListBox *)listbox;

        clb->Check( sel, !clb->IsChecked(sel) );

        wxCommandEvent event( wxEVT_COMMAND_CHECKLISTBOX_TOGGLED, listbox->GetId() );
        event.SetEventObject( listbox );
        event.SetInt( sel );
        listbox->HandleWindowEvent( event );
    }
#endif // wxUSE_CHECKLISTBOX

    if ((gdk_event->state == 0) &&
         (((listbox->GetWindowStyleFlag() & wxLB_MULTIPLE) != 0) ||
          ((listbox->GetWindowStyleFlag() & wxLB_EXTENDED) != 0)) )
    {
            listbox->m_blockEvent = true;

            int i;
            for (i = 0; i < (int)listbox->GetCount(); i++)
                if (i != sel)
                    gtk_list_unselect_item( GTK_LIST(listbox->m_list), i );

            listbox->m_blockEvent = false;

            return false;
    }

    /* emit wxEVT_COMMAND_LISTBOX_DOUBLECLICKED later */
    g_hasDoubleClicked = (gdk_event->type == GDK_2BUTTON_PRESS);

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "key_press_event"
//-----------------------------------------------------------------------------

extern "C" {
static gint
gtk_listbox_key_press_callback( GtkWidget *widget, GdkEventKey *gdk_event, wxListBox *listbox )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (g_blockEventsOnDrag)
        return FALSE;

    bool ret = false;

    if ((gdk_event->keyval == GDK_Tab) || (gdk_event->keyval == GDK_ISO_Left_Tab))
    {
        wxNavigationKeyEvent new_event;
        /* GDK reports GDK_ISO_Left_Tab for SHIFT-TAB */
        new_event.SetDirection( (gdk_event->keyval == GDK_Tab) );
        /* CTRL-TAB changes the (parent) window, i.e. switch notebook page */
        new_event.SetWindowChange( (gdk_event->state & GDK_CONTROL_MASK) );
        new_event.SetCurrentFocus( listbox );
        ret = listbox->HandleWindowEvent( new_event );
    }

    if ((gdk_event->keyval == GDK_Return) && (!ret))
    {
        // eat return in all modes
        ret = true;
    }

#if wxUSE_CHECKLISTBOX
    if ((gdk_event->keyval == ' ') && (listbox->m_hasCheckBoxes) && (!ret))
    {
        int sel = listbox->GtkGetIndex( widget );

        wxCheckListBox *clb = (wxCheckListBox *)listbox;

        clb->Check( sel, !clb->IsChecked(sel) );

        wxCommandEvent new_event( wxEVT_COMMAND_CHECKLISTBOX_TOGGLED, listbox->GetId() );
        new_event.SetEventObject( listbox );
        new_event.SetInt( sel );
        ret = listbox->HandleWindowEvent( new_event );
    }
#endif // wxUSE_CHECKLISTBOX

    // Check or uncheck item with SPACE
    if ((gdk_event->keyval == ' ') && (!ret) &&
         (((listbox->GetWindowStyleFlag() & wxLB_MULTIPLE) != 0) ||
          ((listbox->GetWindowStyleFlag() & wxLB_EXTENDED) != 0)) )
    {
        int sel = listbox->GtkGetIndex( widget );

        if (sel != -1)
        {
            ret = true;

            if (listbox->IsSelected( sel ))
                gtk_list_unselect_item( listbox->m_list, sel );
            else
                gtk_list_select_item( listbox->m_list, sel );

            wxCommandEvent new_event(wxEVT_COMMAND_LISTBOX_SELECTED, listbox->GetId() );
            new_event.SetEventObject( listbox );
            wxArrayInt aSelections;
            int n, count = listbox->GetSelections(aSelections);
            if ( count > 0 )
            {
                n = aSelections[0];
                if ( listbox->HasClientObjectData() )
                    new_event.SetClientObject( listbox->GetClientObject(n) );
                else if ( listbox->HasClientUntypedData() )
                    new_event.SetClientData( listbox->GetClientData(n) );
                new_event.SetString( listbox->GetString(n) );
            }
            else
            {
                n = -1;
            }
            new_event.SetInt(n);
            listbox->HandleWindowEvent( new_event );
        }
    }

    if (ret)
    {
        gtk_signal_emit_stop_by_name( GTK_OBJECT(widget), "key_press_event" );
        return TRUE;
    }

    return FALSE;
}
}

//-----------------------------------------------------------------------------
// "select" and "deselect"
//-----------------------------------------------------------------------------

static void gtk_listitem_select_cb( GtkWidget *widget,
                                    wxListBox *listbox,
                                    bool is_selection )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (!listbox->m_hasVMT) return;
    if (g_blockEventsOnDrag) return;

    if (listbox->m_blockEvent) return;

    wxCommandEvent event(wxEVT_COMMAND_LISTBOX_SELECTED, listbox->GetId() );
    event.SetEventObject( listbox );

    // indicate whether this is a selection or a deselection
    event.SetExtraLong( is_selection );

    if ((listbox->GetWindowStyleFlag() & wxLB_SINGLE) != 0)
    {
        int sel = listbox->GtkGetIndex( widget );

        if (listbox->m_prevSelection != sel)
            gtk_list_unselect_item( listbox->m_list, listbox->m_prevSelection );

        listbox->m_prevSelection = sel;
    }

    wxArrayInt aSelections;
    int n, count = listbox->GetSelections(aSelections);
    if ( count > 0 )
    {
        n = aSelections[0];
        if ( listbox->HasClientObjectData() )
            event.SetClientObject( listbox->GetClientObject(n) );
        else if ( listbox->HasClientUntypedData() )
            event.SetClientData( listbox->GetClientData(n) );
        event.SetString( listbox->GetString(n) );
    }
    else
    {
        n = -1;
    }

    event.SetInt(n);

//    No longer required with new code in wxLB_SINGLE
//    listbox->GetEventHandler()->AddPendingEvent( event );
    listbox->HandleWindowEvent( event );
}

extern "C" {
static void gtk_listitem_select_callback( GtkWidget *widget, wxListBox *listbox )
{
    gtk_listitem_select_cb( widget, listbox, TRUE );
}
}

extern "C" {
static void gtk_listitem_deselect_callback( GtkWidget *widget, wxListBox *listbox )
{
    gtk_listitem_select_cb( widget, listbox, FALSE );
}
}

//-----------------------------------------------------------------------------
// wxListBox
//-----------------------------------------------------------------------------

extern "C" {
static gint
gtk_listbox_realized_callback( GtkWidget *WXUNUSED(widget), wxListBox *win )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    GList *child = win->m_list->children;
    for (child = win->m_list->children; child != NULL; child = child->next)
        gtk_widget_show( GTK_WIDGET(child->data) );

    return false;
}
}

//-----------------------------------------------------------------------------
// wxListBox
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxListBox, wxControlWithItems)

// ----------------------------------------------------------------------------
// construction
// ----------------------------------------------------------------------------

wxListBox::wxListBox()
{
    m_list = NULL;
#if wxUSE_CHECKLISTBOX
    m_hasCheckBoxes = false;
#endif // wxUSE_CHECKLISTBOX
}

bool wxListBox::Create( wxWindow *parent, wxWindowID id,
                        const wxPoint &pos, const wxSize &size,
                        const wxArrayString& choices,
                        long style, const wxValidator& validator,
                        const wxString &name )
{
    wxCArrayString chs(choices);

    return Create( parent, id, pos, size, chs.GetCount(), chs.GetStrings(),
                   style, validator, name );
}

bool wxListBox::Create( wxWindow *parent, wxWindowID id,
                        const wxPoint &pos, const wxSize &size,
                        int n, const wxString choices[],
                        long style, const wxValidator& validator,
                        const wxString &name )
{
    m_needParent = true;
    m_acceptsFocus = true;
    m_prevSelection = 0;  // or -1 ??
    m_blockEvent = false;

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, validator, name ))
    {
        wxFAIL_MSG( wxT("wxListBox creation failed") );
        return false;
    }

    m_widget = gtk_scrolled_window_new( NULL, NULL );
    if (style & wxLB_ALWAYS_SB)
    {
      gtk_scrolled_window_set_policy( GTK_SCROLLED_WINDOW(m_widget),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS );
    }
    else
    {
      gtk_scrolled_window_set_policy( GTK_SCROLLED_WINDOW(m_widget),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC );
    }

    m_list = GTK_LIST( gtk_list_new() );

    GtkSelectionMode mode;
    if (style & wxLB_MULTIPLE)
    {
        mode = GTK_SELECTION_MULTIPLE;
    }
    else if (style & wxLB_EXTENDED)
    {
        mode = GTK_SELECTION_EXTENDED;
    }
    else
    {
        // if style was 0 set single mode
        m_windowStyle |= wxLB_SINGLE;
        mode = GTK_SELECTION_SINGLE;
    }

    gtk_list_set_selection_mode( GTK_LIST(m_list), mode );

    gtk_scrolled_window_add_with_viewport( GTK_SCROLLED_WINDOW(m_widget), GTK_WIDGET(m_list) );

    /* make list scroll when moving the focus down using cursor keys */
    gtk_container_set_focus_vadjustment(
        GTK_CONTAINER(m_list),
        gtk_scrolled_window_get_vadjustment(
            GTK_SCROLLED_WINDOW(m_widget)));

    gtk_widget_show( GTK_WIDGET(m_list) );

    gtk_signal_connect( GTK_OBJECT(m_list), "realize",
                        GTK_SIGNAL_FUNC(gtk_listbox_realized_callback), (gpointer) this );

    if ( style & wxLB_SORT )
    {
        // this will change Append() behaviour
        m_strings = new wxSortedArrayString;
    }
    else
    {
        m_strings = NULL;
    }

    Append(n, choices);

    m_parent->DoAddChild( this );

    PostCreation(size);
    SetInitialSize(size); // need this too because this is a wxControlWithItems

    return true;
}

wxListBox::~wxListBox()
{
    m_hasVMT = false;

    Clear();

    delete m_strings;
}

// ----------------------------------------------------------------------------
// adding items
// ----------------------------------------------------------------------------

int wxListBox::DoInsertItems(const wxArrayStringsAdapter& items,
                             unsigned int pos,
                             void **clientData,
                             wxClientDataType type)
{
    wxCHECK_MSG( m_list != NULL, wxNOT_FOUND, wxT("invalid listbox") );

    const unsigned count = GetCount();
    wxCHECK_MSG( pos <= count, wxNOT_FOUND,
                    wxT("invalid index in wxListBox::InsertItems") );

    // code elsewhere supposes we have as many items in m_clientList as items
    // in the listbox
    wxASSERT_MSG( m_clientList.GetCount() == count,
                      wxT("bug in client data management") );

    InvalidateBestSize();

    const unsigned numItems = items.GetCount();

    for ( unsigned int n = 0; n < numItems; ++n, ++pos )
    {
        const wxString& item = items[n];

        const unsigned idx = m_strings ? m_strings->Add(item)
                                       : pos;

        GtkAddItem(item, idx == GetCount() ? (unsigned) -1 : idx);

        m_clientList.Insert(idx, NULL);

        AssignNewItemClientData(idx, clientData, n, type);
    }

    wxASSERT_MSG( m_clientList.GetCount() == GetCount(),
                      wxT("bug in client data management") );

    return pos - 1;
}

void wxListBox::GtkAddItem( const wxString &item, int pos )
{
    wxCHECK_RET( m_list != NULL, wxT("invalid listbox") );

    GtkWidget *list_item;

    wxString label(item);
#if wxUSE_CHECKLISTBOX
    if (m_hasCheckBoxes)
    {
        label.Prepend(wxCHECKLBOX_STRING);
    }
#endif // wxUSE_CHECKLISTBOX

    list_item = gtk_list_item_new_with_label( wxGTK_CONV( label ) );

    GList *gitem_list = g_list_alloc ();
    gitem_list->data = list_item;

    if (pos == -1)
        gtk_list_append_items( GTK_LIST (m_list), gitem_list );
    else
        gtk_list_insert_items( GTK_LIST (m_list), gitem_list, pos );

    gtk_signal_connect_after( GTK_OBJECT(list_item), "select",
      GTK_SIGNAL_FUNC(gtk_listitem_select_callback), (gpointer)this );

    if (HasFlag(wxLB_MULTIPLE) || HasFlag(wxLB_EXTENDED))
        gtk_signal_connect_after( GTK_OBJECT(list_item), "deselect",
          GTK_SIGNAL_FUNC(gtk_listitem_deselect_callback), (gpointer)this );

    gtk_signal_connect( GTK_OBJECT(list_item),
                        "button_press_event",
                        (GtkSignalFunc)gtk_listbox_button_press_callback,
                        (gpointer) this );

    gtk_signal_connect_after( GTK_OBJECT(list_item),
                        "button_release_event",
                        (GtkSignalFunc)gtk_listbox_button_release_callback,
                        (gpointer) this );

    gtk_signal_connect( GTK_OBJECT(list_item),
                           "key_press_event",
                           (GtkSignalFunc)gtk_listbox_key_press_callback,
                           (gpointer)this );


    gtk_signal_connect( GTK_OBJECT(list_item), "focus_in_event",
            GTK_SIGNAL_FUNC(gtk_listitem_focus_in_callback), (gpointer)this );

    gtk_signal_connect( GTK_OBJECT(list_item), "focus_out_event",
            GTK_SIGNAL_FUNC(gtk_listitem_focus_out_callback), (gpointer)this );

    ConnectWidget( list_item );

    if (GTK_WIDGET_REALIZED(m_widget))
    {
        gtk_widget_show( list_item );

        gtk_widget_realize( list_item );
        gtk_widget_realize( GTK_BIN(list_item)->child );

#if wxUSE_TOOLTIPS
        if (m_tooltip) m_tooltip->Apply( this );
#endif
    }

    // Apply current widget style to the new list_item
    GtkRcStyle *style = CreateWidgetStyle();
    if (style)
    {
        gtk_widget_modify_style( GTK_WIDGET( list_item ), style );
        GtkBin *bin = GTK_BIN( list_item );
        gtk_widget_modify_style( GTK_WIDGET( bin->child ), style );
        gtk_rc_style_unref( style );
    }
}

// ----------------------------------------------------------------------------
// deleting items
// ----------------------------------------------------------------------------

void wxListBox::DoClear()
{
    wxCHECK_RET( m_list != NULL, wxT("invalid listbox") );

    gtk_list_clear_items( m_list, 0, (int)GetCount() );

    if ( GTK_LIST(m_list)->last_focus_child != NULL  )
    {
        // This should be NULL, I think.
        GTK_LIST(m_list)->last_focus_child = NULL;
    }

    m_clientList.Clear();

    if ( m_strings )
        m_strings->Clear();
}

void wxListBox::DoDeleteOneItem(unsigned int n)
{
    wxCHECK_RET( m_list != NULL, wxT("invalid listbox") );

    GList *child = g_list_nth( m_list->children, n );

    wxCHECK_RET( child, wxT("wrong listbox index") );

    GList *list = g_list_append( NULL, child->data );
    gtk_list_remove_items( m_list, list );
    g_list_free( list );

    wxList::compatibility_iterator node = m_clientList.Item( n );
    if ( node )
    {
        m_clientList.Erase( node );
    }

    if ( m_strings )
        m_strings->RemoveAt(n);
}

// ----------------------------------------------------------------------------
// client data
// ----------------------------------------------------------------------------

void wxListBox::DoSetItemClientData(unsigned int n, void* clientData)
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid listbox control") );

    wxList::compatibility_iterator node = m_clientList.Item( n );
    wxCHECK_RET( node, wxT("invalid index in wxListBox::DoSetItemClientData") );

    node->SetData( (wxObject*) clientData );
}

void* wxListBox::DoGetItemClientData(unsigned int n) const
{
    wxCHECK_MSG( m_widget != NULL, NULL, wxT("invalid listbox control") );

    wxList::compatibility_iterator node = m_clientList.Item( n );
    wxCHECK_MSG( node, NULL, wxT("invalid index in wxListBox::DoGetItemClientData") );

    return node->GetData();
}

// ----------------------------------------------------------------------------
// string list access
// ----------------------------------------------------------------------------

wxString wxListBox::GetRealLabel(GList *item) const
{
    GtkBin *bin = GTK_BIN( item->data );
    GtkLabel *label = GTK_LABEL( bin->child );

    wxString str;

    str = wxString( label->label );

#if wxUSE_CHECKLISTBOX
    // checklistboxes have "[±] " prepended to their lables, remove it
    //
    // NB: 4 below is the length of wxCHECKLBOX_STRING from wx/gtk1/checklst.h
    if ( m_hasCheckBoxes )
        str.erase(0, 4);
#endif // wxUSE_CHECKLISTBOX

    return str;
}

void wxListBox::SetString(unsigned int n, const wxString &string)
{
    wxCHECK_RET( m_list != NULL, wxT("invalid listbox") );

    GList *child = g_list_nth( m_list->children, n );
    if (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        GtkLabel *label = GTK_LABEL( bin->child );

        wxString str;
#if wxUSE_CHECKLISTBOX
        if (m_hasCheckBoxes)
            str += wxCHECKLBOX_STRING;
#endif // wxUSE_CHECKLISTBOX
        str += string;

        gtk_label_set( label, wxGTK_CONV( str ) );
    }
    else
    {
        wxFAIL_MSG(wxT("wrong listbox index"));
    }
}

wxString wxListBox::GetString(unsigned int n) const
{
    wxCHECK_MSG( m_list != NULL, wxEmptyString, wxT("invalid listbox") );

    GList *child = g_list_nth( m_list->children, n );
    if (child)
    {
        return GetRealLabel(child);
    }

    wxFAIL_MSG(wxT("wrong listbox index"));

    return wxEmptyString;
}

unsigned int wxListBox::GetCount() const
{
    wxCHECK_MSG( m_list != NULL, 0, wxT("invalid listbox") );

    GList *children = m_list->children;
    return g_list_length(children);
}

int wxListBox::FindString( const wxString &item, bool bCase ) const
{
    wxCHECK_MSG( m_list != NULL, wxNOT_FOUND, wxT("invalid listbox") );

    GList *child = m_list->children;
    int count = 0;
    while (child)
    {
        if ( item.IsSameAs( GetRealLabel(child), bCase ) )
            return count;

        count++;
        child = child->next;
    }

    // it's not an error if the string is not found -> no wxCHECK

    return wxNOT_FOUND;
}

// ----------------------------------------------------------------------------
// selection
// ----------------------------------------------------------------------------

int wxListBox::GetSelection() const
{
    wxCHECK_MSG( m_list != NULL, wxNOT_FOUND, wxT("invalid listbox") );

    GList *child = m_list->children;
    int count = 0;
    while (child)
    {
        if (GTK_WIDGET(child->data)->state == GTK_STATE_SELECTED) return count;
        count++;
        child = child->next;
    }
    return wxNOT_FOUND;
}

int wxListBox::GetSelections( wxArrayInt& aSelections ) const
{
    wxCHECK_MSG( m_list != NULL, wxNOT_FOUND, wxT("invalid listbox") );

    // get the number of selected items first
    GList *child = m_list->children;
    int count = 0;
    for (child = m_list->children; child != NULL; child = child->next)
    {
        if (GTK_WIDGET(child->data)->state == GTK_STATE_SELECTED)
            count++;
    }

    aSelections.Empty();

    if (count > 0)
    {
        // now fill the list
        aSelections.Alloc(count); // optimization attempt
        int i = 0;
        for (child = m_list->children; child != NULL; child = child->next, i++)
        {
            if (GTK_WIDGET(child->data)->state == GTK_STATE_SELECTED)
                 aSelections.Add(i);
        }
    }

    return count;
}

bool wxListBox::IsSelected( int n ) const
{
    wxCHECK_MSG( m_list != NULL, false, wxT("invalid listbox") );

    GList *target = g_list_nth( m_list->children, n );

    wxCHECK_MSG( target, false, wxT("invalid listbox index") );

    return (GTK_WIDGET(target->data)->state == GTK_STATE_SELECTED) ;
}

void wxListBox::DoSetSelection( int n, bool select )
{
    wxCHECK_RET( m_list != NULL, wxT("invalid listbox") );

    m_blockEvent = true;

    if (select)
    {
        if ((m_windowStyle & wxLB_SINGLE) != 0)
            gtk_list_unselect_item( m_list, m_prevSelection );
        gtk_list_select_item( m_list, n );
        m_prevSelection = n;
    }
    else
        gtk_list_unselect_item( m_list, n );

    m_blockEvent = false;
}

void wxListBox::DoSetFirstItem( int n )
{
    wxCHECK_RET( m_list, wxT("invalid listbox") );

    if (gdk_pointer_is_grabbed () && GTK_WIDGET_HAS_GRAB (m_list))
        return;

    // terribly efficient
    const gchar *vadjustment_key = "gtk-vadjustment";
    guint vadjustment_key_id = g_quark_from_static_string (vadjustment_key);

    GtkAdjustment *adjustment =
       (GtkAdjustment*) gtk_object_get_data_by_id (GTK_OBJECT (m_list), vadjustment_key_id);
    wxCHECK_RET( adjustment, wxT("invalid listbox code") );

    GList *target = g_list_nth( m_list->children, n );
    wxCHECK_RET( target, wxT("invalid listbox index") );

    GtkWidget *item = GTK_WIDGET(target->data);
    wxCHECK_RET( item, wxT("invalid listbox code") );

    if (item->allocation.y == -1)
    {
        wxlistbox_idle_struct* data = new wxlistbox_idle_struct;
        data->m_listbox = this;
        data->m_item = n;
        data->m_tag = gtk_idle_add_priority( 800, wxlistbox_idle_callback, (gpointer) data );

        return;
    }

    float y = item->allocation.y;
    if (y > adjustment->upper - adjustment->page_size)
        y = adjustment->upper - adjustment->page_size;
    gtk_adjustment_set_value( adjustment, y );
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

int wxListBox::GtkGetIndex( GtkWidget *item ) const
{
    if (item)
    {
        GList *child = m_list->children;
        int count = 0;
        while (child)
        {
            if (GTK_WIDGET(child->data) == item) return count;
            count++;
            child = child->next;
        }
    }
    return -1;
}

#if wxUSE_TOOLTIPS
void wxListBox::ApplyToolTip( GtkTooltips *tips, const wxChar *tip )
{
    GList *child = m_list->children;
    while (child)
    {
        gtk_tooltips_set_tip( tips, GTK_WIDGET( child->data ), wxConvCurrent->cWX2MB(tip), NULL );
        child = child->next;
    }
}
#endif // wxUSE_TOOLTIPS

GtkWidget *wxListBox::GetConnectWidget()
{
    // return GTK_WIDGET(m_list);
    return m_widget;
}

bool wxListBox::IsOwnGtkWindow( GdkWindow *window )
{
    return m_widget->window == window ||
                GTK_WIDGET(m_list)->window == window;
}

void wxListBox::DoApplyWidgetStyle(GtkRcStyle *style)
{
    if (m_hasBgCol && m_backgroundColour.Ok())
    {
        GdkWindow *window = GTK_WIDGET(m_list)->window;
        if ( window )
        {
            m_backgroundColour.CalcPixel( gdk_window_get_colormap( window ) );
            gdk_window_set_background( window, m_backgroundColour.GetColor() );
            gdk_window_clear( window );
        }
    }

    GList *child = m_list->children;
    while (child)
    {
        gtk_widget_modify_style( GTK_WIDGET(child->data), style );

        GtkBin *bin = GTK_BIN( child->data );
        GtkWidget *label = GTK_WIDGET( bin->child );
        gtk_widget_modify_style( label, style );

        child = child->next;
    }
}

void wxListBox::OnInternalIdle()
{
    wxCursor cursor = m_cursor;
    if (g_globalCursor.Ok()) cursor = g_globalCursor;

    if (GTK_WIDGET(m_list)->window && cursor.Ok())
    {
        /* I now set the cursor the anew in every OnInternalIdle call
           as setting the cursor in a parent window also effects the
           windows above so that checking for the current cursor is
           not possible. */

        gdk_window_set_cursor( GTK_WIDGET(m_list)->window, cursor.GetCursor() );

        GList *child = m_list->children;
        while (child)
        {
            GtkBin *bin = GTK_BIN( child->data );
            GtkWidget *label = GTK_WIDGET( bin->child );

            if (!label->window)
                break;
            else
                gdk_window_set_cursor( label->window, cursor.GetCursor() );

            child = child->next;
        }
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

wxSize wxListBox::DoGetBestSize() const
{
    int lbWidth = 100;  // some defaults
    int lbHeight = 110;
    int wLine;

    // Find the widest line
    for(unsigned int i = 0; i < GetCount(); i++) {
        wxString str(GetString(i));
        GetTextExtent(str, &wLine, NULL);
        lbWidth = wxMax(lbWidth, wLine);
    }

    // Add room for the scrollbar
    lbWidth += wxSystemSettings::GetMetric(wxSYS_VSCROLL_X);

    // And just a bit more
    int cx, cy;
    GetTextExtent( wxT("X"), &cx, &cy);
    lbWidth += 3 * cx;

    // don't make the listbox too tall (limit height to around 10 items) but don't
    // make it too small neither
    lbHeight = (cy+4) * wxMin(wxMax(GetCount(), 3), 10);

    wxSize best(lbWidth, lbHeight);
    CacheBestSize(best);
    return best;
}

void wxListBox::FixUpMouseEvent(GtkWidget *widget, wxCoord& x, wxCoord& y)
{
    // the mouse event coords are relative to the listbox items, we need to
    // translate them to the normal client coords
    x += widget->allocation.x;
    y += widget->allocation.y;
}


// static
wxVisualAttributes
wxListBox::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    return GetDefaultAttributesFromGTKWidget(gtk_list_new, true);
}

#endif // wxUSE_LISTBOX
