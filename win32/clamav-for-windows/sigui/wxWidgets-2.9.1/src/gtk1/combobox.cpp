/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/combobox.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_COMBOBOX

#include "wx/combobox.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/settings.h"
    #include "wx/textctrl.h"    // for wxEVT_COMMAND_TEXT_UPDATED
    #include "wx/arrstr.h"
#endif

#include "wx/gtk1/private.h"

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

extern bool   g_blockEventsOnDrag;
static int    g_SelectionBeforePopup = wxID_NONE; // this means the popup is hidden

//-----------------------------------------------------------------------------
//  "changed" - typing and list item matches get changed, select-child
//              if it doesn't match an item then just get a single changed
//-----------------------------------------------------------------------------

extern "C" {
static void
gtk_text_changed_callback( GtkWidget *WXUNUSED(widget), wxComboBox *combo )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (combo->m_ignoreNextUpdate)
    {
        combo->m_ignoreNextUpdate = false;
        return;
    }

    if (!combo->m_hasVMT) return;

    wxCommandEvent event( wxEVT_COMMAND_TEXT_UPDATED, combo->GetId() );
    event.SetString( combo->GetValue() );
    event.SetEventObject( combo );
    combo->HandleWindowEvent( event );
}
}

extern "C" {
static void
gtk_dummy_callback(GtkEntry *WXUNUSED(entry), GtkCombo *WXUNUSED(combo))
{
}
}

extern "C" {
static void
gtk_popup_hide_callback(GtkCombo *WXUNUSED(gtk_combo), wxComboBox *combo)
{
    // when the popup is hidden, throw a SELECTED event only if the combobox
    // selection changed.
    const int curSelection = combo->GetCurrentSelection();

    const bool hasChanged = curSelection != g_SelectionBeforePopup;

    // reset the selection flag to value meaning that it is hidden and do it
    // now, before generating the events, so that GetSelection() returns the
    // new value from the event handler
    g_SelectionBeforePopup = wxID_NONE;

    if ( hasChanged )
    {
        wxCommandEvent event( wxEVT_COMMAND_COMBOBOX_SELECTED, combo->GetId() );
        event.SetInt( curSelection );
        event.SetString( combo->GetStringSelection() );
        event.SetEventObject( combo );
        combo->HandleWindowEvent( event );

        // for consistency with the other ports, send TEXT event
        wxCommandEvent event2( wxEVT_COMMAND_TEXT_UPDATED, combo->GetId() );
        event2.SetString( combo->GetStringSelection() );
        event2.SetEventObject( combo );
        combo->HandleWindowEvent( event2 );
    }
}
}

extern "C" {
static void
gtk_popup_show_callback(GtkCombo *WXUNUSED(gtk_combo), wxComboBox *combo)
{
    // store the combobox selection value before the popup is shown
    g_SelectionBeforePopup = combo->GetCurrentSelection();
}
}

//-----------------------------------------------------------------------------
// "select-child" - click/cursor get select-child, changed, select-child
//-----------------------------------------------------------------------------

extern "C" {
static void
gtk_combo_select_child_callback( GtkList *WXUNUSED(list), GtkWidget *WXUNUSED(widget), wxComboBox *combo )
{
    if (g_isIdle) wxapp_install_idle_handler();

    if (!combo->m_hasVMT) return;

    if (g_blockEventsOnDrag) return;

    int curSelection = combo->GetCurrentSelection();

    if (combo->m_prevSelection == curSelection) return;

    GtkWidget *list = GTK_COMBO(combo->m_widget)->list;
    gtk_list_unselect_item( GTK_LIST(list), combo->m_prevSelection );

    combo->m_prevSelection = curSelection;

    // Quickly set the value of the combo box
    // as GTK+ does that only AFTER the event
    // is sent.
    gtk_signal_disconnect_by_func( GTK_OBJECT(GTK_COMBO(combo->GetHandle())->entry),
      GTK_SIGNAL_FUNC(gtk_text_changed_callback), (gpointer)combo );
    combo->SetValue( combo->GetStringSelection() );
    gtk_signal_connect_after( GTK_OBJECT(GTK_COMBO(combo->GetHandle())->entry), "changed",
      GTK_SIGNAL_FUNC(gtk_text_changed_callback), (gpointer)combo );

    // throw a SELECTED event only if the combobox popup is hidden (wxID_NONE)
    // because when combobox popup is shown, gtk_combo_select_child_callback is
    // called each times the mouse is over an item with a pressed button so a lot
    // of SELECTED event could be generated if the user keep the mouse button down
    // and select other items ...
    if (g_SelectionBeforePopup == wxID_NONE)
    {
        wxCommandEvent event( wxEVT_COMMAND_COMBOBOX_SELECTED, combo->GetId() );
        event.SetInt( curSelection );
        event.SetString( combo->GetStringSelection() );
        event.SetEventObject( combo );
        combo->HandleWindowEvent( event );

        // for consistency with the other ports, don't generate text update
        // events while the user is browsing the combobox neither
        wxCommandEvent event2( wxEVT_COMMAND_TEXT_UPDATED, combo->GetId() );
        event2.SetString( combo->GetValue() );
        event2.SetEventObject( combo );
        combo->HandleWindowEvent( event2 );
    }
}
}

//-----------------------------------------------------------------------------
// wxComboBox
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxComboBox,wxControl)

BEGIN_EVENT_TABLE(wxComboBox, wxControl)
    EVT_SIZE(wxComboBox::OnSize)
    EVT_CHAR(wxComboBox::OnChar)

    EVT_MENU(wxID_CUT, wxComboBox::OnCut)
    EVT_MENU(wxID_COPY, wxComboBox::OnCopy)
    EVT_MENU(wxID_PASTE, wxComboBox::OnPaste)
    EVT_MENU(wxID_UNDO, wxComboBox::OnUndo)
    EVT_MENU(wxID_REDO, wxComboBox::OnRedo)
    EVT_MENU(wxID_CLEAR, wxComboBox::OnDelete)
    EVT_MENU(wxID_SELECTALL, wxComboBox::OnSelectAll)

    EVT_UPDATE_UI(wxID_CUT, wxComboBox::OnUpdateCut)
    EVT_UPDATE_UI(wxID_COPY, wxComboBox::OnUpdateCopy)
    EVT_UPDATE_UI(wxID_PASTE, wxComboBox::OnUpdatePaste)
    EVT_UPDATE_UI(wxID_UNDO, wxComboBox::OnUpdateUndo)
    EVT_UPDATE_UI(wxID_REDO, wxComboBox::OnUpdateRedo)
    EVT_UPDATE_UI(wxID_CLEAR, wxComboBox::OnUpdateDelete)
    EVT_UPDATE_UI(wxID_SELECTALL, wxComboBox::OnUpdateSelectAll)
END_EVENT_TABLE()

bool wxComboBox::Create( wxWindow *parent, wxWindowID id,
                         const wxString& value,
                         const wxPoint& pos, const wxSize& size,
                         const wxArrayString& choices,
                         long style, const wxValidator& validator,
                         const wxString& name )
{
    wxCArrayString chs(choices);

    return Create( parent, id, value, pos, size, chs.GetCount(),
                   chs.GetStrings(), style, validator, name );
}

bool wxComboBox::Create( wxWindow *parent, wxWindowID id, const wxString& value,
                         const wxPoint& pos, const wxSize& size,
                         int n, const wxString choices[],
                         long style, const wxValidator& validator,
                         const wxString& name )
{
    m_ignoreNextUpdate = false;
    m_needParent = true;
    m_acceptsFocus = true;
    m_prevSelection = 0;

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, validator, name ))
    {
        wxFAIL_MSG( wxT("wxComboBox creation failed") );
        return false;
    }

    m_widget = gtk_combo_new();
    GtkCombo *combo = GTK_COMBO(m_widget);

    // Disable GTK's broken events ...
    gtk_signal_disconnect( GTK_OBJECT(combo->entry), combo->entry_change_id );
    // ... and add surrogate handler.
    combo->entry_change_id = gtk_signal_connect (GTK_OBJECT (combo->entry), "changed",
                  (GtkSignalFunc) gtk_dummy_callback, combo);

    // make it more useable
    gtk_combo_set_use_arrows_always( GTK_COMBO(m_widget), TRUE );

    // and case-sensitive
    gtk_combo_set_case_sensitive( GTK_COMBO(m_widget), TRUE );

    GtkWidget *list = GTK_COMBO(m_widget)->list;

    // gtk_list_set_selection_mode( GTK_LIST(list), GTK_SELECTION_MULTIPLE );

    for (int i = 0; i < n; i++)
    {
        GtkWidget *list_item = gtk_list_item_new_with_label( wxGTK_CONV( choices[i] ) );

        m_clientDataList.Append( NULL );
        m_clientObjectList.Append( NULL );

        gtk_container_add( GTK_CONTAINER(list), list_item );

        gtk_widget_show( list_item );
    }

    m_parent->DoAddChild( this );

    m_focusWidget = combo->entry;

    PostCreation(size);

    ConnectWidget( combo->button );

    // MSW's combo box shows the value and the selection is -1
    gtk_entry_set_text( GTK_ENTRY(combo->entry), wxGTK_CONV(value) );
    gtk_list_unselect_all( GTK_LIST(combo->list) );

    if (style & wxCB_READONLY)
        gtk_entry_set_editable( GTK_ENTRY( combo->entry ), FALSE );

    // "show" and "hide" events are generated when user click on the combobox button which popups a list
    // this list is the "popwin" gtk widget
    gtk_signal_connect( GTK_OBJECT(GTK_COMBO(combo)->popwin), "hide",
                        GTK_SIGNAL_FUNC(gtk_popup_hide_callback), (gpointer)this );
    gtk_signal_connect( GTK_OBJECT(GTK_COMBO(combo)->popwin), "show",
                        GTK_SIGNAL_FUNC(gtk_popup_show_callback), (gpointer)this );

    gtk_signal_connect_after( GTK_OBJECT(combo->entry), "changed",
      GTK_SIGNAL_FUNC(gtk_text_changed_callback), (gpointer)this );

    gtk_signal_connect_after( GTK_OBJECT(combo->list), "select-child",
      GTK_SIGNAL_FUNC(gtk_combo_select_child_callback), (gpointer)this );

    SetInitialSize(size); // need this too because this is a wxControlWithItems

    // This is required for tool bar support
//    wxSize setsize = GetSize();
//    gtk_widget_set_usize( m_widget, setsize.x, setsize.y );

    return true;
}

wxComboBox::~wxComboBox()
{
    wxList::compatibility_iterator node = m_clientObjectList.GetFirst();
    while (node)
    {
        wxClientData *cd = (wxClientData*)node->GetData();
        if (cd) delete cd;
        node = node->GetNext();
    }
    m_clientObjectList.Clear();

    m_clientDataList.Clear();
}

void wxComboBox::SetFocus()
{
    if ( m_hasFocus )
    {
        // don't do anything if we already have focus
        return;
    }

    gtk_widget_grab_focus( m_focusWidget );
}

int wxComboBox::DoInsertItems(const wxArrayStringsAdapter& items,
                              unsigned int pos,
                              void **clientData,
                              wxClientDataType type)
{
    wxCHECK_MSG( m_widget != NULL, -1, wxT("invalid combobox") );

    DisableEvents();

    GtkWidget *list = GTK_COMBO(m_widget)->list;

    GtkRcStyle *style = CreateWidgetStyle();

    const unsigned int count = items.GetCount();
    for( unsigned int i = 0; i < count; ++i, ++pos )
    {
        GtkWidget *
            list_item = gtk_list_item_new_with_label( wxGTK_CONV( items[i] ) );

        if ( pos == GetCount() )
        {
            gtk_container_add( GTK_CONTAINER(list), list_item );
        }
        else // insert, not append
        {
            GList *gitem_list = g_list_alloc ();
            gitem_list->data = list_item;
            gtk_list_insert_items( GTK_LIST (list), gitem_list, pos );
        }

        if (GTK_WIDGET_REALIZED(m_widget))
        {
            gtk_widget_realize( list_item );
            gtk_widget_realize( GTK_BIN(list_item)->child );

            if (style)
            {
                gtk_widget_modify_style( GTK_WIDGET( list_item ), style );
                GtkBin *bin = GTK_BIN( list_item );
                GtkWidget *label = GTK_WIDGET( bin->child );
                gtk_widget_modify_style( label, style );
            }

        }

        gtk_widget_show( list_item );

        if ( m_clientDataList.GetCount() < GetCount() )
            m_clientDataList.Insert( pos, NULL );
        if ( m_clientObjectList.GetCount() < GetCount() )
            m_clientObjectList.Insert( pos, NULL );

        AssignNewItemClientData(pos, clientData, i, type);
    }

    if ( style )
        gtk_rc_style_unref( style );

    EnableEvents();

    InvalidateBestSize();

    return pos - 1;
}

void wxComboBox::DoSetItemClientData(unsigned int n, void* clientData)
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    wxList::compatibility_iterator node = m_clientDataList.Item( n );
    if (!node) return;

    node->SetData( (wxObject*) clientData );
}

void* wxComboBox::DoGetItemClientData(unsigned int n) const
{
    wxCHECK_MSG( m_widget != NULL, NULL, wxT("invalid combobox") );

    wxList::compatibility_iterator node = m_clientDataList.Item( n );

    return node ? node->GetData() : NULL;
}

void wxComboBox::DoClear()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    DisableEvents();

    GtkWidget *list = GTK_COMBO(m_widget)->list;
    gtk_list_clear_items( GTK_LIST(list), 0, (int)GetCount() );

    m_clientObjectList.Clear();

    m_clientDataList.Clear();

    EnableEvents();

    InvalidateBestSize();
}

void wxComboBox::DoDeleteOneItem(unsigned int n)
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    GtkList *listbox = GTK_LIST( GTK_COMBO(m_widget)->list );

    GList *child = g_list_nth( listbox->children, n );

    if (!child)
    {
        wxFAIL_MSG(wxT("wrong index"));
        return;
    }

    DisableEvents();

    GList *list = g_list_append( NULL, child->data );
    gtk_list_remove_items( listbox, list );
    g_list_free( list );

    wxList::compatibility_iterator node = m_clientObjectList.Item( n );
    if (node)
    {
        m_clientObjectList.Erase( node );
    }

    node = m_clientDataList.Item( n );
    if (node)
        m_clientDataList.Erase( node );

    EnableEvents();

    InvalidateBestSize();
}

void wxComboBox::SetString(unsigned int n, const wxString &text)
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    GtkWidget *list = GTK_COMBO(m_widget)->list;

    GList *child = g_list_nth( GTK_LIST(list)->children, n );
    if (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        GtkLabel *label = GTK_LABEL( bin->child );
        gtk_label_set_text(label, wxGTK_CONV(text));
    }
    else
    {
        wxFAIL_MSG( wxT("wxComboBox: wrong index") );
    }

    InvalidateBestSize();
}

int wxComboBox::FindString( const wxString &item, bool bCase ) const
{
    wxCHECK_MSG( m_widget != NULL, wxNOT_FOUND, wxT("invalid combobox") );

    GtkWidget *list = GTK_COMBO(m_widget)->list;

    GList *child = GTK_LIST(list)->children;
    int count = 0;
    while (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        GtkLabel *label = GTK_LABEL( bin->child );
        wxString str( label->label );
        if (item.IsSameAs( str , bCase ) )
            return count;

        count++;
        child = child->next;
    }

    return wxNOT_FOUND;
}

int wxComboBox::GetSelection() const
{
    // if the popup is currently opened, use the selection as it had been
    // before it dropped down
    return g_SelectionBeforePopup == wxID_NONE ? GetCurrentSelection()
                                               : g_SelectionBeforePopup;
}

int wxComboBox::GetCurrentSelection() const
{
    wxCHECK_MSG( m_widget != NULL, -1, wxT("invalid combobox") );

    GtkWidget *list = GTK_COMBO(m_widget)->list;

    GList *selection = GTK_LIST(list)->selection;
    if (selection)
    {
        GList *child = GTK_LIST(list)->children;
        int count = 0;
        while (child)
        {
            if (child->data == selection->data) return count;
            count++;
            child = child->next;
        }
    }

    return wxNOT_FOUND;
}

wxString wxComboBox::GetString(unsigned int n) const
{
    wxCHECK_MSG( m_widget != NULL, wxEmptyString, wxT("invalid combobox") );

    GtkWidget *list = GTK_COMBO(m_widget)->list;

    wxString str;
    GList *child = g_list_nth( GTK_LIST(list)->children, n );
    if (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        GtkLabel *label = GTK_LABEL( bin->child );
        str = wxString( label->label );
    }
    else
    {
        wxFAIL_MSG( wxT("wxComboBox: wrong index") );
    }

    return str;
}

wxString wxComboBox::GetStringSelection() const
{
    wxCHECK_MSG( m_widget != NULL, wxEmptyString, wxT("invalid combobox") );

    GtkWidget *list = GTK_COMBO(m_widget)->list;

    GList *selection = GTK_LIST(list)->selection;
    if (selection)
    {
        GtkBin *bin = GTK_BIN( selection->data );
        GtkLabel *label = GTK_LABEL( bin->child );
        wxString tmp( label->label );
        return tmp;
    }

    wxFAIL_MSG( wxT("wxComboBox: no selection") );

    return wxEmptyString;
}

unsigned int wxComboBox::GetCount() const
{
    wxCHECK_MSG( m_widget != NULL, 0, wxT("invalid combobox") );

    GtkWidget *list = GTK_COMBO(m_widget)->list;

    GList *child = GTK_LIST(list)->children;
    unsigned int count = 0;
    while (child) { count++; child = child->next; }
    return count;
}

void wxComboBox::SetSelection( int n )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    DisableEvents();

    GtkWidget *list = GTK_COMBO(m_widget)->list;
    gtk_list_unselect_item( GTK_LIST(list), m_prevSelection );
    gtk_list_select_item( GTK_LIST(list), n );
    m_prevSelection = n;

    EnableEvents();
}

wxString wxComboBox::DoGetValue() const
{
    GtkEntry *entry = GTK_ENTRY( GTK_COMBO(m_widget)->entry );
    wxString tmp( wxGTK_CONV_BACK( gtk_entry_get_text( entry ) ) );

#if 0
    for (int i = 0; i < wxStrlen(tmp.c_str()) +1; i++)
    {
        wxChar c = tmp[i];
        printf( "%d ", (int) (c) );
    }
    printf( "\n" );
#endif

    return tmp;
}

void wxComboBox::SetValue( const wxString& value )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    gtk_entry_set_text( GTK_ENTRY(entry), wxGTK_CONV( value ) );

    InvalidateBestSize();
}

void wxComboBox::WriteText(const wxString& value)
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    GtkEditable * const edit = GTK_EDITABLE(entry);

    gtk_editable_delete_selection(edit);
    gint len = gtk_editable_get_position(edit);
    gtk_editable_insert_text(edit, wxGTK_CONV(value), -1, &len);
    gtk_editable_set_position(edit, len);
}

void wxComboBox::Copy()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    gtk_editable_copy_clipboard( GTK_EDITABLE(entry) DUMMY_CLIPBOARD_ARG );
}

void wxComboBox::Cut()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    gtk_editable_cut_clipboard( GTK_EDITABLE(entry) DUMMY_CLIPBOARD_ARG );
}

void wxComboBox::Paste()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    gtk_editable_paste_clipboard( GTK_EDITABLE(entry) DUMMY_CLIPBOARD_ARG);
}

void wxComboBox::Undo()
{
    // TODO
}

void wxComboBox::Redo()
{
    // TODO
}

void wxComboBox::SelectAll()
{
    SetSelection(0, GetLastPosition());
}

bool wxComboBox::CanUndo() const
{
    // TODO
    return false;
}

bool wxComboBox::CanRedo() const
{
    // TODO
    return false;
}

bool wxComboBox::HasSelection() const
{
    long from, to;
    GetSelection(&from, &to);
    return from != to;
}

bool wxComboBox::CanCopy() const
{
    // Can copy if there's a selection
    return HasSelection();
}

bool wxComboBox::CanCut() const
{
    return CanCopy() && IsEditable();
}

bool wxComboBox::CanPaste() const
{
    // TODO: check for text on the clipboard
    return IsEditable() ;
}

bool wxComboBox::IsEditable() const
{
    return !HasFlag(wxCB_READONLY);
}


void wxComboBox::SetInsertionPoint( long pos )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    if ( pos == GetLastPosition() )
        pos = -1;

    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    gtk_entry_set_position( GTK_ENTRY(entry), (int)pos );
}

long wxComboBox::GetInsertionPoint() const
{
    return (long) GET_EDITABLE_POS( GTK_COMBO(m_widget)->entry );
}

wxTextPos wxComboBox::GetLastPosition() const
{
    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    int pos = GTK_ENTRY(entry)->text_length;
    return (long) pos-1;
}

void wxComboBox::Replace( long from, long to, const wxString& value )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid combobox") );

    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    gtk_editable_delete_text( GTK_EDITABLE(entry), (gint)from, (gint)to );
    if (value.IsNull()) return;
    gint pos = (gint)to;

#if wxUSE_UNICODE
    wxCharBuffer buffer = wxConvUTF8.cWX2MB( value );
    gtk_editable_insert_text( GTK_EDITABLE(entry), (const char*) buffer, strlen( (const char*) buffer ), &pos );
#else
    gtk_editable_insert_text( GTK_EDITABLE(entry), value.c_str(), value.length(), &pos );
#endif
}

void wxComboBox::SetSelection( long from, long to )
{
    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    gtk_editable_select_region( GTK_EDITABLE(entry), (gint)from, (gint)to );
}

void wxComboBox::GetSelection( long* from, long* to ) const
{
    if (IsEditable())
    {
        GtkEditable *editable = GTK_EDITABLE(GTK_COMBO(m_widget)->entry);
        *from = (long) editable->selection_start_pos;
        *to = (long) editable->selection_end_pos;
    }
}

void wxComboBox::SetEditable( bool editable )
{
    GtkWidget *entry = GTK_COMBO(m_widget)->entry;
    gtk_entry_set_editable( GTK_ENTRY(entry), editable );
}

void wxComboBox::OnChar( wxKeyEvent &event )
{
    if ( event.GetKeyCode() == WXK_RETURN )
    {
        // GTK automatically selects an item if its in the list
        wxCommandEvent eventEnter(wxEVT_COMMAND_TEXT_ENTER, GetId());
        eventEnter.SetString( GetValue() );
        eventEnter.SetInt( GetSelection() );
        eventEnter.SetEventObject( this );

        if (!HandleWindowEvent( eventEnter ))
        {
            // This will invoke the dialog default action, such
            // as the clicking the default button.

            wxWindow *top_frame = m_parent;
            while (top_frame->GetParent() && !(top_frame->IsTopLevel()))
                top_frame = top_frame->GetParent();

            if (top_frame && GTK_IS_WINDOW(top_frame->m_widget))
            {
                GtkWindow *window = GTK_WINDOW(top_frame->m_widget);

                if (window->default_widget)
                        gtk_widget_activate (window->default_widget);
            }
        }

        // Catch GTK event so that GTK doesn't open the drop
        // down list upon RETURN.
        return;
    }

    event.Skip();
}

void wxComboBox::DisableEvents()
{
    gtk_signal_disconnect_by_func( GTK_OBJECT(GTK_COMBO(m_widget)->list),
      GTK_SIGNAL_FUNC(gtk_combo_select_child_callback), (gpointer)this );
    gtk_signal_disconnect_by_func( GTK_OBJECT(GTK_COMBO(m_widget)->entry),
      GTK_SIGNAL_FUNC(gtk_text_changed_callback), (gpointer)this );
}

void wxComboBox::EnableEvents()
{
    gtk_signal_connect_after( GTK_OBJECT(GTK_COMBO(m_widget)->list), "select-child",
      GTK_SIGNAL_FUNC(gtk_combo_select_child_callback), (gpointer)this );
    gtk_signal_connect_after( GTK_OBJECT(GTK_COMBO(m_widget)->entry), "changed",
      GTK_SIGNAL_FUNC(gtk_text_changed_callback), (gpointer)this );
}

void wxComboBox::OnSize( wxSizeEvent &event )
{
    // NB: In some situations (e.g. on non-first page of a wizard, if the
    //     size used is default size), GtkCombo widget is resized correctly,
    //     but it's look is not updated, it's rendered as if it was much wider.
    //     No other widgets are affected, so it looks like a bug in GTK+.
    //     Manually requesting resize calculation (as gtk_pizza_set_size does)
    //     fixes it.
    if (GTK_WIDGET_VISIBLE(m_widget))
        gtk_widget_queue_resize(m_widget);

    event.Skip();
}

void wxComboBox::DoApplyWidgetStyle(GtkRcStyle *style)
{
//    gtk_widget_modify_style( GTK_COMBO(m_widget)->button, syle );

    gtk_widget_modify_style( GTK_COMBO(m_widget)->entry, style );
    gtk_widget_modify_style( GTK_COMBO(m_widget)->list, style );

    GtkList *list = GTK_LIST( GTK_COMBO(m_widget)->list );
    GList *child = list->children;
    while (child)
    {
        gtk_widget_modify_style( GTK_WIDGET(child->data), style );

        GtkBin *bin = GTK_BIN(child->data);
        gtk_widget_modify_style( bin->child, style );

        child = child->next;
    }
}

GtkWidget* wxComboBox::GetConnectWidget()
{
    return GTK_COMBO(m_widget)->entry;
}

bool wxComboBox::IsOwnGtkWindow( GdkWindow *window )
{
    return ( (window == GTK_ENTRY( GTK_COMBO(m_widget)->entry )->text_area) ||
             (window == GTK_COMBO(m_widget)->button->window ) );
}

wxSize wxComboBox::DoGetBestSize() const
{
    wxSize ret( wxControl::DoGetBestSize() );

    // we know better our horizontal extent: it depends on the longest string
    // in the combobox
    if ( m_widget )
    {
        int width;
        unsigned int count = GetCount();
        for ( unsigned int n = 0; n < count; n++ )
        {
            GetTextExtent(GetString(n), &width, NULL, NULL, NULL );
            if ( width > ret.x )
                ret.x = width;
        }
    }

    // empty combobox should have some reasonable default size too
    if ( ret.x < 100 )
        ret.x = 100;

    CacheBestSize(ret);
    return ret;
}

// static
wxVisualAttributes
wxComboBox::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    return GetDefaultAttributesFromGTKWidget(gtk_combo_new, true);
}

// ----------------------------------------------------------------------------
// standard event handling
// ----------------------------------------------------------------------------

void wxComboBox::OnCut(wxCommandEvent& WXUNUSED(event))
{
    Cut();
}

void wxComboBox::OnCopy(wxCommandEvent& WXUNUSED(event))
{
    Copy();
}

void wxComboBox::OnPaste(wxCommandEvent& WXUNUSED(event))
{
    Paste();
}

void wxComboBox::OnUndo(wxCommandEvent& WXUNUSED(event))
{
    Undo();
}

void wxComboBox::OnRedo(wxCommandEvent& WXUNUSED(event))
{
    Redo();
}

void wxComboBox::OnDelete(wxCommandEvent& WXUNUSED(event))
{
    long from, to;
    GetSelection(& from, & to);
    if (from != -1 && to != -1)
        Remove(from, to);
}

void wxComboBox::OnSelectAll(wxCommandEvent& WXUNUSED(event))
{
    SetSelection(-1, -1);
}

void wxComboBox::OnUpdateCut(wxUpdateUIEvent& event)
{
    event.Enable( CanCut() );
}

void wxComboBox::OnUpdateCopy(wxUpdateUIEvent& event)
{
    event.Enable( CanCopy() );
}

void wxComboBox::OnUpdatePaste(wxUpdateUIEvent& event)
{
    event.Enable( CanPaste() );
}

void wxComboBox::OnUpdateUndo(wxUpdateUIEvent& event)
{
    event.Enable( CanUndo() );
}

void wxComboBox::OnUpdateRedo(wxUpdateUIEvent& event)
{
    event.Enable( CanRedo() );
}

void wxComboBox::OnUpdateDelete(wxUpdateUIEvent& event)
{
    event.Enable(HasSelection() && IsEditable()) ;
}

void wxComboBox::OnUpdateSelectAll(wxUpdateUIEvent& event)
{
    event.Enable(GetLastPosition() > 0);
}

#endif
