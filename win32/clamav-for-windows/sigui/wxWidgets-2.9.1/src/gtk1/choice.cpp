/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/choice.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_CHOICE

#include "wx/choice.h"

#ifndef WX_PRECOMP
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

//-----------------------------------------------------------------------------
// "activate"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_choice_clicked_callback( GtkWidget *WXUNUSED(widget), wxChoice *choice )
{
    if (g_isIdle)
      wxapp_install_idle_handler();

    if (!choice->m_hasVMT) return;

    if (g_blockEventsOnDrag) return;

    int selection = wxNOT_FOUND;

    GtkMenuShell *menu_shell = GTK_MENU_SHELL( gtk_option_menu_get_menu( GTK_OPTION_MENU(choice->GetHandle()) ) );
    int count = 0;

    GList *child = menu_shell->children;
    while (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        if (!bin->child)
        {
            selection = count;
            break;
        }
        child = child->next;
        count++;
    }

    choice->m_selection_hack = selection;

    wxCommandEvent event(wxEVT_COMMAND_CHOICE_SELECTED, choice->GetId() );
    int n = choice->GetSelection();

    event.SetInt( n );
    event.SetString( choice->GetStringSelection() );
    event.SetEventObject(choice);

    if ( choice->HasClientObjectData() )
        event.SetClientObject( choice->GetClientObject(n) );
    else if ( choice->HasClientUntypedData() )
        event.SetClientData( choice->GetClientData(n) );

    choice->HandleWindowEvent(event);
}
}

//-----------------------------------------------------------------------------
// wxChoice
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxChoice, wxControlWithItems)

wxChoice::wxChoice()
{
    m_strings = NULL;
}

bool wxChoice::Create( wxWindow *parent, wxWindowID id,
                       const wxPoint &pos, const wxSize &size,
                       const wxArrayString& choices,
                       long style, const wxValidator& validator,
                       const wxString &name )
{
    wxCArrayString chs(choices);

    return Create( parent, id, pos, size, chs.GetCount(), chs.GetStrings(),
                   style, validator, name );
}

bool wxChoice::Create( wxWindow *parent, wxWindowID id,
                       const wxPoint &pos, const wxSize &size,
                       int n, const wxString choices[],
                       long style, const wxValidator& validator, const wxString &name )
{
    m_needParent = true;
#if (GTK_MINOR_VERSION > 0)
    m_acceptsFocus = true;
#endif

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, validator, name ))
    {
        wxFAIL_MSG( wxT("wxChoice creation failed") );
        return false;
    }

    m_widget = gtk_option_menu_new();

    if ( style & wxCB_SORT )
    {
        // if our m_strings != NULL, Append() will check for it and insert
        // items in the correct order
        m_strings = new wxSortedArrayString;
    }

    // begin with no selection
    m_selection_hack = wxNOT_FOUND;

    GtkWidget *menu = gtk_menu_new();

    for (unsigned int i = 0; i < (unsigned int)n; i++)
    {
        GtkAddHelper(menu, i, choices[i]);
    }

    gtk_option_menu_set_menu( GTK_OPTION_MENU(m_widget), menu );

    m_parent->DoAddChild( this );

    PostCreation(size);
    SetInitialSize(size); // need this too because this is a wxControlWithItems

    return true;
}

wxChoice::~wxChoice()
{
    Clear();

    delete m_strings;
}

int wxChoice::DoInsertItems(const wxArrayStringsAdapter & items,
                            unsigned int pos,
                            void **clientData, wxClientDataType type)
{
    wxCHECK_MSG( m_widget != NULL, -1, wxT("invalid choice control") );

    const unsigned int count = items.GetCount();

    GtkWidget *menu = gtk_option_menu_get_menu( GTK_OPTION_MENU(m_widget) );

    for ( unsigned int i = 0; i < count; ++i, ++pos )
    {
        int n = GtkAddHelper(menu, pos, items[i]);
        if ( n == wxNOT_FOUND )
            return n;

        AssignNewItemClientData(n, clientData, i, type);
    }

    // if the item to insert is at or before the selection, and the selection is valid
    if (((int)pos <= m_selection_hack) && (m_selection_hack != wxNOT_FOUND))
    {
        // move the selection forward
        m_selection_hack += count;
    }

    return pos - 1;
}

void wxChoice::DoSetItemClientData(unsigned int n, void* clientData)
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid choice control") );

    wxList::compatibility_iterator node = m_clientList.Item( n );
    wxCHECK_RET( node, wxT("invalid index in wxChoice::DoSetItemClientData") );

    node->SetData( (wxObject*) clientData );
}

void* wxChoice::DoGetItemClientData(unsigned int n) const
{
    wxCHECK_MSG( m_widget != NULL, NULL, wxT("invalid choice control") );

    wxList::compatibility_iterator node = m_clientList.Item( n );
    wxCHECK_MSG( node, NULL, wxT("invalid index in wxChoice::DoGetItemClientData") );

    return node->GetData();
}

void wxChoice::DoClear()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid choice") );

    gtk_option_menu_remove_menu( GTK_OPTION_MENU(m_widget) );
    GtkWidget *menu = gtk_menu_new();
    gtk_option_menu_set_menu( GTK_OPTION_MENU(m_widget), menu );

    m_clientList.Clear();

    if ( m_strings )
        m_strings->Clear();

    // begin with no selection
    m_selection_hack = wxNOT_FOUND;
}

void wxChoice::DoDeleteOneItem(unsigned int n)
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid choice") );

    wxCHECK_RET( IsValid(n), wxT("invalid index in wxChoice::Delete") );

    // if the item to delete is before the selection, and the selection is valid
    if (((int)n < m_selection_hack) && (m_selection_hack != wxNOT_FOUND))
    {
        // move the selection back one
        m_selection_hack--;
    }
    else if ((int)n == m_selection_hack)
    {
        // invalidate the selection
        m_selection_hack = wxNOT_FOUND;
    }

    // VZ: apparently GTK+ doesn't have a built-in function to do it (not even
    //     in 2.0), hence this dumb implementation -- still better than nothing
    const unsigned int count = GetCount();

    wxList::compatibility_iterator node = m_clientList.GetFirst();

    wxArrayString items;
    wxArrayPtrVoid itemsData;
    items.Alloc(count);
    for ( unsigned i = 0; i < count; i++, node = node->GetNext() )
    {
        if ( i != n )
        {
            items.Add(GetString(i));
            itemsData.Add(node->GetData());
        }
    }

    wxChoice::DoClear();

    void ** const data = &itemsData[0];
    if ( HasClientObjectData() )
        Append(items, reinterpret_cast<wxClientData **>(data));
    else
        Append(items, data);
}

int wxChoice::FindString( const wxString &string, bool bCase ) const
{
    wxCHECK_MSG( m_widget != NULL, wxNOT_FOUND, wxT("invalid choice") );

    // If you read this code once and you think you understand
    // it, then you are very wrong. Robert Roebling.

    GtkMenuShell *menu_shell = GTK_MENU_SHELL( gtk_option_menu_get_menu( GTK_OPTION_MENU(m_widget) ) );
    int count = 0;
    GList *child = menu_shell->children;
    while (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        GtkLabel *label = NULL;
        if (bin->child)
            label = GTK_LABEL(bin->child);
        if (!label)
            label = GTK_LABEL( BUTTON_CHILD(m_widget) );

        wxASSERT_MSG( label != NULL , wxT("wxChoice: invalid label") );

         wxString tmp( label->label );

         if (string.IsSameAs( tmp, bCase ))
            return count;

        child = child->next;
        count++;
    }

    return wxNOT_FOUND;
}

int wxChoice::GetSelection() const
{
    wxCHECK_MSG( m_widget != NULL, wxNOT_FOUND, wxT("invalid choice") );

    return m_selection_hack;

}

void wxChoice::SetString(unsigned int n, const wxString& str )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid choice") );

    GtkMenuShell *menu_shell = GTK_MENU_SHELL( gtk_option_menu_get_menu( GTK_OPTION_MENU(m_widget) ) );
    unsigned int count = 0;
    GList *child = menu_shell->children;
    while (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        if (count == n)
        {
            GtkLabel *label = NULL;
            if (bin->child)
                label = GTK_LABEL(bin->child);
            if (!label)
                label = GTK_LABEL( BUTTON_CHILD(m_widget) );

            wxASSERT_MSG( label != NULL , wxT("wxChoice: invalid label") );

            gtk_label_set_text( label, wxGTK_CONV( str ) );

            return;
        }
        child = child->next;
        count++;
    }
}

wxString wxChoice::GetString(unsigned int n) const
{
    wxCHECK_MSG( m_widget != NULL, wxEmptyString, wxT("invalid choice") );

    GtkMenuShell *menu_shell = GTK_MENU_SHELL( gtk_option_menu_get_menu( GTK_OPTION_MENU(m_widget) ) );
    unsigned int count = 0;
    GList *child = menu_shell->children;
    while (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        if (count == n)
        {
            GtkLabel *label = NULL;
            if (bin->child)
                label = GTK_LABEL(bin->child);
            if (!label)
                label = GTK_LABEL( BUTTON_CHILD(m_widget) );

            wxASSERT_MSG( label != NULL , wxT("wxChoice: invalid label") );

            return wxString( label->label );
        }
        child = child->next;
        count++;
    }

    wxFAIL_MSG( wxT("wxChoice: invalid index in GetString()") );

    return wxEmptyString;
}

unsigned int wxChoice::GetCount() const
{
    wxCHECK_MSG( m_widget != NULL, 0, wxT("invalid choice") );

    GtkMenuShell *menu_shell = GTK_MENU_SHELL( gtk_option_menu_get_menu( GTK_OPTION_MENU(m_widget) ) );
    unsigned int count = 0;
    GList *child = menu_shell->children;
    while (child)
    {
        count++;
        child = child->next;
    }
    return count;
}

void wxChoice::SetSelection( int n )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid choice") );

    int tmp = n;
    gtk_option_menu_set_history( GTK_OPTION_MENU(m_widget), (gint)tmp );

    // set the local selection variable manually
    if (IsValid((unsigned int)n))
    {
        // a valid selection has been made
        m_selection_hack = n;
    }
    else if ((n == wxNOT_FOUND) || (GetCount() == 0))
    {
        // invalidates the selection if there are no items
        // or if it is specifically set to wxNOT_FOUND
        m_selection_hack = wxNOT_FOUND;
    }
    else
    {
        // this selects the first item by default if the selection is out of bounds
        m_selection_hack = 0;
    }
}

void wxChoice::DoApplyWidgetStyle(GtkRcStyle *style)
{
    GtkMenuShell *menu_shell = GTK_MENU_SHELL( gtk_option_menu_get_menu( GTK_OPTION_MENU(m_widget) ) );

    gtk_widget_modify_style( m_widget, style );
    gtk_widget_modify_style( GTK_WIDGET( menu_shell ), style );

    GList *child = menu_shell->children;
    while (child)
    {
        gtk_widget_modify_style( GTK_WIDGET( child->data ), style );

        GtkBin *bin = GTK_BIN( child->data );
        GtkWidget *label = NULL;
        if (bin->child)
            label = bin->child;
        if (!label)
            label = BUTTON_CHILD(m_widget);

        gtk_widget_modify_style( label, style );

        child = child->next;
    }
}

int wxChoice::GtkAddHelper(GtkWidget *menu, unsigned int pos, const wxString& item)
{
    wxCHECK_MSG(pos<=m_clientList.GetCount(), -1, wxT("invalid index"));

    GtkWidget *menu_item = gtk_menu_item_new_with_label( wxGTK_CONV( item ) );

    size_t index;
    if ( m_strings )
    {
        // sorted control, need to insert at the correct index
        index = m_strings->Add(item);

        gtk_menu_insert( GTK_MENU(menu), menu_item, index );

        if ( index )
        {
            m_clientList.Insert( m_clientList.Item(index - 1),
                                 NULL );
        }
        else
        {
            m_clientList.Insert( NULL );
        }
    }
    else
    {
        // don't call wxChoice::GetCount() from here because it doesn't work
        // if we're called from ctor (and GtkMenuShell is still NULL)

        // normal control, just append
        if (pos == m_clientList.GetCount())
        {
            gtk_menu_append( GTK_MENU(menu), menu_item );
            m_clientList.Append( NULL );
            index = m_clientList.GetCount() - 1;
        }
        else
        {
            gtk_menu_insert( GTK_MENU(menu), menu_item, pos );
            m_clientList.Insert( pos, NULL );
            index = pos;
        }
    }

    if (GTK_WIDGET_REALIZED(m_widget))
    {
        gtk_widget_realize( menu_item );
        gtk_widget_realize( GTK_BIN(menu_item)->child );

        ApplyWidgetStyle();
    }

    // The best size of a wxChoice should probably
    // be changed everytime the control has been
    // changed, but at least after adding an item
    // it has to change. Adapted from Matt Ownby.
    InvalidateBestSize();

    gtk_signal_connect_after( GTK_OBJECT( menu_item ), "activate",
      GTK_SIGNAL_FUNC(gtk_choice_clicked_callback), (gpointer*)this );

    gtk_widget_show( menu_item );

    // return the index of the item in the control
    return index;
}

wxSize wxChoice::DoGetBestSize() const
{
    wxSize ret( wxControl::DoGetBestSize() );

    // we know better our horizontal extent: it depends on the longest string
    // we have
    ret.x = 0;
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

        // add extra for the choice "=" button

        // VZ: I don't know how to get the right value, it seems to be in
        //     GtkOptionMenuProps struct from gtkoptionmenu.c but we can't get
        //     to it - maybe we can use gtk_option_menu_size_request() for this
        //     somehow?
        //
        //     This default value works only for the default GTK+ theme (i.e.
        //     no theme at all) (FIXME)
        static const int widthChoiceIndicator = 35;
        ret.x += widthChoiceIndicator;
    }

    // but not less than the minimal width
    if ( ret.x < 80 )
        ret.x = 80;

    // If this request_size is called with no entries then
    // the returned height is wrong. Give it a reasonable
    // default value.
    if (ret.y <= 18)
        ret.y = 8 + GetCharHeight();

    CacheBestSize(ret);
    return ret;
}

bool wxChoice::IsOwnGtkWindow( GdkWindow *window )
{
    return (window == m_widget->window);
}

// static
wxVisualAttributes
wxChoice::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    return GetDefaultAttributesFromGTKWidget(gtk_option_menu_new);
}


#endif // wxUSE_CHOICE
