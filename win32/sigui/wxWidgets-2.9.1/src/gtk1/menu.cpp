/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/menu.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/menu.h"
#include "wx/stockitem.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/bitmap.h"
#endif

#if wxUSE_ACCEL
    #include "wx/accel.h"
#endif // wxUSE_ACCEL

#include "wx/gtk1/private.h"

#include <gdk/gdkkeysyms.h>

#define ACCEL_OBJECT        GtkObject
#define ACCEL_OBJECTS(a)    (a)->attach_objects
#define ACCEL_OBJ_CAST(obj) GTK_OBJECT(obj)

// we use normal item but with a special id for the menu title
static const int wxGTK_TITLE_ID = -3;

// defined in window.cpp
extern guint32 wxGtkTimeLastClick;

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

#if wxUSE_ACCEL
static wxString GetGtkHotKey( const wxMenuItem& item );
#endif

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

static wxString wxReplaceUnderscore( const wxString& title )
{
    const wxChar *pc;

    // GTK 1.2 wants to have "_" instead of "&" for accelerators
    wxString str;
    pc = title;
    while (*pc != wxT('\0'))
    {
        if ((*pc == wxT('&')) && (*(pc+1) == wxT('&')))
        {
            // "&" is doubled to indicate "&" instead of accelerator
            ++pc;
            str << wxT('&');
        }
        else if (*pc == wxT('&'))
        {
            str << wxT('_');
        }
        else
        {
            if ( *pc == wxT('_') )
            {
                // underscores must be doubled to prevent them from being
                // interpreted as accelerator character prefix by GTK
                str << *pc;
            }

            str << *pc;
        }
        ++pc;
    }

    // wxPrintf( wxT("before %s after %s\n"), title.c_str(), str.c_str() );

    return str;
}

static wxString wxConvertFromGTKToWXLabel(const wxString& gtkLabel)
{
    wxString label;
    for ( const wxChar *pc = gtkLabel.c_str(); *pc; pc++ )
    {
        // '_' is the escape character for GTK+.

        if ( *pc == wxT('_') && *(pc+1) == wxT('_'))
        {
            // An underscore was escaped.
            label += wxT('_');
            pc++;
        }
        else if ( *pc == wxT('_') )
        {
            // Convert GTK+ hotkey symbol to wxWidgets/Windows standard
            label += wxT('&');
        }
        else if ( *pc == wxT('&') )
        {
            // Double the ampersand to escape it as far as wxWidgets is concerned
            label += wxT("&&");
        }
        else
        {
            // don't remove ampersands '&' since if we have them in the menu title
            // it means that they were doubled to indicate "&" instead of accelerator
            label += *pc;
        }
    }

    return label;
}


//-----------------------------------------------------------------------------
// activate message from GTK
//-----------------------------------------------------------------------------

static void DoCommonMenuCallbackCode(wxMenu *menu, wxMenuEvent& event)
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    event.SetEventObject( menu );

    wxEvtHandler* handler = menu->GetEventHandler();
    if (handler && handler->ProcessEvent(event))
        return;

    wxWindow *win = menu->GetWindow();
    if (win)
        win->HandleWindowEvent( event );
}

extern "C" {

static void gtk_menu_open_callback( GtkWidget *WXUNUSED(widget), wxMenu *menu )
{
    wxMenuEvent event(wxEVT_MENU_OPEN, -1, menu);

    DoCommonMenuCallbackCode(menu, event);
}

static void gtk_menu_close_callback( GtkWidget *WXUNUSED(widget), wxMenuBar *menubar )
{
    if ( !menubar->GetMenuCount() )
    {
        // if menubar is empty we can't call GetMenu(0) below
        return;
    }

    wxMenuEvent event( wxEVT_MENU_CLOSE, -1, NULL );

    DoCommonMenuCallbackCode(menubar->GetMenu(0), event);
}

}

//-----------------------------------------------------------------------------
// wxMenuBar
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxMenuBar,wxWindow)

void wxMenuBar::Init(size_t n, wxMenu *menus[], const wxString titles[], long style)
{
    // the parent window is known after wxFrame::SetMenu()
    m_needParent = false;
    m_style = style;

    if (!PreCreation( NULL, wxDefaultPosition, wxDefaultSize ) ||
        !CreateBase( NULL, -1, wxDefaultPosition, wxDefaultSize, style, wxDefaultValidator, wxT("menubar") ))
    {
        wxFAIL_MSG( wxT("wxMenuBar creation failed") );
        return;
    }

    m_menubar = gtk_menu_bar_new();
    m_accel = gtk_accel_group_new();

    if (style & wxMB_DOCKABLE)
    {
        m_widget = gtk_handle_box_new();
        gtk_container_add( GTK_CONTAINER(m_widget), GTK_WIDGET(m_menubar) );
        gtk_widget_show( GTK_WIDGET(m_menubar) );
    }
    else
    {
        m_widget = GTK_WIDGET(m_menubar);
    }

    PostCreation();

    ApplyWidgetStyle();

    for (size_t i = 0; i < n; ++i )
        Append(menus[i], titles[i]);

    // VZ: for some reason connecting to menus "deactivate" doesn't work (we
    //     don't get it when the menu is dismissed by clicking outside the
    //     toolbar) so we connect to the global one, even if it means that we
    //     can't pass the menu which was closed in wxMenuEvent object
    gtk_signal_connect( GTK_OBJECT(GTK_MENU_SHELL(m_menubar)),
                        "deactivate",
                        GTK_SIGNAL_FUNC(gtk_menu_close_callback),
                        (gpointer)this );

}

wxMenuBar::wxMenuBar(size_t n, wxMenu *menus[], const wxString titles[], long style)
{
    Init(n, menus, titles, style);
}

wxMenuBar::wxMenuBar(long style)
{
    Init(0, NULL, NULL, style);
}

wxMenuBar::wxMenuBar()
{
    Init(0, NULL, NULL, 0);
}

wxMenuBar::~wxMenuBar()
{
}

static void DetachFromFrame( wxMenu *menu, wxWindow *win )
{
    wxWindow *top_frame = win;
    while (top_frame->GetParent() && !(top_frame->IsTopLevel()))
        top_frame = top_frame->GetParent();

    // support for native hot keys
    gtk_accel_group_detach( menu->m_accel, ACCEL_OBJ_CAST(top_frame->m_widget) );

    wxMenuItemList::compatibility_iterator node = menu->GetMenuItems().GetFirst();
    while (node)
    {
        wxMenuItem *menuitem = node->GetData();
        if (menuitem->IsSubMenu())
            DetachFromFrame( menuitem->GetSubMenu(), win );
        node = node->GetNext();
    }
}

static void AttachToFrame( wxMenu *menu, wxWindow *win )
{
    wxWindow *top_frame = win;
    while (top_frame->GetParent() && !(top_frame->IsTopLevel()))
        top_frame = top_frame->GetParent();

    // support for native hot keys
    ACCEL_OBJECT *obj = ACCEL_OBJ_CAST(top_frame->m_widget);
    if ( !g_slist_find( ACCEL_OBJECTS(menu->m_accel), obj ) )
        gtk_accel_group_attach( menu->m_accel, obj );

    wxMenuItemList::compatibility_iterator node = menu->GetMenuItems().GetFirst();
    while (node)
    {
        wxMenuItem *menuitem = node->GetData();
        if (menuitem->IsSubMenu())
            AttachToFrame( menuitem->GetSubMenu(), win );
        node = node->GetNext();
    }
}

void wxMenuBar::Attach( wxFrame *win )
{
    wxMenuBarBase::Attach(win);

    wxWindow *top_frame = win;
    while (top_frame->GetParent() && !(top_frame->IsTopLevel()))
        top_frame = top_frame->GetParent();

    // support for native key accelerators indicated by underscroes
    ACCEL_OBJECT *obj = ACCEL_OBJ_CAST(top_frame->m_widget);
    if ( !g_slist_find( ACCEL_OBJECTS(m_accel), obj ) )
        gtk_accel_group_attach( m_accel, obj );

    wxMenuList::compatibility_iterator node = m_menus.GetFirst();
    while (node)
    {
        wxMenu *menu = node->GetData();
        AttachToFrame( menu, win );
        node = node->GetNext();
    }
}

void wxMenuBar::Detach()
{
    wxWindow *top_frame = m_menuBarFrame;
    while (top_frame->GetParent() && !(top_frame->IsTopLevel()))
        top_frame = top_frame->GetParent();

    // support for native key accelerators indicated by underscroes
    gtk_accel_group_detach( m_accel, ACCEL_OBJ_CAST(top_frame->m_widget) );

    wxMenuList::compatibility_iterator node = m_menus.GetFirst();
    while (node)
    {
        wxMenu *menu = node->GetData();
        DetachFromFrame( menu, top_frame );
        node = node->GetNext();
    }

    wxMenuBarBase::Detach();
}

bool wxMenuBar::Append( wxMenu *menu, const wxString &title )
{
    if ( !wxMenuBarBase::Append( menu, title ) )
        return false;

    return GtkAppend(menu, title);
}

bool wxMenuBar::GtkAppend(wxMenu *menu, const wxString& title, int pos)
{
    wxString str( wxReplaceUnderscore( title ) );

    // This doesn't have much effect right now.
    menu->SetTitle( str );

    // The "m_owner" is the "menu item"
    menu->m_owner = gtk_menu_item_new_with_label( wxGTK_CONV( str ) );
    GtkLabel *label = GTK_LABEL( GTK_BIN(menu->m_owner)->child );
    // set new text
    gtk_label_set_text( label, wxGTK_CONV( str ) );
    // reparse key accel
    guint accel_key = gtk_label_parse_uline (GTK_LABEL(label), wxGTK_CONV( str ) );
    if (accel_key != GDK_VoidSymbol)
    {
        gtk_widget_add_accelerator (menu->m_owner,
                                    "activate_item",
                                    m_accel, //gtk_menu_ensure_uline_accel_group(GTK_MENU(m_menubar)),
                                    accel_key,
                                    GDK_MOD1_MASK,
                                    GTK_ACCEL_LOCKED);
    }

    gtk_widget_show( menu->m_owner );

    gtk_menu_item_set_submenu( GTK_MENU_ITEM(menu->m_owner), menu->m_menu );

    if (pos == -1)
        gtk_menu_shell_append( GTK_MENU_SHELL(m_menubar), menu->m_owner );
    else
        gtk_menu_shell_insert( GTK_MENU_SHELL(m_menubar), menu->m_owner, pos );

    gtk_signal_connect( GTK_OBJECT(menu->m_owner), "activate",
                        GTK_SIGNAL_FUNC(gtk_menu_open_callback),
                        (gpointer)menu );

    if (m_menuBarFrame)
    {
        AttachToFrame( menu, m_menuBarFrame );

            // OPTIMISE ME:  we should probably cache this, or pass it
            //               directly, but for now this is a minimal
            //               change to validate the new dynamic sizing.
            //               see (and refactor :) similar code in Remove
            //               below.

            m_menuBarFrame->UpdateMenuBarSize();
    }

    return true;
}

bool wxMenuBar::Insert(size_t pos, wxMenu *menu, const wxString& title)
{
    if ( !wxMenuBarBase::Insert(pos, menu, title) )
        return false;

    // TODO

    if ( !GtkAppend(menu, title, (int)pos) )
        return false;

    return true;
}

wxMenu *wxMenuBar::Replace(size_t pos, wxMenu *menu, const wxString& title)
{
    // remove the old item and insert a new one
    wxMenu *menuOld = Remove(pos);
    if ( menuOld && !Insert(pos, menu, title) )
    {
        return NULL;
    }

    // either Insert() succeeded or Remove() failed and menuOld is NULL
    return menuOld;
}

wxMenu *wxMenuBar::Remove(size_t pos)
{
    wxMenu *menu = wxMenuBarBase::Remove(pos);
    if ( !menu )
        return NULL;

    gtk_menu_item_remove_submenu( GTK_MENU_ITEM(menu->m_owner) );
    gtk_container_remove(GTK_CONTAINER(m_menubar), menu->m_owner);

    gtk_widget_destroy( menu->m_owner );
    menu->m_owner = NULL;

    if (m_menuBarFrame)
    {
        // OPTIMISE ME:  see comment in GtkAppend
        m_menuBarFrame->UpdateMenuBarSize();
    }

    return menu;
}

static int FindMenuItemRecursive( const wxMenu *menu, const wxString &menuString, const wxString &itemString )
{
    if (wxMenuItem::GetLabelText(wxConvertFromGTKToWXLabel(menu->GetTitle())) == wxMenuItem::GetLabelText(menuString))
    {
        int res = menu->FindItem( itemString );
        if (res != wxNOT_FOUND)
            return res;
    }

    wxMenuItemList::compatibility_iterator node = menu->GetMenuItems().GetFirst();
    while (node)
    {
        wxMenuItem *item = node->GetData();
        if (item->IsSubMenu())
            return FindMenuItemRecursive(item->GetSubMenu(), menuString, itemString);

        node = node->GetNext();
    }

    return wxNOT_FOUND;
}

int wxMenuBar::FindMenuItem( const wxString &menuString, const wxString &itemString ) const
{
    wxMenuList::compatibility_iterator node = m_menus.GetFirst();
    while (node)
    {
        wxMenu *menu = node->GetData();
        int res = FindMenuItemRecursive( menu, menuString, itemString);
        if (res != -1)
            return res;
        node = node->GetNext();
    }

    return wxNOT_FOUND;
}

// Find a wxMenuItem using its id. Recurses down into sub-menus
static wxMenuItem* FindMenuItemByIdRecursive(const wxMenu* menu, int id)
{
    wxMenuItem* result = menu->FindChildItem(id);

    wxMenuItemList::compatibility_iterator node = menu->GetMenuItems().GetFirst();
    while ( node && result == NULL )
    {
        wxMenuItem *item = node->GetData();
        if (item->IsSubMenu())
        {
            result = FindMenuItemByIdRecursive( item->GetSubMenu(), id );
        }
        node = node->GetNext();
    }

    return result;
}

wxMenuItem* wxMenuBar::FindItem( int id, wxMenu **menuForItem ) const
{
    wxMenuItem* result = 0;
    wxMenuList::compatibility_iterator node = m_menus.GetFirst();
    while (node && result == 0)
    {
        wxMenu *menu = node->GetData();
        result = FindMenuItemByIdRecursive( menu, id );
        node = node->GetNext();
    }

    if ( menuForItem )
    {
        *menuForItem = result ? result->GetMenu() : NULL;
    }

    return result;
}

void wxMenuBar::EnableTop( size_t pos, bool flag )
{
    wxMenuList::compatibility_iterator node = m_menus.Item( pos );

    wxCHECK_RET( node, wxT("menu not found") );

    wxMenu* menu = node->GetData();

    if (menu->m_owner)
        gtk_widget_set_sensitive( menu->m_owner, flag );
}

wxString wxMenuBar::GetMenuLabel( size_t pos ) const
{
    wxMenuList::compatibility_iterator node = m_menus.Item( pos );

    wxCHECK_MSG( node, wxT("invalid"), wxT("menu not found") );

    wxMenu* menu = node->GetData();

    return wxConvertFromGTKToWXLabel(menu->GetTitle());
}

void wxMenuBar::SetMenuLabel( size_t pos, const wxString& label )
{
    wxMenuList::compatibility_iterator node = m_menus.Item( pos );

    wxCHECK_RET( node, wxT("menu not found") );

    wxMenu* menu = node->GetData();

    const wxString str( wxReplaceUnderscore( label ) );

    menu->SetTitle( str );

    if (menu->m_owner)
    {
        GtkLabel *glabel = GTK_LABEL( GTK_BIN(menu->m_owner)->child );

        /* set new text */
        gtk_label_set( glabel, wxGTK_CONV( str ) );

        /* reparse key accel */
        (void)gtk_label_parse_uline (GTK_LABEL(glabel), wxGTK_CONV( str ) );
        gtk_accel_label_refetch( GTK_ACCEL_LABEL(glabel) );
    }

}

//-----------------------------------------------------------------------------
// "activate"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_menu_clicked_callback( GtkWidget *widget, wxMenu *menu )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    int id = menu->FindMenuIdByMenuItem(widget);

    /* should find it for normal (not popup) menu */
    wxASSERT_MSG( (id != -1) || (menu->GetWindow() != NULL),
                  wxT("menu item not found in gtk_menu_clicked_callback") );

    if (!menu->IsEnabled(id))
        return;

    wxMenuItem* item = menu->FindChildItem( id );
    wxCHECK_RET( item, wxT("error in menu item callback") );

    if ( item->GetId() == wxGTK_TITLE_ID )
    {
        // ignore events from the menu title
        return;
    }

    if (item->IsCheckable())
    {
        bool isReallyChecked = item->IsChecked(),
            isInternallyChecked = item->wxMenuItemBase::IsChecked();

        // ensure that the internal state is always consistent with what is
        // shown on the screen
        item->wxMenuItemBase::Check(isReallyChecked);

        // we must not report the events for the radio button going up nor the
        // events resulting from the calls to wxMenuItem::Check()
        if ( (item->GetKind() == wxITEM_RADIO && !isReallyChecked) ||
             (isInternallyChecked == isReallyChecked) )
        {
            return;
        }
    }


    // Is this menu on a menubar?  (possibly nested)
    wxFrame* frame = NULL;
    if(menu->IsAttached())
        frame = menu->GetMenuBar()->GetFrame();

    // FIXME: why do we have to call wxFrame::GetEventHandler() directly here?
    //        normally wxMenu::SendEvent() should be enough, if it doesn't work
    //        in wxGTK then we have a bug in wxMenu::GetWindow() which
    //        should be fixed instead of working around it here...
    if (frame)
    {
        // If it is attached then let the frame send the event.
        // Don't call frame->ProcessCommand(id) because it toggles
        // checkable items and we've already done that above.
        wxCommandEvent commandEvent(wxEVT_COMMAND_MENU_SELECTED, id);
        commandEvent.SetEventObject(frame);
        if (item->IsCheckable())
            commandEvent.SetInt(item->IsChecked());
        commandEvent.SetEventObject(menu);

        frame->HandleWindowEvent(commandEvent);
    }
    else
    {
        // otherwise let the menu have it
        menu->SendEvent(id, item->IsCheckable() ? item->IsChecked() : -1);
    }
}
}

//-----------------------------------------------------------------------------
// "select"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_menu_hilight_callback( GtkWidget *widget, wxMenu *menu )
{
    if (g_isIdle) wxapp_install_idle_handler();

    int id = menu->FindMenuIdByMenuItem(widget);

    wxASSERT( id != -1 ); // should find it!

    if (!menu->IsEnabled(id))
        return;

    wxMenuEvent event( wxEVT_MENU_HIGHLIGHT, id );
    event.SetEventObject( menu );

    wxEvtHandler* handler = menu->GetEventHandler();
    if (handler && handler->ProcessEvent(event))
        return;

    wxWindow *win = menu->GetWindow();
    if (win) win->HandleWindowEvent( event );
}
}

//-----------------------------------------------------------------------------
// "deselect"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_menu_nolight_callback( GtkWidget *widget, wxMenu *menu )
{
    if (g_isIdle) wxapp_install_idle_handler();

    int id = menu->FindMenuIdByMenuItem(widget);

    wxASSERT( id != -1 ); // should find it!

    if (!menu->IsEnabled(id))
        return;

    wxMenuEvent event( wxEVT_MENU_HIGHLIGHT, -1 );
    event.SetEventObject( menu );

    wxEvtHandler* handler = menu->GetEventHandler();
    if (handler && handler->ProcessEvent(event))
        return;

    wxWindow *win = menu->GetWindow();
    if (win)
        win->HandleWindowEvent( event );
}
}

//-----------------------------------------------------------------------------
// wxMenuItem
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxMenuItem, wxObject)

wxMenuItem *wxMenuItemBase::New(wxMenu *parentMenu,
                                int id,
                                const wxString& name,
                                const wxString& help,
                                wxItemKind kind,
                                wxMenu *subMenu)
{
    return new wxMenuItem(parentMenu, id, name, help, kind, subMenu);
}

wxMenuItem::wxMenuItem(wxMenu *parentMenu,
                       int id,
                       const wxString& text,
                       const wxString& help,
                       wxItemKind kind,
                       wxMenu *subMenu)
          : wxMenuItemBase(parentMenu, id, text, help, kind, subMenu)
{
    Init();
}

wxMenuItem::wxMenuItem(wxMenu *parentMenu,
                       int id,
                       const wxString& text,
                       const wxString& help,
                       bool isCheckable,
                       wxMenu *subMenu)
          : wxMenuItemBase(parentMenu, id, text, help,
                           isCheckable ? wxITEM_CHECK : wxITEM_NORMAL, subMenu)
{
    Init();
}

void wxMenuItem::Init()
{
    m_labelWidget = NULL;
    m_menuItem = NULL;

    DoSetText(m_text);
}

wxMenuItem::~wxMenuItem()
{
   // don't delete menu items, the menus take care of that
}

wxString wxMenuItem::GetItemLabel() const
{
    wxString label = wxConvertFromGTKToWXLabel(m_text);
    if (!m_hotKey.IsEmpty())
        label = label + wxT("\t") + m_hotKey;
    return label;
}

void wxMenuItem::SetItemLabel( const wxString& string )
{
    wxString str = string;
    if ( str.empty() && !IsSeparator() )
    {
        wxASSERT_MSG(wxIsStockID(GetId()), wxT("A non-stock menu item with an empty label?"));
        str = wxGetStockLabel(GetId(), wxSTOCK_WITH_ACCELERATOR |
                                       wxSTOCK_WITH_MNEMONIC);
    }

    // Some optimization to avoid flicker
    wxString oldLabel = m_text;
    oldLabel = wxStripMenuCodes(oldLabel);
    oldLabel.Replace(wxT("_"), wxEmptyString);
    wxString label1 = wxStripMenuCodes(str);
    wxString oldhotkey = GetHotKey();    // Store the old hotkey in Ctrl-foo format
    wxCharBuffer oldbuf = wxGTK_CONV( GetGtkHotKey(*this) );  // and as <control>foo

    DoSetText(str);

    if (oldLabel == label1 &&
             oldhotkey == GetHotKey())    // Make sure we can change a hotkey even if the label is unaltered
        return;

    if (m_menuItem)
    {
        GtkLabel *label;
        if (m_labelWidget)
            label = (GtkLabel*) m_labelWidget;
        else
            label = GTK_LABEL( GTK_BIN(m_menuItem)->child );

        // set new text
        gtk_label_set( label, wxGTK_CONV( m_text ) );

        // reparse key accel
        (void)gtk_label_parse_uline (GTK_LABEL(label), wxGTK_CONV(m_text) );
        gtk_accel_label_refetch( GTK_ACCEL_LABEL(label) );
    }

    guint accel_key;
    GdkModifierType accel_mods;
    gtk_accelerator_parse( (const char*) oldbuf, &accel_key, &accel_mods);
    if (accel_key != 0)
    {
        gtk_widget_remove_accelerator( GTK_WIDGET(m_menuItem),
                                       m_parentMenu->m_accel,
                                       accel_key,
                                       accel_mods );
    }

    wxCharBuffer buf = wxGTK_CONV( GetGtkHotKey(*this) );
    gtk_accelerator_parse( (const char*) buf, &accel_key, &accel_mods);
    if (accel_key != 0)
    {
        gtk_widget_add_accelerator( GTK_WIDGET(m_menuItem),
                                    "activate",
                                    m_parentMenu->m_accel,
                                    accel_key,
                                    accel_mods,
                                    GTK_ACCEL_VISIBLE);
    }
}

// it's valid for this function to be called even if m_menuItem == NULL
void wxMenuItem::DoSetText( const wxString& str )
{
    // '\t' is the deliminator indicating a hot key
    wxString text;
    text.reserve(str.length());

    const wxChar *pc = str;
    while ( (*pc != wxT('\0')) && (*pc != wxT('\t')) )
    {
        if ((*pc == wxT('&')) && (*(pc+1) == wxT('&')))
        {
            // "&" is doubled to indicate "&" instead of accelerator
            ++pc;
            text << wxT('&');
        }
        else if (*pc == wxT('&'))
        {
            text << wxT('_');
        }
        else if ( *pc == wxT('_') )    // escape underscores
        {
            text << wxT("__");
        }
        else
        {
            text << *pc;
        }
        ++pc;
    }

    m_hotKey = wxEmptyString;

    if ( *pc == wxT('\t') )
    {
       pc++;
       m_hotKey = pc;
    }

    m_text = text;
}

#if wxUSE_ACCEL

wxAcceleratorEntry *wxMenuItem::GetAccel() const
{
    if ( !GetHotKey() )
    {
        // nothing
        return NULL;
    }

    // accelerator parsing code looks for them after a TAB, so insert a dummy
    // one here
    wxString label;
    label << wxT('\t') << GetHotKey();

    return wxAcceleratorEntry::Create(label);
}

#endif // wxUSE_ACCEL

void wxMenuItem::Check( bool check )
{
    wxCHECK_RET( m_menuItem, wxT("invalid menu item") );

    if (check == m_isChecked)
        return;

    wxMenuItemBase::Check( check );

    switch ( GetKind() )
    {
        case wxITEM_CHECK:
        case wxITEM_RADIO:
            gtk_check_menu_item_set_state( (GtkCheckMenuItem*)m_menuItem, (gint)check );
            break;

        default:
            wxFAIL_MSG( wxT("can't check this item") );
    }
}

void wxMenuItem::Enable( bool enable )
{
    wxCHECK_RET( m_menuItem, wxT("invalid menu item") );

    gtk_widget_set_sensitive( m_menuItem, enable );
    wxMenuItemBase::Enable( enable );
}

bool wxMenuItem::IsChecked() const
{
    wxCHECK_MSG( m_menuItem, false, wxT("invalid menu item") );

    wxCHECK_MSG( IsCheckable(), false,
                 wxT("can't get state of uncheckable item!") );

    return ((GtkCheckMenuItem*)m_menuItem)->active != 0;
}

//-----------------------------------------------------------------------------
// wxMenu
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxMenu,wxEvtHandler)

void wxMenu::Init()
{
    m_accel = gtk_accel_group_new();
    m_menu = gtk_menu_new();
    // NB: keep reference to the menu so that it is not destroyed behind
    //     our back by GTK+ e.g. when it is removed from menubar:
    gtk_widget_ref(m_menu);

    m_owner = NULL;

    // Tearoffs are entries, just like separators. So if we want this
    // menu to be a tear-off one, we just append a tearoff entry
    // immediately.
    if ( m_style & wxMENU_TEAROFF )
    {
        GtkWidget *tearoff = gtk_tearoff_menu_item_new();

        gtk_menu_append(GTK_MENU(m_menu), tearoff);
    }

    m_prevRadio = NULL;

    // append the title as the very first entry if we have it
    if ( !m_title.empty() )
    {
        Append(wxGTK_TITLE_ID, m_title);
        AppendSeparator();
    }
}

wxMenu::~wxMenu()
{
   WX_CLEAR_LIST(wxMenuItemList, m_items);

   if ( GTK_IS_WIDGET( m_menu ))
   {
       // see wxMenu::Init
       gtk_widget_unref( m_menu );
       // if the menu is inserted in another menu at this time, there was
       // one more reference to it:
       if ( m_owner )
           gtk_widget_destroy( m_menu );
   }
}

bool wxMenu::GtkAppend(wxMenuItem *mitem, int pos)
{
    GtkWidget *menuItem;

    wxString text;
    GtkLabel* label = NULL;

    if ( mitem->IsSeparator() )
    {
        // TODO
        menuItem = gtk_menu_item_new();
    }
    else if (mitem->GetBitmap().Ok())
    {
        text = mitem->wxMenuItemBase::GetItemLabel();
        const wxBitmap *bitmap = &mitem->GetBitmap();

        // TODO
        wxUnusedVar(bitmap);
        menuItem = gtk_menu_item_new_with_label( wxGTK_CONV( text ) );
        label = GTK_LABEL( GTK_BIN(menuItem)->child );

        m_prevRadio = NULL;
    }
    else // a normal item
    {
        // text has "_" instead of "&" after mitem->SetItemLabel() so don't use it
        text =  mitem->wxMenuItemBase::GetItemLabel() ;

        switch ( mitem->GetKind() )
        {
            case wxITEM_CHECK:
            {
                menuItem = gtk_check_menu_item_new_with_label( wxGTK_CONV( text ) );
                label = GTK_LABEL( GTK_BIN(menuItem)->child );
                // set new text
                gtk_label_set_text( label, wxGTK_CONV( text ) );
                m_prevRadio = NULL;
                break;
            }

            case wxITEM_RADIO:
            {
                GSList *group = NULL;
                if ( m_prevRadio == NULL )
                {
                    // start of a new radio group
                    m_prevRadio = menuItem = gtk_radio_menu_item_new_with_label( group, wxGTK_CONV( text ) );
                    label = GTK_LABEL( GTK_BIN(menuItem)->child );
                    // set new text
                    gtk_label_set_text( label, wxGTK_CONV( text ) );
                }
                else // continue the radio group
                {
                    group = gtk_radio_menu_item_group (GTK_RADIO_MENU_ITEM (m_prevRadio));
                    m_prevRadio = menuItem = gtk_radio_menu_item_new_with_label( group, wxGTK_CONV( text ) );
                    label = GTK_LABEL( GTK_BIN(menuItem)->child );
                }
                break;
            }

            default:
                wxFAIL_MSG( wxT("unexpected menu item kind") );
                // fall through

            case wxITEM_NORMAL:
            {
                menuItem = gtk_menu_item_new_with_label( wxGTK_CONV( text ) );
                label = GTK_LABEL( GTK_BIN(menuItem)->child );
                m_prevRadio = NULL;
                break;
            }
        }

    }

    guint accel_key;
    GdkModifierType accel_mods;
    wxCharBuffer buf = wxGTK_CONV( GetGtkHotKey(*mitem) );

    // wxPrintf( wxT("item: %s hotkey %s\n"), mitem->GetItemLabel().c_str(), GetGtkHotKey(*mitem).c_str() );
    gtk_accelerator_parse( (const char*) buf, &accel_key, &accel_mods);
    if (accel_key != 0)
    {
        gtk_widget_add_accelerator (GTK_WIDGET(menuItem),
                                    "activate",
                                    m_accel,
                                    accel_key,
                                    accel_mods,
                                    GTK_ACCEL_VISIBLE);
    }

    if (pos == -1)
        gtk_menu_shell_append(GTK_MENU_SHELL(m_menu), menuItem);
    else
        gtk_menu_shell_insert(GTK_MENU_SHELL(m_menu), menuItem, pos);

    gtk_widget_show( menuItem );

    if ( !mitem->IsSeparator() )
    {
        wxASSERT_MSG( menuItem, wxT("invalid menuitem") );

        gtk_signal_connect( GTK_OBJECT(menuItem), "select",
                            GTK_SIGNAL_FUNC(gtk_menu_hilight_callback),
                            (gpointer)this );

        gtk_signal_connect( GTK_OBJECT(menuItem), "deselect",
                            GTK_SIGNAL_FUNC(gtk_menu_nolight_callback),
                            (gpointer)this );

        if ( mitem->IsSubMenu() && mitem->GetKind() != wxITEM_RADIO && mitem->GetKind() != wxITEM_CHECK )
        {
            gtk_menu_item_set_submenu( GTK_MENU_ITEM(menuItem), mitem->GetSubMenu()->m_menu );

            gtk_widget_show( mitem->GetSubMenu()->m_menu );
        }
        else
        {
            gtk_signal_connect( GTK_OBJECT(menuItem), "activate",
                                GTK_SIGNAL_FUNC(gtk_menu_clicked_callback),
                                (gpointer)this );
        }

        guint accel_key = gtk_label_parse_uline (GTK_LABEL(label), wxGTK_CONV( text ) );
        if (accel_key != GDK_VoidSymbol)
        {
            gtk_widget_add_accelerator (menuItem,
                                        "activate_item",
                                        gtk_menu_ensure_uline_accel_group(GTK_MENU(m_menu)),
                                        accel_key,
                                        GDK_MOD1_MASK,
                                        GTK_ACCEL_LOCKED);
        }
    }

    mitem->SetMenuItem(menuItem);

    if (ms_locked)
    {
        // This doesn't even exist!
        // gtk_widget_lock_accelerators(mitem->GetMenuItem());
    }

    return true;
}

wxMenuItem* wxMenu::DoAppend(wxMenuItem *mitem)
{
    if (!GtkAppend(mitem))
        return NULL;

    return wxMenuBase::DoAppend(mitem);
}

wxMenuItem* wxMenu::DoInsert(size_t pos, wxMenuItem *item)
{
    if ( !wxMenuBase::DoInsert(pos, item) )
        return NULL;

    // TODO
    if ( !GtkAppend(item, (int)pos) )
        return NULL;

    return item;
}

wxMenuItem *wxMenu::DoRemove(wxMenuItem *item)
{
    if ( !wxMenuBase::DoRemove(item) )
        return NULL;

    // TODO: this code doesn't delete the item factory item and this seems
    //       impossible as of GTK 1.2.6.
    gtk_widget_destroy( item->GetMenuItem() );

    return item;
}

int wxMenu::FindMenuIdByMenuItem( GtkWidget *menuItem ) const
{
    wxMenuItemList::compatibility_iterator node = m_items.GetFirst();
    while (node)
    {
        wxMenuItem *item = node->GetData();
        if (item->GetMenuItem() == menuItem)
            return item->GetId();
        node = node->GetNext();
    }

    return wxNOT_FOUND;
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

#if wxUSE_ACCEL

static wxString GetGtkHotKey( const wxMenuItem& item )
{
    wxString hotkey;

    wxAcceleratorEntry *accel = item.GetAccel();
    if ( accel )
    {
        int flags = accel->GetFlags();
        if ( flags & wxACCEL_ALT )
            hotkey += wxT("<alt>");
        if ( flags & wxACCEL_CTRL )
            hotkey += wxT("<control>");
        if ( flags & wxACCEL_SHIFT )
            hotkey += wxT("<shift>");

        int code = accel->GetKeyCode();
        switch ( code )
        {
            case WXK_F1:
            case WXK_F2:
            case WXK_F3:
            case WXK_F4:
            case WXK_F5:
            case WXK_F6:
            case WXK_F7:
            case WXK_F8:
            case WXK_F9:
            case WXK_F10:
            case WXK_F11:
            case WXK_F12:
            case WXK_F13:
            case WXK_F14:
            case WXK_F15:
            case WXK_F16:
            case WXK_F17:
            case WXK_F18:
            case WXK_F19:
            case WXK_F20:
            case WXK_F21:
            case WXK_F22:
            case WXK_F23:
            case WXK_F24:
                hotkey += wxString::Format(wxT("F%d"), code - WXK_F1 + 1);
                break;

                // TODO: we should use gdk_keyval_name() (a.k.a.
                //       XKeysymToString) here as well as hardcoding the keysym
                //       names this might be not portable
           case WXK_INSERT:
                hotkey << wxT("Insert" );
                break;
            case WXK_DELETE:
                hotkey << wxT("Delete" );
                break;
            case WXK_UP:
                hotkey << wxT("Up" );
                break;
            case WXK_DOWN:
                hotkey << wxT("Down" );
                break;
            case WXK_PAGEUP:
                hotkey << wxT("Page_Up" );
                break;
            case WXK_PAGEDOWN:
                hotkey << wxT("Page_Down" );
                break;
            case WXK_LEFT:
                hotkey << wxT("Left" );
                break;
            case WXK_RIGHT:
                hotkey << wxT("Right" );
                break;
            case WXK_HOME:
                hotkey << wxT("Home" );
                break;
            case WXK_END:
                hotkey << wxT("End" );
                break;
            case WXK_RETURN:
                hotkey << wxT("Return" );
                break;
            case WXK_BACK:
                hotkey << wxT("BackSpace" );
                break;
            case WXK_TAB:
                hotkey << wxT("Tab" );
                break;
            case WXK_ESCAPE:
                hotkey << wxT("Esc" );
                break;
            case WXK_SPACE:
                hotkey << wxT("space" );
                break;
            case WXK_MULTIPLY:
                hotkey << wxT("Multiply" );
                break;
            case WXK_ADD:
                hotkey << wxT("Add" );
                break;
            case WXK_SEPARATOR:
                hotkey << wxT("Separator" );
                break;
            case WXK_SUBTRACT:
                hotkey << wxT("Subtract" );
                break;
            case WXK_DECIMAL:
                hotkey << wxT("Decimal" );
                break;
            case WXK_DIVIDE:
                hotkey << wxT("Divide" );
                break;
            case WXK_CANCEL:
                hotkey << wxT("Cancel" );
                break;
            case WXK_CLEAR:
                hotkey << wxT("Clear" );
                break;
            case WXK_MENU:
                hotkey << wxT("Menu" );
                break;
            case WXK_PAUSE:
                hotkey << wxT("Pause" );
                break;
            case WXK_CAPITAL:
                hotkey << wxT("Capital" );
                break;
            case WXK_SELECT:
                hotkey << wxT("Select" );
                break;
            case WXK_PRINT:
                hotkey << wxT("Print" );
                break;
            case WXK_EXECUTE:
                hotkey << wxT("Execute" );
                break;
            case WXK_SNAPSHOT:
                hotkey << wxT("Snapshot" );
                break;
            case WXK_HELP:
                hotkey << wxT("Help" );
                break;
            case WXK_NUMLOCK:
                hotkey << wxT("Num_Lock" );
                break;
            case WXK_SCROLL:
                hotkey << wxT("Scroll_Lock" );
                break;
            case WXK_NUMPAD_INSERT:
                hotkey << wxT("KP_Insert" );
                break;
            case WXK_NUMPAD_DELETE:
                hotkey << wxT("KP_Delete" );
                break;
             case WXK_NUMPAD_SPACE:
                hotkey << wxT("KP_Space" );
                break;
            case WXK_NUMPAD_TAB:
                hotkey << wxT("KP_Tab" );
                break;
            case WXK_NUMPAD_ENTER:
                hotkey << wxT("KP_Enter" );
                break;
            case WXK_NUMPAD_F1: case WXK_NUMPAD_F2: case WXK_NUMPAD_F3:
            case WXK_NUMPAD_F4:
                hotkey += wxString::Format(wxT("KP_F%d"), code - WXK_NUMPAD_F1 + 1);
                break;
            case WXK_NUMPAD_HOME:
                hotkey << wxT("KP_Home" );
                break;
            case WXK_NUMPAD_LEFT:
                hotkey << wxT("KP_Left" );
                break;
             case WXK_NUMPAD_UP:
                hotkey << wxT("KP_Up" );
                break;
            case WXK_NUMPAD_RIGHT:
                hotkey << wxT("KP_Right" );
                break;
            case WXK_NUMPAD_DOWN:
                hotkey << wxT("KP_Down" );
                break;
            case WXK_NUMPAD_PAGEUP:
                hotkey << wxT("KP_Page_Up" );
                break;
            case WXK_NUMPAD_PAGEDOWN:
                hotkey << wxT("KP_Page_Down" );
                break;
            case WXK_NUMPAD_END:
                hotkey << wxT("KP_End" );
                break;
            case WXK_NUMPAD_BEGIN:
                hotkey << wxT("KP_Begin" );
                break;
            case WXK_NUMPAD_EQUAL:
                hotkey << wxT("KP_Equal" );
                break;
            case WXK_NUMPAD_MULTIPLY:
                hotkey << wxT("KP_Multiply" );
                break;
            case WXK_NUMPAD_ADD:
                hotkey << wxT("KP_Add" );
                break;
            case WXK_NUMPAD_SEPARATOR:
                hotkey << wxT("KP_Separator" );
                break;
            case WXK_NUMPAD_SUBTRACT:
                hotkey << wxT("KP_Subtract" );
                break;
            case WXK_NUMPAD_DECIMAL:
                hotkey << wxT("KP_Decimal" );
                break;
            case WXK_NUMPAD_DIVIDE:
                hotkey << wxT("KP_Divide" );
                break;
           case WXK_NUMPAD0: case WXK_NUMPAD1: case WXK_NUMPAD2:
           case WXK_NUMPAD3: case WXK_NUMPAD4: case WXK_NUMPAD5:
           case WXK_NUMPAD6: case WXK_NUMPAD7: case WXK_NUMPAD8: case WXK_NUMPAD9:
                hotkey += wxString::Format(wxT("KP_%d"), code - WXK_NUMPAD0);
                break;
            case WXK_WINDOWS_LEFT:
                hotkey << wxT("Super_L" );
                break;
            case WXK_WINDOWS_RIGHT:
                hotkey << wxT("Super_R" );
                break;
            case WXK_WINDOWS_MENU:
                hotkey << wxT("Menu" );
                break;
            case WXK_COMMAND:
                hotkey << wxT("Command" );
                break;
          /* These probably wouldn't work as there is no SpecialX in gdk/keynames.txt
            case WXK_SPECIAL1: case WXK_SPECIAL2: case WXK_SPECIAL3: case WXK_SPECIAL4:
            case WXK_SPECIAL5: case WXK_SPECIAL6: case WXK_SPECIAL7: case WXK_SPECIAL8:
            case WXK_SPECIAL9:  case WXK_SPECIAL10:  case WXK_SPECIAL11: case WXK_SPECIAL12:
            case WXK_SPECIAL13: case WXK_SPECIAL14: case WXK_SPECIAL15: case WXK_SPECIAL16:
            case WXK_SPECIAL17: case WXK_SPECIAL18: case WXK_SPECIAL19:  case WXK_SPECIAL20:
                hotkey += wxString::Format(wxT("Special%d"), code - WXK_SPECIAL1 + 1);
                break;
          */
                // if there are any other keys wxAcceleratorEntry::Create() may
                // return, we should process them here

            default:
                if ( code < 127 )
                {
                    wxString name = wxGTK_CONV_BACK( gdk_keyval_name((guint)code) );
                    if ( !name.empty() )
                    {
                        hotkey << name;
                        break;
                    }
                }

                wxFAIL_MSG( wxT("unknown keyboard accel") );
        }

        delete accel;
    }

    return hotkey;
}

#endif // wxUSE_ACCEL

// ----------------------------------------------------------------------------
// Pop-up menu stuff
// ----------------------------------------------------------------------------

#if wxUSE_MENUS_NATIVE

extern "C" WXDLLIMPEXP_CORE
void gtk_pop_hide_callback( GtkWidget *WXUNUSED(widget), bool* is_waiting  )
{
    *is_waiting = false;
}

extern "C" WXDLLIMPEXP_CORE
void wxPopupMenuPositionCallback( GtkMenu *menu,
                                  gint *x, gint *y,
                                  gpointer user_data )
{
    // ensure that the menu appears entirely on screen
    GtkRequisition req;
    gtk_widget_get_child_requisition(GTK_WIDGET(menu), &req);

    wxSize sizeScreen = wxGetDisplaySize();
    wxPoint *pos = (wxPoint*)user_data;

    gint xmax = sizeScreen.x - req.width,
         ymax = sizeScreen.y - req.height;

    *x = pos->x < xmax ? pos->x : xmax;
    *y = pos->y < ymax ? pos->y : ymax;
}

bool wxWindowGTK::DoPopupMenu( wxMenu *menu, int x, int y )
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid window") );

    wxCHECK_MSG( menu != NULL, false, wxT("invalid popup-menu") );

    // NOTE: if you change this code, you need to update
    //       the same code in taskbar.cpp as well. This
    //       is ugly code duplication, I know.

    menu->UpdateUI();

    bool is_waiting = true;

    gulong handler = gtk_signal_connect( GTK_OBJECT(menu->m_menu),
                                         "hide",
                                         GTK_SIGNAL_FUNC(gtk_pop_hide_callback),
                                         (gpointer)&is_waiting );

    wxPoint pos;
    gpointer userdata;
    GtkMenuPositionFunc posfunc;
    if ( x == -1 && y == -1 )
    {
        // use GTK's default positioning algorithm
        userdata = NULL;
        posfunc = NULL;
    }
    else
    {
        pos = ClientToScreen(wxPoint(x, y));
        userdata = &pos;
        posfunc = wxPopupMenuPositionCallback;
    }

    wxMenuEvent eventOpen(wxEVT_MENU_OPEN, -1, menu);
    DoCommonMenuCallbackCode(menu, eventOpen);

    gtk_menu_popup(
                  GTK_MENU(menu->m_menu),
                  NULL,           // parent menu shell
                  NULL,           // parent menu item
                  posfunc,                      // function to position it
                  userdata,                     // client data
                  0,                            // button used to activate it
                  wxGtkTimeLastClick            // the time of activation
                );

    while (is_waiting)
    {
        gtk_main_iteration();
    }

    gtk_signal_disconnect(GTK_OBJECT(menu->m_menu), handler);

    wxMenuEvent eventClose(wxEVT_MENU_CLOSE, -1, menu);
    DoCommonMenuCallbackCode(menu, eventClose);

    return true;
}

#endif // wxUSE_MENUS_NATIVE
