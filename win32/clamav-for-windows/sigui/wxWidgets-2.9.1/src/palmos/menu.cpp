/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/menu.cpp
// Purpose:     wxMenu, wxMenuBar, wxMenuItem
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/12/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_MENUS

#include "wx/menu.h"

#ifndef WX_PRECOMP
    #include "wx/frame.h"
    #include "wx/utils.h"
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#if wxUSE_OWNER_DRAWN
    #include "wx/ownerdrw.h"
#endif

#ifdef __WXPALMOS6__
#include <Loader.h>
#else // __WXPALMOS5__
#include <UIResources.h> // MenuRscType
#endif

#include <Form.h>
#include <Menu.h>

// ----------------------------------------------------------------------------
// global variables
// ----------------------------------------------------------------------------

extern wxMenu *wxCurrentPopupMenu;

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// the (popup) menu title has this special id
static const int idMenuTitle = -3;

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// ============================================================================
// implementation
// ============================================================================

#include "wx/listimpl.cpp"

WX_DEFINE_LIST( wxMenuInfoList )

#if wxUSE_EXTENDED_RTTI

WX_DEFINE_FLAGS( wxMenuStyle )

wxBEGIN_FLAGS( wxMenuStyle )
    wxFLAGS_MEMBER(wxMENU_TEAROFF)
wxEND_FLAGS( wxMenuStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxMenu, wxEvtHandler,"wx/menu.h")

wxCOLLECTION_TYPE_INFO( wxMenuItem * , wxMenuItemList ) ;

template<> void wxCollectionToVariantArray( wxMenuItemList const &theList, wxxVariantArray &value)
{
    wxListCollectionToVariantArray<wxMenuItemList::compatibility_iterator>( theList , value ) ;
}

wxBEGIN_PROPERTIES_TABLE(wxMenu)
    wxEVENT_PROPERTY( Select , wxEVT_COMMAND_MENU_SELECTED , wxCommandEvent)
    wxPROPERTY( Title, wxString , SetTitle, GetTitle, wxString(), 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxREADONLY_PROPERTY_FLAGS( MenuStyle , wxMenuStyle , long , GetStyle , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
    wxPROPERTY_COLLECTION( MenuItems , wxMenuItemList , wxMenuItem* , Append , GetMenuItems , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxMenu)
wxEND_HANDLERS_TABLE()

wxDIRECT_CONSTRUCTOR_2( wxMenu , wxString , Title , long , MenuStyle  )

WX_DEFINE_FLAGS( wxMenuBarStyle )

wxBEGIN_FLAGS( wxMenuBarStyle )
    wxFLAGS_MEMBER(wxMB_DOCKABLE)
wxEND_FLAGS( wxMenuBarStyle )

// the negative id would lead the window (its superclass !) to vetoe streaming out otherwise
bool wxMenuBarStreamingCallback( const wxObject *WXUNUSED(object), wxWriter * , wxPersister * , wxxVariantArray & )
{
    return true ;
}

IMPLEMENT_DYNAMIC_CLASS_XTI_CALLBACK(wxMenuBar, wxWindow ,"wx/menu.h",wxMenuBarStreamingCallback)

IMPLEMENT_DYNAMIC_CLASS_XTI(wxMenuInfo, wxObject , "wx/menu.h" )

wxBEGIN_PROPERTIES_TABLE(wxMenuInfo)
    wxREADONLY_PROPERTY( Menu , wxMenu* , GetMenu , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxREADONLY_PROPERTY( Title , wxString , GetTitle , wxString() , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxMenuInfo)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_2( wxMenuInfo , wxMenu* , Menu , wxString , Title )

wxCOLLECTION_TYPE_INFO( wxMenuInfo * , wxMenuInfoList ) ;

template<> void wxCollectionToVariantArray( wxMenuInfoList const &theList, wxxVariantArray &value)
{
    wxListCollectionToVariantArray<wxMenuInfoList::compatibility_iterator>( theList , value ) ;
}

wxBEGIN_PROPERTIES_TABLE(wxMenuBar)
    wxPROPERTY_COLLECTION( MenuInfos , wxMenuInfoList , wxMenuInfo* , Append , GetMenuInfos , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxMenuBar)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_DUMMY( wxMenuBar )

#else
IMPLEMENT_DYNAMIC_CLASS(wxMenu, wxEvtHandler)
IMPLEMENT_DYNAMIC_CLASS(wxMenuBar, wxWindow)
IMPLEMENT_DYNAMIC_CLASS(wxMenuInfo, wxObject)
#endif

const wxMenuInfoList& wxMenuBar::GetMenuInfos() const
{
    wxMenuInfoList* list = const_cast< wxMenuInfoList* >( &m_menuInfos ) ;
    WX_CLEAR_LIST( wxMenuInfoList , *list ) ;
    for( size_t i = 0 ; i < GetMenuCount() ; ++i )
    {
        wxMenuInfo* info = new wxMenuInfo() ;
        info->Create( const_cast<wxMenuBar*>(this)->GetMenu(i) , GetMenuLabel(i) ) ;
        list->Append( info ) ;
    }
    return m_menuInfos ;
}

// ---------------------------------------------------------------------------
// wxMenu construction, adding and removing menu items
// ---------------------------------------------------------------------------

// Construct a menu with optional title (then use append)
void wxMenu::Init()
{
}

// The wxWindow destructor will take care of deleting the submenus.
wxMenu::~wxMenu()
{
}

void wxMenu::Break()
{
}

void wxMenu::Attach(wxMenuBarBase *menubar)
{
    wxMenuBase::Attach(menubar);
}

#if wxUSE_ACCEL

int wxMenu::FindAccel(int id) const
{
    return wxNOT_FOUND;
}

void wxMenu::UpdateAccel(wxMenuItem *item)
{
}

#endif // wxUSE_ACCEL

// append a new item or submenu to the menu
bool wxMenu::DoInsertOrAppend(wxMenuItem *pItem, size_t pos)
{
    if ( IsAttached() && GetMenuBar()->IsAttached() )
    {
        // Regenerate the menu resource
        GetMenuBar()->Refresh();
    }

    return true;
}

void wxMenu::EndRadioGroup()
{
}

wxMenuItem* wxMenu::DoAppend(wxMenuItem *item)
{
    wxCHECK_MSG( item, NULL, wxT("NULL item in wxMenu::DoAppend") );

    if(!wxMenuBase::DoAppend(item) || !DoInsertOrAppend(item))
    {
        return NULL;
    }
    else if(IsAttached() && GetMenuBar()->IsAttached())
    {
        // Regenerate the menu resource
        GetMenuBar()->Refresh();
    }

    return item;
}

wxMenuItem* wxMenu::DoInsert(size_t pos, wxMenuItem *item)
{
    if (wxMenuBase::DoInsert(pos, item) && DoInsertOrAppend(item, pos))
        return item;
    else
        return NULL;
}

wxMenuItem *wxMenu::DoRemove(wxMenuItem *item)
{
    // we need to find the items position in the child list
    size_t pos;
    wxMenuItemList::compatibility_iterator node = GetMenuItems().GetFirst();
    for ( pos = 0; node; pos++ )
    {
        if ( node->GetData() == item )
            break;

        node = node->GetNext();
    }

    // DoRemove() (unlike Remove) can only be called for existing item!
    wxCHECK_MSG( node, NULL, wxT("bug in wxMenu::Remove logic") );

    // remove the item from the menu
    wxMenuItem *ret=wxMenuBase::DoRemove(item);

    if ( IsAttached() && GetMenuBar()->IsAttached() )
    {
        // Regenerate the menu resource
        GetMenuBar()->Refresh();
    }

    return ret;
}

// ---------------------------------------------------------------------------
// accelerator helpers
// ---------------------------------------------------------------------------

#if wxUSE_ACCEL

// create the wxAcceleratorEntries for our accels and put them into provided
// array - return the number of accels we have
size_t wxMenu::CopyAccels(wxAcceleratorEntry *accels) const
{
    size_t count = GetAccelCount();
    for ( size_t n = 0; n < count; n++ )
    {
        *accels++ = *m_accels[n];
    }

    return count;
}

#endif // wxUSE_ACCEL

// ---------------------------------------------------------------------------
// set wxMenu title
// ---------------------------------------------------------------------------

void wxMenu::SetTitle(const wxString& label)
{
    m_title = label;

    if ( IsAttached() && GetMenuBar()->IsAttached() )
    {
        // Regenerate the menu resource
        GetMenuBar()->Refresh();
    }
}

// ---------------------------------------------------------------------------
// event processing
// ---------------------------------------------------------------------------

bool wxMenu::PalmCommand(WXUINT WXUNUSED(param), WXWORD id)
{
    return false;
}

// ---------------------------------------------------------------------------
// other
// ---------------------------------------------------------------------------

wxWindow *wxMenu::GetWindow() const
{
    return NULL;
}

// ---------------------------------------------------------------------------
// Menu Bar
// ---------------------------------------------------------------------------

void wxMenuBar::Init()
{
}

wxMenuBar::wxMenuBar()
{
}

wxMenuBar::wxMenuBar( long WXUNUSED(style) )
{
}

wxMenuBar::wxMenuBar(size_t count, wxMenu *menus[], const wxString titles[], long WXUNUSED(style))
{
}

wxMenuBar::~wxMenuBar()
{
}

// ---------------------------------------------------------------------------
// wxMenuBar helpers
// ---------------------------------------------------------------------------

void wxMenuBar::Refresh()
{
    wxCHECK_RET( IsAttached(), wxT("can't refresh unattached menubar") );

       // Regenerate the menu resource
    LoadMenu();
}

WXHMENU wxMenuBar::Create()
{
    return NULL;
}

int wxMenuBar::PalmPositionForWxMenu(wxMenu *menu, int wxpos)
{
    return -1;
}

// ---------------------------------------------------------------------------
// wxMenuBar functions to work with the top level submenus
// ---------------------------------------------------------------------------

void wxMenuBar::EnableTop(size_t pos, bool enable)
{
    // Palm OS does not have support for grayed or disabled items
}

void wxMenuBar::SetMenuLabel(size_t pos, const wxString& label)
{
    wxCHECK_RET( pos < GetMenuCount(), wxT("invalid menu index") );

    m_titles[pos] = label;

    if ( !IsAttached() )
    {
        return;
    }

       // Regenerate the menu resource
    Refresh();
}

wxString wxMenuBar::GetMenuLabel(size_t pos) const
{
    wxCHECK_MSG( pos < GetMenuCount(), wxEmptyString,
                 wxT("invalid menu index in wxMenuBar::GetMenuLabel") );

    return m_titles[pos];
}

// ---------------------------------------------------------------------------
// wxMenuBar construction
// ---------------------------------------------------------------------------

wxMenu *wxMenuBar::Replace(size_t pos, wxMenu *menu, const wxString& title)
{
   wxMenu *menuOld = wxMenuBarBase::Replace(pos, menu, title);
    if ( !menuOld )
        return NULL;

    m_titles[pos] = title;

    if ( IsAttached() )
    {
        // Regenerate the menu resource
        Refresh();
    }

    return menuOld;
}

bool wxMenuBar::Insert(size_t pos, wxMenu *menu, const wxString& title)
{
    if ( !wxMenuBarBase::Insert(pos, menu, title) )
        return false;

    m_titles.Insert(title, pos);

    if ( IsAttached() )
    {
        // Regenerate the menu resource
        Refresh();
    }

    return true;
}

bool wxMenuBar::Append(wxMenu *menu, const wxString& title)
{
    if ( !wxMenuBarBase::Append(menu, title) )
        return false;

    m_titles.Add(title);

    if(IsAttached())
    {
        // Regenerate the menu resource
        Refresh();
    }

    return true;
}

wxMenu *wxMenuBar::Remove(size_t pos)
{
    wxMenu *menu = wxMenuBarBase::Remove(pos);
    if ( !menu )
        return NULL;

    m_titles.RemoveAt(pos);

    if (IsAttached())
    {
        // Regenerate the menu resource
        Refresh();
    }

    return menu;
}

#if wxUSE_ACCEL

void wxMenuBar::RebuildAccelTable()
{
}

#endif // wxUSE_ACCEL

int wxMenuBar::ProcessCommand(int ItemID)
{
    if(!IsAttached())
        return -1;

    int MenuNum=(ItemID/1000)-1;
    int ItemNum=(ItemID-(1000*(MenuNum+1)));

    // Should never happen, but it doesn't hurt to check anyway.
    if(MenuNum>GetMenuCount())
        return -1;

    // Get the menu
    wxMenu *ActiveMenu=GetMenu(MenuNum);

    // Make sure this is a valid item.
    if(ItemNum>ActiveMenu->GetMenuItemCount())
        return -1;

    // Get the item
    wxMenuItem *ActiveItem=ActiveMenu->FindItemByPosition(ItemNum);
    int ActiveID=ActiveItem->GetId();

    return ActiveID;
}

/* Palm OS does not have good dynamic menu support.  About all you can do with
 * the standard API calls is to add new items to an existing drop-down menu and
 * hide/show items in a drop-down menu.  It is impossible to add, hide, or
 * change the label on a drop-down menu.
 *
 * The easiest and simplest way around this limitation is to modify the Palm OS
 * MenuBarType structure directly.  This gives limited ability to change the
 * label on a drop-down menu.  I have not been able to find a safe way to add,
 * delete, or resize drop-down menus in OS 6.
 *
 * The following routine attempt to work around these limitations present in the
 * Palm OS API to provide limited dynamic menu support.  This solution is far
 * from perfect, but the only other option is to wait for PalmSource to add full
 * dynamic menu support, or to recreate the Palm OS menu system from scratch.
 *
 * This system is limited in that no more than 4 drop-down menus are allowed per
 * menu bar, and the label for each drop-down menu is limited to 8 characters of
 * text.  However, this menu system should work for most applications.
 *
 * Basically the menu routines select one of four menu bars, depending on
 * whether or not the requested menu bar has one, two, three, or four drop-down
 * menus.
 *
 * These four "template" menu bars contain one, two, three, or four drop-down
 * menus.  Each menu has a dummy menu item attached to it to allow the Palm OS
 * MenuAddItem function to add the real items.
 *
 * The labels on the drop-down menus are then replaced with the labels of the
 * real menus.
 *
 * The menu is then attached to the active window and the MenuAddItem API
 * function is called to add the items to each drop-down menu.  Finally,
 * MenuHideItem is called to remove the dummy items from each drop-down menu.
 */
void wxMenuBar::LoadMenu()
{
    int i=0;
    int j=0;
#ifdef __WXPALMOS6__
    // Handle to the currently running application database
    DmOpenRef    AppDB;

    // Get app database reference - needed for some Palm OS Menu API calls.
    SysGetModuleDatabase(SysGetRefNum(), NULL, &AppDB);
#endif // __WXPALMOS6__

    // Get the number of menus
    int NumMenus=GetMenuCount();

    // Set up the pointers and handles
    char *PalmOSMenuBarPtr;
    MemHandle PalmOSMenuBar;

    // Load the menu template and set up the menu pointers
    if(NumMenus==1)
    {
        PalmOSMenuBar = POS_DmGetResource (AppDB, MenuRscType, 1000);
        PalmOSMenuBarPtr = (char *)MemHandleLock (PalmOSMenuBar);

        PalmOSMenuBarPtr += 74;
    }
    else if(NumMenus==2)
    {
        PalmOSMenuBar = POS_DmGetResource (AppDB, MenuRscType, 2000);
        PalmOSMenuBarPtr = (char *)MemHandleLock (PalmOSMenuBar);

        PalmOSMenuBarPtr += 116;
    }
    else if(NumMenus==3)
    {
        PalmOSMenuBar = POS_DmGetResource (AppDB, MenuRscType, 3000);
        PalmOSMenuBarPtr = (char *)MemHandleLock (PalmOSMenuBar);

        PalmOSMenuBarPtr += 158;
    }
    else
    {
        // We support a maximum of 4 menus, so make sure that do not create
        // more than we can handle.
        NumMenus=4;

        PalmOSMenuBar = POS_DmGetResource (AppDB, MenuRscType, 4000);
        PalmOSMenuBarPtr = (char *)MemHandleLock (PalmOSMenuBar);

        PalmOSMenuBarPtr += 200;
    }

    // Set the proper names for the drop-down triggers.
    for(i=0;i<NumMenus;i++)
    {
        // Clear out the old label
        char buffer[8]={' ',' ',' ',' ',' ',' ',' ',' '};
        MemMove(PalmOSMenuBarPtr,buffer,8);

        wxString MenuTitle=m_titles.Item(i);

        // Make sure we don't copy more than 8 bytes for the label
        int LengthToCopy = MenuTitle.length();
        if(LengthToCopy > 8)
            LengthToCopy = 8;

        MemMove(PalmOSMenuBarPtr,(char*)(&MenuTitle),LengthToCopy);
        PalmOSMenuBarPtr+=11;
    }

    // We are done with the menu pointer.
    MemHandleUnlock(PalmOSMenuBar);
    DmReleaseResource(PalmOSMenuBar);

    // We must make the menu active before we can add items to the drop-down
    // triggers.
    POS_FrmSetMenu (FrmGetActiveForm(), AppDB, NumMenus * 1000);

    /* Add the menu items to the drop-down triggers.  This must be done after
     * setting the triggers, because setting the names of drop-down triggers
     * that have a variable number of items requires carefull calculation of
     * the offsets in the MenuBarType structure.  Setting the triggers first
     * avoids this.
     */
    for(i=0;i<NumMenus;i++)
    {
        wxMenu *CurrentMenu=GetMenu(i);

        for(j=0;j<CurrentMenu->GetMenuItemCount();j++)
        {
            wxMenuItem *CurrentItem=CurrentMenu->FindItemByPosition(j);
            wxString ItemLabel=CurrentItem->GetLabel();

            if(CurrentItem->IsSeparator()==true)
            {
                char Separator=MenuSeparatorChar;
                if(j==0)
                    MenuAddItem(9000+i,((i*1000)+1000)+j,0x00,&Separator);
                else
                    MenuAddItem(((i*1000)+1000)+j-1,((i*1000)+1000)+j,0x00,&Separator);
            }
            else
            {
                if(j==0)
                    MenuAddItem(9000+i,((i*1000)+1000)+j,0x00,(char *)(&ItemLabel));
                else
                    MenuAddItem(((i*1000)+1000)+j-1,((i*1000)+1000)+j,0x00,(char *)(&ItemLabel));
            }
        }

        // Hide the dummy menu item, since we don't need it anymore.
        MenuHideItem(9000+i);
    }
}

void wxMenuBar::Attach(wxFrame *frame)
{
    // before attaching preprocess menus to not include wxID_EXIT item
    // as PalmOS guidelines suggest

    wxMenuItem *item;
    wxMenu *menu;
    int i;

    while( item = FindItem(wxID_EXIT) )
    {
        menu = item->GetMenu();
        if( !menu ) break; // something broken ?

        size_t count = menu->GetMenuItemCount();
        if( count == 0 ) break; // something broken ?

        // if EXIT is last item in menu
        if( menu->FindItemByPosition( count - 1 ) == item )
        {
            menu->Destroy( item );

            // was more than one item?
            // was previous separator ?
            if( count > 2 )
            {
                item = menu->FindItemByPosition( count - 2 );
                if(item && item->IsSeparator())
                    menu->Destroy( item );
            }
        }

        // if EXIT is first item in menu
        else if( menu->FindItemByPosition( 0 ) == item )
        {
            menu->Destroy( item );

            // was more than one item?
            // was previous separator ?
            if( count > 2 )
            {
                item = menu->FindItemByPosition( 0 );
                if(item && item->IsSeparator())
                    menu->Destroy( item );
            }
        }

        // if EXIT is in the middle but before and after are selectors
        else
        {
            i = 1; // 0 case already done
            while ( (i < count) && (menu->FindItemByPosition( 0 ) != item) )
            {
                i++;
            }

            if (i >= count) break;
            if (menu->FindItemByPosition( i ) != item) break;
            menu->Destroy( item );
            item = menu->FindItemByPosition( i );
            if ( item &&
                 item->IsSeparator() &&
                 menu->FindItemByPosition( i-1 )->IsSeparator() )
            {
                // noe need for two neighbouring separators
                menu->Destroy( item );
            }
        }
    }

    // check if we received any empty menu!
    i = 0;
    while(i < GetMenuCount())
    {
        menu = GetMenu(i);

        if( menu && (menu->GetMenuItemCount()==0) )
        {
            menu = Remove( i );
            delete menu;
        }
        else
            i++;
    }

    wxMenuBarBase::Attach(frame);

    LoadMenu();
}

void wxMenuBar::Detach()
{
    wxMenuBarBase::Detach();
}

#endif // wxUSE_MENUS
