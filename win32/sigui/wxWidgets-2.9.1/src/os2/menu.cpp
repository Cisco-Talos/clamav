/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/menu.cpp
// Purpose:     wxMenu, wxMenuBar, wxMenuItem
// Author:      David Webster
// Modified by:
// Created:     10/10/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/menu.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/frame.h"
    #include "wx/utils.h"
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#if wxUSE_OWNER_DRAWN
    #include "wx/ownerdrw.h"
#endif

#include "wx/os2/private.h"

// other standard headers
#include <string.h>

// ----------------------------------------------------------------------------
// global variables
// ----------------------------------------------------------------------------

extern wxMenu*                      wxCurrentPopupMenu;

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

//
// The (popup) menu title has this special id
//
static const int                    idMenuTitle = -3;

//
// The unique ID for Menus
//
USHORT                              wxMenu::m_nextMenuId = 0;

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

    IMPLEMENT_DYNAMIC_CLASS(wxMenu, wxEvtHandler)
    IMPLEMENT_DYNAMIC_CLASS(wxMenuBar, wxEvtHandler)

// ============================================================================
// implementation
// ============================================================================

// ---------------------------------------------------------------------------
// wxMenu construction, adding and removing menu items
// ---------------------------------------------------------------------------

//
// Construct a menu with optional title (then use append)
//
void wxMenu::Init()
{
    m_bDoBreak = false;
    m_nStartRadioGroup = -1;

    //
    // Create the menu (to be used as a submenu or a popup)
    //
    if ((m_hMenu =  ::WinCreateWindow( HWND_DESKTOP
                                      ,WC_MENU
                                      ,"Menu"
                                      ,0L
                                      ,0L
                                      ,0L
                                      ,0L
                                      ,0L
                                      ,NULLHANDLE
                                      ,HWND_TOP
                                      ,0L
                                      ,NULL
                                      ,NULL
                                     )) == 0)
    {
        wxLogLastError(wxT("WinLoadMenu"));
    }
    m_vMenuData.iPosition   = 0;
    m_vMenuData.afStyle     = MIS_SUBMENU | MIS_TEXT;
    m_vMenuData.afAttribute = (USHORT)0;
    m_vMenuData.id          = m_nextMenuId++;
    m_vMenuData.hwndSubMenu = m_hMenu;
    m_vMenuData.hItem       = NULLHANDLE;

    //
    // If we have a title, insert it in the beginning of the menu
    //
    if (!m_title.empty())
    {
        Append( idMenuTitle
               ,m_title
               ,wxEmptyString
               ,wxITEM_NORMAL
              );
        AppendSeparator();
    }
} // end of wxMenu::Init

//
// The wxWindow destructor will take care of deleting the submenus.
//
wxMenu::~wxMenu()
{
    //
    // We should free PM resources only if PM doesn't do it for us
    // which happens if we're attached to a menubar or a submenu of another
    // menu
    if (!IsAttached() && !GetParent())
    {
        if (!::WinDestroyWindow((HWND)GetHmenu()) )
        {
            wxLogLastError(wxT("WinDestroyWindow"));
        }
    }

#if wxUSE_ACCEL
    //
    // Delete accels
    //
    WX_CLEAR_ARRAY(m_vAccels);
#endif // wxUSE_ACCEL
} // end of wxMenu::~wxMenu

void wxMenu::Break()
{
    // this will take effect during the next call to Append()
    m_bDoBreak = true;
} // end of wxMenu::Break

void wxMenu::Attach(
  wxMenuBarBase*                    pMenubar
)
{
    wxMenuBase::Attach(pMenubar);
    EndRadioGroup();
} // end of wxMenu::Break;

#if wxUSE_ACCEL

int wxMenu::FindAccel(
  int                               nId
) const
{
    size_t                          n;
    size_t                          nCount = m_vAccels.GetCount();

    for (n = 0; n < nCount; n++)
        if (m_vAccels[n]->m_command == nId)
            return n;
    return wxNOT_FOUND;
} // end of wxMenu::FindAccel

void wxMenu::UpdateAccel(
  wxMenuItem*                       pItem
)
{
    if (pItem->IsSubMenu())
    {
        wxMenu*                     pSubmenu = pItem->GetSubMenu();
        wxMenuItemList::compatibility_iterator node = pSubmenu->GetMenuItems().GetFirst();

        while (node)
        {
            UpdateAccel(node->GetData());
            node = node->GetNext();
        }
    }
    else if (!pItem->IsSeparator())
    {
        //
        // Recurse upwards: we should only modify m_accels of the top level
        // menus, not of the submenus as wxMenuBar doesn't look at them
        // (alternative and arguable cleaner solution would be to recurse
        // downwards in GetAccelCount() and CopyAccels())
        //
        if (GetParent())
        {
            GetParent()->UpdateAccel(pItem);
            return;
        }

        //
        // Find the (new) accel for this item
        //
        wxAcceleratorEntry*         pAccel = wxAcceleratorEntry::Create(pItem->GetItemLabel());

        if (pAccel)
            pAccel->m_command = pItem->GetId();

        //
        // Find the old one
        //
        size_t                      n = FindAccel(pItem->GetId());

        if (n == (size_t)wxNOT_FOUND)
        {
            //
            // No old, add new if any
            //
            if (pAccel)
                m_vAccels.Add(pAccel);
            else
                return;
        }
        else
        {
            //
            // Replace old with new or just remove the old one if no new
            //
            delete m_vAccels[n];
            if (pAccel)
                m_vAccels[n] = pAccel;
            else
                m_vAccels.RemoveAt(n);
        }

        if (IsAttached())
        {
            GetMenuBar()->RebuildAccelTable();
        }
    }
} // wxMenu::UpdateAccel

#endif // wxUSE_ACCEL

//
// Append a new item or submenu to the menu
//
bool wxMenu::DoInsertOrAppend( wxMenuItem* pItem,
                               size_t      nPos )
{
    wxMenu*    pSubmenu = pItem->GetSubMenu();
    MENUITEM&  rItem = (pSubmenu != NULL)?pSubmenu->m_vMenuData:
                       pItem->m_vMenuData;

    ERRORID    vError;
    wxString   sError;

#if wxUSE_ACCEL
    UpdateAccel(pItem);
#endif // wxUSE_ACCEL

    //
    // If "Break" has just been called, insert a menu break before this item
    // (and don't forget to reset the flag)
    //
    if (m_bDoBreak)
    {
        rItem.afStyle |= MIS_BREAK;
        m_bDoBreak = false;
    }

    //
    // Id is the numeric id for normal menu items and HMENU for submenus as
    // required by ::MM_INSERTITEM message API
    //
    if (pSubmenu != NULL)
    {
        wxASSERT_MSG(pSubmenu->GetHMenu(), wxT("invalid submenu"));
        pSubmenu->SetParent(this);

        rItem.iPosition = 0; // submenus have a 0 position
        rItem.id        = (USHORT)pSubmenu->GetHMenu();
        rItem.afStyle  |= MIS_SUBMENU | MIS_TEXT;
    }
    else
    {
        rItem.id = (USHORT)pItem->GetId();
    }

    char *pData = NULL;

#if wxUSE_OWNER_DRAWN
    if (pItem->IsOwnerDrawn())
    {
        //
        // Want to get {Measure|Draw}Item messages?
        // item draws itself, passing pointer to data doesn't work in OS/2
        // Will eventually need to set the image handle somewhere into vItem.hItem
        //
        rItem.afStyle             |= MIS_OWNERDRAW;
        pData                      = NULL;
        rItem.hItem                = (HBITMAP)pItem->GetBitmap().GetHBITMAP();
        pItem->m_vMenuData.afStyle = rItem.afStyle;
        pItem->m_vMenuData.hItem   = rItem.hItem;
    }
    else
#endif
    if (pItem->IsSeparator())
    {
        rItem.afStyle = MIS_SEPARATOR;
    }
    else
    {
        if (pItem->GetId() == idMenuTitle)
        {
            // Item is an unselectable title to be passed via pData
            rItem.afStyle = MIS_STATIC;
        }
        else
        {
            //
            // Menu is just a normal string (passed in data parameter)
            //
            rItem.afStyle |= MIS_TEXT;
        }
        pData = (char*) pItem->GetItemLabel().wx_str();
    }

    if (nPos == (size_t)-1)
    {
        rItem.iPosition = MIT_END;
    }
    else
    {
        rItem.iPosition = (SHORT)nPos;
    }

    APIRET                          rc;

    rc = (APIRET)::WinSendMsg( GetHmenu()
                              ,MM_INSERTITEM
                              ,(MPARAM)&rItem
                              ,(MPARAM)pData
                             );
#if wxUSE_OWNER_DRAWN
    if (pItem->IsOwnerDrawn())
    {
        MENUITEM                   vMenuItem;

        ::WinSendMsg( GetHmenu()
                     ,MM_QUERYITEM
                     ,MPFROM2SHORT( (USHORT)pItem->GetId()
                                   ,(USHORT)(FALSE)
                                  )
                     ,&vMenuItem
                    );
    }
#endif

    if (rc == (APIRET)MIT_MEMERROR || rc == (APIRET)MIT_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogError(wxT("Error inserting or appending a menuitem. Error: %s\n"), sError.c_str());
        wxLogLastError(wxT("Insert or AppendMenu"));
        return false;
    }

    //
    // If we're already attached to the menubar, we must update it
    //
    if (IsAttached() && GetMenuBar()->IsAttached())
    {
        GetMenuBar()->Refresh();
    }

    return true;
} // end of wxMenu::DoInsertOrAppend

void wxMenu::EndRadioGroup()
{
    //
    // We're not inside a radio group any longer
    //
    m_nStartRadioGroup = -1;
} // end of wxMenu::EndRadioGroup

wxMenuItem* wxMenu::DoAppend( wxMenuItem* pItem )
{
    wxCHECK_MSG( pItem, NULL, wxT("NULL item in wxMenu::DoAppend") );

    bool bCheck = false;

    if (pItem->GetKind() == wxITEM_RADIO)
    {
        int                         nCount = GetMenuItemCount();

        if (m_nStartRadioGroup == -1)
        {
            //
            // Start a new radio group
            //
            m_nStartRadioGroup = nCount;

            //
            // For now it has just one element
            //
            pItem->SetAsRadioGroupStart();
            pItem->SetRadioGroupEnd(m_nStartRadioGroup);

            //
            // Ensure that we have a checked item in the radio group
            //
            bCheck = true;
        }
        else // extend the current radio group
        {
            //
            // We need to update its end item
            //
            pItem->SetRadioGroupStart(m_nStartRadioGroup);

            wxMenuItemList::compatibility_iterator node = GetMenuItems().Item(m_nStartRadioGroup);

            if (node)
            {
                node->GetData()->SetRadioGroupEnd(nCount);
            }
            else
            {
                wxFAIL_MSG( wxT("where is the radio group start item?") );
            }
        }
    }
    else // not a radio item
    {
        EndRadioGroup();
    }

    if (!wxMenuBase::DoAppend(pItem) || !DoInsertOrAppend(pItem))
    {
        return NULL;
    }
    if (bCheck)
    {
        //
        // Check the item initially
        //
        pItem->Check(true);
    }
    return pItem;
} // end of wxMenu::DoAppend

wxMenuItem* wxMenu::DoInsert(
  size_t                            nPos
, wxMenuItem*                       pItem
)
{
    if ( wxMenuBase::DoInsert( nPos
                               ,pItem) &&
             DoInsertOrAppend( pItem
                              ,nPos
                 ))
         return pItem;
    else
        return NULL;
} // end of wxMenu::DoInsert

wxMenuItem* wxMenu::DoRemove(
  wxMenuItem*                       pItem
)
{
    //
    // We need to find the items position in the child list
    //
    size_t                          nPos;
    wxMenuItemList::compatibility_iterator node = GetMenuItems().GetFirst();

    for (nPos = 0; node; nPos++)
    {
        if (node->GetData() == pItem)
            break;
        node = node->GetNext();
    }

    //
    // DoRemove() (unlike Remove) can only be called for existing item!
    //
    wxCHECK_MSG(node, NULL, wxT("bug in wxMenu::Remove logic"));

#if wxUSE_ACCEL
    //
    // Remove the corresponding accel from the accel table
    //
    int                             n = FindAccel(pItem->GetId());

    if (n != wxNOT_FOUND)
    {
        delete m_vAccels[n];
        m_vAccels.RemoveAt(n);
    }

#endif // wxUSE_ACCEL
    //
    // Remove the item from the menu
    //
    ::WinSendMsg( GetHmenu()
                 ,MM_REMOVEITEM
                 ,MPFROM2SHORT(pItem->GetId(), TRUE)
                 ,(MPARAM)0
                );
    if (IsAttached() && GetMenuBar()->IsAttached())
    {
        //
        // Otherwise, the chane won't be visible
        //
        GetMenuBar()->Refresh();
    }

    //
    // And from internal data structures
    //
    return wxMenuBase::DoRemove(pItem);
} // end of wxMenu::DoRemove

// ---------------------------------------------------------------------------
// accelerator helpers
// ---------------------------------------------------------------------------

#if wxUSE_ACCEL

//
// Create the wxAcceleratorEntries for our accels and put them into provided
// array - return the number of accels we have
//
size_t wxMenu::CopyAccels(
  wxAcceleratorEntry*               pAccels
) const
{
    size_t                          nCount = GetAccelCount();

    for (size_t n = 0; n < nCount; n++)
    {
        *pAccels++ = *m_vAccels[n];
    }
    return nCount;
} // end of wxMenu::CopyAccels

#endif // wxUSE_ACCEL

// ---------------------------------------------------------------------------
// set wxMenu title
// ---------------------------------------------------------------------------

void wxMenu::SetTitle( const wxString& rLabel )
{
    bool bHasNoTitle = m_title.empty();
    HWND hMenu = GetHmenu();

    m_title = rLabel;
    if (bHasNoTitle)
    {
        if (!rLabel.empty())
        {
            if (!::WinSetWindowText(hMenu, rLabel.c_str()))
            {
                wxLogLastError(wxT("SetMenuTitle"));
            }
        }
    }
    else
    {
        if (rLabel.empty() )
        {
            ::WinSendMsg( GetHmenu()
                         ,MM_REMOVEITEM
                         ,MPFROM2SHORT(hMenu, TRUE)
                         ,(MPARAM)0
                        );
        }
        else
        {
            //
            // Modify the title
            //
            if (!::WinSetWindowText(hMenu, rLabel.c_str()))
            {
                wxLogLastError(wxT("SetMenuTitle"));
            }
        }
    }
} // end of wxMenu::SetTitle

// ---------------------------------------------------------------------------
// event processing
// ---------------------------------------------------------------------------

bool wxMenu::OS2Command( WXUINT WXUNUSED(uParam),
                         WXWORD vId )
{
    //
    // Ignore commands from the menu title
    //

    if (vId != (WXWORD)idMenuTitle)
    {
        SendEvent( vId
                  ,(int)::WinSendMsg( GetHmenu()
                                     ,MM_QUERYITEMATTR
                                     ,MPFROMSHORT(vId)
                                     ,(MPARAM)MIA_CHECKED
                                    )
                 );
    }
    return true;
} // end of wxMenu::OS2Command

// ---------------------------------------------------------------------------
// other
// ---------------------------------------------------------------------------

wxWindow* wxMenu::GetWindow() const
{
    if (m_invokingWindow != NULL)
        return m_invokingWindow;
    else if ( GetMenuBar() != NULL)
        return GetMenuBar()->GetFrame();

    return NULL;
} // end of wxMenu::GetWindow

// recursive search for item by id
wxMenuItem* wxMenu::FindItem(
  int                               nItemId
, ULONG                             hItem
, wxMenu**                          ppItemMenu
) const
{
    if ( ppItemMenu )
        *ppItemMenu = NULL;

    wxMenuItem*                     pItem = NULL;

    for ( wxMenuItemList::compatibility_iterator node = m_items.GetFirst();
          node && !pItem;
          node = node->GetNext() )
    {
        pItem = node->GetData();

        if ( pItem->GetId() == nItemId && pItem->m_vMenuData.hItem == hItem)
        {
            if ( ppItemMenu )
                *ppItemMenu = (wxMenu *)this;
        }
        else if ( pItem->IsSubMenu() )
        {
            pItem = pItem->GetSubMenu()->FindItem( nItemId
                                                  ,hItem
                                                  ,ppItemMenu
                                                 );
            if (pItem)
                break;
        }
        else
        {
            // don't exit the loop
            pItem = NULL;
        }
    }
    return pItem;
} // end of wxMenu::FindItem

// ---------------------------------------------------------------------------
// Menu Bar
// ---------------------------------------------------------------------------

void wxMenuBar::Init()
{
    m_eventHandler = this;
    m_menuBarFrame = NULL;
    m_hMenu = 0;
} // end of wxMenuBar::Init

wxMenuBar::wxMenuBar()
{
    Init();
} // end of wxMenuBar::wxMenuBar

wxMenuBar::wxMenuBar(
 long                               WXUNUSED(lStyle)
)
{
    Init();
} // end of wxMenuBar::wxMenuBar

wxMenuBar::wxMenuBar(
  int                               nCount
, wxMenu*                           vMenus[]
, const wxString                    sTitles[]
, long                              WXUNUSED(lStyle)
)
{
    Init();

    m_titles.Alloc(nCount);
    for ( int i = 0; i < nCount; i++ )
    {
        m_menus.Append(vMenus[i]);
        m_titles.Add(sTitles[i]);
        vMenus[i]->Attach(this);
    }
} // end of wxMenuBar::wxMenuBar

wxMenuBar::~wxMenuBar()
{
    //
    // We should free PM's resources only if PM doesn't do it for us
    // which happens if we're attached to a frame
    //
    if (m_hMenu && !IsAttached())
    {
        ::WinDestroyWindow((HMENU)m_hMenu);
        m_hMenu = (WXHMENU)NULL;
    }
} // end of wxMenuBar::~wxMenuBar

// ---------------------------------------------------------------------------
// wxMenuBar helpers
// ---------------------------------------------------------------------------

void wxMenuBar::Refresh()
{
    wxCHECK_RET( IsAttached(), wxT("can't refresh unatteched menubar") );

    WinSendMsg(GetWinHwnd(m_menuBarFrame), WM_UPDATEFRAME, (MPARAM)FCF_MENU, (MPARAM)0);
} // end of wxMenuBar::Refresh

WXHMENU wxMenuBar::Create()
{
    HWND hFrame;

    if (m_hMenu != 0 )
        return m_hMenu;

    wxCHECK_MSG(!m_hMenu, TRUE, wxT("menubar already created"));

    //
    // Menubars should be associated with a frame otherwise they are popups
    //
    if (m_menuBarFrame != NULL)
        hFrame = GetWinHwnd(m_menuBarFrame);
    else
        hFrame = HWND_DESKTOP;
    //
    // Create an empty menu and then fill it with insertions
    //
    if ((m_hMenu =  ::WinCreateWindow( hFrame
                                      ,WC_MENU
                                      ,NULL
                                      ,MS_ACTIONBAR | WS_SYNCPAINT | WS_VISIBLE
                                      ,0L
                                      ,0L
                                      ,0L
                                      ,0L
                                      ,hFrame
                                      ,HWND_TOP
                                      ,FID_MENU
                                      ,NULL
                                      ,NULL
                                     )) == 0)
    {
        wxLogLastError(wxT("WinLoadMenu"));
    }
    else
    {
        size_t nCount = GetMenuCount(), i;
        wxMenuList::iterator it;
        for (i = 0, it = m_menus.begin(); i < nCount; i++, it++)
        {
            APIRET   rc;
            ERRORID  vError;
            wxString sError;
            HWND     hSubMenu;

            //
            // Set the parent and owner of the submenues to be the menubar, not the desktop
            //
            hSubMenu = (*it)->m_vMenuData.hwndSubMenu;
            if (!::WinSetParent((*it)->m_vMenuData.hwndSubMenu, m_hMenu, FALSE))
            {
                vError = ::WinGetLastError(vHabmain);
                sError = wxPMErrorToStr(vError);
                wxLogError(wxT("Error setting parent for submenu. Error: %s\n"), sError.c_str());
                return NULLHANDLE;
            }

            if (!::WinSetOwner((*it)->m_vMenuData.hwndSubMenu, m_hMenu))
            {
                vError = ::WinGetLastError(vHabmain);
                sError = wxPMErrorToStr(vError);
                wxLogError(wxT("Error setting parent for submenu. Error: %s\n"), sError.c_str());
                return NULLHANDLE;
            }

            (*it)->m_vMenuData.iPosition = (SHORT)i;

            rc = (APIRET)::WinSendMsg(m_hMenu, MM_INSERTITEM, (MPARAM)&(*it)->m_vMenuData, (MPARAM)m_titles[i].wx_str());
            if (rc == (APIRET)MIT_MEMERROR || rc == (APIRET)MIT_ERROR)
            {
                vError = ::WinGetLastError(vHabmain);
                sError = wxPMErrorToStr(vError);
                wxLogError(wxT("Error inserting or appending a menuitem. Error: %s\n"), sError.c_str());
                return NULLHANDLE;
            }
        }
    }
    return m_hMenu;
} // end of wxMenuBar::Create

// ---------------------------------------------------------------------------
// wxMenuBar functions to work with the top level submenus
// ---------------------------------------------------------------------------

//
// NB: we don't support owner drawn top level items for now, if we do these
//     functions would have to be changed to use wxMenuItem as well
//
void wxMenuBar::EnableTop(
  size_t                            nPos
, bool                              bEnable
)
{
    wxCHECK_RET(IsAttached(), wxT("doesn't work with unattached menubars"));
    USHORT                          uFlag = 0;
    SHORT                           nId;

    if(!bEnable)
       uFlag = MIA_DISABLED;

    nId = SHORT1FROMMR(::WinSendMsg((HWND)m_hMenu, MM_ITEMIDFROMPOSITION, MPFROMSHORT(nPos), (MPARAM)0));
    if (nId == MIT_ERROR)
    {
        wxLogLastError(wxT("LogLastError"));
        return;
    }
    ::WinSendMsg((HWND)m_hMenu, MM_SETITEMATTR, MPFROM2SHORT(nId, TRUE), MPFROM2SHORT(MIA_DISABLED, uFlag));
    Refresh();
} // end of wxMenuBar::EnableTop

void wxMenuBar::SetMenuLabel(
  size_t                            nPos
, const wxString&                   rLabel
)
{
    SHORT                           nId;
    MENUITEM                        vItem;

    wxCHECK_RET(nPos < GetMenuCount(), wxT("invalid menu index"));
    m_titles[nPos] = rLabel;

    if (!IsAttached())
    {
        return;
    }

    nId = SHORT1FROMMR(::WinSendMsg((HWND)m_hMenu, MM_ITEMIDFROMPOSITION, MPFROMSHORT(nPos), (MPARAM)0));
    if (nId == MIT_ERROR)
    {
        wxLogLastError(wxT("LogLastError"));
        return;
    }
    if(!::WinSendMsg( (HWND)m_hMenu
                     ,MM_QUERYITEM
                     ,MPFROM2SHORT(nId, TRUE)
                     ,MPARAM(&vItem)
                    ))
    {
        wxLogLastError(wxT("QueryItem"));
    }
    nId = vItem.id;

    if (::WinSendMsg(GetHmenu(), MM_SETITEMTEXT, MPFROMSHORT(nId), (MPARAM)rLabel.wx_str()));
    {
        wxLogLastError(wxT("ModifyMenu"));
    }
    Refresh();
} // end of wxMenuBar::SetMenuLabel

wxString wxMenuBar::GetMenuLabel(
  size_t                            nPos
) const
{
    wxCHECK_MSG( nPos < GetMenuCount(), wxEmptyString,
                 wxT("invalid menu index in wxMenuBar::GetMenuLabel") );
    return m_titles[nPos];
} // end of wxMenuBar::GetMenuLabel

// ---------------------------------------------------------------------------
// wxMenuBar construction
// ---------------------------------------------------------------------------

wxMenu* wxMenuBar::Replace(
  size_t                             nPos
, wxMenu*                            pMenu
, const wxString&                    rTitle
)
{
    SHORT                            nId;
    wxString                         sTitle = wxPMTextToLabel(rTitle);
    wxMenu*                          pMenuOld = wxMenuBarBase::Replace( nPos
                                                                       ,pMenu
                                                                       ,sTitle
                                                                      );


    nId = SHORT1FROMMR(::WinSendMsg((HWND)m_hMenu, MM_ITEMIDFROMPOSITION, MPFROMSHORT(nPos), (MPARAM)0));
    if (nId == MIT_ERROR)
    {
        wxLogLastError(wxT("LogLastError"));
        return NULL;
    }
    if (!pMenuOld)
        return NULL;
    m_titles[nPos] = sTitle;
    if (IsAttached())
    {
        ::WinSendMsg((HWND)m_hMenu, MM_REMOVEITEM, MPFROM2SHORT(nId, TRUE), (MPARAM)0);
        ::WinSendMsg((HWND)m_hMenu, MM_INSERTITEM, (MPARAM)&pMenu->m_vMenuData, (MPARAM)sTitle.wx_str());

#if wxUSE_ACCEL
        if (pMenuOld->HasAccels() || pMenu->HasAccels())
        {
            //
            // Need to rebuild accell table
            //
            RebuildAccelTable();
        }
#endif // wxUSE_ACCEL
        Refresh();
    }
    return pMenuOld;
} // end of wxMenuBar::Replace

bool wxMenuBar::Insert( size_t          nPos,
                        wxMenu*         pMenu,
                        const wxString& rTitle )
{
    wxString sTitle = wxPMTextToLabel(rTitle);

    if (!wxMenuBarBase::Insert( nPos, pMenu, sTitle ))
        return false;

    m_titles.Insert( sTitle, nPos );

    if (IsAttached())
    {
        pMenu->m_vMenuData.iPosition = (SHORT)nPos;
        ::WinSendMsg( (HWND)m_hMenu
                     ,MM_INSERTITEM
                     ,(MPARAM)&pMenu->m_vMenuData
                     ,(MPARAM)sTitle.wx_str()
                    );
#if wxUSE_ACCEL
        if (pMenu->HasAccels())
        {
            // need to rebuild accell table
            RebuildAccelTable();
        }
#endif // wxUSE_ACCEL
        Refresh();
    }

    return true;
} // end of wxMenuBar::Insert

bool wxMenuBar::Append( wxMenu* pMenu,
                        const wxString& rsTitle )
{
    WXHMENU hSubmenu = pMenu ? pMenu->GetHMenu() : 0;

    wxCHECK_MSG(hSubmenu, false, wxT("can't append invalid menu to menubar"));

    wxString sTitle = wxPMTextToLabel(rsTitle);

    if (!wxMenuBarBase::Append(pMenu, sTitle))
        return false;

    m_titles.Add(sTitle);

    if ( IsAttached() )
    {
        pMenu->m_vMenuData.iPosition = MIT_END;
        ::WinSendMsg((HWND)m_hMenu, MM_INSERTITEM, (MPARAM)&pMenu->m_vMenuData, (MPARAM)sTitle.wx_str());
#if wxUSE_ACCEL
        if (pMenu->HasAccels())
        {
            //
            // Need to rebuild accell table
            //
            RebuildAccelTable();
        }
#endif // wxUSE_ACCEL
        Refresh();
    }
    return true;
} // end of wxMenuBar::Append

wxMenu* wxMenuBar::Remove(
  size_t                            nPos
)
{
    wxMenu*                         pMenu = wxMenuBarBase::Remove(nPos);
    SHORT                           nId;

    if (!pMenu)
        return NULL;

    nId = SHORT1FROMMR(::WinSendMsg( (HWND)GetHmenu()
                                    ,MM_ITEMIDFROMPOSITION
                                    ,MPFROMSHORT(nPos)
                                    ,(MPARAM)0)
                                   );
    if (nId == MIT_ERROR)
    {
        wxLogLastError(wxT("LogLastError"));
        return NULL;
    }
    if (IsAttached())
    {
        ::WinSendMsg( (HWND)GetHmenu()
                     ,MM_REMOVEITEM
                     ,MPFROM2SHORT(nId, TRUE)
                     ,(MPARAM)0
                    );

#if wxUSE_ACCEL
        if (pMenu->HasAccels())
        {
            //
            // Need to rebuild accell table
            //
            RebuildAccelTable();
        }
#endif // wxUSE_ACCEL
        Refresh();
    }
    m_titles.RemoveAt(nPos);
    return pMenu;
} // end of wxMenuBar::Remove

#if wxUSE_ACCEL

void wxMenuBar::RebuildAccelTable()
{
    //
    // Merge the accelerators of all menus into one accel table
    //
    size_t                          nAccelCount = 0;
    size_t                          i;
    size_t                          nCount = GetMenuCount();
    wxMenuList::iterator it;
    for (i = 0, it = m_menus.begin(); i < nCount; i++, it++)
    {
        nAccelCount += (*it)->GetAccelCount();
    }

    if (nAccelCount)
    {
        wxAcceleratorEntry*         pAccelEntries = new wxAcceleratorEntry[nAccelCount];

        nAccelCount = 0;
        for (i = 0, it = m_menus.begin(); i < nCount; i++, it++)
        {
            nAccelCount += (*it)->CopyAccels(&pAccelEntries[nAccelCount]);
        }
        m_vAccelTable = wxAcceleratorTable( nAccelCount
                                           ,pAccelEntries
                                          );
        delete [] pAccelEntries;
    }
} // end of wxMenuBar::RebuildAccelTable

#endif // wxUSE_ACCEL

void wxMenuBar::Attach(
  wxFrame*                          pFrame
)
{
    wxMenuBarBase::Attach(pFrame);

#if wxUSE_ACCEL
    RebuildAccelTable();
    //
    // Ensure the accelerator table is set to the frame (not the client!)
    //
    if (!::WinSetAccelTable( vHabmain
                            ,m_vAccelTable.GetHACCEL()
                            ,(HWND)pFrame->GetFrame()
                           ))
    {
        wxLogLastError(wxT("WinSetAccelTable"));
    }
#endif // wxUSE_ACCEL
} // end of wxMenuBar::Attach

void wxMenuBar::Detach()
{
    ::WinDestroyWindow((HWND)m_hMenu);
    m_hMenu = (WXHMENU)NULL;
    m_menuBarFrame = NULL;
} // end of wxMenuBar::Detach

// ---------------------------------------------------------------------------
// wxMenuBar searching for menu items
// ---------------------------------------------------------------------------

//
// Find the itemString in menuString, and return the item id or wxNOT_FOUND
//
int wxMenuBar::FindMenuItem(
  const wxString&                   rMenuString
, const wxString&                   rItemString
) const
{
    wxString                        sMenuLabel = wxStripMenuCodes(rMenuString);
    size_t                          nCount = GetMenuCount(), i;
    wxMenuList::const_iterator it;
    for (i = 0, it = m_menus.begin(); i < nCount; i++, it++)
    {
        wxString                    sTitle = wxStripMenuCodes(m_titles[i]);

        if (rMenuString == sTitle)
            return (*it)->FindItem(rItemString);
    }
    return wxNOT_FOUND;
} // end of wxMenuBar::FindMenuItem

wxMenuItem* wxMenuBar::FindItem(
  int                               nId
, wxMenu**                          ppItemMenu
) const
{
    if (ppItemMenu)
        *ppItemMenu = NULL;

    wxMenuItem*                     pItem = NULL;
    size_t                          nCount = GetMenuCount(), i;
    wxMenuList::const_iterator it;
    for (i = 0, it = m_menus.begin(); !pItem && (i < nCount); i++, it++)
    {
        pItem = (*it)->FindItem( nId
                                ,ppItemMenu
                               );
    }
    return pItem;
} // end of wxMenuBar::FindItem

wxMenuItem* wxMenuBar::FindItem(
  int                               nId
, ULONG                             hItem
, wxMenu**                          ppItemMenu
) const
{
    if (ppItemMenu)
        *ppItemMenu = NULL;

    wxMenuItem*                     pItem = NULL;
    size_t                          nCount = GetMenuCount(), i;
    wxMenuList::const_iterator it;
    for (i = 0, it = m_menus.begin(); !pItem && (i < nCount); i++, it++)
    {
        pItem = (*it)->FindItem( nId
                                ,hItem
                                ,ppItemMenu
                               );
    }
    return pItem;
} // end of wxMenuBar::FindItem
