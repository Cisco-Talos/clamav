/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/menu.cpp
// Purpose:     wxMenu, wxMenuBar, wxMenuItem
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/menu.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/frame.h"
    #include "wx/settings.h"
    #include "wx/menuitem.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Label.h>
#include <Xm/LabelG.h>
#include <Xm/CascadeBG.h>
#include <Xm/CascadeB.h>
#include <Xm/SeparatoG.h>
#include <Xm/PushBG.h>
#include <Xm/ToggleB.h>
#include <Xm/ToggleBG.h>
#include <Xm/RowColumn.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

// other standard headers
#include <string.h>

IMPLEMENT_DYNAMIC_CLASS(wxMenu, wxEvtHandler)
IMPLEMENT_DYNAMIC_CLASS(wxMenuBar, wxEvtHandler)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// Menus
// ----------------------------------------------------------------------------

// Construct a menu with optional title (then use append)
void wxMenu::Init()
{
    // Motif-specific members
    m_numColumns = 1;
    m_menuWidget = (WXWidget) NULL;
    m_popupShell = (WXWidget) NULL;
    m_buttonWidget = (WXWidget) NULL;
    m_menuId = 0;
    m_topLevelMenu  = NULL;
    m_ownedByMenuBar = false;

    if ( !m_title.empty() )
    {
        Append(-3, m_title) ;
        AppendSeparator() ;
    }
}

// The wxWindow destructor will take care of deleting the submenus.
wxMenu::~wxMenu()
{
    if (m_menuWidget)
    {
        if (m_menuParent)
            DestroyMenu(true);
        else
            DestroyMenu(false);
    }

    // Not sure if this is right
    if (m_menuParent && m_menuBar)
    {
        m_menuParent = NULL;
        //      m_menuBar = NULL;
    }
}

void wxMenu::Break()
{
    m_numColumns++;
}

// function appends a new item or submenu to the menu
wxMenuItem* wxMenu::DoAppend(wxMenuItem *pItem)
{
    return DoInsert(GetMenuItemCount(), pItem);
}

wxMenuItem *wxMenu::DoRemove(wxMenuItem *item)
{
    item->DestroyItem(true);

    return wxMenuBase::DoRemove(item);
}

wxMenuItem* wxMenu::DoInsert(size_t pos, wxMenuItem *item)
{
    if (m_menuWidget)
    {
        // this is a dynamic Append
#ifndef XmNpositionIndex
    wxCHECK_MSG( pos == GetMenuItemCount(), -1, wxT("insert not implemented"));
#endif
        item->CreateItem(m_menuWidget, GetMenuBar(), m_topLevelMenu, pos);
    }

    if ( item->IsSubMenu() )
    {
        item->GetSubMenu()->m_topLevelMenu = m_topLevelMenu;
    }

    return pos == GetMenuItemCount() ? wxMenuBase::DoAppend(item) :
                                       wxMenuBase::DoInsert(pos, item);
}

void wxMenu::SetTitle(const wxString& label)
{
    m_title = label;

    wxMenuItemList::compatibility_iterator node = GetMenuItems().GetFirst();
    if ( !node )
        return;

    wxMenuItem *item = node->GetData ();
    Widget widget = (Widget) item->GetButtonWidget();
    if ( !widget )
        return;

    wxXmString title_str(label);
    XtVaSetValues(widget,
                  XmNlabelString, title_str(),
                  NULL);
}

bool wxMenu::ProcessCommand(wxCommandEvent & event)
{
    // Try the menu's event handler first
    wxEvtHandler * const handler = GetEventHandler();
    bool processed = handler ? handler->SafelyProcessEvent(event) : false;

    // Try the window the menu was popped up from (and up
    // through the hierarchy)
    if ( !processed && GetInvokingWindow())
        processed = GetInvokingWindow()->HandleWindowEvent(event);

    return processed;
}

// ----------------------------------------------------------------------------
// Menu Bar
// ----------------------------------------------------------------------------

void wxMenuBar::Init()
{
    m_eventHandler = this;
    m_menuBarFrame = NULL;
    m_mainWidget = (WXWidget) NULL;
}

wxMenuBar::wxMenuBar(size_t n, wxMenu *menus[], const wxArrayString& titles, long WXUNUSED(style))
{
    wxASSERT( n == titles.GetCount() );

    Init();

    m_titles = titles;
    for ( size_t i = 0; i < n; i++ )
        m_menus.Append(menus[i]);
}

wxMenuBar::wxMenuBar(size_t n, wxMenu *menus[], const wxString titles[], long WXUNUSED(style))
{
    Init();

    for ( size_t i = 0; i < n; i++ )
    {
        m_menus.Append(menus[i]);
        m_titles.Add(titles[i]);
    }
}

wxMenuBar::~wxMenuBar()
{
    // nothing to do: wxMenuBarBase will delete the menus
}

void wxMenuBar::EnableTop(size_t WXUNUSED(pos), bool WXUNUSED(flag))
{
  //    wxFAIL_MSG("TODO");
//  wxLogWarning("wxMenuBar::EnableTop not yet implemented.");
}

void wxMenuBar::SetMenuLabel(size_t pos, const wxString& label)
{
    wxMenu *menu = GetMenu(pos);
    if ( !menu )
        return;

    Widget w = (Widget)menu->GetButtonWidget();
    if (w)
    {
        wxXmString label_str(label);

        XtVaSetValues(w,
                      XmNlabelString, label_str(),
                      NULL);
    }
    m_titles[pos] = label;
}

wxString wxMenuBar::GetMenuLabel(size_t pos) const
{
    wxCHECK_MSG( pos < GetMenuCount(), wxEmptyString,
                 wxT("invalid menu index in wxMenuBar::GetMenuLabel") );
    return m_titles[pos];
}

bool wxMenuBar::Append(wxMenu * menu, const wxString& title)
{
    return Insert(GetMenuCount(), menu, title);
}

bool wxMenuBar::Insert(size_t pos, wxMenu *menu, const wxString& title)
{
    wxCHECK_MSG( pos <= GetMenuCount(), false, wxT("invalid position") );
    wxCHECK_MSG( menu, false, wxT("invalid menu") );
    wxCHECK_MSG( !menu->GetParent() && !menu->GetButtonWidget(), false,
                 wxT("menu already appended") );

    if ( m_menuBarFrame )
    {
        WXWidget w = menu->CreateMenu(this, GetMainWidget(), menu,
                                      pos, title, true);
        wxCHECK_MSG( w, false, wxT("failed to create menu") );
        menu->SetButtonWidget(w);
    }

    m_titles.Insert(title, pos);

    return wxMenuBarBase::Insert(pos, menu, title);
}

wxMenu *wxMenuBar::Replace(size_t pos, wxMenu *menu, const wxString& title)
{
    if ( !wxMenuBarBase::Replace(pos, menu, title) )
        return NULL;

    wxFAIL_MSG(wxT("TODO"));

    return NULL;
}

wxMenu *wxMenuBar::Remove(size_t pos)
{
    wxMenu *menu = wxMenuBarBase::Remove(pos);
    if ( !menu )
        return NULL;

    if ( m_menuBarFrame )
        menu->DestroyMenu(true);

    menu->SetMenuBar(NULL);

    m_titles.RemoveAt(pos);

    return menu;
}

// Find the menu menuString, item itemString, and return the item id.
// Returns -1 if none found.
int wxMenuBar::FindMenuItem(const wxString& menuString, const wxString& itemString) const
{
    const wxString stripped = wxStripMenuCodes(menuString);

    size_t menuCount = GetMenuCount();
    for (size_t i = 0; i < menuCount; i++)
    {
        if ( wxStripMenuCodes(m_titles[i]) == stripped )
            return m_menus.Item(i)->GetData()->FindItem (itemString);
    }
    return wxNOT_FOUND;
}

wxMenuItem *wxMenuBar::FindItem(int id, wxMenu ** itemMenu) const
{
    if (itemMenu)
        *itemMenu = NULL;

    size_t menuCount = GetMenuCount();
    for (size_t i = 0; i < menuCount; i++)
    {
        wxMenuItem *item = m_menus.Item(i)->GetData()->FindItem(id, itemMenu);
        if (item) return item;
    }

    return NULL;
}

// Create menubar
bool wxMenuBar::CreateMenuBar(wxFrame* parent)
{
    m_parent = parent; // bleach... override it!
    PreCreation();
    m_parent = NULL;

    if (m_mainWidget)
    {
        XtVaSetValues((Widget) parent->GetMainWidget(), XmNmenuBar, (Widget) m_mainWidget, NULL);
        /*
        if (!XtIsManaged((Widget) m_mainWidget))
        XtManageChild((Widget) m_mainWidget);
        */
        XtMapWidget((Widget) m_mainWidget);
        return true;
    }

    Widget menuBarW = XmCreateMenuBar ((Widget) parent->GetMainWidget(),
                                       wxMOTIF_STR("MenuBar"), NULL, 0);
    m_mainWidget = (WXWidget) menuBarW;

    size_t menuCount = GetMenuCount();
    for (size_t i = 0; i < menuCount; i++)
    {
        wxMenu *menu = GetMenu(i);
        wxString title(m_titles[i]);
        menu->SetButtonWidget(menu->CreateMenu (this, menuBarW, menu, i, title, true));

        if (strcmp (wxStripMenuCodes(title), "Help") == 0)
            XtVaSetValues ((Widget) menuBarW, XmNmenuHelpWidget, (Widget) menu->GetButtonWidget(), NULL);

        // tear off menu support
#if (XmVersion >= 1002)
        if ( menu->IsTearOff() )
        {
            XtVaSetValues(GetWidget(menu),
                          XmNtearOffModel, XmTEAR_OFF_ENABLED,
                          NULL);
            Widget tearOff = XmGetTearOffControl(GetWidget(menu));
            wxDoChangeForegroundColour((Widget) tearOff, m_foregroundColour);
            wxDoChangeBackgroundColour((Widget) tearOff, m_backgroundColour, true);
        }
#endif
    }

    PostCreation();

    XtVaSetValues((Widget) parent->GetMainWidget(), XmNmenuBar, (Widget) m_mainWidget, NULL);
    XtRealizeWidget ((Widget) menuBarW);
    XtManageChild ((Widget) menuBarW);
    SetMenuBarFrame(parent);

    return true;
}

// Destroy menubar, but keep data structures intact so we can recreate it.
bool wxMenuBar::DestroyMenuBar()
{
    if (!m_mainWidget)
    {
        SetMenuBarFrame(NULL);
        return false;
    }

    XtUnmanageChild ((Widget) m_mainWidget);
    XtUnrealizeWidget ((Widget) m_mainWidget);

    size_t menuCount = GetMenuCount();
    for (size_t i = 0; i < menuCount; i++)
    {
        wxMenu *menu = GetMenu(i);
        menu->DestroyMenu(true);

    }
    XtDestroyWidget((Widget) m_mainWidget);
    m_mainWidget = (WXWidget) 0;

    SetMenuBarFrame(NULL);

    return true;
}

// Since PopupMenu under Motif stills grab right mouse button events
// after it was closed, we need to delete the associated widgets to
// allow next PopUpMenu to appear...
void wxMenu::DestroyWidgetAndDetach()
{
    if (GetMainWidget())
    {
        wxMenu *menuParent = GetParent();
        if ( menuParent )
        {
            wxMenuItemList::compatibility_iterator node = menuParent->GetMenuItems().GetFirst();
            while ( node )
            {
                if ( node->GetData()->GetSubMenu() == this )
                {
                    delete node->GetData();
                    menuParent->GetMenuItems().Erase(node);

                    break;
                }

                node = node->GetNext();
            }
        }

        DestroyMenu(true);
    }

    // Mark as no longer popped up
    m_menuId = -1;
}

/*
* Create a popup or pulldown menu.
* Submenus of a popup will be pulldown.
*
*/

WXWidget wxMenu::CreateMenu (wxMenuBar * menuBar,
                             WXWidget parent,
                             wxMenu * topMenu,
                             size_t menuIndex,
                             const wxString& title,
                             bool pullDown)
{
    Widget menu = (Widget) 0;
    Widget buttonWidget = (Widget) 0;
    Display* dpy = XtDisplay((Widget)parent);
    Arg args[5];
    XtSetArg (args[0], XmNnumColumns, m_numColumns);
    XtSetArg (args[1], XmNpacking, (m_numColumns > 1) ? XmPACK_COLUMN : XmPACK_TIGHT);

    if ( !m_font.Ok() )
    {
        if ( menuBar )
            m_font = menuBar->GetFont();
        else if ( GetInvokingWindow() )
            m_font = GetInvokingWindow()->GetFont();
    }

    XtSetArg (args[2], (String)wxFont::GetFontTag(), m_font.GetFontTypeC(dpy) );

    if (!pullDown)
    {
        menu = XmCreatePopupMenu ((Widget) parent, wxMOTIF_STR("popup"), args, 3);
#if 0
        XtAddCallback(menu,
            XmNunmapCallback,
            (XtCallbackProc)wxMenuPopdownCallback,
            (XtPointer)this);
#endif
    }
    else
    {
        char mnem = wxFindMnemonic (title);
        menu = XmCreatePulldownMenu ((Widget) parent, wxMOTIF_STR("pulldown"), args, 3);

        wxString title2(wxStripMenuCodes(title));
        wxXmString label_str(title2);
        buttonWidget = XtVaCreateManagedWidget(title2,
#if wxUSE_GADGETS
            xmCascadeButtonGadgetClass, (Widget) parent,
#else
            xmCascadeButtonWidgetClass, (Widget) parent,
#endif
            XmNlabelString, label_str(),
            XmNsubMenuId, menu,
            (String)wxFont::GetFontTag(), m_font.GetFontTypeC(dpy),
            XmNpositionIndex, menuIndex,
            NULL);

        if (mnem != 0)
            XtVaSetValues (buttonWidget, XmNmnemonic, mnem, NULL);
    }

    m_menuWidget = (WXWidget) menu;

    m_topLevelMenu = topMenu;

    size_t i = 0;
    for ( wxMenuItemList::compatibility_iterator node = GetMenuItems().GetFirst();
          node;
          node = node->GetNext(), ++i )
    {
        wxMenuItem *item = node->GetData();

        item->CreateItem(menu, menuBar, topMenu, i);
    }

    ChangeFont();

    return buttonWidget;
}

// Destroys the Motif implementation of the menu,
// but maintains the wxWidgets data structures so we can
// do a CreateMenu again.
void wxMenu::DestroyMenu (bool full)
{
    for ( wxMenuItemList::compatibility_iterator node = GetMenuItems().GetFirst();
          node;
          node = node->GetNext() )
    {
        wxMenuItem *item = node->GetData();
        item->SetMenuBar(NULL);

        item->DestroyItem(full);
    }

    if (m_buttonWidget)
    {
        if (full)
        {
            XtVaSetValues((Widget) m_buttonWidget, XmNsubMenuId, NULL, NULL);
            XtDestroyWidget ((Widget) m_buttonWidget);
            m_buttonWidget = (WXWidget) 0;
        }
    }
    if (m_menuWidget && full)
    {
        XtDestroyWidget((Widget) m_menuWidget);
        m_menuWidget = (WXWidget) NULL;
    }
}

WXWidget wxMenu::FindMenuItem (int id, wxMenuItem ** it) const
{
    if (id == m_menuId)
    {
        if (it)
            *it = NULL;
        return m_buttonWidget;
    }

    for ( wxMenuItemList::compatibility_iterator node = GetMenuItems().GetFirst();
          node;
          node = node->GetNext() )
    {
        wxMenuItem *item = node->GetData ();
        if (item->GetId() == id)
        {
            if (it)
                *it = item;
            return item->GetButtonWidget();
        }

        if (item->GetSubMenu())
        {
            WXWidget w = item->GetSubMenu()->FindMenuItem (id, it);
            if (w)
            {
                return w;
            }
        }
    }

    if (it)
        *it = NULL;
    return (WXWidget) NULL;
}

void wxMenu::SetBackgroundColour(const wxColour& col)
{
    m_backgroundColour = col;
    if (!col.Ok())
        return;
    if (m_menuWidget)
        wxDoChangeBackgroundColour(m_menuWidget, (wxColour&) col);
    if (m_buttonWidget)
        wxDoChangeBackgroundColour(m_buttonWidget, (wxColour&) col, true);

    for ( wxMenuItemList::compatibility_iterator node = GetMenuItems().GetFirst();
          node;
          node = node->GetNext() )
    {
        wxMenuItem* item = node->GetData();
        if (item->GetButtonWidget())
        {
            // This crashes because it uses gadgets
            //            wxDoChangeBackgroundColour(item->GetButtonWidget(), (wxColour&) col, true);
        }
        if (item->GetSubMenu())
            item->GetSubMenu()->SetBackgroundColour((wxColour&) col);
    }
}

void wxMenu::SetForegroundColour(const wxColour& col)
{
    m_foregroundColour = col;
    if (!col.Ok())
        return;
    if (m_menuWidget)
        wxDoChangeForegroundColour(m_menuWidget, (wxColour&) col);
    if (m_buttonWidget)
        wxDoChangeForegroundColour(m_buttonWidget, (wxColour&) col);

    for ( wxMenuItemList::compatibility_iterator node = GetMenuItems().GetFirst();
          node;
          node = node->GetNext() )
    {
        wxMenuItem* item = node->GetData();
        if (item->GetButtonWidget())
        {
            // This crashes because it uses gadgets
            //            wxDoChangeForegroundColour(item->GetButtonWidget(), (wxColour&) col);
        }
        if (item->GetSubMenu())
            item->GetSubMenu()->SetForegroundColour((wxColour&) col);
    }
}

void wxMenu::ChangeFont(bool keepOriginalSize)
{
    // Lesstif 0.87 hangs here, but 0.93 does not; MBN: sometimes it does
#if !wxCHECK_LESSTIF() // || wxCHECK_LESSTIF_VERSION( 0, 93 )
    if (!m_font.Ok() || !m_menuWidget)
        return;

    Display* dpy = XtDisplay((Widget) m_menuWidget);

    XtVaSetValues ((Widget) m_menuWidget,
                   wxFont::GetFontTag(), m_font.GetFontTypeC(dpy),
                   NULL);
    if (m_buttonWidget)
    {
        XtVaSetValues ((Widget) m_buttonWidget,
                       wxFont::GetFontTag(), m_font.GetFontTypeC(dpy),
                       NULL);
    }

    for ( wxMenuItemList::compatibility_iterator node = GetMenuItems().GetFirst();
          node;
          node = node->GetNext() )
    {
        wxMenuItem* item = node->GetData();
        if (m_menuWidget && item->GetButtonWidget() && m_font.Ok())
        {
            XtVaSetValues ((Widget) item->GetButtonWidget(),
                           wxFont::GetFontTag(), m_font.GetFontTypeC(dpy),
                           NULL);
        }
        if (item->GetSubMenu())
            item->GetSubMenu()->ChangeFont(keepOriginalSize);
    }
#else
    wxUnusedVar(keepOriginalSize);
#endif
}

void wxMenu::SetFont(const wxFont& font)
{
    m_font = font;
    ChangeFont();
}

bool wxMenuBar::SetBackgroundColour(const wxColour& col)
{
    if (!wxWindowBase::SetBackgroundColour(col))
        return false;
    if (!col.Ok())
        return false;
    if (m_mainWidget)
        wxDoChangeBackgroundColour(m_mainWidget, (wxColour&) col);

    size_t menuCount = GetMenuCount();
    for (size_t i = 0; i < menuCount; i++)
        m_menus.Item(i)->GetData()->SetBackgroundColour((wxColour&) col);

    return true;
}

bool wxMenuBar::SetForegroundColour(const wxColour& col)
{
    if (!wxWindowBase::SetForegroundColour(col))
        return false;
    if (!col.Ok())
        return false;
    if (m_mainWidget)
        wxDoChangeForegroundColour(m_mainWidget, (wxColour&) col);

    size_t menuCount = GetMenuCount();
    for (size_t i = 0; i < menuCount; i++)
        m_menus.Item(i)->GetData()->SetForegroundColour((wxColour&) col);

    return true;
}

void wxMenuBar::ChangeFont(bool WXUNUSED(keepOriginalSize))
{
    // Nothing to do for menubar, fonts are kept in wxMenus
}

bool wxMenuBar::SetFont(const wxFont& font)
{
    m_font = font;
    ChangeFont();

    size_t menuCount = GetMenuCount();
    for (size_t i = 0; i < menuCount; i++)
        m_menus.Item(i)->GetData()->SetFont(font);

    return true;
}
