///////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/menuitem.cpp
// Purpose:     wxMenuItem implementation
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/menuitem.h"
#include "wx/stockitem.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/frame.h"
    #include "wx/menu.h"
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

// ----------------------------------------------------------------------------
// functions prototypes
// ----------------------------------------------------------------------------

static void wxMenuItemCallback(Widget w, XtPointer clientData, XtPointer ptr);
static void wxMenuItemArmCallback(Widget w, XtPointer clientData, XtPointer ptr);
static void wxMenuItemDisarmCallback(Widget w, XtPointer clientData, XtPointer ptr);

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// dynamic classes implementation
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxMenuItem, wxObject)

// ----------------------------------------------------------------------------
// wxMenuItem
// ----------------------------------------------------------------------------

// ctor & dtor
// -----------

wxMenuItem::wxMenuItem(wxMenu *pParentMenu,
                       int id,
                       const wxString& strName,
                       const wxString& strHelp,
                       wxItemKind kind,
                       wxMenu *pSubMenu)
          : wxMenuItemBase(pParentMenu, id, strName, strHelp, kind, pSubMenu)
{
    // Motif-specific
    m_menuBar      = NULL;
    m_buttonWidget = (WXWidget) NULL;
    m_topMenu      = NULL;
}

wxMenuItem::~wxMenuItem()
{
}

// change item state
// -----------------

void wxMenuItem::Enable(bool bDoEnable)
{
    if ( m_isEnabled != bDoEnable )
    {
        if ( !IsSubMenu() )
        {
            // normal menu item
            if (m_buttonWidget)
                XtSetSensitive( (Widget) m_buttonWidget, (Boolean) bDoEnable);
        }
        else                            // submenu
        {
            // Maybe we should apply this to all items in the submenu?
            // Or perhaps it works anyway.
            if (m_buttonWidget)
                XtSetSensitive( (Widget) m_buttonWidget, (Boolean) bDoEnable);
        }

        wxMenuItemBase::Enable(bDoEnable);
    }
}

void wxMenuItem::Check(bool bDoCheck)
{
    wxCHECK_RET( IsCheckable(), "only checkable items may be checked" );

    if ( m_isChecked != bDoCheck )
    {
        if ( m_buttonWidget )
        {
            wxASSERT_MSG( XtIsSubclass((Widget)m_buttonWidget,
                                       xmToggleButtonGadgetClass),
                          wxT("checkable menu item must be a toggle button") );

            XtVaSetValues((Widget)m_buttonWidget,
                          XmNset, (Boolean)bDoCheck,
                          NULL);
        }

        wxMenuItemBase::Check(bDoCheck);
    }
}

// ----------------------------------------------------------------------------
// wxMenuItemBase
// ----------------------------------------------------------------------------

wxMenuItem *wxMenuItemBase::New(wxMenu *parentMenu,
                                int id,
                                const wxString& name,
                                const wxString& help,
                                wxItemKind kind,
                                wxMenu *subMenu)
{
    return new wxMenuItem(parentMenu, id, name, help, kind, subMenu);
}

// ----------------------------------------------------------------------------
// Motif-specific
// ----------------------------------------------------------------------------

void wxMenuItem::CreateItem (WXWidget menu, wxMenuBar * menuBar,
                             wxMenu * topMenu, size_t index)
{
    m_menuBar = menuBar;
    m_topMenu = topMenu;

    if (GetId() == -3)
    {
        // Id=-3 identifies a Title item.
        m_buttonWidget = (WXWidget) XtVaCreateManagedWidget
            (wxStripMenuCodes(m_text),
            xmLabelGadgetClass, (Widget) menu, NULL);
    }
    else if (!IsSeparator() && !m_subMenu)
    {
        wxString txt = m_text;

        if (m_text.IsEmpty())
        {
            wxASSERT_MSG(wxIsStockID(GetId()), wxT("A non-stock menu item with an empty label?"));
            txt = wxGetStockLabel(GetId(), wxSTOCK_WITH_ACCELERATOR|wxSTOCK_WITH_MNEMONIC);
        }

        wxString strName = wxStripMenuCodes(txt);
        if (IsCheckable())
        {
            m_buttonWidget = (WXWidget) XtVaCreateManagedWidget (strName,
                xmToggleButtonGadgetClass, (Widget) menu,
#ifdef XmNpositionIndex
                XmNpositionIndex, index,
#endif
                NULL);
            XtVaSetValues ((Widget) m_buttonWidget, XmNset, (Boolean) IsChecked(), NULL);
        }
        else
            m_buttonWidget = (WXWidget) XtVaCreateManagedWidget (strName,
            xmPushButtonGadgetClass, (Widget) menu,
#ifdef XmNpositionIndex
            XmNpositionIndex, index,
#endif
            NULL);
        char mnem = wxFindMnemonic (m_text);
        if (mnem != 0)
            XtVaSetValues ((Widget) m_buttonWidget, XmNmnemonic, mnem, NULL);

        //// TODO: proper accelerator treatment. What does wxFindAccelerator
        //// look for?
        strName = m_text;
        char *accel = wxFindAccelerator (strName);
        if (accel)
            XtVaSetValues ((Widget) m_buttonWidget, XmNaccelerator, accel, NULL);

        // TODO: What does this do?
        XmString accel_str = wxFindAcceleratorText (strName);
        if (accel_str)
        {
            XtVaSetValues ((Widget) m_buttonWidget, XmNacceleratorText, accel_str, NULL);
            XmStringFree (accel_str);
        }

        if (IsCheckable())
            XtAddCallback ((Widget) m_buttonWidget,
            XmNvalueChangedCallback,
            (XtCallbackProc) wxMenuItemCallback,
            (XtPointer) this);
        else
            XtAddCallback ((Widget) m_buttonWidget,
            XmNactivateCallback,
            (XtCallbackProc) wxMenuItemCallback,
            (XtPointer) this);
        XtAddCallback ((Widget) m_buttonWidget,
            XmNarmCallback,
            (XtCallbackProc) wxMenuItemArmCallback,
            (XtPointer) this);
        XtAddCallback ((Widget) m_buttonWidget,
            XmNdisarmCallback,
            (XtCallbackProc) wxMenuItemDisarmCallback,
            (XtPointer) this);
    }
    else if (IsSeparator())
    {
        m_buttonWidget = (WXWidget) XtVaCreateManagedWidget ("separator",
            xmSeparatorGadgetClass, (Widget) menu,
#ifndef XmNpositionIndex
            XmNpositionIndex, index,
#endif
            NULL);
    }
    else if (m_subMenu)
    {
        m_buttonWidget = m_subMenu->CreateMenu (menuBar, menu, topMenu, index, m_text, true);
        m_subMenu->SetButtonWidget(m_buttonWidget);
        XtAddCallback ((Widget) m_buttonWidget,
            XmNcascadingCallback,
            (XtCallbackProc) wxMenuItemArmCallback,
            (XtPointer) this);
    }
    if (m_buttonWidget)
        XtSetSensitive ((Widget) m_buttonWidget, (Boolean) IsEnabled());
}

void wxMenuItem::DestroyItem(bool full)
{
    if (GetId() == -3)
    {
        ;      // Nothing

    }
    else if (!m_text.empty() && !m_subMenu)
    {
        if (m_buttonWidget)
        {
            if (IsCheckable())
                XtRemoveCallback ((Widget) m_buttonWidget, XmNvalueChangedCallback,
                wxMenuItemCallback, (XtPointer) this);
            else
                XtRemoveCallback ((Widget) m_buttonWidget, XmNactivateCallback,
                wxMenuItemCallback, (XtPointer) this);
            XtRemoveCallback ((Widget) m_buttonWidget, XmNarmCallback,
                wxMenuItemArmCallback, (XtPointer) this);
            XtRemoveCallback ((Widget) m_buttonWidget, XmNdisarmCallback,
                wxMenuItemDisarmCallback, (XtPointer) this);
        }
    }
    else if (IsSeparator())
    {
        ;      // Nothing

    }
    else if (GetSubMenu())
    {
        if (m_buttonWidget)
        {
            XtRemoveCallback ((Widget) m_buttonWidget, XmNcascadingCallback,
                wxMenuItemArmCallback, (XtPointer) this);
        }
        m_subMenu->DestroyMenu(full);
        if (full)
            m_buttonWidget = NULL;
    }

    if (m_buttonWidget && full)
    {
        XtDestroyWidget ((Widget) m_buttonWidget);
        m_buttonWidget = (WXWidget) 0;
    }
}

void wxMenuItem::SetItemLabel(const wxString& label)
{
    char mnem = wxFindMnemonic (label);
    wxString label2 = wxStripMenuCodes(label);

    m_text = label;

    if (m_buttonWidget)
    {
        wxXmString label_str(label2);
        XtVaSetValues ((Widget) m_buttonWidget,
            XmNlabelString, label_str(),
            NULL);
        if (mnem != 0)
            XtVaSetValues ((Widget) m_buttonWidget, XmNmnemonic, mnem, NULL);
        char *accel = wxFindAccelerator (label2);
        if (accel)
            XtVaSetValues ((Widget) m_buttonWidget, XmNaccelerator, accel, NULL);

        XmString accel_str = wxFindAcceleratorText (label2);
        if (accel_str)
        {
            XtVaSetValues ((Widget) m_buttonWidget, XmNacceleratorText, accel_str, NULL);
            XmStringFree (accel_str);
        }
    }
}

// ----------------------------------------------------------------------------
// Motif callbacks
// ----------------------------------------------------------------------------

void wxMenuItemCallback (Widget WXUNUSED(w), XtPointer clientData,
                         XtPointer WXUNUSED(ptr))
{
    wxMenuItem *item = (wxMenuItem *) clientData;
    if (item)
    {
        wxCommandEvent event(wxEVT_COMMAND_MENU_SELECTED, item->GetId());
        event.SetInt( item->GetId() );

        if (item->IsCheckable())
        {
            Boolean isChecked = false;
            XtVaGetValues ((Widget) item->GetButtonWidget(),
                           XmNset, & isChecked,
                           NULL);

            // only set the flag, don't actually check anything
            item->wxMenuItemBase::Check(isChecked);
            event.SetInt(isChecked);
        }

        if (item->GetMenuBar() && item->GetMenuBar()->GetMenuBarFrame())
        {
            event.SetEventObject(item->GetMenuBar()->GetMenuBarFrame());

            item->GetMenuBar()->GetMenuBarFrame()
                ->HandleWindowEvent(event);
        }
        // this is the child of a popup menu
        else if (item->GetTopMenu())
        {
            event.SetEventObject(item->GetTopMenu());

            item->GetTopMenu()->ProcessCommand (event);

            // Since PopupMenu under Motif still grab right mouse
            // button events after it was closed, we need to delete
            // the associated widgets to allow next PopUpMenu to
            // appear; this needs to be done there because doing it in
            // a WorkProc as before may cause crashes if a menu item causes
            // the parent window of the menu to be destroyed
            item->GetTopMenu()->DestroyWidgetAndDetach();
        }
    }
}

void wxMenuItemArmCallback (Widget WXUNUSED(w), XtPointer clientData,
                       XtPointer WXUNUSED(ptr))
{
    wxMenuItem *item = (wxMenuItem *) clientData;
    if (item)
    {
        if (item->GetMenuBar() && item->GetMenuBar()->GetMenuBarFrame())
        {
            wxMenuEvent menuEvent(wxEVT_MENU_HIGHLIGHT, item->GetId());
            menuEvent.SetEventObject(item->GetMenuBar()->GetMenuBarFrame());

            item->GetMenuBar()->GetMenuBarFrame()
                ->HandleWindowEvent(menuEvent);
        }
    }
}

void
wxMenuItemDisarmCallback (Widget WXUNUSED(w), XtPointer clientData,
                          XtPointer WXUNUSED(ptr))
{
    wxMenuItem *item = (wxMenuItem *) clientData;
    if (item)
    {
        if (item->GetMenuBar() && item->GetMenuBar()->GetMenuBarFrame())
        {
            // TODO: not sure this is correct, since -1 means something
            // special to event system
            wxMenuEvent menuEvent(wxEVT_MENU_HIGHLIGHT, -1);
            menuEvent.SetEventObject(item->GetMenuBar()->GetMenuBarFrame());

            item->GetMenuBar()->GetMenuBarFrame()
                ->HandleWindowEvent(menuEvent);
        }
    }
}
