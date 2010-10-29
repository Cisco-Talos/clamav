/////////////////////////////////////////////////////////////////////////
// File:        src/osx/cocoa/taskbar.mm
// Purpose:     Implements wxTaskBarIcon class
// Author:      David Elliott
// Modified by:
// Created:     2004/01/24
// RCS-ID:      $Id: taskbar.mm 35650 2005-09-23 12:56:45Z MR $
// Copyright:   (c) 2004 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"
#if wxUSE_TASKBARICON

#ifndef WX_PRECOMP
    #include "wx/menu.h"
    #include "wx/icon.h"
    #include "wx/log.h"
    #include "wx/dcclient.h"
#endif

#include "wx/taskbar.h"

#include "wx/osx/private.h"

// A category for methods that are only present in Panther's SDK
@interface NSStatusItem(wxNSStatusItemPrePantherCompatibility)
- (void)popUpStatusItemMenu:(NSMenu *)menu;
@end

class wxTaskBarIconWindow;

// ============================================================================
// wxTaskBarIconImpl
//     Base class for the various Cocoa implementations.
// ============================================================================
class wxTaskBarIconImpl
{
public:
    wxTaskBarIconImpl(wxTaskBarIcon *taskBarIcon)
    :   m_taskBarIcon(taskBarIcon)
    ,   m_iconWindow(NULL)
    {}
    virtual bool SetIcon(const wxIcon& icon, const wxString& tooltip = wxEmptyString) = 0;
    virtual bool RemoveIcon() = 0;
    virtual bool PopupMenu(wxMenu *menu) = 0;
    virtual ~wxTaskBarIconImpl();
    inline wxTaskBarIcon* GetTaskBarIcon() { return m_taskBarIcon; }
    wxMenu * CreatePopupMenu()
    { return m_taskBarIcon->CreatePopupMenu(); }

    wxDECLARE_NO_COPY_CLASS(wxTaskBarIconImpl);

protected:
    wxTaskBarIcon *m_taskBarIcon;
    wxTaskBarIconWindow *m_iconWindow;
private:
    wxTaskBarIconImpl();
};

// ============================================================================
// wxTaskBarIconDockImpl
//     An implementation using the Dock icon.
// ============================================================================
class wxTaskBarIconDockImpl: public wxTaskBarIconImpl
{
public:
    wxTaskBarIconDockImpl(wxTaskBarIcon *taskBarIcon);
    virtual ~wxTaskBarIconDockImpl();
    virtual bool SetIcon(const wxIcon& icon, const wxString& tooltip = wxEmptyString);
    virtual bool RemoveIcon();
    virtual bool PopupMenu(wxMenu *menu);

    static WX_NSMenu CocoaGetDockNSMenu();
protected:
    WX_NSMenu CocoaDoGetDockNSMenu();
    WX_NSImage m_originalDockIcon;
    // There can be only one Dock icon, so make sure we keep it that way
    static wxTaskBarIconDockImpl *sm_dockIcon;
private:
    wxTaskBarIconDockImpl();
};

// ============================================================================
// wxTaskBarIconCustomStatusItemImpl
//     An implementation using an NSStatusItem with a custom NSView
// ============================================================================
class wxTaskBarIconCustomStatusItemImpl: public wxTaskBarIconImpl
{
public:
    wxTaskBarIconCustomStatusItemImpl(wxTaskBarIcon *taskBarIcon);
    virtual ~wxTaskBarIconCustomStatusItemImpl();
    virtual bool SetIcon(const wxIcon& icon, const wxString& tooltip = wxEmptyString);
    virtual bool RemoveIcon();
    virtual bool PopupMenu(wxMenu *menu);
protected:
    NSStatusItem *m_cocoaNSStatusItem;
private:
    wxTaskBarIconCustomStatusItemImpl();
};

// ============================================================================
// wxTaskBarIconWindow
//     Used by all implementations to forward events from the wxMenu
// ============================================================================
class wxTaskBarIconWindow: public wxWindow
{
    DECLARE_EVENT_TABLE()
public:
    wxTaskBarIconWindow(wxTaskBarIconImpl *taskBarIconImpl)
    :   wxWindow(NULL,-1)
    ,   m_taskBarIconImpl(taskBarIconImpl)
    {   wxASSERT(m_taskBarIconImpl); }

    void OnMenuEvent(wxCommandEvent& event);
protected:
    wxTaskBarIconImpl *m_taskBarIconImpl;
};

// ============================================================================
// wxTaskBarIconWindowCustom
//     Used by the CustomStatusIcon implementation for the custom NSView.
// ============================================================================
class wxTaskBarIconWindowCustom: public wxTaskBarIconWindow
{
    DECLARE_EVENT_TABLE()
public:
    wxTaskBarIconWindowCustom(wxTaskBarIconImpl *taskBarIconImpl)
    :   wxTaskBarIconWindow(taskBarIconImpl)
    {}
    void SetIcon(const wxIcon& icon)
    {   m_icon = icon; }
    void OnMouseEvent(wxMouseEvent &event);
    void OnPaint(wxPaintEvent &event);
protected:
    wxIcon m_icon;
};

// ============================================================================
// wxTaskBarIcon implementation
//     The facade class.
// ============================================================================
IMPLEMENT_DYNAMIC_CLASS(wxTaskBarIcon, wxEvtHandler)

wxTaskBarIcon::wxTaskBarIcon(wxTaskBarIconType iconType)
{
    if(iconType == DOCK)
        m_impl = new wxTaskBarIconDockImpl(this);
    else if(iconType == CUSTOM_STATUSITEM)
        m_impl = new wxTaskBarIconCustomStatusItemImpl(this);
    else
    {   m_impl = NULL;
        wxFAIL_MSG(wxT("Invalid wxTaskBarIcon type"));
    }
}

wxTaskBarIcon::~wxTaskBarIcon()
{
    delete m_impl;
}

// Operations

bool wxTaskBarIcon::IsIconInstalled() const
{
    return false;
}

bool wxTaskBarIcon::SetIcon(const wxIcon& icon, const wxString& tooltip)
{
    return m_impl->SetIcon(icon,tooltip);
}

bool wxTaskBarIcon::RemoveIcon()
{
    return m_impl->RemoveIcon();
}

bool wxTaskBarIcon::PopupMenu(wxMenu *menu)
{
    return m_impl->PopupMenu(menu);
}

// ============================================================================
// wxTaskBarIconImpl
// ============================================================================

wxTaskBarIconImpl::~wxTaskBarIconImpl()
{
//    wxAutoNSAutoreleasePool pool;
    delete m_iconWindow;
}

// ============================================================================
// wxTaskBarIconDockImpl
// ============================================================================
wxTaskBarIconDockImpl *wxTaskBarIconDockImpl::sm_dockIcon = NULL;

wxTaskBarIconDockImpl::wxTaskBarIconDockImpl(wxTaskBarIcon *taskBarIcon)
:   wxTaskBarIconImpl(taskBarIcon)
{
    m_originalDockIcon = nil;
    wxASSERT_MSG(!sm_dockIcon, wxT("You should never have more than one dock icon!"));
    sm_dockIcon = this;
}

wxTaskBarIconDockImpl::~wxTaskBarIconDockImpl()
{
//    wxAutoNSAutoreleasePool pool;
    if(sm_dockIcon == this)
        sm_dockIcon = NULL;
}

WX_NSMenu wxTaskBarIconDockImpl::CocoaGetDockNSMenu()
{
    if(sm_dockIcon)
        return sm_dockIcon->CocoaDoGetDockNSMenu();
    return nil;
}

WX_NSMenu wxTaskBarIconDockImpl::CocoaDoGetDockNSMenu()
{
    wxMenu *dockMenu = CreatePopupMenu();
    if(!dockMenu)
        return nil;
    if(!m_iconWindow)
        m_iconWindow = new wxTaskBarIconWindow(this);
    dockMenu->SetInvokingWindow(m_iconWindow);
    dockMenu->UpdateUI();
    //dockMenu->SetCocoaDeletes(true);
    return (WX_NSMenu)dockMenu->GetHMenu();
}

bool wxTaskBarIconDockImpl::SetIcon(const wxIcon& WXUNUSED(icon), const wxString& WXUNUSED(tooltip))
{
    wxMacAutoreleasePool pool;
    m_originalDockIcon = [[[NSApplication sharedApplication] applicationIconImage] retain];
    //[[NSApplication sharedApplication] setApplicationIconImage:icon.GetNSImage()];
    return true;
}

bool wxTaskBarIconDockImpl::RemoveIcon()
{
    [[NSApplication sharedApplication] setApplicationIconImage:m_originalDockIcon];
    [m_originalDockIcon release];
    return true;
}

bool wxTaskBarIconDockImpl::PopupMenu(wxMenu *WXUNUSED(menu))
{
    wxFAIL_MSG(wxT("You cannot force the Dock icon menu to popup"));
    return false;
}


// ============================================================================
// wxTaskBarIconCustomStatusItemImpl
// ============================================================================
wxTaskBarIconCustomStatusItemImpl::wxTaskBarIconCustomStatusItemImpl(wxTaskBarIcon *taskBarIcon)
:   wxTaskBarIconImpl(taskBarIcon)
{
    m_cocoaNSStatusItem = nil;
}

wxTaskBarIconCustomStatusItemImpl::~wxTaskBarIconCustomStatusItemImpl()
{
}

bool wxTaskBarIconCustomStatusItemImpl::SetIcon(const wxIcon& icon, const wxString& WXUNUSED(tooltip))
{
    wxMacAutoreleasePool pool;
    if(!m_cocoaNSStatusItem)
    {
        m_cocoaNSStatusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
        [m_cocoaNSStatusItem retain];
    }
    if(!m_iconWindow)
        m_iconWindow= new wxTaskBarIconWindowCustom(this);
    static_cast<wxTaskBarIconWindowCustom*>(m_iconWindow)->SetIcon(icon);
    // FIXME: no less than 10 because most icon types don't work yet
    // and this allows us to see how task bar icons would work
    [(NSView*)m_iconWindow->GetHandle() setFrame:NSMakeRect(0.0,0.0,wxMax(10,icon.GetWidth()),[[NSStatusBar systemStatusBar] thickness])];
    [m_cocoaNSStatusItem setView:(NSView*)m_iconWindow->GetHandle()];
    return true;
}

bool wxTaskBarIconCustomStatusItemImpl::RemoveIcon()
{
    [m_cocoaNSStatusItem release];
    m_cocoaNSStatusItem = nil;
    delete m_iconWindow;
    m_iconWindow = NULL;
    return true;
}

bool wxTaskBarIconCustomStatusItemImpl::PopupMenu(wxMenu *menu)
{
    wxASSERT(menu);
    menu->SetInvokingWindow(m_iconWindow);
    menu->UpdateUI();

    if([m_cocoaNSStatusItem respondsToSelector:@selector(popUpStatusItemMenu:)])
    {   // OS X >= 10.3
        [m_cocoaNSStatusItem popUpStatusItemMenu:(NSMenu*)menu->GetHMenu()];
    }
    else
    {   // pretty good fake for OS X < 10.3
        NSEvent *nsevent = [NSEvent mouseEventWithType:NSLeftMouseDown
            location:NSMakePoint(-1.0,-4.0) modifierFlags:0 timestamp:0
            windowNumber:[[(NSView*)m_iconWindow->GetHandle() window] windowNumber]
            context:[NSGraphicsContext currentContext]
            eventNumber:0 clickCount:1 pressure:0.0];
        [NSMenu popUpContextMenu:menu->GetHMenu() withEvent:nsevent forView:(NSView*)m_iconWindow->GetHandle()];
    }
    menu->SetInvokingWindow(NULL);
    return true;
}

// ============================================================================
// wxTaskBarIconWindow
// ============================================================================
BEGIN_EVENT_TABLE(wxTaskBarIconWindow, wxWindow)
    EVT_MENU(-1, wxTaskBarIconWindow::OnMenuEvent)
END_EVENT_TABLE()

void wxTaskBarIconWindow::OnMenuEvent(wxCommandEvent &event)
{
    m_taskBarIconImpl->GetTaskBarIcon()->ProcessEvent(event);
}

// ============================================================================
// wxTaskBarIconWindowCustom
// ============================================================================
BEGIN_EVENT_TABLE(wxTaskBarIconWindowCustom, wxTaskBarIconWindow)
    EVT_MOUSE_EVENTS(wxTaskBarIconWindowCustom::OnMouseEvent)
    EVT_PAINT(wxTaskBarIconWindowCustom::OnPaint)
END_EVENT_TABLE()

void wxTaskBarIconWindowCustom::OnMouseEvent(wxMouseEvent &event)
{
    wxEventType tbEventType = 0;
    if(event.GetEventType() == wxEVT_MOTION)
        tbEventType = wxEVT_TASKBAR_MOVE;
    else if(event.GetEventType() == wxEVT_LEFT_DOWN)
        tbEventType = wxEVT_TASKBAR_LEFT_DOWN;
    else if(event.GetEventType() == wxEVT_LEFT_UP)
        tbEventType = wxEVT_TASKBAR_LEFT_UP;
    else if(event.GetEventType() == wxEVT_RIGHT_DOWN)
        tbEventType = wxEVT_TASKBAR_RIGHT_DOWN;
    else if(event.GetEventType() == wxEVT_RIGHT_UP)
        tbEventType = wxEVT_TASKBAR_RIGHT_UP;
    else if(event.GetEventType() == wxEVT_LEFT_DCLICK)
        tbEventType = wxEVT_TASKBAR_LEFT_DCLICK;
    else if(event.GetEventType() == wxEVT_RIGHT_DCLICK)
        tbEventType = wxEVT_TASKBAR_RIGHT_DCLICK;
    else
        return;
    wxTaskBarIconEvent tbiEvent(tbEventType,m_taskBarIconImpl->GetTaskBarIcon());
    m_taskBarIconImpl->GetTaskBarIcon()->ProcessEvent(tbiEvent);
}

void wxTaskBarIconWindowCustom::OnPaint(wxPaintEvent &WXUNUSED(event))
{
    wxPaintDC dc(this);
    // FIXME: This is a temporary hack until we can see real icons
    dc.SetBackground(wxBrush(*wxBLUE));
    dc.Clear();
    dc.DrawIcon(m_icon,0,0);
}

#endif //def wxHAS_TASK_BAR_ICON
