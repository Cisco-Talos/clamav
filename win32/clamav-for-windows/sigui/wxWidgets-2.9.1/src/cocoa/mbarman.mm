/////////////////////////////////////////////////////////////////////////////
// Name:        cocoa/mbarman.cpp
// Purpose:     wxMenuBarManager implementation
// Author:      David Elliott
// Modified by:
// Created:     2003/09/04
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"
#if wxUSE_MENUS
#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/menu.h"
    #include "wx/toplevel.h"
#endif // WX_PRECOMP

#include "wx/cocoa/mbarman.h"
#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/objc/objc_uniquifying.h"

#import <Foundation/NSString.h>
#import <Foundation/NSNotification.h>
#import <AppKit/NSMenu.h>
#import <AppKit/NSApplication.h>
#import <AppKit/NSWindow.h>

#ifndef wxUSE_FSCRIPT
#define wxUSE_FSCRIPT 0
#endif

#if wxUSE_FSCRIPT
    #import <FScript/FScriptMenuItem.h>
#endif

// Declare setAppleMenu: in an NSApplication category since Tiger and later
// releases support it but don't declare it as it's considered deprecated.
@interface NSApplication(wxDeprecatedMethodsWeWantToUse)
- (void)setAppleMenu:(NSMenu *)menu;
@end

// ============================================================================
// wxMenuBarManagerObserver
// ============================================================================
@interface wxMenuBarManagerObserver : NSObject
{
    wxMenuBarManager *m_mbarman;
}

- (id)init;
- (id)initWithWxMenuBarManager: (wxMenuBarManager *)mbarman;
- (void)windowDidBecomeKey: (NSNotification *)notification;
#if 0
- (void)windowDidResignKey: (NSNotification *)notification;
- (void)windowDidBecomeMain: (NSNotification *)notification;
- (void)windowDidResignMain: (NSNotification *)notification;
- (void)windowWillClose: (NSNotification *)notification;
#endif // 0
@end // interface wxMenuBarManagerObserver : NSObject
WX_DECLARE_GET_OBJC_CLASS(wxMenuBarManagerObserver,NSObject)

@implementation wxMenuBarManagerObserver : NSObject
- (id)init
{
    wxFAIL_MSG(wxT("[wxMenuBarManagerObserver -init] should never be called!"));
    m_mbarman = NULL;
    return self;
}

- (id)initWithWxMenuBarManager: (wxMenuBarManager *)mbarman
{
    wxASSERT(mbarman);
    m_mbarman = mbarman;
    return [super init];
}

- (void)windowDidBecomeKey: (NSNotification *)notification
{
    wxASSERT(m_mbarman);
    m_mbarman->WindowDidBecomeKey(notification);
}

#if 0
- (void)windowDidResignKey: (NSNotification *)notification
{
    wxASSERT(m_mbarman);
    m_mbarman->WindowDidResignKey(notification);
}

- (void)windowDidBecomeMain: (NSNotification *)notification
{
    wxASSERT(m_mbarman);
    m_mbarman->WindowDidBecomeMain(notification);
}

- (void)windowDidResignMain: (NSNotification *)notification
{
    wxASSERT(m_mbarman);
    m_mbarman->WindowDidResignMain(notification);
}

- (void)windowWillClose: (NSNotification *)notification
{
    wxASSERT(m_mbarman);
    m_mbarman->WindowWillClose(notification);
}
#endif // 0

@end // implementation wxMenuBarManagerObserver : NSObject
WX_IMPLEMENT_GET_OBJC_CLASS(wxMenuBarManagerObserver,NSObject)

// ============================================================================
// wxMenuBarManager
// ============================================================================
wxMenuBarManager *wxMenuBarManager::sm_mbarmanInstance = NULL;

static void AddFScriptItem(NSMenu *menu)
#if wxUSE_FSCRIPT
{
    NSMenuItem *item = [[FScriptMenuItem alloc] init];
    [menu addItem: item];
    [item release];
}
#else
{}
#endif

wxMenuBarManager::wxMenuBarManager()
{
    m_observer = [[WX_GET_OBJC_CLASS(wxMenuBarManagerObserver) alloc]
            initWithWxMenuBarManager:this];
    [[NSNotificationCenter defaultCenter] addObserver:m_observer
            selector:@selector(windowDidBecomeKey:)
            name:NSWindowDidBecomeKeyNotification object:nil];

    // HACK: Reuse the same selector and eventual C++ method and make it
    // check for whether the notification is to become key or main.
    [[NSNotificationCenter defaultCenter] addObserver:m_observer
            selector:@selector(windowDidBecomeKey:)
            name:NSWindowDidBecomeMainNotification object:nil];
#if 0
    [[NSNotificationCenter defaultCenter] addObserver:m_observer
            selector:@selector(windowDidResignKey:)
            name:NSWindowDidResignKeyNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:m_observer
            selector:@selector(windowDidBecomeMain:)
            name:NSWindowDidBecomeMainNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:m_observer
            selector:@selector(windowDidResignMain:)
            name:NSWindowDidResignMainNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:m_observer
            selector:@selector(windowWillClose:)
            name:NSWindowWillCloseNotification object:nil];
#endif // 0
    m_menuApp = nil;
    m_menuServices = nil;
    m_menuWindows = nil;
    m_menuMain = nil;
    m_mainMenuBarInstalled = true;
    m_mainMenuBar = NULL;
    m_currentNSWindow = nil;

    NSApplication *theNSApplication = wxTheApp->GetNSApplication();
    // Create the services menu.
    m_menuServices = [[NSMenu alloc] initWithTitle: @"Services"];
    [theNSApplication setServicesMenu:m_menuServices];

    NSMenuItem *menuitem;
    // Create the application (Apple) menu.
    m_menuApp = [[NSMenu alloc] initWithTitle: @"Apple Menu"];

/**/[m_menuApp addItemWithTitle:@"Preferences..." action:nil keyEquivalent:@""];
/**/[m_menuApp addItem: [NSMenuItem separatorItem]];
/**/AddFScriptItem(m_menuApp);
/**/menuitem = [[NSMenuItem alloc] initWithTitle: @"Services" action:nil keyEquivalent:@""];
    [menuitem setSubmenu:m_menuServices];
    [m_menuApp addItem: menuitem];
    [menuitem release];
/**/[m_menuApp addItem: [NSMenuItem separatorItem]];
/**/menuitem = [[NSMenuItem alloc] initWithTitle:@"Hide" action:@selector(hide:) keyEquivalent:@""];
    [menuitem setTarget: theNSApplication];
    [m_menuApp addItem: menuitem];
    [menuitem release];
/**/menuitem = [[NSMenuItem alloc] initWithTitle:@"Hide Others" action:@selector(hideOtherApplications:) keyEquivalent:@""];
    [menuitem setTarget: theNSApplication];
    [m_menuApp addItem: menuitem];
    [menuitem release];
/**/menuitem = [[NSMenuItem alloc] initWithTitle:@"Show All" action:@selector(unhideAllApplications:) keyEquivalent:@""];
    [menuitem setTarget: theNSApplication];
    [m_menuApp addItem: menuitem];
    [menuitem release];
/**/[m_menuApp addItem: [NSMenuItem separatorItem]];
/**/menuitem = [[NSMenuItem alloc] initWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@"q"];
    [menuitem setTarget: theNSApplication];
    [m_menuApp addItem: menuitem];
    [menuitem release];

    [theNSApplication setAppleMenu:m_menuApp];

    // Create the Windows menu
    m_menuWindows = [[NSMenu alloc] initWithTitle: @"Window"];

/**/[m_menuWindows addItemWithTitle:@"Minimize" action:@selector(performMiniaturize:) keyEquivalent:@""];
/**/[m_menuWindows addItem: [NSMenuItem separatorItem]];
/**/[m_menuWindows addItemWithTitle:@"Bring All to Front" action:@selector(arrangeInFront:) keyEquivalent:@""];

    [theNSApplication setWindowsMenu:m_menuWindows];

    // Create the main menubar
    m_menuMain = [[NSMenu alloc] initWithTitle: @"wxApp Menu"];
/**/NSMenuItem *dummyItem = [[NSMenuItem alloc] initWithTitle:@"App menu"
        /* Note: title gets clobbered by app name anyway */
        action:nil keyEquivalent:@""];
    [dummyItem setSubmenu:m_menuApp];
    [m_menuMain addItem:dummyItem];
    [dummyItem release];
/**/dummyItem = [[NSMenuItem alloc] initWithTitle:@"Window"
        action:nil keyEquivalent:@""];
    [dummyItem setSubmenu:m_menuWindows];
    [m_menuMain addItem:dummyItem];
    [dummyItem release];

    [theNSApplication setMainMenu: m_menuMain];

}

wxMenuBarManager::~wxMenuBarManager()
{
    [m_observer release];
}

void wxMenuBarManager::CreateInstance()
{
    sm_mbarmanInstance = new wxMenuBarManager;
}

void wxMenuBarManager::DestroyInstance()
{
    delete sm_mbarmanInstance;
    sm_mbarmanInstance = NULL;
}

void wxMenuBarManager::SetMenuBar(wxMenuBar* menubar)
{
    m_mainMenuBarInstalled = false;
    if(menubar)
    {
        [[[wxTheApp->GetNSApplication() mainMenu] itemAtIndex:0] setSubmenu:nil];
        [[menubar->GetNSMenu() itemAtIndex:0] setSubmenu:m_menuApp];
        [wxTheApp->GetNSApplication() setMainMenu:menubar->GetNSMenu()];
    }
    else
        InstallMainMenu();
}

void wxMenuBarManager::SetMainMenuBar(wxMenuBar* menubar)
{
    m_mainMenuBar = menubar;
    if(m_mainMenuBarInstalled)
        InstallMainMenu();
}

void wxMenuBarManager::InstallMainMenu()
{
    if(m_mainMenuBar)
        SetMenuBar(m_mainMenuBar);
    else
    {
        m_mainMenuBarInstalled = true;
        [[[wxTheApp->GetNSApplication() mainMenu] itemAtIndex:0] setSubmenu:nil];
        [[m_menuMain itemAtIndex:0] setSubmenu:m_menuApp];
        [wxTheApp->GetNSApplication() setMainMenu:m_menuMain];
    }
}

void wxMenuBarManager::WindowDidBecomeKey(NSNotification *notification)
{
    /* NOTE: m_currentNSWindow might be destroyed but we only ever use it
       to look it up in the hash table.  Do not send messages to it. */

    /*  Update m_currentNSWindow only if we really should.  For instance,
        if a non-wx window is becoming key but a wx window remains main
        then don't change out the menubar.  However, if a non-wx window
        (whether the same window or not) is main, then switch to the
        generic menubar so the wx window that last installed a menubar
        doesn't get menu events it doesn't expect.

        If a wx window is becoming main then check to see if the key
        window is a wx window and if so do nothing because that
        is what would have been done before.

        If a non-wx window is becoming main and 
     */
    NSString *notificationName = [notification name];
    if(NULL == notificationName)
        return;
    else if([NSWindowDidBecomeKeyNotification isEqualTo:notificationName])
    {   // This is the only one that was handled in 2.8 as shipped
        // Generally the key window can change without the main window changing.
        // The user can do this simply by clicking on something in a palette window
        // that needs to become key.
        NSWindow *newKeyWindow = [notification object];
        wxCocoaNSWindow *theWxKeyWindow = wxCocoaNSWindow::GetFromCocoa(newKeyWindow);
        if(theWxKeyWindow != NULL)
        {   // If the new key window is a wx window, handle it as before
            // even if it has not actually changed.
            m_currentNSWindow = newKeyWindow;
        }
        else
        {   // If the new key window is not wx then check the main window.
            NSWindow *mainWindow = [[NSApplication sharedApplication] mainWindow];
            if(m_currentNSWindow == mainWindow)
                // Don't reset if the menubar doesn't need to change.
                return;
            else
                // This is strange because theoretically we should have picked this up
                // already in the main window notification but it's possible that
                // we simply haven't gotten it yet and will about as soon as we return.
                // We already know that the key window isn't wx so fall back to this
                // one and let the code go ahead and set the wx menubar if it is
                // a wx window and set the generic one if it isn't.
                m_currentNSWindow = mainWindow;
        }
    }
    else if([NSWindowDidBecomeMainNotification isEqualTo:notificationName])
    {   // Handling this is new
        // Generally the main window cannot change without the key window changing
        // because if the user clicks on a window that can become main then the
        // window will also become key.
        // However, it's possible that when it becomes main it automatically makes
        // some palette the key window.
        NSWindow *newMainWindow = [notification object];
        // If we already know about the window, bail.
        if(newMainWindow == m_currentNSWindow)
            return;
        else
        {
            NSWindow *keyWindow = [[NSApplication sharedApplication] keyWindow];
            if(keyWindow == m_currentNSWindow)
                // if we already know about the key window, bail
                return;
            else
            {   // As above, sort of strange.  Neither one is current.  Prefer key over main.
                wxCocoaNSWindow *theWxMainWindow = wxCocoaNSWindow::GetFromCocoa(keyWindow);
                if(theWxMainWindow != NULL)
                    m_currentNSWindow = keyWindow;
                else
                    m_currentNSWindow = newMainWindow;
            }
        }
    }
    m_currentNSWindow = [notification object];
    wxCocoaNSWindow *win = wxCocoaNSWindow::GetFromCocoa(m_currentNSWindow);
    if(win)
        InstallMenuBarForWindow(win);
    else
        SetMenuBar(NULL);
}

#if 0
void wxMenuBarManager::WindowDidResignKey(NSNotification *notification)
{
}

void wxMenuBarManager::WindowDidBecomeMain(NSNotification *notification)
{
}

void wxMenuBarManager::WindowDidResignMain(NSNotification *notification)
{
}

void wxMenuBarManager::WindowWillClose(NSNotification *notification)
{
}
#endif // 0

void wxMenuBarManager::InstallMenuBarForWindow(wxCocoaNSWindow *win)
{
    wxASSERT(win);
    wxMenuBar *menubar = win->GetAppMenuBar(win);
    wxLogTrace(wxTRACE_COCOA,wxT("Found menubar=%p for window=%p."),menubar,win);
    SetMenuBar(menubar);
}

void wxMenuBarManager::UpdateMenuBar()
{
    if(m_currentNSWindow)
    {
        wxCocoaNSWindow *win = wxCocoaNSWindow::GetFromCocoa(m_currentNSWindow);
        if(win)
            InstallMenuBarForWindow(win);
    }
}

#endif // wxUSE_MENUS
