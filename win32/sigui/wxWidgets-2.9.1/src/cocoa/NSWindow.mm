/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/NSWindow.mm
// Purpose:     wxCocoaNSWindow
// Author:      David Elliott
// Modified by:
// Created:     2003/03/16
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"
#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/menuitem.h"
#endif // WX_PRECOMP

#include "wx/cocoa/NSWindow.h"

#include "wx/cocoa/objc/objc_uniquifying.h"

#import <Foundation/NSNotification.h>
#import <Foundation/NSString.h>
#include "wx/cocoa/objc/NSWindow.h"

// ============================================================================
// @class wxNSWindowDelegate
// ============================================================================
@interface wxNSWindowDelegate : NSObject
{
    wxCocoaNSWindow *m_wxCocoaInterface;
}

- (id)init;
- (void)setWxCocoaInterface: (wxCocoaNSWindow *)wxCocoaInterface;
- (wxCocoaNSWindow *)wxCocoaInterface;

// Delegate message handlers
- (void)windowDidBecomeKey: (NSNotification *)notification;
- (void)windowDidResignKey: (NSNotification *)notification;
- (void)windowDidBecomeMain: (NSNotification *)notification;
- (void)windowDidResignMain: (NSNotification *)notification;
- (BOOL)windowShouldClose: (id)sender;
- (void)windowWillClose: (NSNotification *)notification;

// Menu item handlers
- (void)wxMenuItemAction: (NSMenuItem *)menuItem;
- (BOOL)validateMenuItem: (NSMenuItem *)menuItem;
@end //interface wxNSWindowDelegate
WX_DECLARE_GET_OBJC_CLASS(wxNSWindowDelegate,NSObject)

@implementation wxNSWindowDelegate : NSObject

- (id)init
{
    m_wxCocoaInterface = NULL;
    return [super init];
}

- (void)setWxCocoaInterface: (wxCocoaNSWindow *)wxCocoaInterface
{
    m_wxCocoaInterface = wxCocoaInterface;
}

- (wxCocoaNSWindow *)wxCocoaInterface
{
    return m_wxCocoaInterface;
}

// Delegate message handlers
- (void)windowDidBecomeKey: (NSNotification *)notification
{
    wxCocoaNSWindow *win = wxCocoaNSWindow::GetFromCocoa([notification object]);
    wxASSERT(win==m_wxCocoaInterface);
    wxCHECK_RET(win,wxT("notificationDidBecomeKey received but no wxWindow exists"));
    win->CocoaDelegate_windowDidBecomeKey();
}

- (void)windowDidResignKey: (NSNotification *)notification
{
    wxCocoaNSWindow *win = wxCocoaNSWindow::GetFromCocoa([notification object]);
    wxASSERT(win==m_wxCocoaInterface);
    wxCHECK_RET(win,wxT("notificationDidResignKey received but no wxWindow exists"));
    win->CocoaDelegate_windowDidResignKey();
}

- (void)windowDidBecomeMain: (NSNotification *)notification
{
    wxCocoaNSWindow *win = wxCocoaNSWindow::GetFromCocoa([notification object]);
    wxASSERT(win==m_wxCocoaInterface);
    wxCHECK_RET(win,wxT("notificationDidBecomeMain received but no wxWindow exists"));
    win->CocoaDelegate_windowDidBecomeMain();
}

- (void)windowDidResignMain: (NSNotification *)notification
{
    wxCocoaNSWindow *win = wxCocoaNSWindow::GetFromCocoa([notification object]);
    wxASSERT(win==m_wxCocoaInterface);
    wxCHECK_RET(win,wxT("notificationDidResignMain received but no wxWindow exists"));
    win->CocoaDelegate_windowDidResignMain();
}

- (BOOL)windowShouldClose: (id)sender
{
    wxLogTrace(wxTRACE_COCOA,wxT("windowShouldClose"));
    wxCocoaNSWindow *tlw = wxCocoaNSWindow::GetFromCocoa(sender);
    wxASSERT(tlw==m_wxCocoaInterface);
    if(tlw && !tlw->CocoaDelegate_windowShouldClose())
    {
        wxLogTrace(wxTRACE_COCOA,wxT("Window will not be closed"));
        return NO;
    }
    wxLogTrace(wxTRACE_COCOA,wxT("Window will be closed"));
    return YES;
}

- (void)windowWillClose: (NSNotification *)notification
{
    wxCocoaNSWindow *win = wxCocoaNSWindow::GetFromCocoa([notification object]);
    wxASSERT(win==m_wxCocoaInterface);
    wxCHECK_RET(win,wxT("windowWillClose received but no wxWindow exists"));
    win->CocoaDelegate_windowWillClose();
}

// Menu item handlers
- (void)wxMenuItemAction: (NSMenuItem *)sender
{
    wxASSERT(m_wxCocoaInterface);
    m_wxCocoaInterface->CocoaDelegate_wxMenuItemAction(sender);
}

- (BOOL)validateMenuItem: (NSMenuItem *)sender
{
    wxASSERT(m_wxCocoaInterface);
    return m_wxCocoaInterface->CocoaDelegate_validateMenuItem(sender);
}

@end //implementation wxNSWindowDelegate
WX_IMPLEMENT_GET_OBJC_CLASS(wxNSWindowDelegate,NSObject)

// ============================================================================
// class wxCocoaNSWindow
// ============================================================================

WX_IMPLEMENT_OBJC_INTERFACE_HASHMAP(NSWindow)

wxCocoaNSWindow::wxCocoaNSWindow(wxTopLevelWindowCocoa *tlw)
:   m_wxTopLevelWindowCocoa(tlw)
{
    m_cocoaDelegate = [[WX_GET_OBJC_CLASS(wxNSWindowDelegate) alloc] init];
    [m_cocoaDelegate setWxCocoaInterface: this];
}

wxCocoaNSWindow::~wxCocoaNSWindow()
{
    [m_cocoaDelegate setWxCocoaInterface: NULL];
    [m_cocoaDelegate release];
}

void wxCocoaNSWindow::AssociateNSWindow(WX_NSWindow cocoaNSWindow)
{
    if(cocoaNSWindow)
    {
        [cocoaNSWindow setReleasedWhenClosed: NO];
        sm_cocoaHash.insert(wxCocoaNSWindowHash::value_type(cocoaNSWindow,this));
        [cocoaNSWindow setDelegate: m_cocoaDelegate];
    }
}

void wxCocoaNSWindow::DisassociateNSWindow(WX_NSWindow cocoaNSWindow)
{
    if(cocoaNSWindow)
    {
        [cocoaNSWindow setDelegate: nil];
        sm_cocoaHash.erase(cocoaNSWindow);
    }
}

wxMenuBar* wxCocoaNSWindow::GetAppMenuBar(wxCocoaNSWindow *win)
{
    return NULL;
}

// ============================================================================
// @class WXNSWindow
// ============================================================================
@implementation WXNSWindow : NSWindow

- (BOOL)canBecomeKeyWindow
{
    bool canBecome = false;
    wxCocoaNSWindow *tlw = wxCocoaNSWindow::GetFromCocoa(self);
    if(!tlw || !tlw->Cocoa_canBecomeKeyWindow(canBecome))
        canBecome = [super canBecomeKeyWindow];
    return canBecome;
}

- (BOOL)canBecomeMainWindow
{
    bool canBecome = false;
    wxCocoaNSWindow *tlw = wxCocoaNSWindow::GetFromCocoa(self);
    if(!tlw || !tlw->Cocoa_canBecomeMainWindow(canBecome))
        canBecome = [super canBecomeMainWindow];
    return canBecome;
}

@end // implementation WXNSWindow
WX_IMPLEMENT_GET_OBJC_CLASS(WXNSWindow,NSWindow)

// ============================================================================
// @class WXNSPanel
// ============================================================================
@implementation WXNSPanel : NSPanel

- (BOOL)canBecomeKeyWindow
{
    bool canBecome = false;
    wxCocoaNSWindow *tlw = wxCocoaNSWindow::GetFromCocoa(self);
    if(!tlw || !tlw->Cocoa_canBecomeKeyWindow(canBecome))
        canBecome = [super canBecomeKeyWindow];
    return canBecome;
}

- (BOOL)canBecomeMainWindow
{
    bool canBecome = false;
    wxCocoaNSWindow *tlw = wxCocoaNSWindow::GetFromCocoa(self);
    if(!tlw || !tlw->Cocoa_canBecomeMainWindow(canBecome))
        canBecome = [super canBecomeMainWindow];
    return canBecome;
}

@end // implementation WXNSPanel
WX_IMPLEMENT_GET_OBJC_CLASS(WXNSPanel,NSPanel)
