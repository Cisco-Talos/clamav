/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/mdi.mm
// Purpose:     wxMDIParentFrame, wxMDIChildFrame, wxMDIClientWindow
// Author:      David Elliott
// Modified by:
// Created:     2003/09/08
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_MDI

#include "wx/mdi.h"

#include "wx/cocoa/objc/objc_uniquifying.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif // WX_PRECOMP

// #include "wx/cocoa/autorelease.h"
#include "wx/cocoa/mbarman.h"

#import <AppKit/NSWindow.h>
#import <Foundation/NSNotification.h>
// #import <AppKit/NSApplication.h>
// #import <AppKit/NSView.h>

#include "wx/listimpl.cpp"
WX_DEFINE_LIST(wxCocoaMDIChildFrameList);

WX_DECLARE_HASH_MAP(int, wxMDIChildFrame*, wxIntegerHash, wxIntegerEqual, wxIntMDIChildFrameHashMap);

// ============================================================================
// wxMDIParentFrameObserver
// ============================================================================
@interface wxMDIParentFrameObserver : NSObject
{
    wxMDIParentFrame *m_mdiParent;
}

- (id)init;
- (id)initWithWxMDIParentFrame: (wxMDIParentFrame *)mdiParent;
- (void)windowDidBecomeMain: (NSNotification *)notification;
@end // interface wxMDIParentFrameObserver : NSObject
WX_DECLARE_GET_OBJC_CLASS(wxMDIParentFrameObserver,NSObject)

@implementation wxMDIParentFrameObserver : NSObject
- (id)init
{
    wxFAIL_MSG(wxT("[wxMDIParentFrameObserver -init] should never be called!"));
    m_mdiParent = NULL;
    return self;
}

- (id)initWithWxMDIParentFrame: (wxMDIParentFrame *)mdiParent
{
    wxASSERT(mdiParent);
    m_mdiParent = mdiParent;
    return [super init];
}

- (void)windowDidBecomeMain: (NSNotification *)notification
{
    wxASSERT(m_mdiParent);
    m_mdiParent->WindowDidBecomeMain(notification);
}

@end // implementation wxMDIParentFrameObserver : NSObject
WX_IMPLEMENT_GET_OBJC_CLASS(wxMDIParentFrameObserver,NSObject)

// ========================================================================
// wxMDIParentFrame
// ========================================================================
IMPLEMENT_DYNAMIC_CLASS(wxMDIParentFrame,wxFrame)
BEGIN_EVENT_TABLE(wxMDIParentFrame,wxFrame)
END_EVENT_TABLE()

void wxMDIParentFrame::Init()
{
    m_clientWindow = NULL;
    m_currentChild = NULL;
    m_observer = [[WX_GET_OBJC_CLASS(wxMDIParentFrameObserver) alloc]
            initWithWxMDIParentFrame:this];
    [[NSNotificationCenter defaultCenter] addObserver:m_observer
            selector:@selector(windowDidBecomeMain:)
            name:NSWindowDidBecomeMainNotification object:nil];
}

bool wxMDIParentFrame::Create(wxWindow *parent,
        wxWindowID winid, const wxString& title,
        const wxPoint& pos, const wxSize& size,
        long style, const wxString& name)
{
    if ( !wxFrame::Create(parent,winid,title,pos,size,style,name) )
        return false;

    m_clientWindow = OnCreateClient();

    return m_clientWindow != NULL;
}

wxMDIParentFrame::~wxMDIParentFrame()
{
    for(wxCocoaMDIChildFrameList::compatibility_iterator node =
            m_mdiChildren.GetFirst(); node; node = m_mdiChildren.GetFirst())
    {
        wxMDIChildFrame *child = node->GetData();
        // Delete it NOW
        delete child;
        wxASSERT_MSG(!m_mdiChildren.Find(child),
            wxT("MDI child didn't remove itself using RemoveMDIChild()"));
    }
    [m_observer release];
}

void wxMDIParentFrame::AddMDIChild(wxMDIChildFrame *child)
{
    m_mdiChildren.Append(child);
}

void wxMDIParentFrame::RemoveMDIChild(wxMDIChildFrame *child)
{
    m_mdiChildren.DeleteObject(child);
    if(child==m_currentChild)
        SetActiveChild(NULL);
}

void wxMDIParentFrame::SetActiveChild(wxMDIChildFrame *child)
{
    m_currentChild = child;
    wxMenuBarManager::GetInstance()->UpdateMenuBar();
}

wxMenuBar *wxMDIParentFrame::GetAppMenuBar(wxCocoaNSWindow *win)
{
    if(m_currentChild && (win==this))
        return m_currentChild->GetAppMenuBar(win);
    return wxFrame::GetAppMenuBar(win);
}

void wxMDIParentFrame::CocoaDelegate_windowDidBecomeKey(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxMDIParentFrame=%p::CocoaDelegate_windowDidBecomeKey"),this);
    if(sm_cocoaDeactivateWindow && sm_cocoaDeactivateWindow==m_currentChild)
    {
        sm_cocoaDeactivateWindow = NULL;
    }
    #if 0
    else if(sm_cocoaDeactivateWindow == this)
    {
        sm_cocoaDeactivateWindow = NULL;
    }
    #endif
    else
    {
        if(m_currentChild)
        {
            NSWindow *nswin = m_currentChild->GetNSWindow();
            if(![nswin isMainWindow])
                [nswin makeMainWindow];
        }
        wxFrame::CocoaDelegate_windowDidBecomeKey();
    }
}

void wxMDIParentFrame::CocoaDelegate_windowDidResignKey(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxMDIParentFrame=%p::CocoaDelegate_windowDidResignKey"),this);
    if(m_closed)
        wxFrame::CocoaDelegate_windowDidResignKey();
    else
        sm_cocoaDeactivateWindow = this;
}

// We should not become the main window as we aren't a document window
// MDI "Children" should be the main window
bool wxMDIParentFrame::Cocoa_canBecomeMainWindow(bool &canBecome)
{
    canBecome = m_mdiChildren.IsEmpty(); return true;
}

void wxMDIParentFrame::WindowDidBecomeMain(NSNotification *notification)
{
    // If we aren't the key window, we don't care
    if(![m_cocoaNSWindow isKeyWindow])
        return;
    wxCocoaNSWindow *win = wxCocoaNSWindow::GetFromCocoa([notification object]);
    // If we are key and becoming main, that's great
    if(win==this)
        return;
    // If one of our children is becoming main, also great
    for(wxCocoaMDIChildFrameList::compatibility_iterator node =
            m_mdiChildren.GetFirst(); node; node = node->GetNext())
    {
        wxMDIChildFrame *child = node->GetData();
        if(win==child)
            return;
    }
    // Some other window is becoming main, but we are key
    // Make the new main window the key window
    [[notification object] makeKeyWindow];
    if(!m_currentChild)
    {
        wxIntMDIChildFrameHashMap hashmap;
        for(wxCocoaMDIChildFrameList::compatibility_iterator node =
                m_mdiChildren.GetFirst(); node; node = node->GetNext())
        {
            wxMDIChildFrame *child = node->GetData();
            hashmap.insert(wxIntMDIChildFrameHashMap::value_type([child->m_cocoaNSWindow windowNumber],child));
        }
        if(!hashmap.empty())
        {
            NSInteger windowCount = 0;
            NSCountWindows(&windowCount);
            wxASSERT(windowCount>0);
            NSInteger *windowList = new NSInteger[windowCount];
            NSWindowList(windowCount, windowList);
            wxIntMDIChildFrameHashMap::iterator iter = hashmap.end();
            for(int i=0; i<windowCount && iter == hashmap.end(); i++)
                iter=hashmap.find(windowList[i]);
            if(iter != hashmap.end())
                m_currentChild = iter->second;
        }
    }
}

// ========================================================================
// wxMDIChildFrame
// ========================================================================
IMPLEMENT_DYNAMIC_CLASS(wxMDIChildFrame,wxFrame)
BEGIN_EVENT_TABLE(wxMDIChildFrame,wxFrame)
END_EVENT_TABLE()

void wxMDIChildFrame::Init()
{
    m_mdiParent = NULL;
}

bool wxMDIChildFrame::Create(wxMDIParentFrame *parent,
        wxWindowID winid, const wxString& title,
        const wxPoint& pos, const wxSize& size,
        long style, const wxString& name)
{
    bool success = wxFrame::Create(parent,winid,title,pos,size,style,name);
    if(success)
    {
        m_mdiParent = parent;
        parent->AddMDIChild(this);
    }
    return success;
}

wxMDIChildFrame::~wxMDIChildFrame()
{
    // Just in case Destroy() wasn't called
    m_mdiParent->RemoveMDIChild(this);
}

void wxMDIChildFrame::Activate()
{
}

void wxMDIChildFrame::CocoaDelegate_windowDidBecomeKey(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxMDIChildFrame=%p::CocoaDelegate_windowDidBecomeKey"),this);
    if(sm_cocoaDeactivateWindow && sm_cocoaDeactivateWindow==m_mdiParent)
    {
        sm_cocoaDeactivateWindow = NULL;
        if(m_mdiParent->GetActiveChild() != this)
            sm_cocoaDeactivateWindow = m_mdiParent->GetActiveChild();
    }
    m_mdiParent->SetActiveChild(this);
    wxFrame::CocoaDelegate_windowDidBecomeKey();
}

void wxMDIChildFrame::CocoaDelegate_windowDidBecomeMain(void)
{
    m_mdiParent->SetActiveChild(this);
    wxFrame::CocoaDelegate_windowDidBecomeMain();
}

void wxMDIChildFrame::CocoaDelegate_windowDidResignKey(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxMDIChildFrame=%p::CocoaDelegate_windowDidResignKey"),this);
    sm_cocoaDeactivateWindow = this;
}

bool wxMDIChildFrame::Destroy()
{
    // It's good to do this here before we are really closed
    m_mdiParent->RemoveMDIChild(this);
    return wxFrame::Destroy();
}

// ========================================================================
// wxMDIClientWindow
// ========================================================================
IMPLEMENT_DYNAMIC_CLASS(wxMDIClientWindow,wxWindow)

bool wxMDIClientWindow::CreateClient(wxMDIParentFrame *parent, long style)
{
    return Create(parent, wxID_ANY, wxPoint(0, 0), wxSize(0, 0), style);
}

#endif // wxUSE_MDI
