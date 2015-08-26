/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/frame.mm
// Purpose:     wxFrame
// Author:      David Elliott
// Modified by:
// Created:     2003/03/16
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/frame.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/menu.h"
    #include "wx/toolbar.h"
    #include "wx/statusbr.h"
#endif // WX_PRECOMP

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/mbarman.h"

#import <AppKit/NSWindow.h>
#import <AppKit/NSApplication.h>
#import <AppKit/NSView.h>
#import <AppKit/NSMenuItem.h>

// wxFrame

BEGIN_EVENT_TABLE(wxFrame, wxFrameBase)
END_EVENT_TABLE()

IMPLEMENT_DYNAMIC_CLASS(wxFrame, wxTopLevelWindow)

void wxFrame::Init()
{
    m_frameNSView = nil;
}

bool wxFrame::Create(wxWindow *parent,
           wxWindowID winid,
           const wxString& title,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxString& name)
{
    bool rt = wxTopLevelWindow::Create(parent,winid,title,pos,size,style,name);

    return rt;
}

wxFrame::~wxFrame()
{
    [m_frameNSView release];
}

// -------------------------------------------------------------------
// Menubar
void wxFrame::AttachMenuBar(wxMenuBar *mbar)
{
    wxFrameBase::AttachMenuBar(mbar);
    wxMenuBarManager::GetInstance()->UpdateMenuBar();
}

void wxFrame::DetachMenuBar()
{
    wxFrameBase::DetachMenuBar();
    wxMenuBarManager::GetInstance()->UpdateMenuBar();
}

void wxFrame::SetMenuBar(wxMenuBar *menubar)
{
    if ( menubar == GetMenuBar() )
    {
        // nothing to do
        return;
    }

    wxFrameBase::DetachMenuBar();
    wxFrameBase::AttachMenuBar(menubar);
    wxMenuBarManager::GetInstance()->UpdateMenuBar();
}

wxMenuBar* wxFrame::GetAppMenuBar(wxCocoaNSWindow *win)
{
    if(GetMenuBar())
        return GetMenuBar();
    return wxFrameBase::GetAppMenuBar(win);
}

void wxFrame::CocoaDelegate_wxMenuItemAction(WX_NSMenuItem menuItem)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxFrame::wxMenuItemAction"));
    wxMenuItem *item = wxMenuItem::GetFromCocoa(menuItem);
    wxCHECK_RET(item,wxT("wxMenuItemAction received but no wxMenuItem exists!"));

    wxMenu *menu = item->GetMenu();
    wxCHECK_RET(menu,wxT("wxMenuItemAction received but wxMenuItem is not in a wxMenu!"));

    // Since we're handling the delegate messages there's a very good chance
    // we'll receive a menu action from an item with a nil target.
    wxMenuBar *menubar = menu->GetMenuBar();
    if(menubar)
    {
        wxFrame *frame = menubar->GetFrame();
        wxASSERT_MSG(frame==this, wxT("Received wxMenuItemAction in NSWindow delegate from a menu item attached to a different frame."));
        frame->ProcessCommand(item->GetId());
    }
    else
        wxLogDebug(wxT("Received wxMenuItemAction in NSWindow delegate from an unknown menu item."));
}

bool wxFrame::CocoaDelegate_validateMenuItem(WX_NSMenuItem menuItem)
{
    SEL itemAction = [menuItem action];
    if(itemAction == @selector(wxMenuItemAction:))
    {
        wxMenuItem *item = wxMenuItem::GetFromCocoa(menuItem);
        wxCHECK_MSG(item,false,wxT("validateMenuItem received but no wxMenuItem exists!"));
        // TODO: do more sanity checking
        return item->IsEnabled();
    }
    // TODO: else if cut/copy/paste
    wxLogDebug(wxT("Asked to validate an unknown menu item"));
    return false;
}

// -------------------------------------------------------------------
// Origin/Size
wxPoint wxFrame::GetClientAreaOrigin() const
{
    return wxPoint(0,0);
}

void wxFrame::CocoaSetWxWindowSize(int width, int height)
{
    if(m_frameStatusBar)
        height += m_frameStatusBar->GetSize().y;
#if wxUSE_TOOLBAR
    if(m_frameToolBar)
        height += m_frameToolBar->GetSize().y;
#endif //wxUSE_TOOLBAR
    wxTopLevelWindow::CocoaSetWxWindowSize(width,height);
}

// -------------------------------------------------------------------
WX_NSView wxFrame::GetNonClientNSView()
{
    if(m_frameNSView)
        return m_frameNSView;
    return GetNSViewForSuperview();
}

void wxFrame::CocoaReplaceView(WX_NSView oldView, WX_NSView newView)
{
    // If we have the additional toolbar/statbar view, then the
    // default replaceSubview will work. Otherwise, the old view
    // should be the content view and should be replaced that way
    if(m_frameNSView)
        wxWindow::CocoaReplaceView(oldView, newView);
    else
        wxTopLevelWindow::CocoaReplaceView(oldView, newView);
}

void wxFrame::UpdateFrameNSView()
{
    if(!m_frameNSView)
    {	// NOTE: We only need a plain NSView here since we don't associate it with ourselves.
        m_frameNSView = [[NSView alloc] initWithFrame:[[m_cocoaNSWindow contentView] frame]];
        [m_cocoaNSWindow setContentView: m_frameNSView];
        [m_frameNSView addSubview:m_cocoaNSView];
    }
    NSRect frameRect = [m_frameNSView frame];
    float tbarheight = 0.0;
#if wxUSE_TOOLBAR
    if(m_frameToolBar)
    {
        NSView *tbarNSView = m_frameToolBar->GetNSViewForSuperview();
        // If the toolbar doesn't have a superview then set it to our
        // content view.
        if(![tbarNSView superview])
            [m_frameNSView addSubview: tbarNSView];
        // Do this after addSubView so that SetSize can work
        m_frameToolBar->SetSize(m_frameToolBar->DoGetBestSize());
        NSRect tbarRect = [tbarNSView frame];
        tbarRect.size.width = frameRect.size.width;
        tbarRect.origin.x = 0.0;
        tbarRect.origin.y = frameRect.size.height - tbarRect.size.height;
        [tbarNSView setFrame:tbarRect];
        // width expands, bottom margin expands
        [tbarNSView setAutoresizingMask: NSViewWidthSizable|NSViewMinYMargin];
        tbarheight = tbarRect.size.height;
    }
#endif //wxUSE_TOOLBAR
    float sbarheight = 0.0;
    if(m_frameStatusBar)
    {
        NSView *sbarNSView = m_frameStatusBar->GetNSViewForSuperview();
        if(![sbarNSView superview])
            [m_frameNSView addSubview: sbarNSView];
        NSRect sbarRect = [sbarNSView frame];
        sbarRect.size.width = frameRect.size.width;
        sbarRect.origin.x = 0.0;
        sbarRect.origin.y = 0.0;
        [sbarNSView setFrame:sbarRect];
        // width expands, top margin expands
        [sbarNSView setAutoresizingMask: NSViewWidthSizable|NSViewMaxYMargin];
        sbarheight = sbarRect.size.height;
    }
    wxLogTrace(wxTRACE_COCOA,wxT("frame height=%f, tbar=%f, sbar=%f"),frameRect.size.height,tbarheight,sbarheight);
    NSRect innerRect = [m_cocoaNSView frame];
    innerRect.size.height = frameRect.size.height - tbarheight - sbarheight;
    innerRect.origin.y = sbarheight;
    [m_cocoaNSView setFrame:innerRect];
    [m_cocoaNSView setAutoresizingMask: NSViewWidthSizable|NSViewHeightSizable];
    // Don't let the frame get smaller than the toolbar+statusbar height
    NSRect frameMinRect = [NSWindow frameRectForContentRect:
            NSMakeRect(0.0,0.0,0.0,tbarheight+sbarheight)
        styleMask: [m_cocoaNSWindow styleMask]];
    [m_cocoaNSWindow setMinSize:frameMinRect.size];
}

void wxFrame::SetStatusBar(wxStatusBar *statusbar)
{
    if(m_frameStatusBar)
    {
        [m_frameStatusBar->GetNSViewForSuperview() removeFromSuperview];
        [m_frameStatusBar->GetNSViewForSuperview() setAutoresizingMask: NSViewMinYMargin];
        if(m_frameStatusBar->GetParent())
            m_frameStatusBar->GetParent()->CocoaAddChild(m_frameStatusBar);
    }
    m_frameStatusBar = statusbar;
    if(m_frameStatusBar)
    {
        m_frameStatusBar->CocoaRemoveFromParent();
    }
    UpdateFrameNSView();
}

wxStatusBar* wxFrame::CreateStatusBar(int number,
                                          long style,
                                          wxWindowID winid,
                                          const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    wxFrameBase::CreateStatusBar(number,style,winid,name);
    if(m_frameStatusBar)
    {
        m_frameStatusBar->CocoaRemoveFromParent();
    }
    UpdateFrameNSView();
    return m_frameStatusBar;
}

#if wxUSE_TOOLBAR
void wxFrame::SetToolBar(wxToolBar *toolbar)
{
    if(m_frameToolBar)
    {
        m_frameToolBar->SetOwningFrame(NULL);
        [m_frameToolBar->GetNSViewForSuperview() removeFromSuperview];
        [m_frameToolBar->GetNSViewForSuperview() setAutoresizingMask: NSViewMinYMargin];
        if(m_frameToolBar->GetParent())
            m_frameToolBar->GetParent()->CocoaAddChild(m_frameToolBar);
    }
    m_frameToolBar = toolbar;
    if(m_frameToolBar)
    {
        m_frameToolBar->CocoaRemoveFromParent();
        m_frameToolBar->SetOwningFrame(this);
    }
    UpdateFrameNSView();
}

wxToolBar* wxFrame::CreateToolBar(long style,
                                      wxWindowID winid,
                                      const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    return wxFrameBase::CreateToolBar(style,winid,name);
}
#endif // wxUSE_TOOLBAR

void wxFrame::PositionStatusBar()
{
}
