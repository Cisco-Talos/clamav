///////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/toplevel.mm
// Purpose:     implements wxTopLevelWindow for Cocoa
// Author:      David Elliott
// Modified by:
// Created:     2002/11/27
// RCS-ID:      $Id$
// Copyright:   (c) 2002 David Elliott
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

#include "wx/toplevel.h"

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/menuitem.h"
    #include "wx/frame.h"
    #include "wx/log.h"
    #include "wx/app.h"
#endif //WX_PRECOMP

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"
#include "wx/cocoa/ObjcRef.h"

#include "wx/cocoa/objc/NSView.h"
#include "wx/cocoa/objc/NSWindow.h"
#import <AppKit/NSPanel.h>
#import <AppKit/NSButtonCell.h>
#import <AppKit/NSControl.h>

// ----------------------------------------------------------------------------
// globals
// ----------------------------------------------------------------------------

// list of all frames and modeless dialogs
wxWindowList       wxModelessWindows;

// ============================================================================
// wxTopLevelWindowCocoa implementation
// ============================================================================

wxTopLevelWindowCocoa *wxTopLevelWindowCocoa::sm_cocoaDeactivateWindow = NULL;

// ----------------------------------------------------------------------------
// wxTopLevelWindowCocoa creation
// ----------------------------------------------------------------------------
BEGIN_EVENT_TABLE(wxTopLevelWindowCocoa,wxTopLevelWindowBase)
    EVT_CLOSE(wxTopLevelWindowCocoa::OnCloseWindow)
END_EVENT_TABLE()

void wxTopLevelWindowCocoa::Init()
{
    m_iconized =
    m_maximizeOnShow =
    m_closed = false;
}

unsigned int wxTopLevelWindowCocoa::NSWindowStyleForWxStyle(long style)
{
    unsigned int styleMask = 0;
    if(style & wxCAPTION)
        styleMask |= NSTitledWindowMask;
    if(style & wxMINIMIZE_BOX)
        styleMask |= NSMiniaturizableWindowMask;
    #if 0
    if(style & wxMAXIMIZE_BOX)
        styleMask |= NSWindowMask;
        #endif
    if(style & wxCLOSE_BOX)
        styleMask |= NSClosableWindowMask;
    if(style & wxRESIZE_BORDER)
        styleMask |= NSResizableWindowMask;
    if(style & wxSIMPLE_BORDER)
        styleMask |= NSBorderlessWindowMask;
    return styleMask;
}

NSRect wxTopLevelWindowCocoa::MakeInitialNSWindowContentRect(const wxPoint& pos, const wxSize& size, unsigned int cocoaStyleMask)
{
    // Arbitrarily use (100,100) as the origin when default coords are given.
    wxCoord x = pos.x!=wxDefaultCoord ? pos.x : 100;
    wxCoord y = pos.y!=wxDefaultCoord ? pos.y : 100;

    wxCoord w = WidthDefault(size.x);
    wxCoord h = HeightDefault(size.y);

    NSPoint cocoaOrigin = OriginInCocoaScreenCoordinatesForRectInWxDisplayCoordinates(x,y,w,h,true);

    return [NSWindow
            contentRectForFrameRect:NSMakeRect(cocoaOrigin.x,cocoaOrigin.y,w,h)
            styleMask:cocoaStyleMask];

}

bool wxTopLevelWindowCocoa::Create(wxWindow *parent,
                                 wxWindowID winid,
                                 const wxString& title,
                                 const wxPoint& pos,
                                 const wxSize& size,
                                 long style,
                                 const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    wxTopLevelWindows.Append(this);

    if(!CreateBase(parent,winid,pos,size,style,wxDefaultValidator,name))
        return false;

    if ( parent )
        parent->AddChild(this);

    unsigned int cocoaStyle = NSWindowStyleForWxStyle(style);
    if(style & wxFRAME_TOOL_WINDOW)
        cocoaStyle |= NSUtilityWindowMask;

    NSRect cocoaRect = MakeInitialNSWindowContentRect(pos,size,cocoaStyle);

    m_cocoaNSWindow = NULL;
    m_cocoaNSView = NULL;
    // NOTE: We may need to deal with the contentView becoming a wx NSView as well.
    NSWindow *newWindow;
    // Create a WXNSPanel or a WXNSWindow depending on what type of window is desired.
    if(style & wxFRAME_TOOL_WINDOW)
        newWindow = [[WX_GET_OBJC_CLASS(WXNSPanel) alloc] initWithContentRect:cocoaRect styleMask:cocoaStyle backing:NSBackingStoreBuffered defer:NO];
    else
        newWindow = [[WX_GET_OBJC_CLASS(WXNSWindow) alloc] initWithContentRect:cocoaRect styleMask:cocoaStyle backing:NSBackingStoreBuffered defer:NO];
    // Make sure the default content view is a WXNSView
    [newWindow setContentView: [[WX_GET_OBJC_CLASS(WXNSView) alloc] initWithFrame: [[newWindow contentView] frame]]];
    // Associate the window and view
    SetNSWindow(newWindow);

    // NOTE: SetNSWindow has retained the Cocoa object for this object.
    // Because we do not release on close, the following release matches the
    // above alloc and thus the retain count will be 1.
    [m_cocoaNSWindow release];

    if(style & wxFRAME_NO_TASKBAR)
        [m_cocoaNSWindow setExcludedFromWindowsMenu: YES];
    if(style & wxSTAY_ON_TOP)
        [m_cocoaNSWindow setLevel:NSFloatingWindowLevel];
    [m_cocoaNSWindow setTitle:wxNSStringWithWxString(title)];
    return true;
}

wxTopLevelWindowCocoa::~wxTopLevelWindowCocoa()
{
    wxASSERT(sm_cocoaDeactivateWindow!=this);
    wxAutoNSAutoreleasePool pool;
    DestroyChildren();
    if(m_cocoaNSView)
        SendDestroyEvent();
    SetNSWindow(NULL);
}

bool wxTopLevelWindowCocoa::Destroy()
{
    if(sm_cocoaDeactivateWindow==this)
    {
        sm_cocoaDeactivateWindow = NULL;
        wxTopLevelWindowCocoa::CocoaDelegate_windowDidResignKey();
    }
    return wxTopLevelWindowBase::Destroy();
}

// ----------------------------------------------------------------------------
// wxTopLevelWindowCocoa Cocoa Specifics
// ----------------------------------------------------------------------------

wxMenuBar* wxTopLevelWindowCocoa::GetAppMenuBar(wxCocoaNSWindow *win)
{
    wxTopLevelWindowCocoa *parent = wxDynamicCast(GetParent(),wxTopLevelWindow);
    if(parent)
        return parent->GetAppMenuBar(win);
    return NULL;
}

void wxTopLevelWindowCocoa::SetNSWindow(WX_NSWindow cocoaNSWindow)
{
    bool need_debug = cocoaNSWindow || m_cocoaNSWindow;
    if(need_debug) wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("wxTopLevelWindowCocoa=%p::SetNSWindow [m_cocoaNSWindow=%p retainCount]=%d"),this,m_cocoaNSWindow,[m_cocoaNSWindow retainCount]);
    DisassociateNSWindow(m_cocoaNSWindow);
    wxGCSafeRetain(cocoaNSWindow);
    wxGCSafeRelease(m_cocoaNSWindow);
    m_cocoaNSWindow = cocoaNSWindow;
    // NOTE: We are no longer using posing so we won't get events on the
    // window's view unless it was explicitly created as the wx view class.
    if(m_cocoaNSWindow)
        SetNSView([m_cocoaNSWindow contentView]);
    else
        SetNSView(NULL);
    AssociateNSWindow(m_cocoaNSWindow);
    if(need_debug) wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("wxTopLevelWindowCocoa=%p::SetNSWindow [cocoaNSWindow=%p retainCount]=%d"),this,cocoaNSWindow,[cocoaNSWindow retainCount]);
}

void wxTopLevelWindowCocoa::CocoaReplaceView(WX_NSView oldView, WX_NSView newView)
{
    if([m_cocoaNSWindow contentView] == (id)oldView)
        [m_cocoaNSWindow setContentView:newView];
}

/*static*/ void wxTopLevelWindowCocoa::DeactivatePendingWindow()
{
    if(sm_cocoaDeactivateWindow)
        sm_cocoaDeactivateWindow->wxTopLevelWindowCocoa::CocoaDelegate_windowDidResignKey();
    sm_cocoaDeactivateWindow = NULL;
}

void wxTopLevelWindowCocoa::CocoaDelegate_windowDidBecomeKey(void)
{
    DeactivatePendingWindow();
    wxLogTrace(wxTRACE_COCOA,wxT("wxTopLevelWindowCocoa=%p::CocoaDelegate_windowDidBecomeKey"),this);
    wxActivateEvent event(wxEVT_ACTIVATE, true, GetId());
    event.SetEventObject(this);
    HandleWindowEvent(event);
}

void wxTopLevelWindowCocoa::CocoaDelegate_windowDidResignKey(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxTopLevelWindowCocoa=%p::CocoaDelegate_windowDidResignKey"),this);
    wxActivateEvent event(wxEVT_ACTIVATE, false, GetId());
    event.SetEventObject(this);
    HandleWindowEvent(event);
}

void wxTopLevelWindowCocoa::CocoaDelegate_windowDidBecomeMain(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxTopLevelWindowCocoa=%p::CocoaDelegate_windowDidBecomeMain"),this);
}

void wxTopLevelWindowCocoa::CocoaDelegate_windowDidResignMain(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxTopLevelWindowCocoa=%p::CocoaDelegate_windowDidResignMain"),this);
}

void wxTopLevelWindowCocoa::CocoaDelegate_windowWillClose(void)
{
    m_closed = true;
    Destroy();
}

bool wxTopLevelWindowCocoa::CocoaDelegate_windowShouldClose()
{
    return wxWindowBase::Close(false);
}

void wxTopLevelWindowCocoa::CocoaDelegate_wxMenuItemAction(WX_NSMenuItem menuItem)
{
}

bool wxTopLevelWindowCocoa::CocoaDelegate_validateMenuItem(WX_NSMenuItem menuItem)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxTopLevelWindowCocoa maximize/minimize
// ----------------------------------------------------------------------------

void wxTopLevelWindowCocoa::Maximize(bool maximize)
{
}

bool wxTopLevelWindowCocoa::IsMaximized() const
{
    return false ;
}

void wxTopLevelWindowCocoa::Iconize(bool iconize)
{
}

bool wxTopLevelWindowCocoa::IsIconized() const
{
    return false;
}

void wxTopLevelWindowCocoa::Restore()
{
}

bool wxTopLevelWindowCocoa::Show(bool show)
{
    if(m_isShown == show)
        return false;
    wxAutoNSAutoreleasePool pool;
    if(show)
    {
        // Send the window a size event because wxWidgets apps expect it
        // NOTE: This should really only be done the first time a window
        // is shown.  I doubt this will cause any problems though.
        wxSizeEvent event(GetSize(), GetId());
        event.SetEventObject(this);
        HandleWindowEvent(event);

        [m_cocoaNSWindow makeKeyAndOrderFront:m_cocoaNSWindow];
    }
    else
        [m_cocoaNSWindow orderOut:m_cocoaNSWindow];
    m_isShown = show;
    return true;
}

bool wxTopLevelWindowCocoa::Close(bool force)
{
    if(force)
        return wxWindowBase::Close(force);
    // performClose  will fake the user clicking the close button which
    // will invoke windowShouldClose which will call the base class version
    // of Close() which will NOT Destroy() the window (see below) but
    // if closing is not stopped, then performClose will go ahead and
    // close the window which will send the close notifications setting
    // m_closed to true and Destroy()ing the window.
    [m_cocoaNSWindow performClose:m_cocoaNSWindow];
    return m_closed;
}

void wxTopLevelWindowCocoa::OnCloseWindow(wxCloseEvent& event)
{
    // If the event was forced, close the window which will Destroy() it
    if(!event.CanVeto())
        [m_cocoaNSWindow close];
    // if the event was not forced, it's probably because the user clicked
    // the close button, or Close(false) was called which (see above) is
    // redirected to performClose and thus Cocoa itself will close the window
}

// ----------------------------------------------------------------------------
// wxTopLevelWindowCocoa misc
// ----------------------------------------------------------------------------

void wxTopLevelWindowCocoa::SetTitle(const wxString& title)
{
    [m_cocoaNSWindow setTitle:wxNSStringWithWxString(title)];
}

wxString wxTopLevelWindowCocoa::GetTitle() const
{
    return wxStringWithNSString([m_cocoaNSWindow title]);
}

wxWindow* wxTopLevelWindowCocoa::SetDefaultItem(wxWindow *win)
{
    wxWindow *old = wxTopLevelWindowBase::SetDefaultItem(win);

    NSCell *newCell;
    if(win != NULL)
    {
        NSView *newView = win->GetNSView();
        // newView does not have to be an NSControl, we only cast to NSControl*
        // to silence the warning about cell not being implemented.
        if(newView != nil && [newView respondsToSelector:@selector(cell)])
            newCell = [(NSControl*)newView cell];
        else
            newCell = nil;
    
        if(newCell != nil && ![newCell isKindOfClass:[NSButtonCell class]])
        {   // It's not an NSButtonCell, set the default to nil.
            newCell = nil;
        }
    }
    else
        newCell = nil;

    [GetNSWindow() setDefaultButtonCell:(NSButtonCell*)newCell];
    return old;
}

bool wxTopLevelWindowCocoa::ShowFullScreen(bool show, long style)
{
    return false;
}

bool wxTopLevelWindowCocoa::IsFullScreen() const
{
    return false;
}

void wxTopLevelWindowCocoa::CocoaSetWxWindowSize(int width, int height)
{
    // Set the NSView size by setting the frame size to enclose it
    unsigned int styleMask = [m_cocoaNSWindow styleMask];
    NSRect oldFrameRect = [m_cocoaNSWindow frame];
    NSRect contentRect = [NSWindow
        contentRectForFrameRect: oldFrameRect
        styleMask: styleMask];
    contentRect.size.width = width;
    contentRect.size.height = height;
    NSRect newFrameRect = [NSWindow
        frameRectForContentRect: contentRect
        styleMask: styleMask];

    // Cocoa uses +y is up but wxWidgets uses +y is down.  We want an increase/decrease in height
    // to not effect where the top of the window is placed so we set the new y origin relative the
    // old one taking the height change into account.
    newFrameRect.origin.y = oldFrameRect.origin.y + oldFrameRect.size.height - newFrameRect.size.height;
    
    [m_cocoaNSWindow setFrame: newFrameRect display: NO];
}

void wxTopLevelWindowCocoa::DoMoveWindow(int x, int y, int width, int height)
{
    wxLogTrace(wxTRACE_COCOA_TopLevelWindow_Size,wxT("wxTopLevelWindow=%p::DoMoveWindow(%d,%d,%d,%d)"),this,x,y,width,height);

    NSPoint cocoaOrigin = OriginInCocoaScreenCoordinatesForRectInWxDisplayCoordinates(x,y,width,height,false);

    NSRect cocoaRect = NSMakeRect(cocoaOrigin.x,cocoaOrigin.y,width,height);
    [m_cocoaNSWindow setFrame: cocoaRect display:NO];
}

void wxTopLevelWindowCocoa::DoGetSize(int *w, int *h) const
{
    NSRect cocoaRect = [m_cocoaNSWindow frame];
    if(w)
        *w=(int)cocoaRect.size.width;
    if(h)
        *h=(int)cocoaRect.size.height;
    wxLogTrace(wxTRACE_COCOA_TopLevelWindow_Size,wxT("wxTopLevelWindow=%p::DoGetSize = (%d,%d)"),this,(int)cocoaRect.size.width,(int)cocoaRect.size.height);
}

void wxTopLevelWindowCocoa::DoGetPosition(int *x, int *y) const
{
    NSRect windowFrame = [m_cocoaNSWindow frame];
    
    wxPoint theWxOrigin = OriginInWxDisplayCoordinatesForRectInCocoaScreenCoordinates(windowFrame);

    if(*x)
        *x = theWxOrigin.x;
    if(*y)
        *y = theWxOrigin.y;
    
    wxLogTrace(wxTRACE_COCOA_TopLevelWindow_Size,wxT("wxTopLevelWindow=%p::DoGetPosition = (%d,%d)"),this,(int)theWxOrigin.x,(int)theWxOrigin.y);
}
