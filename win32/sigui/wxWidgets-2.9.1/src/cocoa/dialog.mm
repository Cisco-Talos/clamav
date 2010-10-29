/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/dialog.mm
// Purpose:     wxDialog class
// Author:      David Elliott
// Modified by:
// Created:     2002/12/15
// RCS-ID:      $Id$
// Copyright:   2002 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/dialog.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/settings.h"
#endif //WX_PRECOMP

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <AppKit/NSPanel.h>
#import <AppKit/NSApplication.h>
#import <AppKit/NSEvent.h>
#import <Foundation/NSRunLoop.h>

// Lists to keep track of windows, so we can disable/enable them
// for modal dialogs
static wxWindowList wxModalDialogs;

IMPLEMENT_DYNAMIC_CLASS(wxDialog, wxTopLevelWindow)

WX_IMPLEMENT_COCOA_OWNER(wxDialog,NSPanel,NSWindow,NSWindow)

void wxDialog::Init()
{
    m_isModal = false;
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_3DFACE));
}

bool wxDialog::Create(wxWindow *parent, wxWindowID winid,
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

    if (parent)
        parent->AddChild(this);

    unsigned int cocoaStyle = NSWindowStyleForWxStyle(style);

    NSRect cocoaRect = MakeInitialNSWindowContentRect(pos,size,cocoaStyle);

    m_cocoaNSWindow = NULL;
    SetNSPanel([[NSPanel alloc] initWithContentRect:cocoaRect styleMask:cocoaStyle backing:NSBackingStoreBuffered defer:NO]);
    // NOTE: SetNSWindow has retained the Cocoa object for this object.
    // Because we do not release on close, the following release matches the
    // above alloc and thus the retain count will be 1.
    [m_cocoaNSWindow release];
    wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("wxDialog m_cocoaNSWindow retainCount=%d"),[m_cocoaNSWindow retainCount]);
    [m_cocoaNSWindow setTitle:wxNSStringWithWxString(title)];
    [m_cocoaNSWindow setHidesOnDeactivate:NO];

    return true;
}

wxDialog::~wxDialog()
{
    DisassociateNSPanel(GetNSPanel());
}

void wxDialog::CocoaDelegate_windowWillClose(void)
{
    m_closed = true;
    /* Actually, this isn't true anymore */
    wxLogTrace(wxTRACE_COCOA,wxT("Woah: Dialogs are not generally closed"));
}

void wxDialog::SetModal(bool flag)
{
    wxFAIL_MSG( wxT("wxDialog:SetModal obsolete now") );
}

bool wxDialog::Show(bool show)
{
    if(m_isShown == show)
        return false;

    if(show)
    {
        wxAutoNSAutoreleasePool pool;

    	if (CanDoLayoutAdaptation())
        	DoLayoutAdaptation();

        InitDialog();
        if(IsModal())
        {   // ShowModal() will show the dialog
            m_isShown = true;
            return true;
        }
    }
    else
    {
        if(IsModal())
        {   // this doesn't hide the dialog, base class Show(false) does.
            wxLogTrace(wxTRACE_COCOA,wxT("abortModal"));
            [wxTheApp->GetNSApplication() abortModal];
            wxModalDialogs.DeleteObject(this);
            m_isModal = false;
        }
    }
    return wxTopLevelWindow::Show(show);
}

// Shows the dialog and begins a modal event loop.  When the event loop
// is stopped (via EndModal()) it returns the exit code.
int wxDialog::ShowModal()
{
    wxCHECK_MSG(!IsModal(),GetReturnCode(),wxT("wxDialog::ShowModal called within its own modal loop"));

    // Show(true) will set m_isShown = true
    m_isShown = false;
    m_isModal = true;
    wxModalDialogs.Append(this);

    wxLogTrace(wxTRACE_COCOA,wxT("runModal"));
    NSApplication *theNSApp = wxTheApp->GetNSApplication();
    // If the app hasn't started, flush the event queue
    // If we don't do this, the Dock doesn't get the message that
    // the app has started so will refuse to activate it.
    if(![theNSApp isRunning])
    {
        // We should only do a few iterations so one pool should be okay
        wxAutoNSAutoreleasePool pool;
        while(NSEvent *event = [theNSApp
                    nextEventMatchingMask:NSAnyEventMask
                    untilDate:[NSDate distantPast]
                    inMode:NSDefaultRunLoopMode
                    dequeue: YES])
        {
            [theNSApp sendEvent: event];
        }
    }

    Show(true);
    do {
        wxAutoNSAutoreleasePool pool;
        [wxTheApp->GetNSApplication() runModalForWindow:m_cocoaNSWindow];
    } while(0);
    wxLogTrace(wxTRACE_COCOA,wxT("runModal END"));

    return GetReturnCode();
}

void wxDialog::EndModal(int retCode)
{
    wxASSERT_MSG(IsModal(), wxT("EndModal() should only be used within ShowModal()"));
    SetReturnCode(retCode);
    Show(false);
}
