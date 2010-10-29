/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/dirdlg.mm
// Purpose:     wxDirDialog for wxCocoa
// Author:      Ryan Norton
// Modified by: Hiroyuki Nakamura(maloninc)
// Created:     2006-01-10
// RCS-ID:      $Id$
// Copyright:   (c) Ryan Norton
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

#if wxUSE_DIRDLG

#include "wx/dirdlg.h"

#ifndef WX_PRECOMP
    #include "wx/msgdlg.h"
    #include "wx/filedlg.h"
    #include "wx/app.h"
#endif

#include "wx/filename.h"

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <AppKit/NSOpenPanel.h>
#import <AppKit/NSSavePanel.h>

#import <Foundation/NSArray.h>
// ============================================================================
// implementation
// ============================================================================

IMPLEMENT_CLASS(wxCocoaDirDialog, wxDialog)

// ----------------------------------------------------------------------------
// wxDirDialog
// ----------------------------------------------------------------------------

wxDirDialog::wxDirDialog(wxWindow *parent, const wxString& message,
        const wxString& defaultPath, long style, const wxPoint& pos,
        const wxSize& size, const wxString& name)
{
    wxTopLevelWindows.Append(this);

    m_message = message;

    SetWindowStyle(style);
    m_parent = parent;
    m_path = defaultPath;

    wxASSERT(CreateBase(parent,wxID_ANY,pos,wxDefaultSize,style,wxDefaultValidator,wxDialogNameStr));

    if ( parent )
        parent->AddChild(this);

    m_cocoaNSWindow = nil;
    m_cocoaNSView = nil;

    //If the user requests to save - use a NSSavePanel
    //else use a NSOpenPanel
    if (HasFlag(wxFD_SAVE))
    {
        SetNSPanel([NSSavePanel savePanel]);

        [GetNSSavePanel() setTitle:wxNSStringWithWxString(message)];

        [GetNSSavePanel() setPrompt:@"Save"];
        [GetNSSavePanel() setTreatsFilePackagesAsDirectories:YES];
        [GetNSSavePanel() setCanSelectHiddenExtension:YES];
    }
    else //m_dialogStyle & wxFD_OPEN
    {
        SetNSPanel([NSOpenPanel openPanel]);
        [m_cocoaNSWindow setTitle:wxNSStringWithWxString(message)];

        [(NSOpenPanel*)m_cocoaNSWindow setResolvesAliases:YES];
        [(NSOpenPanel*)m_cocoaNSWindow setCanChooseFiles:NO];
        [(NSOpenPanel*)m_cocoaNSWindow setCanChooseDirectories:YES];
        [GetNSSavePanel() setPrompt:@"Open"];
    }

    if (HasFlag(wxDD_NEW_DIR_BUTTON)) //m_dialogStyle & wxDD_NEW_DIR_BUTTON
    {
        [(NSOpenPanel*)m_cocoaNSWindow setCanCreateDirectories:YES];
    }
}

wxDirDialog::~wxDirDialog()
{
}

int wxDirDialog::ShowModal()
{
    wxAutoNSAutoreleasePool thePool;

    m_fileNames.Empty();

    int nResult;

    if (HasFlag(wxFD_SAVE))
    {
        nResult = [GetNSSavePanel()
                    runModalForDirectory:wxNSStringWithWxString(m_dir)
                    file:wxNSStringWithWxString(m_fileName)];

        if (nResult == NSOKButton)
        {
            m_fileNames.Add(wxStringWithNSString([GetNSSavePanel() filename]));
            m_path = m_fileNames[0];
        }
    }
    else //m_dialogStyle & wxFD_OPEN
    {
        nResult = [(NSOpenPanel*)m_cocoaNSWindow
                    runModalForDirectory:wxNSStringWithWxString(m_dir)
                    file:wxNSStringWithWxString(m_fileName)
                    types:NULL];

        if (nResult == NSOKButton)
        {
            for(unsigned i = 0; i < [[(NSOpenPanel*)m_cocoaNSWindow filenames] count]; ++i)
            {
                m_fileNames.Add(wxStringWithNSString([[(NSOpenPanel*)m_cocoaNSWindow filenames] objectAtIndex:(i)]));
            }

            m_path = m_fileNames[0];
        }
    }

    return nResult == NSOKButton ? wxID_OK : wxID_CANCEL;
}

#endif // wxUSE_DIRDLG
