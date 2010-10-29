/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/filedlg.mm
// Purpose:     wxFileDialog for wxCocoa
// Author:      Ryan Norton
// Modified by:
// Created:     2004-10-02
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

#if wxUSE_FILEDLG

#include "wx/filedlg.h"

#ifndef WX_PRECOMP
    #include "wx/msgdlg.h"
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

IMPLEMENT_CLASS(wxCocoaFileDialog, wxFileDialogBase)

// ----------------------------------------------------------------------------
// wxFileDialog
// ----------------------------------------------------------------------------

wxFileDialog::wxFileDialog(wxWindow *parent,
                           const wxString& message,
                           const wxString& defaultDir,
                           const wxString& defaultFileName,
                           const wxString& wildCard,
                           long style,
                           const wxPoint& pos,
                           const wxSize& sz,
                           const wxString& name)
            : wxFileDialogBase(parent, message, defaultDir, defaultFileName,
                               wildCard, style, pos, sz, name)
{
    wxTopLevelWindows.Append(this);

    wxASSERT(CreateBase(parent,wxID_ANY,pos,wxDefaultSize,style,wxDefaultValidator,wxDialogNameStr));

    if ( parent )
        parent->AddChild(this);

    m_cocoaNSWindow = nil;
    m_cocoaNSView = nil;

    //Init the wildcard array
    m_wildcards = [[NSMutableArray alloc] initWithCapacity:0];

    //If the user requests to save - use a NSSavePanel
    //else use a NSOpenPanel
    if (HasFlag(wxFD_SAVE))
    {
        SetNSPanel([NSSavePanel savePanel]);

        [GetNSSavePanel() setTitle:wxNSStringWithWxString(message)];

        [GetNSSavePanel() setPrompt:@"Save"];
        [GetNSSavePanel() setTreatsFilePackagesAsDirectories:YES];
        [GetNSSavePanel() setCanSelectHiddenExtension:YES];

//        Cached as per-app in obj-c
//        [GetNSSavePanel() setExtensionHidden:YES];

        //
        // NB:  Note that only Panther supports wildcards
        // with save dialogs - not that wildcards in save
        // dialogs are all that useful, anyway :)
        //
    }
    else //m_dialogStyle & wxFD_OPEN
    {
        SetNSPanel([NSOpenPanel openPanel]);
        [m_cocoaNSWindow setTitle:wxNSStringWithWxString(message)];

        [(NSOpenPanel*)m_cocoaNSWindow setAllowsMultipleSelection:(HasFlag(wxFD_MULTIPLE))];
        [(NSOpenPanel*)m_cocoaNSWindow setResolvesAliases:YES];
        [(NSOpenPanel*)m_cocoaNSWindow setCanChooseFiles:YES];
        [(NSOpenPanel*)m_cocoaNSWindow setCanChooseDirectories:NO];
        [GetNSSavePanel() setPrompt:@"Open"];

        //convert wildcards - open panel only takes file extensions -
        //no actual wildcards here :)
        size_t lastwcpos = 0;
        bool bDescription = true;
        size_t i;
        for(i = wildCard.find('|');
                i != wxString::npos;
                i = wildCard.find('|', lastwcpos+1))
        {
            size_t oldi = i;

            if(!bDescription)
            {
                bDescription = !bDescription;

                //work backwards looking for a period
                while(i != lastwcpos && wildCard[--i] != '.') {}

                if(i == lastwcpos)
                {
                    //no extension - can't use this wildcard
                    lastwcpos = oldi;
                    continue;
                }

                [m_wildcards addObject:wxNSStringWithWxString(wildCard.substr(i+1, oldi-i-1))];
            }
            else
                bDescription = !bDescription;
            lastwcpos = oldi;
        }

        if (!bDescription)
        {
            //get last wildcard
            size_t oldi = wildCard.length();
            i = oldi;

            //work backwards looking for a period
            while(i != lastwcpos && wildCard[--i] != '.') {}

            if(i != lastwcpos)
                [m_wildcards addObject:wxNSStringWithWxString(wildCard.substr(i+1, oldi-i-1))];
        }

        if ([m_wildcards count] == 0)
        {
            [m_wildcards release];
            m_wildcards = nil;
        }
    }
}

wxFileDialog::~wxFileDialog()
{
    [m_wildcards release];
}

void wxFileDialog::GetPaths(wxArrayString& paths) const
{
    paths.Empty();

    wxString dir(m_dir);
    if ( m_dir.Last() != wxT('\\') )
        dir += wxT('\\');

    size_t count = m_fileNames.GetCount();
    for ( size_t n = 0; n < count; n++ )
    {
        if (wxFileName(m_fileNames[n]).IsAbsolute())
            paths.Add(m_fileNames[n]);
        else
            paths.Add(dir + m_fileNames[n]);
    }
}

void wxFileDialog::GetFilenames(wxArrayString& files) const
{
    files = m_fileNames;
}

void wxFileDialog::SetPath(const wxString& path)
{
    wxString ext;
    wxFileName::SplitPath(path, &m_dir, &m_fileName, &ext);
    if ( !ext.empty() )
        m_fileName << wxT('.') << ext;
}

int wxFileDialog::ShowModal()
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
                    types:m_wildcards];

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

#endif // wxUSE_FILEDLG
