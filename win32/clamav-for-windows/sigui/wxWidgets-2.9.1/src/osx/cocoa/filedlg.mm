/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/filedlg.mm
// Purpose:     wxFileDialog for wxCocoa
// Author:      Ryan Norton
// Modified by:
// Created:     2004-10-02
// RCS-ID:      $Id: filedlg.mm 40007 2006-07-05 13:10:46Z SC $
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
#include "wx/tokenzr.h"

#include "wx/osx/private.h"

// ============================================================================
// implementation
// ============================================================================

// Open Items:
// - support for old style MacOS creator / type combos
// - parameter support for descending into packages as directories (setTreatsFilePackagesAsDirectories)

IMPLEMENT_CLASS(wxFileDialog, wxFileDialogBase)

wxFileDialog::wxFileDialog(
    wxWindow *parent, const wxString& message,
    const wxString& defaultDir, const wxString& defaultFileName, const wxString& wildCard,
    long style, const wxPoint& pos, const wxSize& sz, const wxString& name)
    : wxFileDialogBase(parent, message, defaultDir, defaultFileName, wildCard, style, pos, sz, name)
{
}

bool wxFileDialog::SupportsExtraControl() const
{
    return true;
}

NSArray* GetTypesFromFilter( const wxString filter )
{
    NSMutableArray* types = nil;
    if ( !filter.empty() )
    {
        wxArrayString names ;
        wxArrayString extensions;

        wxString filter2(filter) ;
        int filterIndex = 0;
        bool isName = true ;
        wxString current ;

        for ( unsigned int i = 0; i < filter2.length() ; i++ )
        {
            if ( filter2.GetChar(i) == wxT('|') )
            {
                if ( isName )
                {
                    names.Add( current ) ;
                }
                else
                {
                    extensions.Add( current ) ;
                    ++filterIndex ;
                }

                isName = !isName ;
                current = wxEmptyString ;
            }
            else
            {
                current += filter2.GetChar(i) ;
            }
        }
        // we allow for compatibility reason to have a single filter expression (like *.*) without
        // an explanatory text, in that case the first part is name and extension at the same time

        wxASSERT_MSG( filterIndex == 0 || !isName , wxT("incorrect format of format string") ) ;
        if ( current.empty() )
            extensions.Add( names[filterIndex] ) ;
        else
            extensions.Add( current ) ;
        if ( filterIndex == 0 || isName )
            names.Add( current ) ;

        ++filterIndex ;

        const size_t extCount = extensions.GetCount();
        for ( size_t i = 0 ; i < extCount; i++ )
        {
            wxString extensiongroup = extensions[i];
            wxStringTokenizer tokenizer( extensiongroup , wxT(";") ) ;
            while ( tokenizer.HasMoreTokens() )
            {
                wxString extension = tokenizer.GetNextToken() ;
                // Remove leading '*'
                if (extension.length() && (extension.GetChar(0) == '*'))
                    extension = extension.Mid( 1 );

                // Remove leading '.'
                if (extension.length() && (extension.GetChar(0) == '.'))
                    extension = extension.Mid( 1 );

                // Remove leading '*', this is for handling *.*
                if (extension.length() && (extension.GetChar(0) == '*'))
                    extension = extension.Mid( 1 );

                if ( extension.IsEmpty() )
                {
                    if ( types != nil )
                        [types release];
                    return nil;
                }

                if ( types == nil )
                    types = [[NSMutableArray alloc] init];

                wxCFStringRef cfext(extension);
                [types addObject: (NSString*)cfext.AsNSString()  ];
#if 0
                // add support for classic fileType / creator here
                wxUint32 fileType, creator;
                // extension -> mactypes
#endif
            }

        }
    }
    return types;
}

void wxFileDialog::ShowWindowModal()
{
    wxCFStringRef cf( m_message );
    wxCFStringRef dir( m_dir );
    wxCFStringRef file( m_fileName );

    wxNonOwnedWindow* parentWindow = NULL;
    
    m_modality = wxDIALOG_MODALITY_WINDOW_MODAL;

    if (GetParent())
        parentWindow = dynamic_cast<wxNonOwnedWindow*>(wxGetTopLevelParent(GetParent()));

    wxASSERT_MSG(parentWindow, "Window modal display requires parent.");
    
    if (HasFlag(wxFD_SAVE))
    {
        NSSavePanel* sPanel = [NSSavePanel savePanel];

        SetupExtraControls(sPanel);

        // makes things more convenient:
        [sPanel setCanCreateDirectories:YES];
        [sPanel setMessage:cf.AsNSString()];
        // if we should be able to descend into pacakges we must somehow
        // be able to pass this in
        [sPanel setTreatsFilePackagesAsDirectories:NO];
        [sPanel setCanSelectHiddenExtension:YES];
        
        NSWindow* nativeParent = parentWindow->GetWXWindow();
        ModalDialogDelegate* sheetDelegate = [[ModalDialogDelegate alloc] init];
        [sheetDelegate setImplementation: this];
        [sPanel beginSheetForDirectory:dir.AsNSString() file:file.AsNSString()
            modalForWindow: nativeParent modalDelegate: sheetDelegate
            didEndSelector: @selector(sheetDidEnd:returnCode:contextInfo:)
            contextInfo: nil];
    }
    else 
    {
        NSArray* types = GetTypesFromFilter( m_wildCard ) ;
        NSOpenPanel* oPanel = [NSOpenPanel openPanel];
        
        SetupExtraControls(oPanel);

        [oPanel setTreatsFilePackagesAsDirectories:NO];
        [oPanel setCanChooseDirectories:NO];
        [oPanel setResolvesAliases:YES];
        [oPanel setCanChooseFiles:YES];
        [oPanel setMessage:cf.AsNSString()];
    
        NSWindow* nativeParent = parentWindow->GetWXWindow();
        ModalDialogDelegate* sheetDelegate = [[ModalDialogDelegate alloc] init];
        [sheetDelegate setImplementation: this];
        [oPanel beginSheetForDirectory:dir.AsNSString() file:file.AsNSString()
            types: types modalForWindow: nativeParent
            modalDelegate: sheetDelegate
            didEndSelector: @selector(sheetDidEnd:returnCode:contextInfo:)
            contextInfo: nil];
    }
}

void wxFileDialog::SetupExtraControls(WXWindow nativeWindow)
{
    NSSavePanel* panel = (NSSavePanel*) nativeWindow;
    
    wxNonOwnedWindow::Create( GetParent(), nativeWindow );
    
    if (HasExtraControlCreator())
    {
        CreateExtraControl();
        wxWindow* control = GetExtraControl();
        if ( control )
        {
            NSView* accView = control->GetHandle();
            [accView removeFromSuperview];
            [panel setAccessoryView:accView];
        }
        else
        {
            [panel setAccessoryView:nil];
        }
    }
}

int wxFileDialog::ShowModal()
{
    wxCFStringRef cf( m_message );

    wxCFStringRef dir( m_dir );
    wxCFStringRef file( m_fileName );

    m_path = wxEmptyString;
    m_fileNames.Clear();
    m_paths.Clear();
    // since we don't support retrieving the matching filter
    m_filterIndex = -1;

    wxNonOwnedWindow* parentWindow = NULL;
    int returnCode = -1;

    if (GetParent())
    {
        parentWindow = dynamic_cast<wxNonOwnedWindow*>(wxGetTopLevelParent(GetParent()));
    }

    if (HasFlag(wxFD_SAVE))
    {
        NSSavePanel* sPanel = [NSSavePanel savePanel];

        SetupExtraControls(sPanel);

        // makes things more convenient:
        [sPanel setCanCreateDirectories:YES];
        [sPanel setMessage:cf.AsNSString()];
        // if we should be able to descend into pacakges we must somehow
        // be able to pass this in
        [sPanel setTreatsFilePackagesAsDirectories:NO];
        [sPanel setCanSelectHiddenExtension:YES];

        if ( HasFlag(wxFD_OVERWRITE_PROMPT) )
        {
        }

        returnCode = [sPanel runModalForDirectory:dir.AsNSString() file:file.AsNSString() ];
        ModalFinishedCallback(sPanel, returnCode);

        [sPanel setAccessoryView:nil];
    }
    else
    {
        NSArray* types = GetTypesFromFilter( m_wildCard ) ;
        NSOpenPanel* oPanel = [NSOpenPanel openPanel];
        
        SetupExtraControls(oPanel);
                
        [oPanel setTreatsFilePackagesAsDirectories:NO];
        [oPanel setCanChooseDirectories:NO];
        [oPanel setResolvesAliases:YES];
        [oPanel setCanChooseFiles:YES];
        [oPanel setMessage:cf.AsNSString()];

        returnCode = [oPanel runModalForDirectory:dir.AsNSString()
                        file:file.AsNSString() types:types];

        ModalFinishedCallback(oPanel, returnCode);
        
        [oPanel setAccessoryView:nil];
        
        if ( types != nil )
            [types release];
    }

    return GetReturnCode();
}

void wxFileDialog::ModalFinishedCallback(void* panel, int returnCode)
{
    int result = wxID_CANCEL;
    if (HasFlag(wxFD_SAVE))
    {
        if (returnCode == NSOKButton )
        {
            NSSavePanel* sPanel = (NSSavePanel*)panel;
            result = wxID_OK;

            m_path = wxCFStringRef::AsString([sPanel filename]);
            m_fileName = wxFileNameFromPath(m_path);
            m_dir = wxPathOnly( m_path );
        }
    }
    else
    {
        NSOpenPanel* oPanel = (NSOpenPanel*)panel;
        if (returnCode == NSOKButton )
        {
            panel = oPanel;
            result = wxID_OK;
            NSArray* filenames = [oPanel filenames];
            for ( size_t i = 0 ; i < [filenames count] ; ++ i )
            {
                wxString fnstr = wxCFStringRef::AsString([filenames objectAtIndex:i]);
                m_paths.Add( fnstr );
                m_fileNames.Add( wxFileNameFromPath(fnstr) );
                if ( i == 0 )
                {
                    m_path = fnstr;
                    m_fileName = wxFileNameFromPath(fnstr);
                    m_dir = wxPathOnly( fnstr );
                }
            }
        }
    }
    SetReturnCode(result);
    
    if (GetModality() == wxDIALOG_MODALITY_WINDOW_MODAL)
        SendWindowModalDialogEvent ( wxEVT_WINDOW_MODAL_DIALOG_CLOSED  );
    
    [(NSSavePanel*) panel setAccessoryView:nil];
}

#endif // wxUSE_FILEDLG
