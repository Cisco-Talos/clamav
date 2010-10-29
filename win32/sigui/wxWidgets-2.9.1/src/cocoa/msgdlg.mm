 /////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/dirdlg.mm
// Purpose:     wxMessageDialog for wxCocoa
// Author:      Gareth Simpson
// Created:     2007-10-09
// RCS-ID:      $Id$
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

#if wxUSE_MSGDLG


#include "wx/msgdlg.h"


#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif


#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <AppKit/NSAlert.h>
// ============================================================================
// implementation
// ============================================================================

IMPLEMENT_CLASS(wxCocoaMessageDialog, wxDialog)

// ----------------------------------------------------------------------------
// wxDirDialog
// ----------------------------------------------------------------------------

wxCocoaMessageDialog::wxCocoaMessageDialog(wxWindow *parent,
                                           const wxString& message,
                                           const wxString& caption,
                                           long style,
                                           const wxPoint& pos)
    : wxMessageDialogWithCustomLabels(parent, message, caption, style)
{

    wxTopLevelWindows.Append(this);

    wxASSERT(CreateBase(parent,wxID_ANY,wxDefaultPosition,wxDefaultSize,style,wxDefaultValidator,wxDialogNameStr));

    if ( parent )
        parent->AddChild(this);


    m_cocoaNSWindow = nil;
    m_cocoaNSView = nil;
}

void wxCocoaMessageDialog::DoSetCustomLabel(wxString& var, const ButtonLabel& value)
{
    wxMessageDialogWithCustomLabels::DoSetCustomLabel(var, value);

    var.Replace("&", "");
}

int wxCocoaMessageDialog::ShowModal()
{
    wxAutoNSAutoreleasePool thePool;

    NSAlert *alert = [[[NSAlert alloc] init] autorelease];

    const long style = GetMessageDialogStyle();

    NSAlertStyle nsStyle = NSInformationalAlertStyle;

    switch ( GetEffectiveIcon() )
    {
        case wxICON_ERROR:
            nsStyle = NSCriticalAlertStyle;
            break;

        case wxICON_WARNING:
            nsStyle = NSWarningAlertStyle;
            break;
    }

    [alert setAlertStyle:nsStyle];




    // work out what to display
    // if the extended text is empty then we use the caption as the title
    // and the message as the text (for backwards compatibility)
    // but if the extended message is not empty then we use the message as the title
    // and the extended message as the text because that makes more sense
    if (m_extendedMessage.empty())
    {
        [alert setMessageText:wxNSStringWithWxString(m_caption)];
        [alert setInformativeText:wxNSStringWithWxString(m_message)];
    }
    else
    {
        [alert setMessageText:wxNSStringWithWxString(m_message)];
        [alert setInformativeText:wxNSStringWithWxString(m_extendedMessage)];
    }

    //    The wxReturn value corresponding to each button
    int buttonId[4] = { 0, 0, 0, wxID_CANCEL /* time-out */ };
    if (style & wxYES_NO)
    {
        if ( style & wxNO_DEFAULT )
        {
            [alert addButtonWithTitle:wxNSStringWithWxString(GetNoLabel())];
            [alert addButtonWithTitle:wxNSStringWithWxString(GetYesLabel())];
            buttonId[0] = wxID_NO;
            buttonId[1] = wxID_YES;
        }
        else
        {
            [alert addButtonWithTitle:wxNSStringWithWxString(GetYesLabel())];
            [alert addButtonWithTitle:wxNSStringWithWxString(GetNoLabel())];
            buttonId[0] = wxID_YES;
            buttonId[1] = wxID_NO;
        }
        if (style & wxCANCEL)
        {
            [alert addButtonWithTitle:wxNSStringWithWxString(GetCancelLabel())];
            buttonId[2] = wxID_CANCEL;
        }
    }
    else
    {
        // the MSW implementation even shows an OK button if it is not specified, we'll do the same
        buttonId[0] = wxID_OK;
        // using null as default title does not work on earlier systems
        [alert addButtonWithTitle:wxNSStringWithWxString(GetOKLabel())];
        if (style & wxCANCEL)
        {
            [alert addButtonWithTitle:wxNSStringWithWxString(GetCancelLabel())];
            buttonId[1] = wxID_CANCEL;
        }
    }

    int ret = [alert runModal];


    return buttonId[ret-NSAlertFirstButtonReturn];
}

#endif // wxUSE_DIRDLG

