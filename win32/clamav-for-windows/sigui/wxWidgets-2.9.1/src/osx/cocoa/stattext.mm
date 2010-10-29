/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/cocoa/stattext.mm
// Purpose:     wxStaticText
// Author:      Stefan Csomor
// Modified by:
// Created:     04/01/98
// RCS-ID:      $Id: stattext.cpp 54845 2008-07-30 14:52:41Z SC $
// Copyright:   (c) Stefan Csomor
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_STATTEXT

#include "wx/stattext.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/dc.h"
    #include "wx/dcclient.h"
    #include "wx/settings.h"
#endif // WX_PRECOMP

#include "wx/osx/private.h"

#include <stdio.h>

@interface wxNSStaticTextView : NSTextField
{
}
@end

@implementation wxNSStaticTextView

+ (void)initialize
{
    static BOOL initialized = NO;
    if (!initialized)
    {
        initialized = YES;
        wxOSXCocoaClassAddWXMethods( self );
    }
}

@end

class wxStaticTextCocoaImpl : public wxWidgetCocoaImpl
{
public:
    wxStaticTextCocoaImpl( wxWindowMac* peer , WXWidget w , NSLineBreakMode lineBreak) : wxWidgetCocoaImpl(peer, w)
    {
        m_lineBreak = lineBreak;
    }

    virtual void SetLabel(const wxString& title, wxFontEncoding encoding)
    {
        wxNSStaticTextView* v = (wxNSStaticTextView*)GetWXWidget();
        wxWindow* wxpeer = GetWXPeer();
        NSCell* cell = [v cell];
        wxCFStringRef text( title , encoding );

        NSMutableParagraphStyle *paragraphStyle = [[NSMutableParagraphStyle alloc] init];
        [paragraphStyle setLineBreakMode:m_lineBreak];
        int style = wxpeer->GetWindowStyleFlag();
        if (style & wxALIGN_CENTER)
            [paragraphStyle setAlignment: NSCenterTextAlignment];
        else if (style & wxALIGN_RIGHT)
            [paragraphStyle setAlignment: NSRightTextAlignment];

        NSDictionary *dict = [NSDictionary dictionaryWithObjectsAndKeys:paragraphStyle, NSParagraphStyleAttributeName, nil];
        NSAttributedString *attrstring = [[NSAttributedString alloc] initWithString:text.AsNSString() attributes:dict];
        [cell setAttributedStringValue:attrstring];
        [attrstring release];
        [paragraphStyle release];
    }
private :
    NSLineBreakMode m_lineBreak;
};

wxSize wxStaticText::DoGetBestSize() const
{
    return wxWindowMac::DoGetBestSize() ;
}

wxWidgetImplType* wxWidgetImpl::CreateStaticText( wxWindowMac* wxpeer,
                                    wxWindowMac* WXUNUSED(parent),
                                    wxWindowID WXUNUSED(id),
                                    const wxString& WXUNUSED(label),
                                    const wxPoint& pos,
                                    const wxSize& size,
                                    long style,
                                    long WXUNUSED(extraStyle))
{
    NSRect r = wxOSXGetFrameForControl( wxpeer, pos , size ) ;
    wxNSStaticTextView* v = [[wxNSStaticTextView alloc] initWithFrame:r];

    [v setEditable:NO];
    [v setDrawsBackground:NO];
    [v setSelectable: NO];
    [v setBezeled:NO];
    [v setBordered:NO];

    NSLineBreakMode linebreak = NSLineBreakByWordWrapping;
    if ( ((wxStaticText*)wxpeer)->IsEllipsized() )
    {
        if ( style & wxST_ELLIPSIZE_MIDDLE )
            linebreak = NSLineBreakByTruncatingMiddle;
        else if (style & wxST_ELLIPSIZE_END )
            linebreak = NSLineBreakByTruncatingTail;
        else if (style & wxST_ELLIPSIZE_START )
            linebreak = NSLineBreakByTruncatingHead;
    }
    else
    {
        [[v cell] setWraps:YES];
    }

    wxWidgetCocoaImpl* c = new wxStaticTextCocoaImpl( wxpeer, v, linebreak );
    return c;
}

#endif //if wxUSE_STATTEXT
