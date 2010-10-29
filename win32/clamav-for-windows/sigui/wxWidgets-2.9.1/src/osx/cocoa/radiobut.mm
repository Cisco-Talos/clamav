/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/cocoa/radiobut.mm
// Purpose:     wxRadioButton
// Author:      Stefan Csomor
// Modified by:
// Created:     ??/??/98
// RCS-ID:      $Id: radiobut.cpp 54129 2008-06-11 19:30:52Z SC $
// Copyright:   (c) AUTHOR
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_RADIOBTN

#include "wx/radiobut.h"
#include "wx/osx/private.h"

wxWidgetImplType* wxWidgetImpl::CreateRadioButton( wxWindowMac* wxpeer,
                                    wxWindowMac* WXUNUSED(parent),
                                    wxWindowID WXUNUSED(id),
                                    const wxString& WXUNUSED(label),
                                    const wxPoint& pos,
                                    const wxSize& size,
                                    long WXUNUSED(style),
                                    long WXUNUSED(extraStyle))
{
    NSRect r = wxOSXGetFrameForControl( wxpeer, pos , size ) ;
    wxNSButton* v = [[wxNSButton alloc] initWithFrame:r];

    [v setButtonType:NSRadioButton];

    wxWidgetCocoaImpl* c = new wxWidgetCocoaImpl( wxpeer, v );
    return c;
}

#endif
