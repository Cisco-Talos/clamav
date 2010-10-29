/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/statbmp.mm
// Purpose:     wxStaticBitmap
// Author:      David Elliott
// Modified by:
// Created:     2003/02/15
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/statbmp.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif //WX_PRECOMP

#include "wx/cocoa/autorelease.h"

#import <AppKit/NSImageView.h>

IMPLEMENT_DYNAMIC_CLASS(wxStaticBitmap, wxControl)

BEGIN_EVENT_TABLE(wxStaticBitmap, wxControl)
END_EVENT_TABLE()
// WX_IMPLEMENT_COCOA_OWNER(wxStaticBitmap,NSTextField,NSControl,NSView)

bool wxStaticBitmap::Create(wxWindow *parent, wxWindowID winid,
           const wxBitmap& bitmap,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    if(!CreateControl(parent,winid,pos,size,style,wxDefaultValidator,name))
        return false;
    SetNSView([[NSImageView alloc] initWithFrame: MakeDefaultNSRect(size)]);
    [m_cocoaNSView release];

    [GetNSImageView() setImage:bitmap.GetNSImage(true)];
    m_bitmap = bitmap;

    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxStaticBitmap::~wxStaticBitmap()
{
}

void wxStaticBitmap::SetIcon(const wxIcon& icon)
{
}

void wxStaticBitmap::SetBitmap(const wxBitmap& bitmap)
{
    [GetNSImageView() setImage:bitmap.GetNSImage(true)];
    m_bitmap = bitmap;
}

wxBitmap wxStaticBitmap::GetBitmap() const
{
    return m_bitmap;
}
