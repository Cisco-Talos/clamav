/////////////////////////////////////////////////////////////////////////////
// Name:        cocoa/glcanvas.mm
// Purpose:     wxGLContext, wxGLCanvas
// Author:      David Elliott
// Modified by:
// Created:     2004/09/29
// RCS-ID:      $Id$
// Copyright:   (c) 2004 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_GLCANVAS

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif //WX_PRECOMP
#include "wx/glcanvas.h"

#include "wx/cocoa/autorelease.h"

#import <AppKit/NSOpenGL.h>
#import <AppKit/NSOpenGLView.h>

wxGLContext::wxGLContext(wxGLCanvas *win, const wxGLContext *other)
{
    // TODO
}

wxGLContext::~wxGLContext()
{
}

void wxGLContext::SetCurrent(const wxGLCanvas& win) const
{
    [[win.GetNSOpenGLView() openGLContext] makeCurrentContext];
}

IMPLEMENT_CLASS(wxGLCanvas, wxWindow)
// WX_IMPLEMENT_COCOA_OWNER(wxGLCanvas,NSOpenGLView,NSView,NSView)

bool wxGLCanvas::Create(wxWindow *parent,
                        wxWindowID winid,
                        const wxPoint& pos,
                        const wxSize& size,
                        long style,
                        const wxString& name,
                        const int *attribList,
                        const wxPalette& palette)
{
    wxAutoNSAutoreleasePool pool;
    if(!CreateBase(parent,winid,pos,size,style,wxDefaultValidator,name))
        return false;
    SetNSView([[NSOpenGLView alloc] initWithFrame: MakeDefaultNSRect(size)
                pixelFormat:[NSOpenGLView defaultPixelFormat]]);
    [m_cocoaNSView release];
    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxGLCanvas::~wxGLCanvas()
{
}

void wxGLCanvas::SwapBuffers()
{
    [[GetNSOpenGLView() openGLContext] flushBuffer];
}

#endif // wxUSE_GLCANVAS
