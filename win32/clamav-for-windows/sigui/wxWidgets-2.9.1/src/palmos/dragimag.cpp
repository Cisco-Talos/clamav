/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/dragimag.cpp
// Purpose:     wxDragImage
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10.13.04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
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

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_DRAGIMAGE

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/window.h"
    #include "wx/dcclient.h"
    #include "wx/dcscreen.h"
    #include "wx/dcmemory.h"
    #include "wx/settings.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/frame.h"
    #include "wx/image.h"
#endif

#include "wx/palmos/dragimag.h"
#include "wx/palmos/private.h"

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxDragImage, wxObject)

#define GetHimageList() ((HIMAGELIST) m_hImageList)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxDragImage ctors/dtor
// ----------------------------------------------------------------------------

wxDragImage::wxDragImage()
{
}

wxDragImage::~wxDragImage()
{
}

void wxDragImage::Init()
{
}

// Attributes
////////////////////////////////////////////////////////////////////////////


// Operations
////////////////////////////////////////////////////////////////////////////

// Create a drag image from a bitmap and optional cursor
bool wxDragImage::Create(const wxBitmap& image, const wxCursor& cursor)
{
    return false;
}

// Create a drag image from an icon and optional cursor
bool wxDragImage::Create(const wxIcon& image, const wxCursor& cursor)
{
    return false;
}

// Create a drag image from a string and optional cursor
bool wxDragImage::Create(const wxString& str, const wxCursor& cursor)
{
    return false;
}

#if wxUSE_TREECTRL
// Create a drag image for the given tree control item
bool wxDragImage::Create(const wxTreeCtrl& treeCtrl, wxTreeItemId& id)
{
    return false;
}
#endif

#if wxUSE_LISTCTRL
// Create a drag image for the given list control item
bool wxDragImage::Create(const wxListCtrl& listCtrl, long id)
{
    return false;
}
#endif

// Begin drag
bool wxDragImage::BeginDrag(const wxPoint& hotspot, wxWindow* window, bool fullScreen, wxRect* rect)
{
    return false;
}

// Begin drag. hotspot is the location of the drag position relative to the upper-left
// corner of the image. This is full screen only. fullScreenRect gives the
// position of the window on the screen, to restrict the drag to.
bool wxDragImage::BeginDrag(const wxPoint& hotspot, wxWindow* window, wxWindow* fullScreenRect)
{
    return false;
}

// End drag
bool wxDragImage::EndDrag()
{
    return false;
}

// Move the image: call from OnMouseMove. Pt is in window client coordinates if window
// is non-NULL, or in screen coordinates if NULL.
bool wxDragImage::Move(const wxPoint& pt)
{
    return false;
}

bool wxDragImage::Show()
{
    return false;
}

bool wxDragImage::Hide()
{
    return false;
}


#endif // wxUSE_DRAGIMAGE
