/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/dcmemory.mm
// Purpose:     wxMemoryDCImpl class
// Author:      David Elliott
// Modified by:
// Created:     2003/03/16
// RCS-ID:      $Id$
// Copyright:   (c) 2002 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif //WX_PRECOMP

#include "wx/cocoa/dcmemory.h"
#include "wx/cocoa/autorelease.h"

#import <AppKit/NSImage.h>
#import <AppKit/NSAffineTransform.h>
#import <AppKit/NSGraphicsContext.h>
#import <AppKit/NSColor.h>
#import <AppKit/NSBezierPath.h>

//-----------------------------------------------------------------------------
// wxMemoryDCImpl
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxMemoryDCImpl,wxCocoaDCImpl)

void wxMemoryDCImpl::Init()
{
    m_cocoaNSImage = NULL;
    m_ok = false;
}

wxMemoryDCImpl::wxMemoryDCImpl(wxMemoryDC *owner, wxDC *WXUNUSED(dc))
:   wxCocoaDCImpl(owner)
{
    Init();
}

wxMemoryDCImpl::~wxMemoryDCImpl(void)
{
    CocoaUnwindStackAndLoseFocus();
    [m_cocoaNSImage release];
}

bool wxMemoryDCImpl::CocoaLockFocus()
{
    if(m_cocoaNSImage)
    {
        [m_cocoaNSImage lockFocus];
        sm_cocoaDCStack.Insert(this);
        NSAffineTransform *newTransform = CocoaGetWxToBoundsTransform([m_cocoaNSImage isFlipped], [m_cocoaNSImage size].height);
        [newTransform retain];
        [m_cocoaWxToBoundsTransform release];
        m_cocoaWxToBoundsTransform = newTransform;
        CocoaApplyTransformations();
        return true;
    }
    return false;
}

bool wxMemoryDCImpl::CocoaUnlockFocus()
{
    [m_cocoaNSImage unlockFocus];
    return true;
}

// NOTE: The AppKit is unable to draw onto an NSBitmapImageRep so we must
// instead copy the data to an offscreen window, then copy it back
void wxMemoryDCImpl::DoSelect( const wxBitmap& bitmap )
{
    wxAutoNSAutoreleasePool pool;
    if(m_selectedBitmap.Ok())
    {
        CocoaTakeFocus();
        wxASSERT(m_cocoaNSImage);
        // Replace the bitmap's native data with a newly created one based on the
        // NSImage that has been (potentially) drawn upon.  Note that this may and
        // probably will in many cases change the bitmap's format.
        // There is nothing we can do about this using pure Cocoa code.  Even using
        // CGBitmapContext is not an option because it only supports a limited
        // number of bitmap formats.  Specifically, 24-bpp is not supported.
        m_selectedBitmap.SetNSBitmapImageRep(
            [[NSBitmapImageRep alloc]
                initWithFocusedViewRect:NSMakeRect(0.0,0.0,
                    m_selectedBitmap.GetWidth(),
                    m_selectedBitmap.GetHeight())]);
    }
    CocoaUnwindStackAndLoseFocus();
    [m_cocoaNSImage release];
    m_cocoaNSImage = nil;
    m_selectedBitmap = bitmap;
    if(m_selectedBitmap.Ok())
    {
        // Create an offscreen window of the same size
        m_cocoaNSImage = [[NSImage alloc]
                initWithSize:NSMakeSize(m_selectedBitmap.GetWidth(),
                    m_selectedBitmap.GetHeight())];

        // Now copy the data
        // Pass false to GetNSImage so the mask is not applied as an alpha channel.
        // Cocoa uses premultiplied alpha so applying the mask would cause all
        // color information masked out to be turned black which is undesirable.
        // FIXME: Currently, the mask will not be updated if any drawing occurs.
        // My only suggestion is for wxCocoa users to eschew the mask in favor
        // of an alpha channel or to recreate the mask after drawing.
        // The only way to fix this is to draw twice, once as normal and again
        // onto the mask to update it.  That would require overriding every
        // single drawing primitive (e.g. DoDrawLine, DoDrawRectangle, etc.)
        // and would be a major undertaking.
        NSImage *nsimage = [m_selectedBitmap.GetNSImage(false) retain];
        [m_cocoaNSImage lockFocus];
        [nsimage drawAtPoint: NSMakePoint(0,0)
            fromRect: NSMakeRect(0.0,0.0,m_selectedBitmap.GetWidth(),m_selectedBitmap.GetHeight())
            operation: NSCompositeCopy
            fraction: 1.0];
        [m_cocoaNSImage unlockFocus];

        [nsimage release];
    }
}

void wxMemoryDCImpl::DoGetSize( int *width, int *height ) const
{
    if(width)
        *width = m_selectedBitmap.GetWidth();
    if(height)
        *height = m_selectedBitmap.GetHeight();
}

bool wxMemoryDCImpl::CocoaDoBlitOnFocusedDC(wxCoord xdest, wxCoord ydest,
    wxCoord width, wxCoord height, wxCoord xsrc, wxCoord ysrc,
    int logicalFunc, bool useMask, wxCoord xsrcMask, wxCoord ysrcMask)
{
    if(!m_selectedBitmap.Ok())
        return false;

    NSAffineTransform *transform = [NSAffineTransform transform];
    [transform translateXBy:xdest yBy:ydest];

    NSAffineTransform *flipTransform = [NSAffineTransform transform];
    /*  x' = 1x + 0y + 0
        y' = 0x + -1y + window's height
    */
    NSAffineTransformStruct matrix = {
        1,  0
    ,   0, -1
    ,   0, height
    };
    [flipTransform setTransformStruct: matrix];

    NSGraphicsContext *context = [NSGraphicsContext currentContext];
    [context saveGraphicsState];
    [transform concat];
    [flipTransform concat];

    NSImage *sourceImage;
    if(useMask)
    {
        sourceImage = [m_cocoaNSImage copy];
        // Apply the mask to the copied image
        NSBitmapImageRep *maskRep = m_selectedBitmap.GetMask()->GetNSBitmapImageRep();
        NSImage *maskImage = [[NSImage alloc] initWithSize:[maskRep size]];
        [maskImage addRepresentation:maskRep];
        [sourceImage lockFocus];
        [maskImage compositeToPoint:NSZeroPoint operation:NSCompositeDestinationIn];
        [sourceImage unlockFocus];
        [maskImage release];
    }
    else
    {   // retain the m_cocoaNSImage so it has the same ownership as the copy done in the other case.
        sourceImage = [m_cocoaNSImage retain];
    }
    NSCompositingOperation drawingOp;
    switch(logicalFunc)
    {
    case wxCOPY:
        // Even if not using the mask, the image might have an alpha channel
        // so always use NSCompositeSourceOver.  If the image is fully opaque
        // it works out the same as NSCompositeCopy.
        drawingOp = NSCompositeSourceOver;
        break;
    // FIXME: implement more raster ops
    default:
        wxLogDebug(wxT("wxCocoa does not support blitting with raster operation %d."), logicalFunc);
        // Just use the default operation.
        drawingOp = NSCompositeCopy;
    }

    wxLogTrace(wxTRACE_COCOA,wxT("[m_cocoaNSImage isFlipped]=%d"), [m_cocoaNSImage isFlipped]);
    [sourceImage drawAtPoint: NSMakePoint(0,0)
        fromRect: NSMakeRect(xsrc,
            m_selectedBitmap.GetHeight()-height-ysrc,
            width, height)
        operation: drawingOp
        fraction: 1.0];

    [sourceImage release]; // It was either retained, copied, or allocated.
    [context restoreGraphicsState];
    return false;
}

bool wxMemoryDCImpl::CocoaGetBounds(void *rectData)
{
    if(!rectData)
        return false;
    if(!m_cocoaNSImage)
        return false;
    NSRect *pRect = (NSRect*)rectData;
    pRect->origin.x = 0.0;
    pRect->origin.y = 0.0;
    pRect->size = [m_cocoaNSImage size];
    return true;
}

