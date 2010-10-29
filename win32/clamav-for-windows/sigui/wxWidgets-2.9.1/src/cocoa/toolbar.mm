/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/toolbar.mm
// Purpose:     wxToolBar
// Author:      David Elliott
// Modified by:
// Created:     2003/08/17
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
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

#if wxUSE_TOOLBAR_NATIVE

#include "wx/toolbar.h"

#ifndef WX_PRECOMP
    #include "wx/frame.h"
    #include "wx/log.h"
#endif // WX_PRECOMP

#include "wx/cocoa/string.h"
#include "wx/cocoa/autorelease.h"

#import <AppKit/NSView.h>
#import <AppKit/NSButtonCell.h>
#import <AppKit/NSMatrix.h>
#import <AppKit/NSImage.h>
#import <AppKit/NSEvent.h>
#import <AppKit/NSColor.h>
#import <AppKit/NSAttributedString.h>
#import <AppKit/NSFont.h>

#include <math.h>

// ========================================================================
// wxToolBarTool
// ========================================================================
class wxToolBarTool : public wxToolBarToolBase
{
public:
    wxToolBarTool(wxToolBar *tbar, int toolid, const wxString& label,
            const wxBitmap& bitmap1, const wxBitmap& bitmap2,
            wxItemKind kind, wxObject *clientData,
            const wxString& shortHelpString, const wxString& longHelpString)
    :   wxToolBarToolBase(tbar, toolid, label, bitmap1, bitmap2, kind,
            clientData, shortHelpString, longHelpString)
    {
        Init();
        CreateButtonCell();
    }

    wxToolBarTool(wxToolBar *tbar, wxControl *control, const wxString& label)
        : wxToolBarToolBase(tbar, control, label)
    {
        Init();
    }
    ~wxToolBarTool();

    bool CreateButtonCell();

    // is this a radio button?
    //
    // unlike GetKind(), can be called for any kind of tools, not just buttons
    bool IsRadio() const { return IsButton() && GetKind() == wxITEM_RADIO; }

    NSRect GetFrameRect()
    {   return m_frameRect; }
    void SetFrameRect(NSRect frameRect)
    {   m_frameRect = frameRect; }
    void DrawTool(NSView *nsview);

    NSButtonCell *GetNSButtonCell()
    {   return m_cocoaNSButtonCell; }
protected:
    void Init();
    NSButtonCell *m_cocoaNSButtonCell;
    NSRect m_frameRect;
};

// ========================================================================
// wxToolBarTool
// ========================================================================
void wxToolBarTool::Init()
{
    m_cocoaNSButtonCell = NULL;
    m_frameRect = NSZeroRect;
}

void wxToolBar::CocoaToolClickEnded()
{
    wxASSERT(m_mouseDownTool);
    wxCommandEvent event(wxEVT_COMMAND_MENU_SELECTED, m_mouseDownTool->GetId());
    InitCommandEvent(event);
    Command(event);
}

wxToolBarTool::~wxToolBarTool()
{
    [m_cocoaNSButtonCell release];
}

bool wxToolBarTool::CreateButtonCell()
{
    wxAutoNSAutoreleasePool pool;

    NSImage *nsimage = [m_bmpNormal.GetNSImage(true) retain];
    m_cocoaNSButtonCell = [[NSButtonCell alloc] initTextCell:nil];
    [m_cocoaNSButtonCell setImage:nsimage];
    NSAttributedString *attributedTitle = [[NSAttributedString alloc] initWithString:wxNSStringWithWxString(m_label) attributes:[NSDictionary dictionaryWithObject:[NSFont labelFontOfSize:0.0] forKey:NSFontAttributeName]];
//    [m_cocoaNSButtonCell setTitle:wxNSStringWithWxString(m_label)];
    [m_cocoaNSButtonCell setAttributedTitle:[attributedTitle autorelease]];

    // Create an alternate image in the style of NSToolBar
    if(nsimage)
    {
        NSImage *alternateImage = [[NSImage alloc] initWithSize:[nsimage size]];
        [alternateImage lockFocus];
        // Paint the entire image with solid black at 50% transparency
        NSRect imageRect = NSZeroRect;
        imageRect.size = [alternateImage size];
        [[NSColor colorWithCalibratedWhite:0.0 alpha:0.5] set];
        NSRectFill(imageRect);
        // Composite the original image with the alternate image
        [nsimage compositeToPoint:NSZeroPoint operation:NSCompositeDestinationAtop];
        [alternateImage unlockFocus];
        [m_cocoaNSButtonCell setAlternateImage:alternateImage];
        [alternateImage release];
    }
    [nsimage release];

    NSMutableAttributedString *alternateTitle = [[NSMutableAttributedString alloc] initWithAttributedString:[m_cocoaNSButtonCell attributedTitle]];
    [alternateTitle applyFontTraits:NSBoldFontMask range:NSMakeRange(0,[alternateTitle length])];
    [m_cocoaNSButtonCell setAttributedAlternateTitle:alternateTitle];
    [alternateTitle release];

    // ----
    [m_cocoaNSButtonCell setImagePosition:NSImageBelow];
//    [m_cocoaNSButtonCell setBezeled:NO];
    [m_cocoaNSButtonCell setButtonType:NSMomentaryChangeButton];
    [m_cocoaNSButtonCell setBordered:NO];
//    [m_cocoaNSButtonCell setHighlightsBy:NSContentsCellMask|NSPushInCellMask];
//    [m_cocoaNSButtonCell setShowsStateBy:NSContentsCellMask|NSPushInCellMask];
    return true;
}

void wxToolBarTool::DrawTool(NSView *nsview)
{
    [m_cocoaNSButtonCell drawWithFrame:m_frameRect inView:nsview];
}

// ========================================================================
// wxToolBar
// ========================================================================
IMPLEMENT_DYNAMIC_CLASS(wxToolBar, wxControl)

//-----------------------------------------------------------------------------
// wxToolBar construction
//-----------------------------------------------------------------------------

void wxToolBar::Init()
{
    m_owningFrame = NULL;
    m_mouseDownTool = NULL;
}

wxToolBar::~wxToolBar()
{
}

bool wxToolBar::Create( wxWindow *parent,
                        wxWindowID winid,
                        const wxPoint& pos,
                        const wxSize& size,
                        long style,
                        const wxString& name )
{
    // Call wxControl::Create so we get a wxNonControlNSControl
    if ( !wxToolBarBase::Create(parent, winid, pos, size, style,
                                wxDefaultValidator, name) )
        return false;

    FixupStyle();

    return true;
}

wxToolBarToolBase *wxToolBar::CreateTool(int toolid,
                                         const wxString& text,
                                         const wxBitmap& bitmap1,
                                         const wxBitmap& bitmap2,
                                         wxItemKind kind,
                                         wxObject *clientData,
                                         const wxString& shortHelpString,
                                         const wxString& longHelpString)
{
    return new wxToolBarTool(this, toolid, text, bitmap1, bitmap2, kind,
                             clientData, shortHelpString, longHelpString);
}

wxToolBarToolBase *
wxToolBar::CreateTool(wxControl *control, const wxString& label)
{
    return new wxToolBarTool(this, control, label);
}

void wxToolBar::SetWindowStyleFlag( long style )
{
    wxToolBarBase::SetWindowStyleFlag(style);
}

bool wxToolBar::DoInsertTool(size_t pos, wxToolBarToolBase *toolBase)
{
    return true;
}

bool wxToolBar::DoDeleteTool(size_t WXUNUSED(pos), wxToolBarToolBase *toolBase)
{
    Realize();
    return true;
}

bool wxToolBar::Cocoa_acceptsFirstMouse(bool &acceptsFirstMouse, WX_NSEvent theEvent)
{
    acceptsFirstMouse = true; return true;
}

bool wxToolBar::Cocoa_drawRect(const NSRect &rect)
{
    wxToolBarToolsList::compatibility_iterator node;
    for(node = m_tools.GetFirst(); node; node = node->GetNext())
    {
        wxToolBarTool *tool = static_cast<wxToolBarTool*>(node->GetData());
        tool->DrawTool(m_cocoaNSView);
    }
    return wxToolBarBase::Cocoa_drawRect(rect);
}

static const NSSize toolPadding = { 4.0, 4.0 };

static NSRect AddToolPadding(NSRect toolRect)
{
        toolRect.origin.x -= toolPadding.width;
        toolRect.size.width += 2.0*toolPadding.width;
        toolRect.origin.y -= toolPadding.height;
        toolRect.size.height += 2.0*toolPadding.height;
        return toolRect;
}

bool wxToolBar::Cocoa_mouseDragged(WX_NSEvent theEvent)
{
    if(m_mouseDownTool && [m_cocoaNSView
            mouse:[m_cocoaNSView convertPoint:[theEvent locationInWindow]
                fromView:nil]
            inRect:AddToolPadding(m_mouseDownTool->GetFrameRect())])
    {
        NSButtonCell *buttonCell = m_mouseDownTool->GetNSButtonCell();
        if(buttonCell)
        {
            [buttonCell retain];
            [buttonCell setHighlighted: YES];
            if([buttonCell trackMouse: theEvent
                inRect:AddToolPadding(m_mouseDownTool->GetFrameRect()) ofView:m_cocoaNSView
                untilMouseUp:NO])
            {
                CocoaToolClickEnded();
                m_mouseDownTool = NULL;
                wxLogTrace(wxTRACE_COCOA,wxT("Button was clicked after drag!"));
            }
            [buttonCell setHighlighted: NO];
            [buttonCell release];
        }
    }
    return wxToolBarBase::Cocoa_mouseDragged(theEvent);
}

bool wxToolBar::Cocoa_mouseDown(WX_NSEvent theEvent)
{
    wxToolBarTool *tool = CocoaFindToolForPosition([m_cocoaNSView convertPoint:[theEvent locationInWindow] fromView:nil]);
    if(tool)
    {
        NSButtonCell *buttonCell = tool->GetNSButtonCell();
        if(buttonCell)
        {
            [buttonCell retain];
            m_mouseDownTool = tool;
            [buttonCell setHighlighted: YES];
            if([buttonCell trackMouse: theEvent
                inRect:AddToolPadding(tool->GetFrameRect()) ofView:m_cocoaNSView
                untilMouseUp:NO])
            {
                CocoaToolClickEnded();
                m_mouseDownTool = NULL;
                wxLogTrace(wxTRACE_COCOA,wxT("Button was clicked!"));
            }
            [buttonCell setHighlighted: NO];
            [buttonCell release];
        }
    }
    return wxToolBarBase::Cocoa_mouseDown(theEvent);
}

bool wxToolBar::Realize()
{
    wxAutoNSAutoreleasePool pool;

    wxToolBarToolsList::compatibility_iterator node;
    NSSize totalSize = NSZeroSize;
    // This is for horizontal, TODO: vertical
    for(node = m_tools.GetFirst(); node; node = node->GetNext())
    {
        wxToolBarTool *tool = static_cast<wxToolBarTool*>(node->GetData());
        if(tool->IsControl())
        {
            totalSize.width = ceil(totalSize.width);
            wxControl *control = tool->GetControl();
            wxSize controlSize = control->GetSize();
            control->SetPosition(wxPoint((wxCoord)totalSize.width,0));
            totalSize.width += controlSize.x;
            if(controlSize.y > totalSize.height)
                totalSize.height = controlSize.y;
        }
        else if(tool->IsSeparator())
        {
            totalSize.width += 2.0;
        }
        else
        {
            NSButtonCell *buttonCell = tool->GetNSButtonCell();
            NSSize toolSize = [buttonCell cellSize];
            tool->SetFrameRect(NSMakeRect(totalSize.width+toolPadding.width,toolPadding.height,toolSize.width,toolSize.height));
            toolSize.width += 2.0*toolPadding.width;
            toolSize.height += 2.0*toolPadding.height;
            totalSize.width += toolSize.width;
            if(toolSize.height > totalSize.height)
                totalSize.height = toolSize.height;
        }
    }
    m_bestSize = wxSize((wxCoord)ceil(totalSize.width),(wxCoord)ceil(totalSize.height));
    if(m_owningFrame)
        m_owningFrame->UpdateFrameNSView();
    return true;
}

wxSize wxToolBar::DoGetBestSize() const
{
    return m_bestSize;
}

// ----------------------------------------------------------------------------
// wxToolBar tools state
// ----------------------------------------------------------------------------

void wxToolBar::DoEnableTool(wxToolBarToolBase *toolBase, bool enable)
{
}

void wxToolBar::DoToggleTool( wxToolBarToolBase *toolBase, bool toggle )
{
}

void wxToolBar::DoSetToggle(wxToolBarToolBase * WXUNUSED(tool),
                            bool WXUNUSED(toggle))
{
}

// ----------------------------------------------------------------------------
// wxToolBar geometry
// ----------------------------------------------------------------------------

wxToolBarToolBase *wxToolBar::FindToolForPosition(wxCoord x, wxCoord y) const
{
    return NULL;
}

wxToolBarTool *wxToolBar::CocoaFindToolForPosition(const NSPoint& pos) const
{
    wxToolBarToolsList::compatibility_iterator node;
    for(node = m_tools.GetFirst(); node; node = node->GetNext())
    {
        wxToolBarTool *tool = static_cast<wxToolBarTool*>(node->GetData());
        if(tool->IsControl())
        {
            // TODO
        }
        else if(tool->IsSeparator())
        {   // Do nothing
        }
        else
        {
            if([m_cocoaNSView mouse:pos inRect:AddToolPadding(tool->GetFrameRect())])
                return tool;
        }
    }
    return NULL;
}

void wxToolBar::SetMargins( int x, int y )
{
}

void wxToolBar::SetToolSeparation( int separation )
{
    m_toolSeparation = separation;
}

void wxToolBar::SetToolShortHelp( int id, const wxString& helpString )
{
}

// ----------------------------------------------------------------------------
// wxToolBar idle handling
// ----------------------------------------------------------------------------

void wxToolBar::OnInternalIdle()
{
}

#endif // wxUSE_TOOLBAR_NATIVE
