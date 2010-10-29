/////////////////////////////////////////////////////////////////////////////
// Name:        cocoa/notebook.mm
// Purpose:     wxNotebook
// Author:      David Elliott
// Modified by:
// Created:     2004/04/08
// RCS-ID:      $Id$
// Copyright:   (c) 2004 David Elliott
// Licence:   	wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_NOTEBOOK

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif //WX_PRECOMP
#include "wx/notebook.h"
#include "wx/imaglist.h"

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"
#include "wx/cocoa/objc/objc_uniquifying.h"

#import <AppKit/NSTabView.h>
#import <AppKit/NSTabViewItem.h>
#import <AppKit/NSImage.h>

// testing:
#import <AppKit/NSPasteboard.h>
#import <Foundation/NSArray.h>

// ========================================================================
// WXCTabViewImageItem
// ========================================================================
@interface WXCTabViewImageItem : NSTabViewItem
{
    NSImage *m_image;
}

- (id)init;
- (id)initWithIdentifier: (id)identifier;
- (void)dealloc;

- (NSSize)sizeOfLabel:(BOOL)shouldTruncateLabel;
- (void)drawLabel:(BOOL)shouldTruncateLabel inRect:(NSRect)tabRect;

- (NSImage*)image;
- (void)setImage:(NSImage*)image;
@end // interface WXCTabViewImageItem : NSTabViewItem
WX_DECLARE_GET_OBJC_CLASS(WXCTabViewImageItem,NSTabViewItem)

@implementation WXCTabViewImageItem : NSTabViewItem
- (id)init
{
    return [self initWithIdentifier:nil];
}

- (id)initWithIdentifier: (id)identifier;
{
    m_image = nil;
    return [super initWithIdentifier:identifier];
}

- (void)dealloc
{
    [m_image release];
    [super dealloc];
}

- (NSSize)sizeOfLabel:(BOOL)shouldTruncateLabel
{
    NSSize labelSize = [super sizeOfLabel:shouldTruncateLabel];
    if(!m_image)
        return labelSize;
    NSSize imageSize = [m_image size];
    // scale image size
    if(imageSize.height > labelSize.height)
    {
        imageSize.width *= labelSize.height/imageSize.height;
        imageSize.height *= labelSize.height/imageSize.height;
        [m_image setScalesWhenResized:YES];
        [m_image setSize: imageSize];
    }
    labelSize.width += imageSize.width;
    return labelSize;
}

- (void)drawLabel:(BOOL)shouldTruncateLabel inRect:(NSRect)tabRect
{
    if(m_image)
    {
        NSSize imageSize = [m_image size];
        [m_image compositeToPoint:NSMakePoint(tabRect.origin.x,
                tabRect.origin.y+imageSize.height)
            operation:NSCompositeSourceOver];
        tabRect.size.width -= imageSize.width;
        tabRect.origin.x += imageSize.width;
    }
    [super drawLabel:shouldTruncateLabel inRect:tabRect];
}

- (NSImage*)image
{
    return m_image;
}

- (void)setImage:(NSImage*)image
{
    [image retain];
    [m_image release];
    m_image = image;
    if(!m_image)
        return;
    [[NSPasteboard generalPasteboard]
        declareTypes:[NSArray arrayWithObject:NSTIFFPboardType]
        owner:nil];
    [[NSPasteboard generalPasteboard]
        setData:[m_image TIFFRepresentation]
        forType:NSTIFFPboardType];
}

@end // implementation WXCTabViewImageItem : NSTabViewItem
WX_IMPLEMENT_GET_OBJC_CLASS(WXCTabViewImageItem,NSTabViewItem)

// ========================================================================
// wxNotebook
// ========================================================================
IMPLEMENT_DYNAMIC_CLASS(wxNotebook, wxBookCtrlBase)
BEGIN_EVENT_TABLE(wxNotebook, wxNotebookBase)
END_EVENT_TABLE()
WX_IMPLEMENT_COCOA_OWNER(wxNotebook,NSTabView,NSView,NSView)

bool wxNotebook::Create(wxWindow *parent, wxWindowID winid,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    if(!CreateControl(parent,winid,pos,size,style,wxDefaultValidator,name))
        return false;
    m_cocoaNSView = NULL;
    SetNSTabView([[NSTabView alloc] initWithFrame:MakeDefaultNSRect(size)]);

    do
    {
        NSTabViewType tabViewType;
        if(style & wxNB_TOP)
            tabViewType = NSTopTabsBezelBorder;
        else if(style & wxNB_LEFT)
            tabViewType = NSLeftTabsBezelBorder;
        else if(style & wxNB_RIGHT)
            tabViewType = NSRightTabsBezelBorder;
        else if(style & wxNB_BOTTOM)
            tabViewType = NSBottomTabsBezelBorder;
        else
            break;
        [GetNSTabView() setTabViewType:tabViewType];
    } while(0);

    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxNotebook::~wxNotebook()
{
}

void wxNotebook::SetPadding(const wxSize& padding)
{   // Can't do
}

void wxNotebook::SetTabSize(const wxSize& sz)
{   // Can't do
}

void wxNotebook::SetPageSize(const wxSize& size)
{
}


wxNotebookPage *wxNotebook::DoRemovePage(size_t nPage)
{
    wxNotebookPage *page = wxNotebookBase::DoRemovePage(nPage);
    if(!page)
        return NULL;
    NSTabViewItem *tvitem = [GetNSTabView() tabViewItemAtIndex: nPage];
    wxASSERT(tvitem);
    [tvitem retain];
    [GetNSTabView() removeTabViewItem:tvitem];
    // Remove the child window as a notebook page
    wxASSERT(static_cast<NSView*>([tvitem view]) == page->GetNSViewForSuperview());
    [tvitem setView:nil];
    [tvitem release];
    // Make it back into a normal child window
    [m_cocoaNSView addSubview: page->GetNSViewForSuperview()];
    
    return page;
}

bool wxNotebook::DeletePage(size_t nPage)
{
    return wxNotebookBase::DeletePage(nPage);
}

bool wxNotebook::InsertPage( size_t pos,
                 wxNotebookPage *page, const wxString& title,
                 bool bSelect, int imageId)
{
    wxAutoNSAutoreleasePool pool;
    m_pages.Insert(page,pos);
    NSTabViewItem *tvitem = [[WX_GET_OBJC_CLASS(WXCTabViewImageItem) alloc] initWithIdentifier:nil];
    [tvitem setLabel: wxNSStringWithWxString(title)];
    const wxBitmap *bmp = (imageId!=-1)?m_imageList->GetBitmapPtr(imageId):NULL;
    if(bmp)
        [(WXCTabViewImageItem*) tvitem setImage: bmp->GetNSImage(true)];

    NSView *pageNSView = page->GetNSViewForSuperview();
    // Remove it as a normal child
    wxASSERT(m_cocoaNSView == [pageNSView superview]);
    [pageNSView removeFromSuperview];
    // And make it a notebook page
    [tvitem setView: pageNSView];

    [GetNSTabView() insertTabViewItem:tvitem atIndex:pos];
    [tvitem release];

    return true;
}

bool wxNotebook::DeleteAllPages()
{
    while(!m_pages.IsEmpty())
        DeletePage(0);
    return true;
}


bool wxNotebook::SetPageText(size_t nPage, const wxString& title)
{
    NSTabViewItem *tvitem = [GetNSTabView() tabViewItemAtIndex: nPage];
    if(!tvitem)
        return false;
    [tvitem setLabel: wxNSStringWithWxString(title)];
    return true;
}

wxString wxNotebook::GetPageText(size_t nPage) const
{
    return wxStringWithNSString([[GetNSTabView() tabViewItemAtIndex: nPage] label]);
}


int wxNotebook::GetPageImage(size_t nPage) const
{
    // To do this we'd need to keep track of this, which we don't!
    return -1;
}

bool wxNotebook::SetPageImage(size_t nPage, int nImage)
{
    const wxBitmap *bmp = nImage!=-1?m_imageList->GetBitmapPtr(nImage):NULL;
    if(!bmp)
        return false;
    NSTabViewItem *tvitem = [GetNSTabView() tabViewItemAtIndex: nPage];
    if(!tvitem)
        return false;
    [(WXCTabViewImageItem*) tvitem setImage: bmp->GetNSImage(true)];
    return true;
}

int wxNotebook::SetSelection(size_t nPage)
{
    const int pageOld = GetSelection();

    if ( !SendPageChangingEvent(nPage) )
        return pageOld;

    int page = ChangeSelection(nPage);
    if ( page != wxNOT_FOUND )
    {
        SendPageChangedEvent(pageOld);
    }

    return page;
}

int wxNotebook::ChangeSelection(size_t nPage)
{
    wxAutoNSAutoreleasePool pool;
    [GetNSTabView() selectTabViewItemAtIndex:nPage];
    return GetSelection();
}

int wxNotebook::GetSelection() const
{
    NSTabViewItem *selectedItem = [GetNSTabView() selectedTabViewItem];
    if(!selectedItem)
        return -1;
    return [GetNSTabView() indexOfTabViewItem:selectedItem];
}

void wxNotebook::CocoaDelegate_tabView_didSelectTabViewItem(WX_NSTabViewItem tabViewItem)
{
    // FIXME: oldSel probably == newSel
    wxBookCtrlEvent event(wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGED, GetId(),
        [GetNSTabView() indexOfTabViewItem:tabViewItem], GetSelection());
    event.SetEventObject(this);
    GetEventHandler()->ProcessEvent(event);
}

bool wxNotebook::CocoaDelegate_tabView_shouldSelectTabViewItem(WX_NSTabViewItem tabViewItem)
{
    wxBookCtrlEvent event(wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGING, GetId(),
        [GetNSTabView() indexOfTabViewItem:tabViewItem], GetSelection());
    event.SetEventObject(this);
    return !HandleWindowEvent(event) || event.IsAllowed();
}

#endif // wxUSE_NOTEBOOK
