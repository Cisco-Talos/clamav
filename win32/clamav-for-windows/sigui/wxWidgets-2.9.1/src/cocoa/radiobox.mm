/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/radiobox.mm
// Purpose:     wxRadioBox
// Author:      David Elliott
// Modified by:
// Created:     2003/02/15
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
//              (c) 2007 Software 2000 Ltd.
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_RADIOBOX

#include "wx/radiobox.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/arrstr.h"
#endif //WX_PRECOMP

#include "wx/cocoa/string.h"
#include "wx/cocoa/autorelease.h"

#import <Foundation/NSArray.h>
#include "wx/cocoa/objc/NSView.h"
#import <AppKit/NSButton.h>
#import <AppKit/NSBox.h>
#import <AppKit/NSMatrix.h>

IMPLEMENT_DYNAMIC_CLASS(wxRadioBox, wxControl)
BEGIN_EVENT_TABLE(wxRadioBox, wxControl)
END_EVENT_TABLE()

void wxRadioBox::AssociateNSBox(WX_NSBox cocoaObjcClass)
{
    NSMatrix *radioBox = [(WX_NSBox)cocoaObjcClass contentView];
    // Associate the NSMatrix (the NSBox's contentView) with the wxCocoaNSControl MI base class.
    AssociateNSControl(radioBox);
    // Set the target/action.. we don't really need to unset these
    [radioBox setTarget:wxCocoaNSControl::sm_cocoaTarget];
    [radioBox setAction:@selector(wxNSControlAction:)];
}

void wxRadioBox::DisassociateNSBox(WX_NSBox cocoaObjcClass)
{
    DisassociateNSControl([(WX_NSBox)cocoaObjcClass contentView]);
}

WX_IMPLEMENT_COCOA_OWNER(wxRadioBox,NSBox,NSView,NSView)

bool wxRadioBox::Create(wxWindow *parent, wxWindowID winid,
            const wxString& title,
            const wxPoint& pos,
            const wxSize& size,
            const wxArrayString& choices,
            int majorDim,
            long style, const wxValidator& validator,
            const wxString& name)
{
    wxCArrayString chs(choices);

    return Create(parent, winid, title, pos, size, chs.GetCount(),
                  chs.GetStrings(), majorDim, style, validator, name);
}

bool wxRadioBox::Create(wxWindow *parent, wxWindowID winid,
            const wxString& title,
            const wxPoint& pos,
            const wxSize& size,
            int n, const wxString choices[],
            int majorDim,
            long style, const wxValidator& validator,
            const wxString& name)
{
    // We autorelease heavily so we want our own pool
    wxAutoNSAutoreleasePool pool;

    if(!CreateControl(parent,winid,pos,size,style,validator,name))
        return false;

    majorDim = majorDim == 0 ? n : majorDim;
    // TODO: Don't forget to call SetMajorDim
    // We can't yet as we can't implement GetCount() until after
    // we make the NSMatrix.
    int minorDim = (n + majorDim - 1) / majorDim;


    // Create a prototype cell for use with the NSMatrix build
    NSCell *currCell = [[NSButtonCell alloc] initTextCell:@""];
    [(NSButtonCell*)currCell setButtonType:NSRadioButton];

    // Build up an array of all cells plus any extra empty cells
    NSMutableArray *allCells = [NSMutableArray arrayWithCapacity:n];
    for(int i=0; i<n; ++i)
    {
        CocoaSetLabelForObject(choices[i], currCell);
        [allCells addObject: currCell];
        [currCell release];
        // NOTE: We can still safely message currCell as the array has retained it.
        currCell = [currCell copy];
    }
    [currCell release];

    // NOTE: Although an image cell with no image is documented to return NSZeroSize from
    // the cellSize method, the documentation is WRONG.  It will actually return a huge size
    // (thousands) which makes every cell in the matrix that big. Not good.
    // Be safe and initialize a text cell with an empty string.  That always works.
    currCell = [[NSCell alloc] initTextCell:@""];
    [currCell setEnabled:NO]; // Don't allow user to select this cell
    for(int i=n; i < majorDim * minorDim; ++i)
    {
        [allCells addObject: currCell];
        // NOTE: Use the same instance.. this should work and save some heap allocations.
#if 0
	[currCell release];
	currCell = [currCell copy];
#endif
    }
    [currCell release];
    currCell = NULL;

    // Although the documentation on addColumnWithCells:/addRowWithCells: explicitly
    // states that it will determine the initial dimension upon the first call if
    // the initial size is 0x0 it LIES.  It will fail an assertion in the code
    // if you use the simpler initWithFrame: initializer.
    // Therefore, we specify the major dimension and leave the minor dimension as 0
    // so that we can add the rows/columns without failing the assertion.
    NSMatrix* radioBox = [[NSMatrix alloc]
		initWithFrame:NSZeroRect
		mode:NSRadioModeMatrix
		cellClass:nil
		numberOfRows:style&wxRA_SPECIFY_COLS?0:majorDim
		numberOfColumns:style&wxRA_SPECIFY_COLS?majorDim:0
	];

    SEL addMajorWithCellsSelector;
    // If column count is the major dimension then we add by row
    if( style & wxRA_SPECIFY_COLS )
        addMajorWithCellsSelector = @selector(addRowWithCells:);
    // If row count is the major dimension then we add by column
    else
        addMajorWithCellsSelector = @selector(addColumnWithCells:);

    for(int i=0; i<minorDim; ++i)
    {
        [radioBox
            performSelector:addMajorWithCellsSelector
            withObject:[allCells subarrayWithRange:NSMakeRange(i*majorDim, majorDim)]];
    }

    NSBox *theBox = [[NSBox alloc] initWithFrame:MakeDefaultNSRect(size)];

    // Replace the box's content view with the NSMatrix we just created
    // IMPORTANT: This must be done before calling SetNSBox.
    [theBox setContentView:radioBox];
    [radioBox release]; // The NSBox retains it for us.

    SetNSBox(theBox);
    [theBox release];


    CocoaSetLabelForObject(title, GetNSBox());
//    [GetNSBox() setBorderType:NSLineBorder]; // why??

    SetMajorDim(majorDim, style);

    // Set the selection to the first item if we have any items.
    // This is for parity with other wx ports which do the same thing.
    if(n > 0)
        SetSelection(0);

    if(m_parent)
        m_parent->CocoaAddChild(this);

    // Do the sizer dance
    [GetNSBox() sizeToFit];
    SetInitialFrameRect(pos, size);

    return true;
}

wxRadioBox::~wxRadioBox()
{
    DisassociateNSBox(GetNSBox());
}

WX_NSMatrix wxRadioBox::GetNSMatrix() const
{
    return (NSMatrix*)[(NSBox*)m_cocoaNSView contentView];
}

    // selection
void wxRadioBox::SetSelection(int n)
{
    int r = GetRowForIndex(n);
    int c = GetColumnForIndex(n);
    [GetNSMatrix() selectCellAtRow:r column:c];
}

int wxRadioBox::GetSelection() const
{
    NSMatrix *radioBox = GetNSMatrix();
    NSInteger r = [radioBox selectedRow];
    NSInteger c = [radioBox selectedColumn];
    if(m_windowStyle & wxRA_SPECIFY_COLS)
        return r * GetMajorDim() + c;
    else
        return c * GetMajorDim() + r;
}

    // string access
unsigned int wxRadioBox::GetCount() const
{
    NSMatrix *radioBox = GetNSMatrix();
    NSInteger rowCount, columnCount;
    [radioBox getNumberOfRows:&rowCount columns:&columnCount];

    // FIXME: This is wrong if padding cells were made
    return rowCount * columnCount;
}

wxString wxRadioBox::GetString(unsigned int n) const
{
    int r = GetRowForIndex(n);
    int c = GetColumnForIndex(n);
    // FIXME: Cocoa stores the mnemonic-stripped title.
    return wxStringWithNSString([[GetNSMatrix() cellAtRow:r column:c] title]);
}

void wxRadioBox::SetString(unsigned int n, const wxString& label)
{
    int r = GetRowForIndex(n);
    int c = GetColumnForIndex(n);
    CocoaSetLabelForObject(label, [GetNSMatrix() cellAtRow:r column:c]);
}

    // change the individual radio button state
bool wxRadioBox::Enable(unsigned int n, bool enable)
{
    int r = GetRowForIndex(n);
    int c = GetColumnForIndex(n);
    NSCell *cell = [GetNSMatrix() cellAtRow:r column:c];
    if(cell == nil)
        return false;
    bool wasEnabled = [cell isEnabled];
    [cell setEnabled:enable];
    return (wasEnabled && !enable) || (!wasEnabled && enable);
}

bool wxRadioBox::Show(unsigned int n, bool show)
{
    // TODO
    // NOTE: Cocoa has no visible state for cells so we'd need to replace the
    // cell with a dummy one to hide it or alternatively subclass NSButtonCell
    // and add the behavior.
    return false;
}

wxSize wxRadioBox::DoGetBestSize() const
{
    // The NSBox responds to sizeToFit by sending sizeToFit to its contentView
    // which is the NSMatrix and does the right thing.
    return wxControl::DoGetBestSize();
}

void wxRadioBox::CocoaTarget_action(void)
{
    wxCommandEvent event(wxEVT_COMMAND_RADIOBOX_SELECTED, GetId());
    InitCommandEvent(event);
    event.SetInt(GetSelection()); // i.e. SetSelection.
    Command(event);
}

#endif
