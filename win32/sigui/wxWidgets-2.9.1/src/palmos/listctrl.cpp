/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/listctrl.cpp
// Purpose:     wxListCtrl
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
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

#if wxUSE_LISTCTRL

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/settings.h"
    #include "wx/dcclient.h"
    #include "wx/textctrl.h"
#endif

#include "wx/imaglist.h"
#include "wx/listctrl.h"

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxListCtrlStyle )

wxBEGIN_FLAGS( wxListCtrlStyle )
    // new style border flags, we put them first to
    // use them for streaming out
    wxFLAGS_MEMBER(wxBORDER_SIMPLE)
    wxFLAGS_MEMBER(wxBORDER_SUNKEN)
    wxFLAGS_MEMBER(wxBORDER_DOUBLE)
    wxFLAGS_MEMBER(wxBORDER_RAISED)
    wxFLAGS_MEMBER(wxBORDER_STATIC)
    wxFLAGS_MEMBER(wxBORDER_NONE)

    // old style border flags
    wxFLAGS_MEMBER(wxSIMPLE_BORDER)
    wxFLAGS_MEMBER(wxSUNKEN_BORDER)
    wxFLAGS_MEMBER(wxDOUBLE_BORDER)
    wxFLAGS_MEMBER(wxRAISED_BORDER)
    wxFLAGS_MEMBER(wxSTATIC_BORDER)
    wxFLAGS_MEMBER(wxBORDER)

    // standard window styles
    wxFLAGS_MEMBER(wxTAB_TRAVERSAL)
    wxFLAGS_MEMBER(wxCLIP_CHILDREN)
    wxFLAGS_MEMBER(wxTRANSPARENT_WINDOW)
    wxFLAGS_MEMBER(wxWANTS_CHARS)
    wxFLAGS_MEMBER(wxFULL_REPAINT_ON_RESIZE)
    wxFLAGS_MEMBER(wxALWAYS_SHOW_SB )
    wxFLAGS_MEMBER(wxVSCROLL)
    wxFLAGS_MEMBER(wxHSCROLL)

    wxFLAGS_MEMBER(wxLC_LIST)
    wxFLAGS_MEMBER(wxLC_REPORT)
    wxFLAGS_MEMBER(wxLC_ICON)
    wxFLAGS_MEMBER(wxLC_SMALL_ICON)
    wxFLAGS_MEMBER(wxLC_ALIGN_TOP)
    wxFLAGS_MEMBER(wxLC_ALIGN_LEFT)
    wxFLAGS_MEMBER(wxLC_AUTOARRANGE)
    wxFLAGS_MEMBER(wxLC_USER_TEXT)
    wxFLAGS_MEMBER(wxLC_EDIT_LABELS)
    wxFLAGS_MEMBER(wxLC_NO_HEADER)
    wxFLAGS_MEMBER(wxLC_SINGLE_SEL)
    wxFLAGS_MEMBER(wxLC_SORT_ASCENDING)
    wxFLAGS_MEMBER(wxLC_SORT_DESCENDING)
    wxFLAGS_MEMBER(wxLC_VIRTUAL)

wxEND_FLAGS( wxListCtrlStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxListCtrl, wxControl,"wx/listctrl.h")

wxBEGIN_PROPERTIES_TABLE(wxListCtrl)
    wxEVENT_PROPERTY( TextUpdated , wxEVT_COMMAND_TEXT_UPDATED , wxCommandEvent )

    wxPROPERTY_FLAGS( WindowStyle , wxListCtrlStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxListCtrl)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_5( wxListCtrl , wxWindow* , Parent , wxWindowID , Id , wxPoint , Position , wxSize , Size , long , WindowStyle )

/*
 TODO : Expose more information of a list's layout etc. via appropriate objects (à la NotebookPageInfo)
*/
#else
IMPLEMENT_DYNAMIC_CLASS(wxListCtrl, wxControl)
#endif

IMPLEMENT_DYNAMIC_CLASS(wxListView, wxListCtrl)
IMPLEMENT_DYNAMIC_CLASS(wxListItem, wxObject)

IMPLEMENT_DYNAMIC_CLASS(wxListEvent, wxNotifyEvent)

BEGIN_EVENT_TABLE(wxListCtrl, wxControl)
    EVT_PAINT(wxListCtrl::OnPaint)
END_EVENT_TABLE()

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxListCtrl construction
// ----------------------------------------------------------------------------

void wxListCtrl::Init()
{
}

bool wxListCtrl::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxPoint& pos,
                        const wxSize& size,
                        long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    return false;
}

void wxListCtrl::UpdateStyle()
{
}

void wxListCtrl::FreeAllInternalData()
{
}

wxListCtrl::~wxListCtrl()
{
}

// ----------------------------------------------------------------------------
// set/get/change style
// ----------------------------------------------------------------------------

// Add or remove a single window style
void wxListCtrl::SetSingleStyle(long style, bool add)
{
}

// ----------------------------------------------------------------------------
// accessors
// ----------------------------------------------------------------------------

/* static */ wxVisualAttributes wxListCtrl::GetClassDefaultAttributes(wxWindowVariant variant)
{
    wxVisualAttributes attrs;

    return attrs;
}

// Sets the foreground, i.e. text, colour
bool wxListCtrl::SetForegroundColour(const wxColour& col)
{
    return false;
}

// Sets the background colour
bool wxListCtrl::SetBackgroundColour(const wxColour& col)
{
    return false;
}

// Gets information about this column
bool wxListCtrl::GetColumn(int col, wxListItem& item) const
{
    return false;
}

// Sets information about this column
bool wxListCtrl::SetColumn(int col, wxListItem& item)
{
    return false;
}

// Gets the column width
int wxListCtrl::GetColumnWidth(int col) const
{
    return 0;
}

// Sets the column width
bool wxListCtrl::SetColumnWidth(int col, int width)
{
    return false;
}

// Gets the number of items that can fit vertically in the
// visible area of the list control (list or report view)
// or the total number of items in the list control (icon
// or small icon view)
int wxListCtrl::GetCountPerPage() const
{
    return 0;
}

// Gets the edit control for editing labels.
wxTextCtrl* wxListCtrl::GetEditControl() const
{
    return NULL;
}

// Gets information about the item
bool wxListCtrl::GetItem(wxListItem& info) const
{
    return false;
}

// Sets information about the item
bool wxListCtrl::SetItem(wxListItem& info)
{
    return false;
}

long wxListCtrl::SetItem(long index, int col, const wxString& label, int imageId)
{
    return 0;
}


// Gets the item state
int wxListCtrl::GetItemState(long item, long stateMask) const
{
    return 0;
}

// Sets the item state
bool wxListCtrl::SetItemState(long item, long state, long stateMask)
{
    return false;
}

// Sets the item image
bool wxListCtrl::SetItemImage(long item, int image, int WXUNUSED(selImage))
{
    return false;
}

// Sets the item image
bool wxListCtrl::SetItemColumnImage(long item, long column, int image)
{
    return false;
}

// Gets the item text
wxString wxListCtrl::GetItemText(long item) const
{
    wxListItem info;

    return info.m_text;
}

// Sets the item text
void wxListCtrl::SetItemText(long item, const wxString& str)
{
}

// Gets the item data
long wxListCtrl::GetItemData(long item) const
{
    return 0;
}

// Sets the item data
bool wxListCtrl::SetItemPtrData(long item, wxUIntPtr data)
{
    return false;
}

wxRect wxListCtrl::GetViewRect() const
{
    wxRect rect;

    return rect;
}

// Gets the item rectangle
bool wxListCtrl::GetItemRect(long item, wxRect& rect, int code) const
{
    return false;
}

// Gets the item position
bool wxListCtrl::GetItemPosition(long item, wxPoint& pos) const
{
    return false;
}

// Sets the item position.
bool wxListCtrl::SetItemPosition(long item, const wxPoint& pos)
{
    return false;
}

// Gets the number of items in the list control
int wxListCtrl::GetItemCount() const
{
    return 0;
}

wxSize wxListCtrl::GetItemSpacing() const
{
    return wxSize(0,0);
}

int wxListCtrl::GetItemSpacing(bool isSmall) const
{
    return 0;
}

void wxListCtrl::SetItemTextColour( long item, const wxColour &col )
{
}

wxColour wxListCtrl::GetItemTextColour( long item ) const
{
    wxColour col;

    return col;
}

void wxListCtrl::SetItemBackgroundColour( long item, const wxColour &col )
{
}

wxColour wxListCtrl::GetItemBackgroundColour( long item ) const
{
    wxColour col;

    return col;
}

// Gets the number of selected items in the list control
int wxListCtrl::GetSelectedItemCount() const
{
    return 0;
}

// Gets the text colour of the listview
wxColour wxListCtrl::GetTextColour() const
{
    wxColour col;
    return col;
}

// Sets the text colour of the listview
void wxListCtrl::SetTextColour(const wxColour& col)
{
}

// Gets the index of the topmost visible item when in
// list or report view
long wxListCtrl::GetTopItem() const
{
    return 0;
}

// Searches for an item, starting from 'item'.
// 'geometry' is one of
// wxLIST_NEXT_ABOVE/ALL/BELOW/LEFT/RIGHT.
// 'state' is a state bit flag, one or more of
// wxLIST_STATE_DROPHILITED/FOCUSED/SELECTED/CUT.
// item can be -1 to find the first item that matches the
// specified flags.
// Returns the item or -1 if unsuccessful.
long wxListCtrl::GetNextItem(long item, int geom, int state) const
{
    return 0;
}


wxImageList *wxListCtrl::GetImageList(int which) const
{
    return NULL;
}

void wxListCtrl::SetImageList(wxImageList *imageList, int which)
{
}

void wxListCtrl::AssignImageList(wxImageList *imageList, int which)
{
}

// ----------------------------------------------------------------------------
// Operations
// ----------------------------------------------------------------------------

// Arranges the items
bool wxListCtrl::Arrange(int flag)
{
    return false;
}

// Deletes an item
bool wxListCtrl::DeleteItem(long item)
{
    return false;
}

// Deletes all items
bool wxListCtrl::DeleteAllItems()
{
    return false;
}

// Deletes all items
bool wxListCtrl::DeleteAllColumns()
{
    return false;
}

// Deletes a column
bool wxListCtrl::DeleteColumn(int col)
{
    return false;
}

// Clears items, and columns if there are any.
void wxListCtrl::ClearAll()
{
}

wxTextCtrl* wxListCtrl::EditLabel(long item, wxClassInfo* textControlClass)
{
    return NULL;
}

// End label editing, optionally cancelling the edit
bool wxListCtrl::EndEditLabel(bool WXUNUSED(cancel))
{
    return false;
}

// Ensures this item is visible
bool wxListCtrl::EnsureVisible(long item)
{
    return false;
}

// Find an item whose label matches this string, starting from the item after 'start'
// or the beginning if 'start' is -1.
long wxListCtrl::FindItem(long start, const wxString& str, bool partial)
{
    return 0;
}

// Find an item whose data matches this data, starting from the item after 'start'
// or the beginning if 'start' is -1.
// NOTE : Lindsay Mathieson - 14-July-2002
//        No longer use ListView_FindItem as the data attribute is now stored
//        in a wxListItemInternalData structure refernced by the actual lParam
long wxListCtrl::FindItem(long start, long data)
{
    return wxNOT_FOUND;
}

// Find an item nearest this position in the specified direction, starting from
// the item after 'start' or the beginning if 'start' is -1.
long wxListCtrl::FindItem(long start, const wxPoint& pt, int direction)
{
    return wxNOT_FOUND;
}

// Determines which item (if any) is at the specified point,
// giving details in 'flags' (see wxLIST_HITTEST_... flags above)
long wxListCtrl::HitTest(const wxPoint& point, int& flags)
{
    return 0;
}

// Inserts an item, returning the index of the new item if successful,
// -1 otherwise.
long wxListCtrl::InsertItem(wxListItem& info)
{
    return 0;
}

long wxListCtrl::InsertItem(long index, const wxString& label)
{
    return 0;
}

// Inserts an image item
long wxListCtrl::InsertItem(long index, int imageIndex)
{
    return 0;
}

// Inserts an image/string item
long wxListCtrl::InsertItem(long index, const wxString& label, int imageIndex)
{
    return 0;
}

// For list view mode (only), inserts a column.
long wxListCtrl::InsertColumn(long col, wxListItem& item)
{
    return 0;
}

long wxListCtrl::InsertColumn(long col,
                              const wxString& heading,
                              int format,
                              int width)
{
    return 0;
}

// scroll the control by the given number of pixels (exception: in list view,
// dx is interpreted as number of columns)
bool wxListCtrl::ScrollList(int dx, int dy)
{
    return false;
}

// Sort items.

// fn is a function which takes 3 long arguments: item1, item2, data.
// item1 is the long data associated with a first item (NOT the index).
// item2 is the long data associated with a second item (NOT the index).
// data is the same value as passed to SortItems.
// The return value is a negative number if the first item should precede the second
// item, a positive number of the second item should precede the first,
// or zero if the two items are equivalent.

// data is arbitrary data to be passed to the sort function.

// Internal structures for proxying the user compare function
// so that we can pass it the *real* user data

// translate lParam data and call user func
struct wxInternalDataSort
{
    wxListCtrlCompare user_fn;
    long data;
};

int CALLBACK wxInternalDataCompareFunc(LPARAM lParam1, LPARAM lParam2,  LPARAM lParamSort)
{
    struct wxInternalDataSort *internalData = (struct wxInternalDataSort *) lParamSort;

    wxListItemInternalData *data1 = (wxListItemInternalData *) lParam1;
    wxListItemInternalData *data2 = (wxListItemInternalData *) lParam2;

    long d1 = (data1 == NULL ? 0 : data1->lParam);
    long d2 = (data2 == NULL ? 0 : data2->lParam);

    return internalData->user_fn(d1, d2, internalData->data);

};

bool wxListCtrl::SortItems(wxListCtrlCompare fn, long data)
{
    return false;
}



// ----------------------------------------------------------------------------
// message processing
// ----------------------------------------------------------------------------

// Necessary for drawing hrules and vrules, if specified
void wxListCtrl::OnPaint(wxPaintEvent& event)
{
}

// ----------------------------------------------------------------------------
// virtual list controls
// ----------------------------------------------------------------------------

wxString wxListCtrl::OnGetItemText(long WXUNUSED(item), long WXUNUSED(col)) const
{
    return wxEmptyString;
}

int wxListCtrl::OnGetItemImage(long WXUNUSED(item)) const
{
    return -1;
}

int wxListCtrl::OnGetItemColumnImage(long item, long column) const
{
    if (!column)
        return OnGetItemImage(item);

    return -1;
}

wxListItemAttr *wxListCtrl::OnGetItemAttr(long WXUNUSED_UNLESS_DEBUG(item)) const
{
    // no attributes by default
    return NULL;
}

void wxListCtrl::SetItemCount(long count)
{
}

void wxListCtrl::RefreshItem(long item)
{
}

void wxListCtrl::RefreshItems(long itemFrom, long itemTo)
{
}

// ----------------------------------------------------------------------------
// internal data stuff
// ----------------------------------------------------------------------------

static wxListItemInternalData *wxGetInternalData(HWND hwnd, long itemId)
{
    return NULL;
};

static wxListItemInternalData *wxGetInternalData(const wxListCtrl *ctl, long itemId)
{
    return wxGetInternalData(GetHwndOf(ctl), itemId);
};

static wxListItemAttr *wxGetInternalDataAttr(wxListCtrl *ctl, long itemId)
{
    return NULL;
};

static void wxDeleteInternalData(wxListCtrl* ctl, long itemId)
{
}

#endif // wxUSE_LISTCTRL
