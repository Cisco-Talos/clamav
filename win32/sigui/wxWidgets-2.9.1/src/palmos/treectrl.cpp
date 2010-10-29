/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/treectrl.cpp
// Purpose:     wxTreeCtrl
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

#if wxUSE_TREECTRL

#include "wx/treectrl.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/settings.h"
#endif

#include "wx/imaglist.h"

// macros to hide the cast ugliness
// --------------------------------

// ptr is the real item id, i.e. wxTreeItemId::m_pItem
#define HITEM_PTR(ptr)     (HTREEITEM)(ptr)

// item here is a wxTreeItemId
#define HITEM(item)     HITEM_PTR((item).m_pItem)

// the native control doesn't support multiple selections under MSW and we
// have 2 ways to emulate them: either using TVS_CHECKBOXES style and let
// checkboxes be the selection status (checked == selected) or by really
// emulating everything, i.e. intercepting mouse and key events &c. The first
// approach is much easier but doesn't work with comctl32.dll < 4.71 and also
// looks quite ugly.
#define wxUSE_CHECKBOXES_IN_MULTI_SEL_TREE 0

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxTreeCtrlStyle )

wxBEGIN_FLAGS( wxTreeCtrlStyle )
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

    wxFLAGS_MEMBER(wxTR_EDIT_LABELS)
    wxFLAGS_MEMBER(wxTR_NO_BUTTONS)
    wxFLAGS_MEMBER(wxTR_HAS_BUTTONS)
    wxFLAGS_MEMBER(wxTR_TWIST_BUTTONS)
    wxFLAGS_MEMBER(wxTR_NO_LINES)
    wxFLAGS_MEMBER(wxTR_FULL_ROW_HIGHLIGHT)
    wxFLAGS_MEMBER(wxTR_LINES_AT_ROOT)
    wxFLAGS_MEMBER(wxTR_HIDE_ROOT)
    wxFLAGS_MEMBER(wxTR_ROW_LINES)
    wxFLAGS_MEMBER(wxTR_HAS_VARIABLE_ROW_HEIGHT)
    wxFLAGS_MEMBER(wxTR_SINGLE)
    wxFLAGS_MEMBER(wxTR_MULTIPLE)
    wxFLAGS_MEMBER(wxTR_EXTENDED)
    wxFLAGS_MEMBER(wxTR_DEFAULT_STYLE)

wxEND_FLAGS( wxTreeCtrlStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxTreeCtrl, wxControl,"wx/treectrl.h")

wxBEGIN_PROPERTIES_TABLE(wxTreeCtrl)
    wxEVENT_PROPERTY( TextUpdated , wxEVT_COMMAND_TEXT_UPDATED , wxCommandEvent )
    wxEVENT_RANGE_PROPERTY( TreeEvent , wxEVT_COMMAND_TREE_BEGIN_DRAG , wxEVT_COMMAND_TREE_STATE_IMAGE_CLICK , wxTreeEvent )
    wxPROPERTY_FLAGS( WindowStyle , wxTreeCtrlStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxTreeCtrl)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_5( wxTreeCtrl , wxWindow* , Parent , wxWindowID , Id , wxPoint , Position , wxSize , Size , long , WindowStyle )
#else
IMPLEMENT_DYNAMIC_CLASS(wxTreeCtrl, wxControl)
#endif

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// indices in gs_expandEvents table below
enum
{
    IDX_COLLAPSE,
    IDX_EXPAND,
    IDX_WHAT_MAX
};

enum
{
    IDX_DONE,
    IDX_DOING,
    IDX_HOW_MAX
};

// handy table for sending events - it has to be initialized during run-time
// now so can't be const any more
static /* const */ wxEventType gs_expandEvents[IDX_WHAT_MAX][IDX_HOW_MAX];

/*
   but logically it's a const table with the following entries:
=
{
    { wxEVT_COMMAND_TREE_ITEM_COLLAPSED, wxEVT_COMMAND_TREE_ITEM_COLLAPSING },
    { wxEVT_COMMAND_TREE_ITEM_EXPANDED,  wxEVT_COMMAND_TREE_ITEM_EXPANDING  }
};
*/

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// construction and destruction
// ----------------------------------------------------------------------------

void wxTreeCtrl::Init()
{
}

bool wxTreeCtrl::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxPoint& pos,
                        const wxSize& size,
                        long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    return false;
}

wxTreeCtrl::~wxTreeCtrl()
{
}

// ----------------------------------------------------------------------------
// accessors
// ----------------------------------------------------------------------------

/* static */ wxVisualAttributes
wxTreeCtrl::GetClassDefaultAttributes(wxWindowVariant variant)
{
    wxVisualAttributes attrs;

    return attrs;
}


// simple wrappers which add error checking in debug mode

bool wxTreeCtrl::DoGetItem(wxTreeViewItem* tvItem) const
{
    return false;
}

void wxTreeCtrl::DoSetItem(wxTreeViewItem* tvItem)
{
}

unsigned int wxTreeCtrl::GetCount() const
{
    // TODO
    return 0;
}

unsigned int wxTreeCtrl::GetIndent() const
{
    return 0;
}

void wxTreeCtrl::SetIndent(unsigned int indent)
{
}

wxImageList *wxTreeCtrl::GetImageList() const
{
    return m_imageListNormal;
}

wxImageList *wxTreeCtrl::GetStateImageList() const
{
    return m_imageListState;
}

void wxTreeCtrl::SetAnyImageList(wxImageList *imageList, int which)
{
}

void wxTreeCtrl::SetImageList(wxImageList *imageList)
{
}

void wxTreeCtrl::SetStateImageList(wxImageList *imageList)
{
}

void wxTreeCtrl::AssignImageList(wxImageList *imageList)
{
}

void wxTreeCtrl::AssignStateImageList(wxImageList *imageList)
{
}

size_t wxTreeCtrl::GetChildrenCount(const wxTreeItemId& item,
                                    bool recursively) const
{
    return 0;
}

// ----------------------------------------------------------------------------
// control colours
// ----------------------------------------------------------------------------

bool wxTreeCtrl::SetBackgroundColour(const wxColour &colour)
{
    return false;
}

bool wxTreeCtrl::SetForegroundColour(const wxColour &colour)
{
    return false;
}

// ----------------------------------------------------------------------------
// Item access
// ----------------------------------------------------------------------------

wxString wxTreeCtrl::GetItemText(const wxTreeItemId& item) const
{
    return wxString(wxT(""));
}

void wxTreeCtrl::SetItemText(const wxTreeItemId& item, const wxString& text)
{
}

int wxTreeCtrl::DoGetItemImageFromData(const wxTreeItemId& item,
                                       wxTreeItemIcon which) const
{
    return -1;
}

void wxTreeCtrl::DoSetItemImageFromData(const wxTreeItemId& item,
                                        int image,
                                        wxTreeItemIcon which) const
{
}

void wxTreeCtrl::DoSetItemImages(const wxTreeItemId& item,
                                 int image,
                                 int imageSel)
{
}

int wxTreeCtrl::GetItemImage(const wxTreeItemId& item,
                             wxTreeItemIcon which) const
{
    return -1;
}

void wxTreeCtrl::SetItemImage(const wxTreeItemId& item, int image,
                              wxTreeItemIcon which)
{
}

wxTreeItemData *wxTreeCtrl::GetItemData(const wxTreeItemId& item) const
{
    return NULL;
}

void wxTreeCtrl::SetItemData(const wxTreeItemId& item, wxTreeItemData *data)
{
}

void wxTreeCtrl::SetIndirectItemData(const wxTreeItemId& item,
                                     wxTreeItemIndirectData *data)
{
}

bool wxTreeCtrl::HasIndirectData(const wxTreeItemId& item) const
{
    return false;
}

void wxTreeCtrl::SetItemHasChildren(const wxTreeItemId& item, bool has)
{
}

void wxTreeCtrl::SetItemBold(const wxTreeItemId& item, bool bold)
{
}

void wxTreeCtrl::SetItemDropHighlight(const wxTreeItemId& item, bool highlight)
{
}

void wxTreeCtrl::RefreshItem(const wxTreeItemId& item)
{
}

wxColour wxTreeCtrl::GetItemTextColour(const wxTreeItemId& item) const
{
    return wxNullColour;
}

wxColour wxTreeCtrl::GetItemBackgroundColour(const wxTreeItemId& item) const
{
    return wxNullColour;
}

wxFont wxTreeCtrl::GetItemFont(const wxTreeItemId& item) const
{
    return wxNullFont;
}

void wxTreeCtrl::SetItemTextColour(const wxTreeItemId& item,
                                   const wxColour& col)
{
}

void wxTreeCtrl::SetItemBackgroundColour(const wxTreeItemId& item,
                                         const wxColour& col)
{
}

void wxTreeCtrl::SetItemFont(const wxTreeItemId& item, const wxFont& font)
{
}

// ----------------------------------------------------------------------------
// Item status
// ----------------------------------------------------------------------------

bool wxTreeCtrl::IsVisible(const wxTreeItemId& item) const
{
    return false;
}

bool wxTreeCtrl::ItemHasChildren(const wxTreeItemId& item) const
{
    return false;
}

bool wxTreeCtrl::IsExpanded(const wxTreeItemId& item) const
{
    return false;
}

bool wxTreeCtrl::IsSelected(const wxTreeItemId& item) const
{
    return false;
}

bool wxTreeCtrl::IsBold(const wxTreeItemId& item) const
{
    return false;
}

// ----------------------------------------------------------------------------
// navigation
// ----------------------------------------------------------------------------

wxTreeItemId wxTreeCtrl::GetRootItem() const
{
    return wxTreeItemId();
}

wxTreeItemId wxTreeCtrl::GetSelection() const
{
    return 0;
}

wxTreeItemId wxTreeCtrl::GetItemParent(const wxTreeItemId& item) const
{
    return 0;
}

wxTreeItemId wxTreeCtrl::GetFirstChild(const wxTreeItemId& item,
                                       wxTreeItemIdValue& cookie) const
{
    return 0;
}

wxTreeItemId wxTreeCtrl::GetNextChild(const wxTreeItemId& WXUNUSED(item),
                                      wxTreeItemIdValue& cookie) const
{
    return 0;
}

wxTreeItemId wxTreeCtrl::GetLastChild(const wxTreeItemId& item) const
{
    return 0;
}

wxTreeItemId wxTreeCtrl::GetNextSibling(const wxTreeItemId& item) const
{
    return 0;
}

wxTreeItemId wxTreeCtrl::GetPrevSibling(const wxTreeItemId& item) const
{
    return 0;
}

wxTreeItemId wxTreeCtrl::GetFirstVisibleItem() const
{
    return 0;
}

wxTreeItemId wxTreeCtrl::GetNextVisible(const wxTreeItemId& item) const
{
    return 0;
}

wxTreeItemId wxTreeCtrl::GetPrevVisible(const wxTreeItemId& item) const
{
    return 0;
}

// ----------------------------------------------------------------------------
// multiple selections emulation
// ----------------------------------------------------------------------------

bool wxTreeCtrl::IsItemChecked(const wxTreeItemId& item) const
{
    return false;
}

void wxTreeCtrl::SetItemCheck(const wxTreeItemId& item, bool check)
{
}

size_t wxTreeCtrl::GetSelections(wxArrayTreeItemIds& selections) const
{
    return 0;
}

// ----------------------------------------------------------------------------
// Usual operations
// ----------------------------------------------------------------------------

wxTreeItemId wxTreeCtrl::DoInsertItem(const wxTreeItemId& parent,
                                      wxTreeItemId hInsertAfter,
                                      const wxString& text,
                                      int image, int selectedImage,
                                      wxTreeItemData *data)
{
    return 0;
}

wxTreeItemId wxTreeCtrl::AddRoot(const wxString& text,
                                 int image, int selectedImage,
                                 wxTreeItemData *data)
{
    return 0;
}

wxTreeItemId wxTreeCtrl::PrependItem(const wxTreeItemId& parent,
                                     const wxString& text,
                                     int image, int selectedImage,
                                     wxTreeItemData *data)
{
    return 0;
}

wxTreeItemId wxTreeCtrl::InsertItem(const wxTreeItemId& parent,
                                    const wxTreeItemId& idPrevious,
                                    const wxString& text,
                                    int image, int selectedImage,
                                    wxTreeItemData *data)
{
    return 0;
}

wxTreeItemId wxTreeCtrl::InsertItem(const wxTreeItemId& parent,
                                    size_t index,
                                    const wxString& text,
                                    int image, int selectedImage,
                                    wxTreeItemData *data)
{
    return 0;
}

wxTreeItemId wxTreeCtrl::AppendItem(const wxTreeItemId& parent,
                                    const wxString& text,
                                    int image, int selectedImage,
                                    wxTreeItemData *data)
{
    return 0;
}

void wxTreeCtrl::Delete(const wxTreeItemId& item)
{
}

// delete all children (but don't delete the item itself)
void wxTreeCtrl::DeleteChildren(const wxTreeItemId& item)
{
}

void wxTreeCtrl::DeleteAllItems()
{
}

void wxTreeCtrl::DoExpand(const wxTreeItemId& item, int flag)
{
}

void wxTreeCtrl::Expand(const wxTreeItemId& item)
{
}

void wxTreeCtrl::Collapse(const wxTreeItemId& item)
{
}

void wxTreeCtrl::CollapseAndReset(const wxTreeItemId& item)
{
}

void wxTreeCtrl::Toggle(const wxTreeItemId& item)
{
}

void wxTreeCtrl::Unselect()
{
}

void wxTreeCtrl::UnselectAll()
{
}

void wxTreeCtrl::SelectItem(const wxTreeItemId& item, bool select)
{
}

void wxTreeCtrl::UnselectItem(const wxTreeItemId& item)
{
}

void wxTreeCtrl::ToggleItemSelection(const wxTreeItemId& item)
{
}

void wxTreeCtrl::EnsureVisible(const wxTreeItemId& item)
{
}

void wxTreeCtrl::ScrollTo(const wxTreeItemId& item)
{
}

wxTextCtrl *wxTreeCtrl::GetEditControl() const
{
    return NULL;
}

void wxTreeCtrl::DeleteTextCtrl()
{
}

wxTextCtrl* wxTreeCtrl::EditLabel(const wxTreeItemId& item,
                                  wxClassInfo* textControlClass)
{
    return NULL;
}

// End label editing, optionally cancelling the edit
void wxTreeCtrl::EndEditLabel(const wxTreeItemId& WXUNUSED(item), bool discardChanges)
{
}

wxTreeItemId wxTreeCtrl::HitTest(const wxPoint& point, int& flags)
{
    return 0;
}

bool wxTreeCtrl::GetBoundingRect(const wxTreeItemId& item,
                                 wxRect& rect,
                                 bool textOnly) const
{
    return false;
}

// ----------------------------------------------------------------------------
// sorting stuff
// ----------------------------------------------------------------------------

/*
// this is just a tiny namespace which is friend to wxTreeCtrl and so can use
// functions such as IsDataIndirect()
class wxTreeSortHelper
{
public:
    static int CALLBACK Compare(LPARAM data1, LPARAM data2, LPARAM tree);

private:
    static wxTreeItemId GetIdFromData(LPARAM lParam)
    {
        return ((wxTreeItemParam*)lParam)->GetItem();
    }
};

int CALLBACK wxTreeSortHelper::Compare(LPARAM pItem1,
                                       LPARAM pItem2,
                                       LPARAM htree)
{
    wxCHECK_MSG( pItem1 && pItem2, 0,
                 wxT("sorting tree without data doesn't make sense") );

    wxTreeCtrl *tree = (wxTreeCtrl *)htree;

    return tree->OnCompareItems(GetIdFromData(tree, pItem1),
                                GetIdFromData(tree, pItem2));
}
*/
int wxTreeCtrl::OnCompareItems(const wxTreeItemId& item1,
                               const wxTreeItemId& item2)
{
    return wxStrcmp(GetItemText(item1), GetItemText(item2));
}

void wxTreeCtrl::SortChildren(const wxTreeItemId& item)
{
    wxCHECK_RET( item.IsOk(), wxT("invalid tree item") );

}

// ----------------------------------------------------------------------------
// State control.
// ----------------------------------------------------------------------------

// why do they define INDEXTOSTATEIMAGEMASK but not the inverse?
#define STATEIMAGEMASKTOINDEX(state) (((state) & TVIS_STATEIMAGEMASK) >> 12)

void wxTreeCtrl::SetState(const wxTreeItemId& node, int state)
{
}

int wxTreeCtrl::GetState(const wxTreeItemId& node)
{
    return 0;
}

#endif // wxUSE_TREECTRL
