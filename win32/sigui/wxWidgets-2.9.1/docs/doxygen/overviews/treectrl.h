/////////////////////////////////////////////////////////////////////////////
// Name:        treectrl.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_treectrl wxTreeCtrl Overview

Classes: wxTreeCtrl, wxImageList

The tree control displays its items in a tree like structure. Each item has
its own (optional) icon and a label. An item may be either collapsed (meaning
that its children are not visible) or expanded (meaning that its children are
shown). Each item in the tree is identified by its @c itemId which is of opaque
data type wxTreeItemId. You can test whether an item is valid by calling
wxTreeItemId::IsOk.

The items text and image may be retrieved and changed with (Get|Set)ItemText
and (Get|Set)ItemImage. In fact, an item may even have two images associated
with it: the normal one and another one for selected state which is
set/retrieved with (Get|Set)ItemSelectedImage functions, but this functionality
might be unavailable on some platforms.

Tree items have several attributes: an item may be selected or not, visible or
not, bold or not. It may also be expanded or collapsed. All these attributes
may be retrieved with the corresponding functions: IsSelected, IsVisible,
IsBold and IsExpanded. Only one item at a time may be selected, selecting
another one (with SelectItem) automatically unselects the previously selected
one.

In addition to its icon and label, a user-specific data structure may be
associated with all tree items. If you wish to do it, you should derive a class
from wxTreeItemData which is a very simple class having only one function
GetId() which returns the id of the item this data is associated with. This
data will be freed by the control itself when the associated item is deleted
(all items are deleted when the control is destroyed), so you shouldn't delete
it yourself (if you do it, you should call SetItemData(@NULL) to prevent the
tree from deleting the pointer second time). The associated data may be
retrieved with GetItemData() function.

Working with trees is relatively straightforward if all the items are added to
the tree at the moment of its creation. However, for large trees it may be
very inefficient. To improve the performance you may want to delay adding the
items to the tree until the branch containing the items is expanded: so, in the
beginning, only the root item is created (with AddRoot). Other items are added
when EVT_TREE_ITEM_EXPANDING event is received: then all items lying
immediately under the item being expanded should be added, but, of course, only
when this event is received for the first time for this item - otherwise, the
items would be added twice if the user expands/collapses/re-expands the branch.

The tree control provides functions for enumerating its items. There are 3
groups of enumeration functions: for the children of a given item, for the
sibling of the given item and for the visible items (those which are currently
shown to the user: an item may be invisible either because its branch is
collapsed or because it is scrolled out of view). Child enumeration functions
require the caller to give them a @e cookie parameter: it is a number which
is opaque to the caller but is used by the tree control itself to allow
multiple enumerations to run simultaneously (this is explicitly allowed). The
only thing to remember is that the @e cookie passed to GetFirstChild and to
GetNextChild should be the same variable (and that nothing should be done with
it by the user code).

Among other features of the tree control are: item sorting with SortChildren
which uses the user-defined comparison function OnCompareItems (by default the
comparison is the alphabetic comparison of tree labels), hit testing
(determining to which portion of the control the given point belongs, useful
for implementing drag-and-drop in the tree) with HitTest and editing of the
tree item labels in place (see EditLabel).

Finally, the tree control has a keyboard interface: the cursor navigation
(arrow) keys may be used to change the current selection. HOME and END are used
to go to the first/last sibling of the current item. '+', '-' and '*' expand,
collapse and toggle the current branch. Note, however, that DEL and INS keys do
nothing by default, but it is common to associate them with deleting an item
from a tree and inserting a new one into it.

*/

