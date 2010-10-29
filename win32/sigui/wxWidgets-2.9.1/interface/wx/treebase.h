/////////////////////////////////////////////////////////////////////////////
// Name:        treebase.h
// Purpose:     interface of wxTreeItemId
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxTreeItemId

    An opaque reference to a tree item.

    @library{wxcore}
    @category{data}

    @see wxTreeCtrl, wxTreeItemData, @ref overview_treectrl
*/
class wxTreeItemId
{
public:
    /**
        Default constructor. A wxTreeItemId is not meant to be constructed
        explicitly by the user; only those returned by the wxTreeCtrl functions
        should be used.
    */
    wxTreeItemId();

    /**
        Returns @true if this instance is referencing a valid tree item.
    */
    bool IsOk() const;

    //@{
    /**
         Operators for comparison between wxTreeItemId objects.
    */
    bool operator ==(const wxTreeItemId& item) const;
    bool operator !=(const wxTreeItemId& item) const;
    //@}

    /**
        Antonym of IsOk(), i.e. returns @true only if the item is not valid.
    */
    bool operator !() const;
};

/**
    @class wxTreeItemData

    wxTreeItemData is some (arbitrary) user class associated with some item. The
    main advantage of having this class is that wxTreeItemData objects are
    destroyed automatically by the tree and, as this class has virtual
    destructor, it means that the memory and any other resources associated with
    a tree item will be automatically freed when it is deleted. Note that we
    don't use wxObject as the base class for wxTreeItemData because the size of
    this class is critical: in many applications, each tree leaf will have
    wxTreeItemData associated with it and the number of leaves may be quite big.

    Also please note that because the objects of this class are deleted by the
    tree using the operator @c delete, they must always be allocated on the heap
    using @c new.

    @library{wxcore}
    @category{containers}

    @see wxTreeCtrl
*/
class wxTreeItemData : public wxClientData
{
public:
    /**
        Default constructor.

        @beginWxPythonOnly
        The following methods are added in wxPython for accessing the object:
        - GetData(): Returns a reference to the Python Object.
        - SetData(obj): Associates a new Python Object with the wxTreeItemData.
        @endWxPythonOnly

        @beginWxPerlOnly
        In wxPerl the constructor accepts a scalar as an optional parameter
        and stores it as client data; use
        - GetData() to retrieve the value.
        - SetData(data) to set it.
        @endWxPerlOnly
    */
    wxTreeItemData();

    /**
        Virtual destructor.
    */
    virtual ~wxTreeItemData();

    /**
        Returns the item associated with this node.
    */
    const wxTreeItemId& GetId() const;

    /**
        Sets the item associated with this node.

        Notice that this function is automatically called by wxTreeCtrl methods
        associating an object of this class with a tree control item such as
        wxTreeCtrl::AppendItem(), wxTreeCtrl::InsertItem() and
        wxTreeCtrl::SetItemData() so there is usually no need to call it
        yourself.
    */
    void SetId(const wxTreeItemId& id);
};

/**
    Indicates which type to associate an image with a wxTreeCtrl item.

    @see wxTreeCtrl::GetItemImage(), wxTreeCtrl::SetItemImage()
*/
enum wxTreeItemIcon
{
    /**
        To get/set the item image for when the item is
        @b not selected and @b not expanded.
    */
    wxTreeItemIcon_Normal,
    /**
        To get/set the item image for when the item is
        @b selected and @b not expanded.
    */
    wxTreeItemIcon_Selected,
    /**
        To get/set the item image for when the item is
        @b not selected and @b expanded.
    */
    wxTreeItemIcon_Expanded,
    /**
        To get/set the item image for when the item is
        @b selected and @b expanded.
    */
    wxTreeItemIcon_SelectedExpanded,
    wxTreeItemIcon_Max
};
