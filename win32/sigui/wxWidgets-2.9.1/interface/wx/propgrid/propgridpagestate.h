/////////////////////////////////////////////////////////////////////////////
// Name:        property.h
// Purpose:     interface of wxPGProperty
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**
    @section propgrid_hittestresult wxPropertyGridHitTestResult

    A return value from wxPropertyGrid::HitTest(),
    contains all you need to know about an arbitrary location on the grid.
*/
struct wxPropertyGridHitTestResult
{
public:

    wxPGProperty* GetProperty() const { return property; }

    /** Column. -1 for margin. */
    int             column;

    /** Index of splitter hit, -1 for none. */
    int             splitter;

    /** If splitter hit, offset to that */
    int             splitterHitOffset;

private:
    /** Property. NULL if empty space below properties was hit */
    wxPGProperty*   property;
};

// -----------------------------------------------------------------------

#define wxPG_IT_CHILDREN(A)         (A<<16)

/** @section propgrid_iterator_flags wxPropertyGridIterator Flags
    @{

    NOTES: At lower 16-bits, there are flags to check if item will be included. At higher
      16-bits, there are same flags, but to instead check if children will be included.
*/

enum wxPG_ITERATOR_FLAGS
{

/** Iterate through 'normal' property items (does not include children of aggregate or hidden items by default).
*/
wxPG_ITERATE_PROPERTIES             = (wxPG_PROP_PROPERTY|wxPG_PROP_MISC_PARENT|wxPG_PROP_AGGREGATE| \
                                       wxPG_PROP_COLLAPSED|((wxPG_PROP_MISC_PARENT|wxPG_PROP_CATEGORY)<<16)),

/** Iterate children of collapsed parents, and individual items that are hidden.
*/
wxPG_ITERATE_HIDDEN                 = (wxPG_PROP_HIDDEN|wxPG_IT_CHILDREN(wxPG_PROP_COLLAPSED)),

/** Iterate children of parent that is an aggregate property (ie. has fixed children).
*/
wxPG_ITERATE_FIXED_CHILDREN         = (wxPG_IT_CHILDREN(wxPG_PROP_AGGREGATE)|wxPG_ITERATE_PROPERTIES),

/** Iterate categories. Note that even without this flag, children of categories
    are still iterated through.
*/
wxPG_ITERATE_CATEGORIES             = (wxPG_PROP_CATEGORY|wxPG_IT_CHILDREN(wxPG_PROP_CATEGORY)|wxPG_PROP_COLLAPSED),

wxPG_ITERATE_ALL_PARENTS            = (wxPG_PROP_MISC_PARENT|wxPG_PROP_AGGREGATE|wxPG_PROP_CATEGORY),

wxPG_ITERATE_ALL_PARENTS_RECURSIVELY        = (wxPG_ITERATE_ALL_PARENTS|wxPG_IT_CHILDREN(wxPG_ITERATE_ALL_PARENTS)),

wxPG_ITERATOR_FLAGS_ALL             = (wxPG_PROP_PROPERTY|wxPG_PROP_MISC_PARENT|wxPG_PROP_AGGREGATE| \
                                      wxPG_PROP_HIDDEN|wxPG_PROP_CATEGORY|wxPG_PROP_COLLAPSED),

wxPG_ITERATOR_MASK_OP_ITEM          = wxPG_ITERATOR_FLAGS_ALL,

wxPG_ITERATOR_MASK_OP_PARENT        = wxPG_ITERATOR_FLAGS_ALL,  // (wxPG_PROP_MISC_PARENT|wxPG_PROP_AGGREGATE|wxPG_PROP_CATEGORY)

/** Combines all flags needed to iterate through visible properties
    (ie. hidden properties and children of collapsed parents are skipped).
*/
wxPG_ITERATE_VISIBLE                = (wxPG_ITERATE_PROPERTIES|wxPG_PROP_CATEGORY|wxPG_IT_CHILDREN(wxPG_PROP_AGGREGATE)),

/** Iterate all items.
*/
wxPG_ITERATE_ALL                    = (wxPG_ITERATE_VISIBLE|wxPG_ITERATE_HIDDEN),

/** Iterate through individual properties (ie. categories and children of
    aggregate properties are skipped).
*/
wxPG_ITERATE_NORMAL                 = (wxPG_ITERATE_PROPERTIES|wxPG_ITERATE_HIDDEN),

/** Default iterator flags.
*/
wxPG_ITERATE_DEFAULT                = wxPG_ITERATE_NORMAL

};

/** @}
*/


/**
    @section propgrid_iterator_class wxPropertyGridIterator

    Preferable way to iterate through contents of wxPropertyGrid,
    wxPropertyGridManager, and wxPropertyGridPage.

    See wxPropertyGridInterface::GetIterator() for more information about usage.

    @library{wxpropgrid}
    @category{propgrid}
*/
class wxPropertyGridIterator : public wxPropertyGridIteratorBase
{
public:

    void Assign( const wxPropertyGridIteratorBase& it );

    bool AtEnd() const { return m_property == NULL; }

    /**
        Get current property.
    */
    wxPGProperty* GetProperty() const { return m_property; }

    /**
        Iterate to the next property.
    */
    void Next( bool iterateChildren = true );

    /**
        Iterate to the previous property.
    */
    void Prev();

protected:
};

// -----------------------------------------------------------------------

/**
    @section propgrid_viterator_class wxPGVIterator

    Abstract implementation of a simple iterator. Can only be used
    to iterate in forward order, and only through the entire container.
    Used to have functions dealing with all properties work with both
    wxPropertyGrid and wxPropertyGridManager.
*/
class wxPGVIterator
{
public:
    wxPGVIterator() { m_pIt = NULL; }
    wxPGVIterator( wxPGVIteratorBase* obj ) { m_pIt = obj; }
    ~wxPGVIterator() { UnRef(); }
    void UnRef() { if (m_pIt) m_pIt->DecRef(); }
    wxPGVIterator( const wxPGVIterator& it )
    {
        m_pIt = it.m_pIt;
        m_pIt->IncRef();
    }
    const wxPGVIterator& operator=( const wxPGVIterator& it )
    {
        UnRef();
        m_pIt = it.m_pIt;
        m_pIt->IncRef();
        return *this;
    }
    void Next() { m_pIt->Next(); }
    bool AtEnd() const { return m_pIt->m_it.AtEnd(); }
    wxPGProperty* GetProperty() const { return m_pIt->m_it.GetProperty(); }
protected:
    wxPGVIteratorBase*  m_pIt;
};


