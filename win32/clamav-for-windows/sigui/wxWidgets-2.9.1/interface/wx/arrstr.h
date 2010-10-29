/////////////////////////////////////////////////////////////////////////////
// Name:        arrstr.h
// Purpose:     interface of wxArrayString
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxArrayString

    wxArrayString is an efficient container for storing wxString objects.

    It has the same features as all wxArray classes, i.e. it dynamically expands
    when new items are added to it (so it is as easy to use as a linked list),
    but the access time to the elements is constant, instead of being linear in
    number of elements as in the case of linked lists. It is also very size
    efficient and doesn't take more space than a C array @e wxString[] type
    (wxArrayString uses its knowledge of internals of wxString class to achieve this).

    This class is used in the same way as other dynamic arrays(), except that no
    ::WX_DEFINE_ARRAY declaration is needed for it.
    When a string is added or inserted in the array, a copy of the string is created,
    so the original string may be safely deleted (e.g. if it was a @e wxChar *
    pointer the memory it was using can be freed immediately after this).
    In general, there is no need to worry about string memory deallocation when using
    this class - it will always free the memory it uses itself.

    The references returned by wxArrayString::Item, wxArrayString::Last or
    wxArrayString::operator[] are not constant, so the array elements may
    be modified in place like this:

    @code
    array.Last().MakeUpper();
    @endcode

    @note none of the methods of wxArrayString is virtual including its
          destructor, so this class should not be used as a base class.

    Although this is not true strictly speaking, this class may be considered as
    a specialization of wxArray class for the wxString member data: it is not
    implemented like this, but it does have all of the wxArray functions.

    It also has the full set of <tt>std::vector<wxString></tt> compatible
    methods, including nested @c iterator and @c const_iterator classes which
    should be used in the new code for forward compatibility with the future
    wxWidgets versions.

    @library{wxbase}
    @category{containers}

    @see wxArray<T>, wxString, @ref overview_string
*/
class wxArrayString : public wxArray
{
public:
    /**
        The function type used with wxArrayString::Sort function.
    */
    typedef int (*CompareFunction)(const wxString& first, const wxString& second);

    /**
        Default constructor.
    */
    wxArrayString();

    /**
        Copy constructor.
    */
    wxArrayString(const wxArrayString& array);

    //@{
    /**
        Constructor from a C string array. Pass a size @a sz and an array @a arr.
    **/
    wxArrayString(size_t sz, const char** arr);
    wxArrayString(size_t sz, const wchar_t** arr);
    //@}

    /**
        Constructor from a wxString array. Pass a size @a sz and array @a arr.
    */
    wxArrayString(size_t sz, const wxString* arr);

    /**
        Destructor frees memory occupied by the array strings. For performance
        reasons it is not virtual, so this class should not be derived from.
    */
    ~wxArrayString();

    /**
        Appends the given number of @a copies of the new item @a str to the
        array and returns the index of the first new item in the array.

        @see Insert()
    */
    size_t Add(const wxString& str, size_t copies = 1);

    /**
        Preallocates enough memory to store @a nCount items.

        This function may be used to improve array class performance before
        adding a known number of items consecutively.
    */
    void Alloc(size_t nCount);

    /**
        Clears the array contents and frees memory.

        @see Empty()
    */
    void Clear();

    /**
        Empties the array: after a call to this function GetCount() will return 0.
        However, this function does not free the memory used by the array and so
        should be used when the array is going to be reused for storing other strings.
        Otherwise, you should use Clear() to empty the array and free memory.
    */
    void Empty();

    /**
        Returns the number of items in the array.
    */
    size_t GetCount() const;

    /**
        Search the element in the array, starting from the beginning if @a bFromEnd
        is @false or from end otherwise. If @a bCase, comparison is case sensitive
        (default), otherwise the case is ignored.

        This function uses linear search for wxArrayString.
        Returns index of the first item matched or @c wxNOT_FOUND if there is no match.
    */
    int Index(const wxString& sz, bool bCase = true, bool bFromEnd = false) const;

    /**
        Insert the given number of @a copies of the new element in the array before the
        position @a nIndex. Thus, for example, to insert the string in the beginning of
        the array you would write:

        @code
        Insert("foo", 0);
        @endcode

        If @a nIndex is equal to GetCount() this function behaves as Add().
    */
    void Insert(wxString lItem, size_t nIndex, size_t copies = 1);

    /**
        Returns @true if the array is empty, @false otherwise. This function returns the
        same result as GetCount() == 0 but is probably easier to read.
    */
    bool IsEmpty() const;

    /**
        Return the array element at position @a nIndex. An assert failure will
        result from an attempt to access an element beyond the end of array in debug
        mode, but no check is done in release mode.

        @see operator[] for the operator version.
    */
    wxString& Item(size_t nIndex) const;

    /**
        Returns the last element of the array. Attempt to access the last element of
        an empty array will result in assert failure in debug build, however no checks
        are done in release mode.
    */
    wxString& Last() const;

    /**
        Removes the first item matching this value. An assert failure is provoked by
        an attempt to remove an element which does not exist in debug build.

        @see Index()
    */
    void Remove(const wxString& sz);

    /**
        Removes @a count items starting at position @a nIndex from the array.
    */
    void RemoveAt(size_t nIndex, size_t count = 1);

    /**
        Releases the extra memory allocated by the array.
        This function is useful to minimize the array memory consumption.

        @see Alloc()
    */
    void Shrink();

    /**
        Sorts the array in alphabetical order or in reverse alphabetical order if
        @a reverseOrder is @true. The sort is case-sensitive.
    */
    void Sort(bool reverseOrder = false);

    /**
        Sorts the array using the specified @a compareFunction for item comparison.
        @a CompareFunction is defined as a function taking two <em>const wxString&</em>
        parameters and returning an @e int value less than, equal to or greater
        than 0 if the first string is less than, equal to or greater than the
        second one.

        Example:
        The following example sorts strings by their length.

        @code
        static int CompareStringLen(const wxString& first, const wxString& second)
        {
            return first.length() - second.length();
        }

        ...

        wxArrayString array;

        array.Add("one");
        array.Add("two");
        array.Add("three");
        array.Add("four");

        array.Sort(CompareStringLen);
        @endcode
    */
    void Sort(CompareFunction compareFunction);

    /**
        Compares 2 arrays respecting the case. Returns @true if the arrays have
        different number of elements or if the elements don't match pairwise.
    */
    bool operator !=(const wxArrayString& array) const;

    /**
        Assignment operator.
    */
    wxArrayString& operator=(const wxArrayString&);

    /**
        Compares 2 arrays respecting the case. Returns @true only if the arrays have
        the same number of elements and the same strings in the same order.
    */
    bool operator ==(const wxArrayString& array) const;

    /**
        Return the array element at position @a nIndex. An assert failure will
        result from an attempt to access an element beyond the end of array in
        debug mode, but no check is done in release mode.

        This is the operator version of the Item() method.
    */
    wxString& operator[](size_t nIndex) const;
};


/**
    @class wxSortedArrayString

    wxSortedArrayString is an efficient container for storing wxString objects
    which always keeps the string in alphabetical order.

    wxSortedArrayString uses binary search in its wxArrayString::Index() function
    (instead of linear search for wxArrayString::Index()) which makes it much more
    efficient if you add strings to the array rarely (because, of course, you have
    to pay for Index() efficiency by having Add() be slower) but search for them
    often. Several methods should not be used with sorted array (basically, all
    those which break the order of items) which is mentioned in their description.

    @todo what about STL? who does it integrates?

    @library{wxbase}
    @category{containers}

    @see wxArray, wxString, @ref overview_string
*/
class wxSortedArrayString : public wxArrayString
{
public:

    /**
        Conversion constructor.

        Constructs a sorted array with the same contents as the (possibly
        unsorted) "array" argument.
    */
    wxSortedArrayString(const wxArrayString& array);

    /**
        @copydoc wxArrayString::Add()

        @warning
        For sorted arrays, the index of the inserted item will not be, in general,
        equal to GetCount() - 1 because the item is inserted at the correct position
        to keep the array sorted and not appended.
    */
    size_t Add(const wxString& str, size_t copies = 1);


    /**
        @copydoc wxArrayString::Index()

        This function uses binary search for wxSortedArrayString, but it ignores
        the @a bCase and @a bFromEnd parameters.
    */
    int Index(const wxString& sz, bool bCase = true,
              bool bFromEnd = false) const;

    /**
        @warning This function should not be used with sorted arrays because it
                 could break the order of items and, for example, subsequent calls
                 to Index() would then not work!

        @warning In STL mode, Insert is private and simply invokes wxFAIL_MSG.
    */
    void Insert(const wxString& str, size_t nIndex,
                size_t copies = 1);

    //@{
    /**
        @warning This function should not be used with sorted array because it could
                 break the order of items and, for example, subsequent calls to Index()
                 would then not work! Also, sorting a wxSortedArrayString doesn't make
                 sense because its elements are always already sorted.

        @warning In STL mode, Sort is private and simply invokes wxFAIL_MSG.
    */
    void Sort(bool reverseOrder = false);
    void Sort(CompareFunction compareFunction);
    //@}
};


// ============================================================================
// Global functions/macros
// ============================================================================

/** @addtogroup group_funcmacro_string */
//@{

/**
    Splits the given wxString object using the separator @a sep and returns the
    result as a wxArrayString.

    If the @a escape character is non-@NULL, then the occurrences of @a sep
    immediately prefixed with @a escape are not considered as separators.
    Note that empty tokens will be generated if there are two or more adjacent
    separators.

    @see wxJoin()

    @header{wx/arrstr.h}
*/
wxArrayString wxSplit(const wxString& str, const wxChar sep,
                      const wxChar escape = '\\');

/**
    Concatenate all lines of the given wxArrayString object using the separator
    @a sep and returns the result as a wxString.

    If the @a escape character is non-@NULL, then it's used as prefix for each
    occurrence of @a sep in the strings contained in @a arr before joining them
    which is necessary in order to be able to recover the original array
    contents from the string later using wxSplit().

    @see wxSplit()

    @header{wx/arrstr.h}
*/
wxString wxJoin(const wxArrayString& arr, const wxChar sep,
                const wxChar escape = '\\');

//@}

