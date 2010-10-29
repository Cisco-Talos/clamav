/////////////////////////////////////////////////////////////////////////////
// Name:        sharedptr.h
// Purpose:     interface of wxSharedPtr<T>
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    A smart pointer with non-intrusive reference counting.

    It is modeled after @c boost::shared_ptr<> and can be used with STL
    containers and wxVector<T> unlike @c std::auto_ptr<> and wxScopedPtr<T>.

    @library{wxbase}
    @category{smartpointers}

    @see wxScopedPtr<T>, wxWeakRef<T>, wxObjectDataPtr<T>
*/
template<typename T>
class wxSharedPtr<T>
{
public:
    /**
        Constructor.

        Creates shared pointer from the raw pointer @a ptr and takes ownership
        of it.
    */
    wxEXPLICIT wxSharedPtr(T* ptr = NULL);

    /**
        Copy constructor.
    */
    wxSharedPtr(const wxSharedPtr<T>& tocopy);

    /**
        Destructor.
    */
    ~wxSharedPtr();

    /**
        Returns pointer to its object or @NULL.
    */
    T* get() const;

    /**
        Conversion to a boolean expression (in a variant which is not
        convertible to anything but a boolean expression).

        If this class contains a valid pointer it will return @true, if it contains
        a @NULL pointer it will return @false.
    */
    operator unspecified_bool_type() const;

    /**
        Returns a reference to the object.

        If the internal pointer is @NULL this method will cause an assert in debug mode.
    */
    T operator*() const;

    /**
        Returns pointer to its object or @NULL.
    */
    T* operator->() const;

    /**
        Assignment operator.

        Releases any previously held pointer and creates a reference to @a ptr.
    */
    wxSharedPtr<T>& operator=(T* ptr);

    /**
        Assignment operator.

        Releases any previously held pointer and creates a reference to the
        same object as @a topcopy.
    */
    wxSharedPtr<T>& operator=(const wxSharedPtr<T>& tocopy);

    /**
        Reset pointer to @a ptr.

        If the reference count of the previously owned pointer was 1 it will be deleted.
    */
    void reset(T* ptr = NULL);

    /**
        Returns @true if this is the only pointer pointing to its object.
    */
    bool unique() const;

    /**
        Returns the number of pointers pointing to its object.
    */
    long use_count() const;
};

