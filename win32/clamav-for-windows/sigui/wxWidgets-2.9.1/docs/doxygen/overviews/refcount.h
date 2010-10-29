/////////////////////////////////////////////////////////////////////////////
// Name:        refcount.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_refcount Reference Counting

@li @ref overview_refcount_ignore
@li @ref overview_refcount_equality
@li @ref overview_refcount_destruct
@li @ref overview_refcount_list
@li @ref overview_refcount_object


<hr>


@section overview_refcount_ignore Why You Shouldn't Care About It

Many wxWidgets objects use a technique known as <em>reference counting</em>,
also known as <em>copy on write</em> (COW). This means that when an object is
assigned to another, no copying really takes place. Only the reference count on
the shared object data is incremented and both objects share the same data (a
very fast operation).

But as soon as one of the two (or more) objects is modified, the data has to be
copied because the changes to one of the objects shouldn't be seen in the
others. As data copying only happens when the object is written to, this is
known as COW.

What is important to understand is that all this happens absolutely
transparently to the class users and that whether an object is shared or not is
not seen from the outside of the class - in any case, the result of any
operation on it is the same.


@section overview_refcount_equality Object Comparison

The == and != operators of @ref overview_refcount_list "the reference counted classes"
always do a <em>deep comparison</em>. This means that the equality operator
will return @true if two objects are identical and not only if they share the
same data.

Note that wxWidgets follows the <em>STL philosophy</em>: when a comparison
operator can not be implemented efficiently (like for e.g. wxImage's ==
operator which would need to compare the entire image's data, pixel-by-pixel),
it's not implemented at all. That's why not all reference counted classes
provide comparison operators.

Also note that if you only need to do a @c shallow comparison between two
wxObject derived classes, you should not use the == and != operators but
rather the wxObject::IsSameAs() function.


@section overview_refcount_destruct Object Destruction

When a COW object destructor is called, it may not delete the data: if it's
shared, the destructor will just decrement the shared data's reference count
without destroying it. Only when the destructor of the last object owning the
data is called, the data is really destroyed. Just like all other COW-things,
this happens transparently to the class users so that you shouldn't care about
it.


@section overview_refcount_list List of Reference Counted Classes

The following classes in wxWidgets have efficient (i.e. fast) assignment
operators and copy constructors since they are reference-counted:

@li wxAcceleratorTable
@li wxAnimation
@li wxBitmap
@li wxBrush
@li wxCursor
@li wxFont
@li wxIcon
@li wxImage
@li wxMetafile
@li wxPalette
@li wxPen
@li wxRegion
@li wxString
@li wxVariant
@li wxVariantData

Note that the list above reports the objects which are reference counted in all
ports of wxWidgets; some ports may use this technique also for other classes.

All the objects implement a function @b IsOk() to test if they are referencing valid
data; when the objects are in uninitialized state, you can only use the @b IsOk() getter;
trying to call any other getter, e.g. wxBrush::GetStyle() on the ::wxNullBrush object,
will result in an assert failure in debug builds.


@section overview_refcount_object Making Your Own Reference Counted Class

Reference counting can be implemented easily using wxObject or using
the intermediate wxRefCounter class directly. 
Alternatively, you can also use the wxObjectDataPtr<T> template.

First, derive a new class from wxRefCounter (or wxObjectRefData when
using a wxObject derived class) and put the memory-consuming data in it.

Then derive a new class from wxObject and implement there the public interface
which will be seen by the user of your class. You'll probably want to add a
function to your class which does the cast from wxObjectRefData to your
class-specific shared data. For example:

@code
MyClassRefData* GetData() const
{
    return wx_static_cast(MyClassRefData*, m_refData);
}
@endcode

In fact, any time you need to read the data from your wxObject-derived class,
you will need to call this function.

@note Any time you need to actually modify the data placed inside your wxObject
derived class, you must first call the wxObject::UnShare() function to ensure
that the modifications won't affect other instances which are eventually
sharing your object's data.

*/

