/////////////////////////////////////////////////////////////////////////////
// Name:        runtimeclass.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_rtti Runtime Type Information (RTTI)

@li @ref overview_rtti_intro
@li @ref overview_rtti_classinfo
@li @ref overview_rtti_example

@see

@li wxObject
@li wxClassInfo


<hr>


@section overview_rtti_intro Introduction

One of the failings of C++ used to be that no runtime information was provided
about a class and its position in the inheritance hierarchy. Another, which
still persists, is that instances of a class cannot be created just by knowing
the name of a class, which makes facilities such as persistent storage hard to
implement.

Most C++ GUI frameworks overcome these limitations by means of a set of macros
and functions and wxWidgets is no exception. As it originated before the
addition of RTTI to the C++ standard and as support for it is still missing
from some (albeit old) compilers, wxWidgets doesn't (yet) use it, but provides
it's own macro-based RTTI system.

In the future, the standard C++ RTTI will be used though and you're encouraged
to use whenever possible the wxDynamicCast macro which, for the implementations
that support it, is defined just as dynamic_cast and uses wxWidgets RTTI for
all the others. This macro is limited to wxWidgets classes only and only works
with pointers (unlike the real dynamic_cast which also accepts references).

Each class that you wish to be known to the type system should have a macro
such as DECLARE_DYNAMIC_CLASS just inside the class declaration. The macro
IMPLEMENT_DYNAMIC_CLASS should be in the implementation file. Note that these
are entirely optional; use them if you wish to check object types, or create
instances of classes using the class name. However, it is good to get into the
habit of adding these macros for all classes.

Variations on these macros are used for multiple inheritance, and abstract
classes that cannot be instantiated dynamically or otherwise.

DECLARE_DYNAMIC_CLASS inserts a static wxClassInfo declaration into the class,
initialized by IMPLEMENT_DYNAMIC_CLASS. When initialized, the wxClassInfo
object inserts itself into a linked list (accessed through wxClassInfo::first
and wxClassInfo::next pointers). The linked list is fully created by the time
all global initialisation is done.

IMPLEMENT_DYNAMIC_CLASS is a macro that not only initialises the static
wxClassInfo member, but defines a global function capable of creating a dynamic
object of the class in question. A pointer to this function is stored in
wxClassInfo, and is used when an object should be created dynamically.

wxObject::IsKindOf uses the linked list of wxClassInfo. It takes a wxClassInfo
argument, so use CLASSINFO(className) to return an appropriate wxClassInfo
pointer to use in this function.

The function wxCreateDynamicObject can be used to construct a new object of a
given type, by supplying a string name. If you have a pointer to the
wxClassInfo object instead, then you can simply call wxClassInfo::CreateObject.


@section overview_rtti_classinfo wxClassInfo

This class stores meta-information about classes. An application may use macros
such as DECLARE_DYNAMIC_CLASS and IMPLEMENT_DYNAMIC_CLASS to record runtime
information about a class, including:

@li It's position in the inheritance hierarchy.
@li The base class name(s) (up to two base classes are permitted).
@li A string representation of the class name.
@li A function that can be called to construct an instance of this class.

The DECLARE_... macros declare a static wxClassInfo variable in a class, which
is initialized by macros of the form IMPLEMENT_... in the implementation C++
file. Classes whose instances may be constructed dynamically are given a global
constructor function which returns a new object.

You can get the wxClassInfo for a class by using the CLASSINFO macro, e.g.
CLASSINFO(wxFrame). You can get the wxClassInfo for an object using
wxObject::GetClassInfo.

@see

@li wxObject
@li wxCreateDynamicObject


@section overview_rtti_example Example

In a header file frame.h:

@code
class wxFrame : public wxWindow
{
    DECLARE_DYNAMIC_CLASS(wxFrame)

private:
    wxString m_title;

public:
...
};
@endcode

In a C++ file frame.cpp:

@code
IMPLEMENT_DYNAMIC_CLASS(wxFrame, wxWindow)

wxFrame::wxFrame()
{
...
}
@endcode

*/

