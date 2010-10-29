/////////////////////////////////////////////////////////////////////////////
// Name:        cpprttidisabled.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_cpp_rtti_disabled Caveats When Not Using C++ RTTI

@li @ref overview_cpp_rtti_disabled_intro
@li @ref overview_cpp_rtti_disabled_bind
@li @ref overview_cpp_rtti_disabled_wxany

@see

@li @ref overview_rtti
@li wxEvtHandler::Bind()
@li wxAny


<hr>


@section overview_cpp_rtti_disabled_intro Introduction

@note C++ RTTI is usually enabled by default in most wxWidgets builds. If you
      do not know if your build has C++ RTTI enabled or not, then it probably
      is enabled, and you should not worry about anything mentioned in this
      section.

While in general wxWidgets standard @ref overview_rtti is used throughout the
library, there are some places where it won't work. One of those places
is template classes.

When available, C++ RTTI is used to address this issue. If you have built the
library with C++ RTTI disabled, an internal RTTI system is substituted.
However, this system is not perfect and one proven scenario where it may break
is a shared library or DLL build. More specifically, a template class instance
created in one physical binary may not be recognized as its correct type when
used in another one.


@section overview_cpp_rtti_disabled_bind Bind() Issues

wxWidgets 2.9.0 introduced a new @ref overview_events_bind system, using
wxEvtHandler::Bind<>() and Unbind<>(). This functionality uses templates
behind the scenes and therefore is vulnerable to breakage in shared library
builds, as described above.

Currently only Unbind<>() needs the type information, so you should be immune
to this problem simply if you only need to use Bind<>() and not Unbind<>().

Also, if you only bind and unbind same event handler inside same binary, you
should be fine.


@section overview_cpp_rtti_disabled_wxany wxAny Issues

wxAny is a dynamic type class which transparently uses templates to generate
data type handlers, and therefore is vulnerable to breakage in shared library
builds, as described above

You should be fine if you only create and use wxAny instances inside same
physical binary. However, if you do need to be able to use wxAny freely
across binary boundaries, (and for sake of code-safety, you probably do),
then specializations for wxAnyValueTypeImpl<> templates need to be defined in
one of your shared library (DLL) files. One specialization is required for
every data type you use with wxAny. Easiest way to do this is using macros
provided in wx/any.h. Note that you @b do @b not need to define
specializations for C built-in types, nor for wxString or wxDateTime, because
these are already provided in wxBase. However, you @b do need to define
specializations for all pointer types except char* and wchar_t*.

Let's define a specialization for imaginary type 'MyClass'. In your shared
library source code you will need to have this line:

@code
    WX_IMPLEMENT_ANY_VALUE_TYPE(wxAnyValueTypeImpl<MyClass>)
@endcode

In your header file you will need the following:

@code
    wxDECLARE_ANY_TYPE(MyClass, WXIMPORT_OR_WXEXPORT)
@endcode

Where WXIMPORT_OR_WXEXPORT is WXEXPORT when being included from the shared
library that called the WX_IMPLEMENT_ANY_VALUE_TYPE() macro, and WXIMPORT
otherwise.

*/

