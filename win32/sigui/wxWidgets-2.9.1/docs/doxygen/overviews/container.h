/////////////////////////////////////////////////////////////////////////////
// Name:        container.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_container Container Classes

Classes: wxList<T>, wxArray<T>, wxVector<T>

wxWidgets uses itself several container classes including doubly-linked lists
and dynamic arrays (i.e. arrays which expand automatically when they become
full). For both historical and portability reasons wxWidgets does not require
the use of STL (which provides the standard implementation of many container
classes in C++) but it can be compiled in STL mode. Additionally, wxWidgets
provides the new wxVector<T> class template which can be used like the std::vector
class and is actually just a typedef to std::vector if wxWidgets is compiled
in STL mode.

wxWidgets non-template container classes don't pretend to be as powerful or full as STL
ones, but they are quite useful and may be compiled with absolutely any C++
compiler. They're used internally by wxWidgets, but may, of course, be used in
your programs as well if you wish.

The list classes in wxWidgets are doubly-linked lists which may either own the
objects they contain (meaning that the list deletes the object when it is
removed from the list or the list itself is destroyed) or just store the
pointers depending on whether or not you called wxList<T>::DeleteContents()
method.

Dynamic arrays resemble C arrays but with two important differences: they
provide run-time range checking in debug builds and they automatically expand
the allocated memory when there is no more space for new items. They come in
two sorts: the "plain" arrays which store either built-in types such as "char",
"int" or "bool" or the pointers to arbitrary objects, or "object arrays" which
own the object pointers to which they store.

For the same portability reasons, the container classes implementation in
wxWidgets does not use templates, but is rather based on C preprocessor i.e. is
done with the macros: WX_DECLARE_LIST() and WX_DEFINE_LIST() for the linked
lists and WX_DECLARE_ARRAY(), WX_DECLARE_OBJARRAY() and WX_DEFINE_OBJARRAY()
for the dynamic arrays.

The "DECLARE" macro declares a new container class containing the elements of
given type and is needed for all three types of container classes: lists,
arrays and objarrays. The "DEFINE" classes must be inserted in your program in
a place where the @e full declaration of container element class is in scope
(i.e. not just forward declaration), otherwise destructors of the container
elements will not be called!

As array classes never delete the items they contain anyhow, there is no
WX_DEFINE_ARRAY() macro for them.

Examples of usage of these macros may be found in wxList<T> and wxArray<T>
documentation.

Finally, wxWidgets predefines several commonly used container classes. wxList
is defined for compatibility with previous versions as a list containing
wxObjects and wxStringList as a list of C-style strings (char *), both of these
classes are deprecated and should not be used in new programs. The following
array classes are defined: wxArrayInt, wxArrayLong, wxArrayPtrVoid and
wxArrayString. The first three store elements of corresponding types, but
wxArrayString is somewhat special: it is an optimized version of wxArray which
uses its knowledge about wxString reference counting schema.

*/

