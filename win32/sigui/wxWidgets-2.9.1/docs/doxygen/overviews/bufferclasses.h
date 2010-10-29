/////////////////////////////////////////////////////////////////////////////
// Name:        bufferclasses.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_bufferclasses Buffer Classes

wxWidgets uses two classes of classes for dealing with buffers in memory.

The first is one for dealing with character buffers, namely wxCharBuffer for
char pointer or multi-byte c strings and wxWCharBuffer for wchar_t pointer or
wide character c strings.

Secondly, wxWidgets uses, although only rarely currently, wxMemoryBuffer for
dealing with raw buffers in memory.

@li @ref overview_bufferclasses_xcb


<hr>


@section overview_bufferclasses_xcb wxXCharBuffer

@subsection overview_bufferclasses_xcb_general General Usage

As mentioned, wxCharBuffer and its wide character variant wxWCharBuffer deal
with c strings in memory.  They have two constructors, one in which you pass
the c string you want them to have a copy of, and another where you specify the
size of the buffer in memory in characters you want.

wxCharBuffer and its variant only contain the c string as a member, so they can
be used safely to c functions with variable arguments such as printf. They also
contain standard assignment, character access operators and a copy constructor.

@subsection overview_bufferclasses_xcb_destruct Destruction

It should be noted that on destruction wxCharBuffer and its wide character
variant delete the c string that hold onto.  If you want to get the pointer to
the buffer and don't want wxCharBuffer to delete it on destruction, use the
member function release to do so.

*/

