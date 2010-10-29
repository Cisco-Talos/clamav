/////////////////////////////////////////////////////////////////////////////
// Name:        funcmacro_thread.h
// Purpose:     Threads function and macro group docs
// Author:      wxWidgets team
// RCS-ID:      $Id: funcmacro_gdi.h 52454 2008-03-12 19:08:48Z BP $
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@defgroup group_funcmacro_thread Threads
@ingroup group_funcmacro

The functions and macros here mainly exist to make it possible to write code
which may be compiled in multi thread build (wxUSE_THREADS = 1) as well as in
single thread configuration (wxUSE_THREADS = 0).

For example, a static variable must be protected against simultaneous access by
multiple threads in the former configuration but in the latter the extra
overhead of using the critical section is not needed. To solve this problem,
the wxCRITICAL_SECTION() macro may be used to create and use the critical
section only when needed.

@sa wxThread, wxMutex, @ref overview_thread

Related class group: @ref group_class_threading

*/

