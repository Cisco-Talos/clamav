/////////////////////////////////////////////////////////////////////////////
// Name:        funcmacro_atomic.h
// Purpose:     Atomic Operation function and macro group docs
// Author:      wxWidgets team
// RCS-ID:      $Id: funcmacro_gdi.h 52454 2008-03-12 19:08:48Z BP $
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@defgroup group_funcmacro_atomic Atomic Operations
@ingroup group_funcmacro

When using multi-threaded applications, it is often required to access or
modify memory which is shared between threads. Atomic integer and pointer
operations are an efficient way to handle this issue (another, less efficient,
way is to use a wxMutex or wxCriticalSection). A native implementation exists
for Windows, Linux, Solaris and Mac OS X; for others, a wxCriticalSection is
used to protect the data.

One particular application is reference counting (used by so-called
@ref group_class_smartpointers "smart pointers").

You should define your variable with the type wxAtomicInt in order to apply
atomic operations to it.

*/

