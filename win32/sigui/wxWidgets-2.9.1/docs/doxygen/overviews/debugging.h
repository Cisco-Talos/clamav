/////////////////////////////////////////////////////////////////////////////
// Name:        debugging.h
// Purpose:     topic overview
// Author:      Vadim Zeitlin
// Copyright:   (c) 2009 Vadim Zeitlin <vadim@wxwidgets.org>
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_debugging Debugging

Classes, functions and macros: wxLog, @ref group_funcmacro_log, @ref group_funcmacro_debug

Various classes, functions and macros are provided in wxWidgets to help you debug
your application: @ref overview_debugging_dbgmacros allow you to insert various
checks in your application which can be compiled out or disabled in release
builds but are extremely useful while developing and @ref
overview_debugging_logging which are not limited to debugging but are also
useful for inserting traces into your application code. Both assertions and
debug logging are also used by wxWidgets itself so you may encounter them even
if you don't use either of these features yourself.


@section overview_debugging_config Configuring debugging support

Starting with wxWidgets 2.9.1 debugging features are always available by
default (and not only in a special "debug" build of the library) and you need
to predefine wxDEBUG_LEVEL symbol as 0 when building both the library and your
application to remove them completely from the generated object code. However
the debugging features are disabled by default when the application itself is
built with @c NDEBUG defined (i.e. in "release" or "production" mode) so there
is no need to do this, unless the resources of the system your application will
be running on are unusually constrained (notice that when asserts are disabled
their condition is not even evaluated so the only run-time cost is a single
condition check and the extra space taken by the asserts in the code).

This automatic deactivation of debugging code is done by IMPLEMENT_APP() macro
so if you don't use you may need to explicitly call wxDISABLE_DEBUG_SUPPORT()
yourself.

Also notice that it is possible to build your own application with a different
value of wxDEBUG_LEVEL than the one which was used for wxWidgets itself. E.g.
you may be using an official binary version of the library which will have
been compiled with default @code wxDEBUG_LEVEL == 1 @endcode but still predefine
wxDEBUG_LEVEL as 0 for your own code.

On the other hand, if you do want to keep the asserts even in production
builds, you will probably want to override the handling of assertion failures
as the default behaviour which pops up a message box notifying the user about
the problem is usually inappropriate. Use wxSetAssertHandler() to set up your
own custom function which should be called instead of the standard assertion
failure handler. Such function could log an appropriate message in the
application log file or maybe notify the user about the problem in some more
user-friendly way.


@section overview_debugging_dbgmacros Assertion macros

wxASSERT(), wxFAIL(), wxCHECK() as well as their other variants (see @ref
group_funcmacro_debug) are similar to the standard assert() macro but are more
flexible and powerful. The first of them is equivalent to assert() itself, i.e.
it simply checks a condition and does nothing if it is true. The second one is
equivalent to checking an always false condition and is supposed to be used for
code paths which are supposed to be inaccessible (e.g. @c default branch of a
@c switch statement which should never be executed). Finally, the wxCHECK()
family of macros verifies the condition just as wxASSERT() does and performs
some action such returning from the function if it fails -- thus, it is useful
for checking the functions preconditions.

All of the above functions exist in @c _MSG variants which allow you to provide
a custom message which will be shown (or, more generally, passed to the assert
handler) if the assertion fails, in addition to the usual file and line number
information and the condition itself.

Example of using an assertion macro:
@code
void GetTheAnswer(int *p)
{
    wxCHECK_RET( p, "pointer can't be NULL in GetTheAnswer()" );

    *p = 42;
};
@endcode

If the condition is false, i.e. @c p is @NULL, the assertion handler is called
and, in any case (even when wxDEBUG_LEVEL is 0), the function returns without
dereferencing the NULL pointer on the next line thus avoiding a crash.

The default assertion handler behaviour depends on whether the application
using wxWidgets was compiled in release build (with @c NDEBUG defined) or debug
one (without) but may be changed in either case as explained above. If it
wasn't changed, then nothing will happen in the release build and a message box
showing the information about the assert as well as allowing to stop the
program, ignore future asserts or break into the debugger is shown. On the
platforms where wxStackWalker is supported the message box will also show the
stack trace at the moment when the assert failed often allowing you to diagnose
the problem without using the debugger at all. You can see an example of such
message box in the @ref page_samples_except.



@section overview_debugging_logging Logging functions

You can use the wxLogDebug and wxLogTrace functions to output debugging information in
debug mode; it will do nothing for non-debugging code.



*/

