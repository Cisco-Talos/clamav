/////////////////////////////////////////////////////////////////////////////
// Name:        funcmacro_debug.h
// Purpose:     Debugging function and macro group docs
// Author:      wxWidgets team
// RCS-ID:      $Id: funcmacro_gdi.h 52454 2008-03-12 19:08:48Z BP $
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@defgroup group_funcmacro_debug Debugging macros
@ingroup group_funcmacro

Useful macros and functions for error checking and defensive programming.
wxWidgets defines three families of the assert-like macros: the wxASSERT() and
wxFAIL() macros only do anything if __WXDEBUG__ is defined (in other words, in
the debug build) but disappear completely in the release build. On the other
hand, the wxCHECK() macros stay in release builds but a check failure doesn't
generate any user-visible effects. Finally, the compile time assertions don't
happen during the run-time but result in the compilation error messages if the
condition they check fail.

Related class group: @ref group_class_debugging.

*/

