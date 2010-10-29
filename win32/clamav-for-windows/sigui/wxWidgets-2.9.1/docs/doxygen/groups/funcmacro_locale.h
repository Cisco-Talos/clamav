/////////////////////////////////////////////////////////////////////////////
// Name:        funcmacro_locale.h
// Purpose:     wxXLocale-enabled functions
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@defgroup group_funcmacro_locale Locale-dependent functions
@ingroup group_funcmacro

Below are a number of functions/macros which accept as last parameter a
specific wxXLocale instance.

For the documentation of function @c wxFunc_l(), please see the documentation
of the standard @c Func() function (see e.g. http://www.cppreference.com/wiki/c/string/start)
and keep in mind that the wxWidgets function takes as last parameter the
locale which should be internally used for locale-dependent operations.

Last, note that when the @c wxHAS_XLOCALE_SUPPORT symbol is not defined,
then wxWidgets will provide implementations of these functions itself 
and that they are not granted to be thread-safe (and they will work only with the
C locale; see @ref xlocale_avail).


*/

