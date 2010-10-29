/////////////////////////////////////////////////////////////////////////////
// Name:        funcmacro_env.h
// Purpose:     Environment function and macro group docs
// Author:      wxWidgets team
// RCS-ID:      $Id: funcmacro_gdi.h 52454 2008-03-12 19:08:48Z BP $
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@defgroup group_funcmacro_env Environment
@ingroup group_funcmacro

These functions allow access to get or change the values of environment
variables in a portable way. They are currently implemented under Win32 and
POSIX-like systems (Unix).

Remember that these functions add/change/delete environment variables of the
current process only. Child processes copy the environment variables of the parent
but do not share them (a wxSetEnv() in the parent process won't change the value
returned by wxGetEnv() in the child process and viceversa).

For more evoluted interprocess communication tecniques see @ref overview_ipc.

*/

