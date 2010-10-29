/////////////////////////////////////////////////////////////////////////////
// Name:        funcmacro_version.h
// Purpose:     Versioning function and macro group docs
// Author:      wxWidgets team
// RCS-ID:      $Id: funcmacro_gdi.h 52454 2008-03-12 19:08:48Z BP $
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@defgroup group_funcmacro_version Versioning
@ingroup group_funcmacro

The following constants are defined in wxWidgets:

@beginDefList
@itemdef{ wxMAJOR_VERSION, The major version of wxWidgets }
@itemdef{ wxMINOR_VERSION, The minor version of wxWidgets }
@itemdef{ wxRELEASE_NUMBER, The release number }
@itemdef{ wxSUBRELEASE_NUMBER, The subrelease number which is 0 for all
    official releases }
@endDefList

For example, the values or these constants for wxWidgets 2.8.7
are 2, 8, 7 and 0.

Additionally, wxVERSION_STRING is a user-readable string containing the full
wxWidgets version and wxVERSION_NUMBER is a combination of the three version
numbers above: for 2.1.15, it is 2115 and it is 2200 for wxWidgets 2.2.

The subrelease number is only used for the sources in between official releases
and so normally is not useful.

@header{wx/version.h}

*/

