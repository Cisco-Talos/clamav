/////////////////////////////////////////////////////////////////////////////
// Name:        envvars.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_envvars Environment Variables

This section describes all environment variables that affect execution of
wxWidgets programs.

@beginDefList
@itemdef{WXTRACE,
        (Debug build only.)
        This variable can be set to a comma-separated list of trace masks used in
        wxLogTrace calls; wxLog::AddTraceMask is called for every mask
        in the list during wxWidgets initialization.}
@itemdef{WXPREFIX,
        (Unix only.)
        Overrides installation prefix. Normally, the prefix
        is hard-coded and is the same as the value passed to @c configure via
        the @c --prefix switch when compiling the library (typically
        @c /usr/local or @c /usr). You can set WXPREFIX if you are for example
        distributing a binary version of an application and you don't know in advance
        where it will be installed.}
@itemdef{WXMODE,
        (wxMGL only.)
        Sets MGL video mode. The value must be in form
        @e widthx@e height-@e depth. The default is @c 640x480-16.}
@itemdef{WXSTDERR,
        (wxMGL only.)
        Redirects stderr output to a file.}

*/

