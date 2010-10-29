/////////////////////////////////////////////////////////////////////////////
// Name:        filesystem.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_fs wxFileSystem Overview

The wxHTML library uses a @b virtual file systems mechanism
similar to the one used in Midnight Commander, Dos Navigator,
FAR or almost any modern file manager. It allows the user to access
data stored in archives as if they were ordinary files. On-the-fly
generated files that exist only in memory are also supported.

@li @ref overview_fs_classes
@li @ref overview_fs_locations
@li @ref overview_fs_combined
@li @ref overview_fs_wxhtmlfs
@li @ref overview_fs_init


<hr>


@section overview_fs_classes Classes

Three classes are used in order to provide virtual file systems mechanism:

@li The wxFSFile class provides information
    about opened file (name, input stream, mime type and anchor).
@li The wxFileSystem class is the interface.
    Its main methods are ChangePathTo() and OpenFile(). This class
    is most often used by the end user.
@li The wxFileSystemHandler is the core
    of virtual file systems mechanism. You can derive your own handler and pass
    it to the VFS mechanism. You can derive your own handler and pass it to
    wxFileSystem's AddHandler() method. In the new handler you only need to
    override the OpenFile() and CanOpen() methods.


@section overview_fs_locations Locations

Locations (aka filenames aka addresses) are constructed from four parts:

@li @b protocol - handler can recognize if it is able to open a
    file by checking its protocol. Examples are "http", "file" or "ftp".
@li <b>right location</b> - is the name of file within the protocol.
    In "http://www.wxwidgets.org/index.html" the right location is "//www.wxwidgets.org/index.html".
@li @b anchor - an anchor is optional and is usually not present.
    In "index.htm#chapter2" the anchor is "chapter2".
@li <b>left location</b> - this is usually an empty string.
    It is used by 'local' protocols such as ZIP.
    See Combined Protocols paragraph for details.


@section overview_fs_combined Combined Protocols

The left location precedes the protocol in the URL string.

It is not used by global protocols like HTTP but it becomes handy when nesting
protocols - for example you may want to access files in a ZIP archive:
file:archives/cpp_doc.zip#zip:reference/fopen.htm#syntax
In this example, the protocol is "zip", right location is
"reference/fopen.htm", anchor is "syntax" and left location
is "file:archives/cpp_doc.zip".

There are @b two protocols used in this example: "zip" and "file".


@section overview_fs_wxhtmlfs File Systems Included in wxHTML

The following virtual file system handlers are part of wxWidgets so far:

@li @b wxArchiveFSHandler:
    A handler for archives such as zip
    and tar. Include file is wx/fs_arc.h. URLs examples:
    "archive.zip#zip:filename", "archive.tar.gz#gzip:#tar:filename".
@li @b wxFilterFSHandler:
    A handler for compression schemes such
    as gzip. Header is wx/fs_filter.h. URLs are in the form, e.g.:
    "document.ps.gz#gzip:".
@li @b wxInternetFSHandler:
    A handler for accessing documents
    via HTTP or FTP protocols. Include file is wx/fs_inet.h.
@li @b wxMemoryFSHandler:
    This handler allows you to access
    data stored in memory (such as bitmaps) as if they were regular files.
    See wxMemoryFSHandler for details.
    Include file is wx/fs_mem.h. URL is prefixed with memory:, e.g.
    "memory:myfile.htm"

In addition, wxFileSystem itself can access local files.


@section overview_fs_init Initializing file system handlers

Use wxFileSystem::AddHandler to initialize a handler, for example:

@code
#include <wx/fs_mem.h>

...

bool MyApp::OnInit()
{
    wxFileSystem::AddHandler(new wxMemoryFSHandler);
...
}
@endcode

*/

