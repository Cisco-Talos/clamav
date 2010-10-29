/////////////////////////////////////////////////////////////////////////////
// Name:        file.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_file File Classes and Functions

Classes: wxFile, wxDir, wxTempFile,  wxTextFile

Functions: see @ref group_funcmacro_file.

wxWidgets provides some functions and classes to facilitate working with files.
As usual, the accent is put on cross-platform features which explains, for
example, the wxTextFile class which may be used to convert
between different types of text files (DOS/Unix/Mac).

wxFile may be used for low-level IO. It contains all the usual functions to work
with files (opening/closing, reading/writing, seeking, and so on) but compared with
using standard C functions, has error checking (in case of an error a message
is logged using wxLog facilities) and closes the file
automatically in the destructor which may be quite convenient.

wxTempFile is a very small file designed to make replacing the files contents
safer - see its documentation for more details.

wxTextFile is a general purpose class for working with small text files on line
by line basis. It is especially well suited for working with configuration files
and program source files. It can be also used to work with files with "non
native" line termination characters and write them as "native" files if needed
(in fact, the files may be written in any format).

wxDir is a helper class for enumerating the files or subdirectories of a
directory. It may be used to enumerate all files, only files satisfying the
given template mask or only non-hidden files.

*/

