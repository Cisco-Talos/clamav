/////////////////////////////////////////////////////////////////////////////
// Name:        devtips.h
// Purpose:     Cross-platform development page of the Doxygen manual
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page page_multiplatform General Cross-Platform Development Tips

This chapter describes some tips related to cross-platform development.

@li @ref page_multiplatform_includefiles
@li @ref page_multiplatform_libraries
@li @ref page_multiplatform_configuration
@li @ref page_multiplatform_makefiles
@li @ref page_multiplatform_winresources
@li @ref page_multiplatform_allocatingobjects
@li @ref page_multiplatform_architecturedependency
@li @ref page_multiplatform_conditionalcompilation
@li @ref page_multiplatform_cpp
@li @ref page_multiplatform_filehandling
@li @ref page_multiplatform_reducingerr
@li @ref page_multiplatform_gui
@li @ref page_multiplatform_debug


<hr>


@section page_multiplatform_includefiles Include Files

The main include file is @c "wx/wx.h"; this includes the most commonly used
modules of wxWidgets.

To save on compilation time, include only those header files relevant to the
source file. If you are using @b precompiled headers, you should include the
following section before any other includes:

@verbatim
// For compilers that support precompilation, includes "wx.h".
#include <wx/wxprec.h>

#ifdef __BORLANDC__
#   pragma hdrstop
#endif

#ifndef WX_PRECOMP
    // Include your minimal set of headers here, or wx.h
#   include <wx/wx.h>
#endif

... now your other include files ...
@endverbatim

The file @c "wx/wxprec.h" includes @c "wx/wx.h". Although this incantation may
seem quirky, it is in fact the end result of a lot of experimentation, and
several Windows compilers to use precompilation which is largely automatic for
compilers with necessary support. Currently it is used for Visual C++
(including embedded Visual C++), Borland C++, Open Watcom C++, Digital Mars C++
and newer versions of GCC. Some compilers might need extra work from the
application developer to set the build environment up as necessary for the
support.



@section page_multiplatform_libraries Libraries

All ports of wxWidgets can create either a @b static library or a @b shared
library.

When a program is linked against a @e static library, the machine code from the
object files for any external functions used by the program is copied from the
library into the final executable.

@e Shared libraries are handled with a more advanced form of linking, which
makes the executable file smaller. They use the extension @c ".so" (Shared
Object) under Linux and @c ".dll" (Dynamic Link Library) under Windows.

An executable file linked against a shared library contains only a small table
of the functions it requires, instead of the complete machine code from the
object files for the external functions. Before the executable file starts
running, the machine code for the external functions is copied into memory from
the shared library file on disk by the operating system - a process referred to
as @e dynamic linking.

Dynamic linking makes executable files smaller and saves disk space, because
one copy of a library can be shared between multiple programs. Most operating
systems also provide a virtual memory mechanism which allows one copy of a
shared library in physical memory to be used by all running programs, saving
memory as well as disk space.

Furthermore, shared libraries make it possible to update a library without
recompiling the programs which use it (provided the interface to the library
does not change).

wxWidgets can also be built in @b multilib and @b monolithic variants. See the
@ref page_libs for more information on these.



@section page_multiplatform_configuration Configuration

When using project files and makefiles directly to build wxWidgets, options are
configurable in the file @c "wx/XXX/setup.h" where XXX is the required
platform (such as @c msw, @c motif, @c gtk, @c mac).

Some settings are a matter of taste, some help with platform-specific problems,
and others can be set to minimize the size of the library. Please see the
@c "setup.h" file and @c "install.txt" files for details on configuration.

When using the @c "configure" script to configure wxWidgets (on Unix and other
platforms where configure is available), the corresponding @c "setup.h" files
are generated automatically along with suitable makefiles.

When using the RPM packages (or DEB or other forms of @e binaries) for
installing wxWidgets on Linux, a correct @c "setup.h" is shipped in the package
and this must not be changed.



@section page_multiplatform_makefiles Makefiles

On Microsoft Windows, wxWidgets has a different set of makefiles for each
compiler, because each compiler's @c 'make' tool is slightly different. Popular
Windows compilers that we cater for, and the corresponding makefile extensions,
include: Microsoft Visual C++ (.vc), Borland C++ (.bcc), OpenWatcom C++ (.wat)
and MinGW/Cygwin (.gcc). Makefiles are provided for the wxWidgets library
itself, samples, demos, and utilities.

On Linux, Mac and OS/2, you use the @c 'configure' command to generate the
necessary makefiles. You should also use this method when building with
MinGW/Cygwin on Windows.

We also provide project files for some compilers, such as Microsoft VC++.
However, we recommend using makefiles to build the wxWidgets library itself,
because makefiles can be more powerful and less manual intervention is
required.

On Windows using a compiler other than MinGW/Cygwin, you would build the
wxWidgets library from the @c "build/msw" directory which contains the relevant
makefiles.

On Windows using MinGW/Cygwin, and on Unix, MacOS X and OS/2, you invoke
'configure' (found in the top-level of the wxWidgets source hierarchy), from
within a suitable empty directory for containing makefiles, object files and
libraries.

For details on using makefiles, configure, and project files, please see
@c "docs/xxx/install.txt" in your distribution, where @c "xxx" is the platform
of interest, such as @c msw, @c gtk, @c x11, @c mac.

All wxWidgets makefiles are generated using Bakefile <http://www.bakefile.org/>.
wxWidgets also provides (in the @c "build/bakefiles/wxpresets" folder) the
wxWidgets bakefile presets. These files allow you to create bakefiles for your
own wxWidgets-based applications very easily.



@section page_multiplatform_winresources Windows Resource Files

wxWidgets application compilation under MS Windows requires at least one extra
file: a resource file.

The least that must be defined in the Windows resource file (extension RC) is
the following statement:

@verbatim
#include "wx/msw/wx.rc"
@endverbatim

which includes essential internal wxWidgets definitions.  The resource script
may also contain references to icons, cursors, etc., for example:

@verbatim
wxicon icon wx.ico
@endverbatim

The icon can then be referenced by name when creating a frame icon. See the
Microsoft Windows SDK documentation.

@note Include "wx.rc" @e after any ICON statements so programs that search your
      executable for icons (such as the Program Manager) find your application
      icon first.



@section page_multiplatform_allocatingobjects Allocating and Deleting wxWidgets Objects

In general, classes derived from wxWindow must dynamically allocated with
@e new and deleted with @e delete. If you delete a window, all of its children
and descendants will be automatically deleted, so you don't need to delete
these descendants explicitly.

When deleting a frame or dialog, use @b Destroy rather than @b delete so that
the wxWidgets delayed deletion can take effect. This waits until idle time
(when all messages have been processed) to actually delete the window, to avoid
problems associated with the GUI sending events to deleted windows.

Don't create a window on the stack, because this will interfere with delayed
deletion.

If you decide to allocate a C++ array of objects (such as wxBitmap) that may be
cleaned up by wxWidgets, make sure you delete the array explicitly before
wxWidgets has a chance to do so on exit, since calling @e delete on array
members will cause memory problems.

wxColour can be created statically: it is not automatically cleaned
up and is unlikely to be shared between other objects; it is lightweight
enough for copies to be made.

Beware of deleting objects such as a wxPen or wxBitmap if they are still in
use. Windows is particularly sensitive to this, so make sure you make calls
like wxDC::SetPen(wxNullPen) or wxDC::SelectObject(wxNullBitmap) before
deleting a drawing object that may be in use. Code that doesn't do this will
probably work fine on some platforms, and then fail under Windows.



@section page_multiplatform_architecturedependency Architecture Dependency

A problem which sometimes arises from writing multi-platform programs is that
the basic C types are not defined the same on all platforms. This holds true
for both the length in bits of the standard types (such as int and long) as
well as their byte order, which might be little endian (typically on Intel
computers) or big endian (typically on some Unix workstations). wxWidgets
defines types and macros that make it easy to write architecture independent
code. The types are:

wxInt32, wxInt16, wxInt8, wxUint32, wxUint16 = wxWord, wxUint8 = wxByte

where wxInt32 stands for a 32-bit signed integer type etc. You can also check
which architecture the program is compiled on using the wxBYTE_ORDER define
which is either wxBIG_ENDIAN or wxLITTLE_ENDIAN (in the future maybe
wxPDP_ENDIAN as well).

The macros handling bit-swapping with respect to the applications endianness
are described in the @ref group_funcmacro_byteorder section.



@section page_multiplatform_conditionalcompilation Conditional Compilation

One of the purposes of wxWidgets is to reduce the need for conditional
compilation in source code, which can be messy and confusing to follow.
However, sometimes it is necessary to incorporate platform-specific features
(such as metafile use under MS Windows). The @ref page_wxusedef symbols listed
in the file @c setup.h may be used for this purpose, along with any
user-supplied ones.



@section page_multiplatform_cpp C++ Issues

The following documents some miscellaneous C++ issues.

@subsection page_multiplatform_cpp_templates Templates

wxWidgets does not use templates (except for some advanced features that are
switched off by default) since it is a notoriously unportable feature.

@subsection page_multiplatform_cpp_rtti Runtime Type Information (RTTI)

wxWidgets does not use C++ run-time type information since wxWidgets provides
its own run-time type information system, implemented using macros.

@subsection page_multiplatform_cpp_precompiledheaders Precompiled Headers

Some compilers, such as Borland C++ and Microsoft C++, support precompiled
headers. This can save a great deal of compiling time. The recommended approach
is to precompile @c "wx.h", using this precompiled header for compiling both
wxWidgets itself and any wxWidgets applications. For Windows compilers, two
dummy source files are provided (one for normal applications and one for
creating DLLs) to allow initial creation of the precompiled header.

However, there are several downsides to using precompiled headers. One is that
to take advantage of the facility, you often need to include more header files
than would normally be the case. This means that changing a header file will
cause more recompilations (in the case of wxWidgets, everything needs to be
recompiled since everything includes @c "wx.h").

A related problem is that for compilers that don't have precompiled headers,
including a lot of header files slows down compilation considerably. For this
reason, you will find (in the common X and Windows parts of the library)
conditional compilation that under Unix, includes a minimal set of headers; and
when using Visual C++, includes @c "wx.h". This should help provide the optimal
compilation for each compiler, although it is biased towards the precompiled
headers facility available in Microsoft C++.



@section page_multiplatform_filehandling File Handling

When building an application which may be used under different environments,
one difficulty is coping with documents which may be moved to different
directories on other machines. Saving a file which has pointers to full
pathnames is going to be inherently unportable.

One approach is to store filenames on their own, with no directory information.
The application then searches into a list of standard paths (platform-specific)
through the use of wxStandardPaths.

Eventually you may want to use also the wxPathList class.

Nowadays the limitations of DOS 8+3 filenames doesn't apply anymore. Most
modern operating systems allow at least 255 characters in the filename; the
exact maximum length, as well as the characters allowed in the filenames, are
OS-specific so you should try to avoid extremely long (> 255 chars) filenames
and/or filenames with non-ANSI characters.

Another thing you need to keep in mind is that all Windows operating systems
are case-insensitive, while Unix operating systems (Linux, Mac, etc) are
case-sensitive.

Also, for text files, different OSes use different End Of Lines (EOL). Windows
uses CR+LF convention, Linux uses LF only, Mac CR only.

The wxTextFile, wxTextInputStream, wxTextOutputStream classes help to abstract
from these differences. Of course, there are also 3rd party utilities such as
@c dos2unix and @c unix2dos which do the EOL conversions.

See also the @ref group_funcmacro_file section of the reference manual for the
description of miscellaneous file handling functions.



@section page_multiplatform_reducingerr Reducing Programming Errors

@subsection page_multiplatform_reducingerr_useassert Use ASSERT

It is good practice to use ASSERT statements liberally, that check for
conditions that should or should not hold, and print out appropriate error
messages.

These can be compiled out of a non-debugging version of wxWidgets and your
application. Using ASSERT is an example of `defensive programming': it can
alert you to problems later on.

See wxASSERT() for more info.

@subsection page_multiplatform_reducingerr_usewxstring Use wxString in Preference to Character Arrays

Using wxString can be much safer and more convenient than using @c wxChar*.

You can reduce the possibility of memory leaks substantially, and it is much
more convenient to use the overloaded operators than functions such as
@c strcmp. wxString won't add a significant overhead to your program; the
overhead is compensated for by easier manipulation (which means less code).

The same goes for other data types: use classes wherever possible.



@section page_multiplatform_gui GUI Design

@li <b>Use Sizers:</b> Don't use absolute panel item positioning if you can
    avoid it. Every platform's native controls have very different sizes.
    Consider using the @ref overview_sizer instead.
@li <b>Use wxWidgets Resource Files:</b> Use @c XRC (wxWidgets resource files)
    where possible, because they can be easily changed independently of source
    code. See the @ref overview_xrc for more info.



@section page_multiplatform_debug Debugging

@subsection page_multiplatform_debug_positivethinking Positive Thinking

It is common to blow up the problem in one's imagination, so that it seems to
threaten weeks, months or even years of work. The problem you face may seem
insurmountable: but almost never is. Once you have been programming for some
time, you will be able to remember similar incidents that threw you into the
depths of despair. But remember, you always solved the problem, somehow!

Perseverance is often the key, even though a seemingly trivial problem can take
an apparently inordinate amount of time to solve. In the end, you will probably
wonder why you worried so much. That's not to say it isn't painful at the time.
Try not to worry -- there are many more important things in life.

@subsection page_multiplatform_debug_simplifyproblem Simplify the Problem

Reduce the code exhibiting the problem to the smallest program possible that
exhibits the problem. If it is not possible to reduce a large and complex
program to a very small program, then try to ensure your code doesn't hide the
problem (you may have attempted to minimize the problem in some way: but now
you want to expose it).

With luck, you can add a small amount of code that causes the program to go
from functioning to non-functioning state. This should give a clue to the
problem. In some cases though, such as memory leaks or wrong deallocation, this
can still give totally spurious results!

@subsection page_multiplatform_debug_usedebugger Use a Debugger

This sounds like facetious advice, but it is surprising how often people don't
use a debugger. Often it is an overhead to install or learn how to use a
debugger, but it really is essential for anything but the most trivial
programs.

@subsection page_multiplatform_debug_uselogging Use Logging Functions

There is a variety of logging functions that you can use in your program: see
@ref group_funcmacro_log.

Using tracing statements may be more convenient than using the debugger in some
circumstances (such as when your debugger doesn't support a lot of debugging
code, or you wish to print a bunch of variables).

@subsection page_multiplatform_debug_usedebuggingfacilities Use the wxWidgets Debugging Facilities

You can use wxDebugContext to check for memory leaks and corrupt memory: in
fact in debugging mode, wxWidgets will automatically check for memory leaks at
the end of the program if wxWidgets is suitably configured. Depending on the
operating system and compiler, more or less specific information about the
problem will be logged.

You should also use @ref group_funcmacro_debug as part of a "defensive
programming" strategy, scattering wxASSERT()s liberally to test for problems in
your code as early as possible. Forward thinking will save a surprising amount
of time in the long run.

See the @ref overview_debugging for further information.

*/

