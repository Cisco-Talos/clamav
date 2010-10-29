Nano-X port
===========

What is it?
===========

The Nano-X port is based on the wxX11 code, and therefore shares
almost all of wxX11's code, including the use of the wxUniversal
widget set. Nano-X is the X-like API of the overall Microwindows
project, which also has a WIN32 API.

The Microwindows web site is at

	http://microwindows.org/

Nano-X is intended to work on devices with very small amounts
of memory. wxWidgets is quite a large library, so if your
memory is measured in KB instead of MB you will need to use
an alternative library, such as FLTK. However, with memory
capacity increasing all the time, wxWidgets could become
an appropriate embedded GUI solution for many projects.
Also, it's possible to think of ways to cut wxWidgets
further down to size, such as disabling advanced controls
or rewriting utility functions. See the section on code size
below.

An alternative to using Nano-X is to use the standard
wxX11 port with Tiny-X, which (as I understand it)
maintains the Xlib API while being sufficiently cut
down to run on small devices, such as the iPAQ.
The Familiar Linux Distribution contains Tiny-X. See:

        http://handhelds.org/mailman/listinfo/familiar

Building wxNano-X
=================

Building is as per the instructions for wxX11 (see readme.txt,
install.txt) but passing --enable-nanox to configure.  You also need
to export the MICROWIN variable, setting it to the top-level of the
Microwindows hierarchy. Remember that MICROWIN needs to be defined
both at configuration time and at subsequent make time, so you
may find it convenient to put it in your .bash_profile or similar
file.

Typically, various features in wxWidgets will be switched off to
conserve space. The sample script below calls configure with typical
options for Nano-X.

Before compiling wxNano-X, you will also need to edit your
Microwindows 'config' file to match the values hard-coded into
configure:

  ERASEMOVE=N (otherwise moving windows will look messy)
  X11=Y
  OPTIMIZE=N
  DEBUG=Y
  VERBOSE=Y

Compile Microwindows by typing 'make' from within the Microwindows src
directory.

Port notes
==========

Nano-X has a different API from Xlib, although there
are many similarities. Instead of changing the wxWidgets
code to reflect Nano-X conventions, a compatibility
layer has been added, in the form of these files:

include/wx/x11/nanox/X11/Xlib.h  ; Xlib compatibility
include/wx/x11/privx.h           ; Useful macros
src/x11/nanox.c                  ; Xlib compatibility

There is also an XtoNX.h compatibility header file
in Microwindows, which we augment with our Xlib.h
and nanox.c.

Unfortunately it is not always possible, or economical,
to provide a complete Xlib emulation, so there are
still wxUSE_NANOX preprocessor directives in the code
for awkward cases. It may be possible to eliminate
some, but probably not all, of these in future.

Port Status
===========

The port is in a very early stage: so far it links
and a window pops up, but that's about it. (The
wxX11 port using straight X11 is much more advanced.)

Things to do:

- implement some incomplete compatibility functions
  in src/x11/nanox.c
- implement the colour database
- add mask capability, without which controls won't
  display properly
- add further configuration options for disabling
  code not normally needed in an embedded device
- optimization and code size reduction
- figuring out why libstdc++-libc is linked to
  binaries -- is this done for any C++ program?

Code Size
=========

Allow about 2.5 MB for a shared wxWidgets library, with the
dynamically linked minimal sample taking about 24KB. If statically
linked, minimal takes up just over 1MB when stripped. This 1MB
includes all of wxWidgets used in the minimal sample including some of
the wxUniversal widgets. As application complexity increases,
the amount of wxWidgets code pulled into statically linked
executables increases, but for large applications, the overhead
of wxWidgets becomes less significant.

Sample sizes:
-------------

Statically-linked minimal (release): 1,024,272 bytes
Statically-linked widgets (release): 1,171,568 bytes

Shared lib, stripped (debug): 2,486,716 bytes
Shared-lib minimal (debug), stripped: 23,896 bytes

Shared lib, stripped (release): 2,315,5004 bytes
Shared-lib minimal (release), stripped: 23,896 bytes
(note: the -O flag was not passed to the minimal
makefile, for some reason)

Strategies for reducing code size
---------------------------------

- Look at the .o files compiled in a build and check
  for particularly large files, or files you wouldn't
  expect to be there in an embedded build.
- Disable options for features that aren't necessary,
  for example: image handlers (BMP, JPEG etc.),
  wxVariant, wxWizard, wxListCtrl, src/univ/themes/gtk.c.
- Add options to configure.in/setup.h where necessary,
  for finer-grained configuration.
- Rewrite functions or classes for alternative stripped-down
  functionality.
- Remove unnecessary functionality or obsolete code from
  wxWidgets.
- Factor out wxWidgets code to reduce repetition.
- Add inlining, remove unnecessary empty functions.
- Separate code out into individual files so that all of
  a .o file doesn't get pulled in, just because an app
  references something else in that file. For example,
  advanced event types could be separated out.
  This assumes that the linker isn't clever enough to
  eliminate redundant functions. The fact that the
  minimal and widgets samples are very close in size
  is evidence that gcc is not doing a good job here.
- Experiment with compiler options.
- Commercially supported compilers may have better
  code generation and/or linker optimisation than the
  one you're currently using.

Sample script for building wxNano-X
===================================

This script assumes that you will invoke it
from a build directory under the wxWidgets
top level. So you might type:

% cd wx2
% mkdir nano-x
% cd nano-x
% makewxnanox

If you need to restart compilation without
reconfiguring, just type 'make' from the same
directory.

-----------------------------:x----------------------

#!/bin/sh
# makewxnanox

export MICROWIN=/home/julians/microwindows/microwindows-0.89pre8

#DEBUGFLAGS="--enable-debug --enable-debug_cntxt --disable-optimise"
DEBUGFLAGS="--disable-debug --disable-debug_cntxt --enable-optimise"

export CONFIGCMD="./configure $DEBUGFLAGS --enable-shared --enable-gui --with-x11 --enable-nanox --enable-log --with-threads --without-sockets --without-odbc --without-libjpeg --without-libtiff --without-png --without-regex --enable-no_exceptions --disable-protocols --disable-ipc --disable-dialupman --disable-apple_ieee --disable-fraction --disable-dynlib --disable-dynamicloader --disable-geometry --disable-fontmap --disable-std_iostreams --disable-filesystem --disable-fs_inet --disable-fs_zip --disable-zipstream --disable-snglinst --disable-mimetype --disable-url --disable-html --disable-constraints --disable-printarch --disable-mdi --disable-postscript --disable-PS-normalized --disable-afmfonts --disable-prologio --disable-resources --disable-dnd --disable-metafile --disable-treelayout --disable-grid --disable-propsheet --disable-splines --disable-joystick --disable-pcx --disable-iff --disable-pnm --disable-tabdialog --disable-newgrid"

echo $CONFIGCMD
if [ ! -f ./configure ]; then
  CONFIGCMD=".$CONFIGCMD"
fi

echo Invoking $CONFIGCMD

rm -f *.cache
$CONFIGCMD

make

-----------------------------:x----------------------
