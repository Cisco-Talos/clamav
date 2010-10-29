wxWidgets PDA/Embedded System Emulator
======================================

This is a simple display emulator for embedded
applications (wxWidgets or other) that use
an X server. The Familiar Linux distribution
is one such environment, using Tiny-X.

wxEmulator uses Xnest, which is the XFree86
X server compiled to show a virtual X desktop
in a window. wxEmulator hijacks the Xnest
window by reparenting its window, and shows
this window with appropriate PDA-style decorations
surrounding it.

No real emulation is done, apart from the work
that Xnest does. You compile your apps on your
host as usual and test them out with the emulator
to get an idea of the constraints of the embedded
system display. Then compile the apps for your
target system with a suitable cross-compiler,
or if you have the luxury of lots of space on
your target device, compile natively on the
target.

It is intended to create a tarball of the
emulator, wxX11 and maybe some other useful
components such as a simple window manager so that
people can quickly start developing embedded
GUI applications without the need for actual
target hardware.

Running wxEmulator
==================

Make sure Xnest is in your PATH. You can download
a binary from the XFree86 ftp server or a mirror,
or you can compile Xnest from source -- but this
downloading XFree86 source in its entirety and
compiling it. Say goodbye to half a gig of disk
space if you take this option.

Then run wxEmulator:

% emulator &

or

% emulator mydevice.wxe &

to specify a configuration file. Run emulator --help
to show what options are available, such as --use-display
for specifying a display other than :100.

After a brief flicker in which wxEmulator steals
Xnest's window, you should see an emulated iPAQ with
a checked screen that indicates raw X with nothing else
running.

Running any X applications with the Xnest display
number (currently 100) will show those applications
in the emulator window instead of the normal desktop.

For example:

% xeyes -display :100 &

Before running any other programs, run a window
manager such as twm:

% twm -display :100 &

If the X program or WM you want to run doesn't support the
-display argument, try exporting the DISPLAY variable
before running it. E.g.:

% export DISPLAY=:100
% xterm &

For details on the configuration file format, please
see default.wxe. Eventually it will support
device buttons.

Compiling wxEmulator
====================

You need to use wxX11 -- no other port is supported.
Configure and make wxX11 in the usual way (see docs/x11/install.txt
at the wxWidgets top level), then compile wxEmulator
using the makefile that configure created.

Have fun!

Julian Smart, March 2002

