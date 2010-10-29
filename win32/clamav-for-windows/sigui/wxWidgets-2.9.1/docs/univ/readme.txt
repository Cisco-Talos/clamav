                              wxUniversal README
                              ==================

Welcome to wxUniversal!

Acknowledgements: wxUniversal wouldn't have been written without the
generous support of SciTech Software. Many thanks to Kendall Bennett and
Tom Ryan!

0. Introduction
---------------

wxUniversal is a port of wxWidgets which implements the various GUI controls
by drawing them itself (using low level wxWidgets classes). Please see

                     http://www.wxwidgets.org/wxuniv.htm

for more details about it.

The advantage of wxUniversal is that you have precise control over the
controls' appearance (it is not always possible to change all aspects of the
native controls) and the theme support: the same program may be changed to
look completely differently without changing a single line of its code but
just changing the theme.

Another advantage is that it makes writing ports of wxWidgets for other
platforms (such as OS/2, BeOS or QNX) much simpler, so it is of special
interest to people interested in porting wxWidgets to another platform.

However, wxUniversal doesn't have a 100% native look and feel unlike the
other wxWidgets ports - this is the price to pay for the extra flexibility.

1. Requirements and supported platforms
---------------------------------------

wxUniversal is used together with another wxWidgets port which provides the
"low level classes" mentioned above. Currently it can be built with wxMSW,
wxGTK or wxX11. In any case, you should download the sources for the
appropriate toolkit in addition to wxUniversal - in fact, you should download
them first and then unpack wxUniversal in the same directory.

The requirements for wxUniversal are the same as for the underlying low level
toolkit.

2. Installing under Win32
-------------------------

If compiling from CVS, please copy include/wx/univ/setup0.h
to include/wx/univ/setup.h before following these steps.

a) Using Visual C++ 6.0/7.x

   Follow wxMSW instructions but make sure to choose one of the "Universal" 
   configurations before building.

b) Cygwin

   Please refer to the Unix section below

   Note that gcc's precompiled headers do not work on current versions of
   Cygwin. If your version of Cygwin is affected you will need to use the
   --disable-precomp-headers configure option.

** the instructions may be out of date as for wxWidgets 2.5.2+ **

c) Other compilers
   Borland: 
   in the wxwindows\src\msw directory run
   'make -f makefile.b32 WXUSINGUNIV=1' to build the library and then run
   'make -f makefile.b32 WXUSINGUNIV=1' in the sample directory  which you wish
   to build using the wxUniversal widgets. Use 'SET WXTHEME=GTK' [or  WIN32 or METAL]
   to test the existing themes

Unfortunately we don't have makefiles for any other compilers yet.
Please contact us if you would like to help us with creating one for the
compiler you use.

Note that you can use the wxUniversal classes, wxMSW and MicroWindows (from
Century Software) to build a different variant of wxUniversal than that
documented here. Please see docs/univ/readme.txt for further information.
Note that this port is not up-to-date and probably needs work
to compile.

Note that by default, wxUniv under MSW uses PostScript printing,
not Windows printing. To change to Windows printing, set
wxUSE_POSTSCRIPT_ARCHITECTURE_IN_MSW to 0 in include/wx/univ/setup.h
before compiling.

3. Installing under Unix
------------------------

Please refer to the installation instructions for wxGTK or wxX11. The only
change for wxUniversal is that you must add "--enable-universal" switch to
the configure command line and for wxX11 even this is unnecessary, i.e. it
is enabled by default.

If compiling from CVS, please copy include/wx/univ/setup0.h
to include/wx/univ/setup.h before configuring.

4. Running wxUniv programs
--------------------------

wxUniv programs all honour the standard option "--theme" which allows to
specify the theme to be used by name. Currently there are the following
themes:

a) win32 -- Windows 95 look and feel
b) metal -- based on win32 but with gradient backgrounds
c) gtk   -- GTK+ 1.x standard look and feel

Thus, to launch a program using gtk theme you may do "./program --theme=gtk".

It is also possible to change the default theme for all wxUniv applications
at once by setting the environment variable WXTHEME to the theme name.

5. Documentation and support
----------------------------

Please note that wxUniversal is not as mature as the other wxWidgets ports
and is currently officially in alpha stage. In particular, it is not really
intended for the end users but rather for developers at the current stage and
this is why we don't provide any binaries for it.

There is no separate documentation for wxUniversal, please refer to wxWidgets
documentation instead.

Support for wxUniversal is available from the same places as for wxWidgets
itself, namely:

* Usenet newsgroup comp.soft-sys.wxwindows

* Mailing lists: see http://lists.wxwindows.org/ for more information

* WWW page: http://www.wxwidgets.org/


 Hope you find wxUniversal useful!

                                                                 Vadim Zeitlin


This file is accurate for the version 2.3.4 of wxUniversal. It was last
modified on Apr 15, 2002.

