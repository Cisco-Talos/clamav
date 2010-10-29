               wxWidgets 2.9.1 Release Notes
               =============================

Welcome to the latest release of wxWidgets, a cross-platform C++
framework for writing advanced GUI applications using native
controls where possible.

In addition to common and advanced GUI facilities such as frames,
scrolling windows, toolbars, tree controls, icons, device contexts,
printing, splitter windows and so on, there are wrappers for common
file operations, and facilities for writing TCP/IP applications,
thread handling, and more.

A detailed reference manual including in-depth overviews for various
topics is supplied in various formats and can be accessed online at
http://docs.wxwidgets.org/


Note about naming: while 2.9.1 is called a "development" release,
this only means that API is not guaranteed to remain unchanged in
the subsequent 2.9.x releases, unlike in the stable 2.8.x branch. We
believe the current version is stable and suitable for use in
production environment.



Changes in this release
-----------------------

This release contains several years worth of improvements compared
to 2.8 version. Notably, Unicode support has been completely
overhauled and made much easier to use. Debugging support, including
when using a release build of the library, was much improved making
it less likely that you use the library incorrectly. Many new GUI
and base classes have been added or improved.

Please see the file docs/changes.txt for more details and make sure
to read the section "Incompatible changes since 2.8" if you upgrade
from a previous wxWidgets release.

This release introduces many important changes and we are looking
forward to your feedback about them. In particular please let us
know about any regressions compared to the previous versions (see
the section "Bug reporting" below) so that we could fix them before
3.0 release.


Platforms supported
-------------------

wxWidgets currently supports the following primary platforms:

- Windows 95/98/ME, NT, 2000, XP, Vista, 7
- Most Unix variants using the GTK+ toolkit (version 2.4 or newer)
- Mac OS X (10.4 or newer) using either Carbon or Cocoa

There is some support for the following platforms:

- Most Unix variants with X11
- Most Unix variants with Motif/Lesstif
- Most Unix variants with GTK+ 1.2
- OS/2
- Windows CE (Pocket PC)

Most popular C++ compilers are supported; see the install.txt
file for each platform (available via docs/html/index.htm) and
http://wiki.wxwidgets.org/Supported_Platforms for the most up to
date status.


Files
-----

The distribution is available in archive formats appropriate to the
target system. See the download pages for details.


Installation
------------

wxWidgets needs to be compiled before you can test out the samples
or write your own applications. For installation information, please
see the install.txt file in the docs subdirectory appropriate for
the platform you use.


Licence information
-------------------

For licensing information, please see the files:

  docs/preamble.txt
  docs/licence.txt
  docs/licendoc.txt
  docs/gpl.txt
  docs/lgpl.txt

Although this may seem complex, it is there to allow authors of
proprietary/commercial applications to use wxWidgets in addition
to those writing GPL'ed applications. In summary, the licence is
LGPL plus a clause allowing unrestricted distribution of
application binaries. To answer a FAQ, you don't have to
distribute any source if you wish to write commercial
applications using wxWidgets.

However, if you distribute wxGTK or wxMotif (with Lesstif)
version of your application, don't forget that it is linked
against GTK+ (or Lesstif) which is covered by LGPL *without*
exception notice. Under Linux systems your app is probably linked
against LGPL glibc as well. Please read carefully LGPL, section
6. which describes conditions for distribution of closed source
applications linked against LGPL library. Basically you should
link dynamically and include source code of LGPL libraries with
your product (unless it is already present in user's system -
like glibc usually is).

If you use TIFF image handler, please see src/tiff/COPYRIGHT
for libtiff licence details.

If you use JPEG image handler, documentation for your program
should contain following sentence: "This software is based in
part on the work of the Independent JPEG Group". See
src/jpeg/README for details.

If you use wxRegEx class on a system without native regular
expressions support (i.e. MS Windows), see src/regex/COPYRIGHT
file for Henry Spencer's regular expression library copyright.

If you use wxXML classes or XRC, see src/expat/COPYING for licence details.


Documentation
-------------

wxWidgets documentation is available online at
http://docs.wxwidgets.org/2.9.1/ and can also be downloaded in HTML
format. To generate documentation in other formats (PDF, CHM, ...)
please use the scripts in docs/doxygen directory.


Bug reporting
-------------

The wxWidgets bug tracker can be browsed at:

    http://trac.wxwidgets.org/report

Please use the search function of our Trac installation to find
any possibly relevant bugs before reporting new ones. Also please
notice that often trying to correct the bug yourself is the
quickest way to fix it. Even if you fail to do it, you may
discover valuable information allowing us to fix it while doing
it. We also give much higher priority to bug reports with patches
fixing the problems so this ensures that your report will be
addressed sooner.


Further information
-------------------

The wxWidgets Web site is located at:

  http://www.wxwidgets.org

The main wxWidgets ftp site is at:

  ftp://biolpc22.york.ac.uk/pub

A wxWidgets CD-ROM with the latest distribution plus an HTML
front-end and hundreds of MB of compilers, utilities and other
material may be ordered from the CD-ROM page: see the wxWidgets
web site.

Have fun!

The wxWidgets Team, July 2010

