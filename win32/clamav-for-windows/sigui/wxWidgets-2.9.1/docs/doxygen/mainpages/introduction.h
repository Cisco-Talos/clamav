/////////////////////////////////////////////////////////////////////////////
// Name:        introduction.h
// Purpose:     Introduction page of the Doxygen manual
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**

@page page_introduction Introduction

@li @ref page_introduction_whatis
@li @ref page_introduction_why
@li @ref page_introduction_requirements
@li @ref page_introduction_where
@li @ref page_introduction_acknowledgements


<hr>


@section page_introduction_whatis What is wxWidgets?

wxWidgets is a C++ framework providing GUI (Graphical User
Interface) and other facilities on more than one platform.  Version 2 and higher
currently support all desktop versions of MS Windows, Unix with GTK+ 1.x or 2.x,
Unix with Motif, Unix with just X11, Unix with DirectFB, Mac OS X, OS/2.

wxWidgets was originally developed at the Artificial Intelligence
Applications Institute, University of Edinburgh, for internal use,
and was first made publicly available in 1992.
Version 2 is a vastly improved version written and maintained by
Julian Smart, Robert Roebling, Vadim Zeitlin, Vaclav Slavik and many others.

This manual contains a class reference and topic overviews.
For a selection of wxWidgets tutorials, please see the documentation page
on the wxWidgets web site: http://www.wxwidgets.org.

Please note that in the following, "MS Windows" often refers to all
platforms related to Microsoft Windows, including 32-bit and 64-bit
variants, unless otherwise stated. All trademarks are acknowledged.



@section page_introduction_why Why another cross-platform development tool?

wxWidgets was developed to provide a cheap and flexible way to maximize
investment in GUI application development.  While a number of commercial
class libraries already existed for cross-platform development,
none met all of the following criteria:

@li low price;
@li source availability;
@li simplicity of programming;
@li support for a wide range of compilers.

Since wxWidgets was started, several other free or almost-free
GUI frameworks have emerged. However, none has the range of
features, flexibility, documentation and the well-established
development team that wxWidgets has.

As open source software, wxWidgets has benefited from comments,
ideas, bug fixes, enhancements and the sheer enthusiasm of
users. This gives wxWidgets a certain advantage over its
commercial competitors (and over free libraries without an
independent development team), plus a robustness against the
transience of one individual or company. This openness and
availability of source code is especially important when the
future of thousands of lines of application code may depend upon
the longevity of the underlying class library.

Version 2 goes much further than previous versions in terms of
generality and features, allowing applications to be produced
that are often indistinguishable from those produced using
single-platform toolkits such as Motif, GTK+ and MFC.

The importance of using a platform-independent class library
cannot be overstated, since GUI application development is very
time-consuming, and sustained popularity of particular GUIs
cannot be guaranteed. Code can very quickly become obsolete if
it addresses the wrong platform or audience.  wxWidgets helps to
insulate the programmer from these winds of change. Although
wxWidgets may not be suitable for every application (such as an
OLE-intensive program), it provides access to most of the
functionality a GUI program normally requires, plus many extras
such as network programming, PostScript output, and HTML
rendering; and it can of course be extended as needs dictate.
As a bonus, it provides a far cleaner and easier programming
interface than the native APIs. Programmers may find it
worthwhile to use wxWidgets even if they are developing on only
one platform.

It is impossible to sum up the functionality of wxWidgets in a few paragraphs, but
here are some of the benefits:

@li Low cost (free, in fact!)
@li You get the source.
@li Available on a variety of popular platforms.
@li Works with almost all popular C++ compilers and Python.
@li Over 70 example programs.
@li Over 1000 pages of printable and on-line documentation.
@li Simple-to-use, object-oriented API.
@li Flexible event system.
@li Graphics calls include lines, rounded rectangles, splines, polylines, etc.
@li Constraint-based and sizer-based layouts.
@li Print/preview and document/view architectures.
@li Toolbar, notebook, tree control, advanced list control classes.
@li PostScript generation under Unix, normal MS Windows printing on the PC.
@li MDI (Multiple Document Interface) support.
@li Can be used to create DLLs under Windows, dynamic libraries on Unix.
@li Common dialogs for file browsing, printing, colour selection, etc.
@li Under MS Windows, support for creating metafiles and copying them to the clipboard.
@li An API for invoking help from applications.
@li Ready-to-use HTML window (supporting a subset of HTML).
@li Network support via a family of socket and protocol classes.
@li Support for platform independent image processing.
@li Built-in support for many file formats (BMP, PNG, JPEG, GIF, XPM, PNM, PCX).


@section page_introduction_requirements wxWidgets requirements

To make use of wxWidgets, you currently need one of the following setups.

(a) MS-Windows:

@li A 32-bit or 64-bit PC running MS Windows.
@li A Windows compiler: MS Visual C++ (embedded Visual C++ for wxWinCE
    port), Borland C++, Watcom C++, Cygwin, MinGW, Metrowerks CodeWarrior,
    Digital Mars C++. See @c install.txt for details about compiler
    version supported.

(b) Unix:

@li Almost any C++ compiler, including GNU C++ and many Unix vendors
    compilers such as Sun CC, HP-UX aCC or SGI mipsPro.
@li Almost any Unix workstation, and one of: GTK+ 2.4 or higher (GTK+ 1.2.10
    may still be supported but wxGTK1 port is not maintained any longer and lacks
    many features of wxGTK2), Motif 1.2 or higher or Lesstif. If using the wxX11
    port, no such widget set is required.

(c) Mac OS/Mac OS X:

@li A PowerPC or Intel Mac running Mac OS X 10.4 or higher
@li The Apple Developer Tools (eg. GNU C++)

Under all platforms it's recommended to have large amounts of free hard disk
space. The exact amount needed depends on the port, compiler and build
configurations but to give an example, a debug build of the library may take up
to 500MB.



@section page_introduction_where Availability and location of wxWidgets

wxWidgets is available by anonymous FTP and World Wide Web
from ftp://biolpc22.york.ac.uk/pub and/or http://www.wxwidgets.org.

You can also buy a CD-ROM using the form on the Web site.



@section page_introduction_acknowledgements Acknowledgements

The following is the list of the core, active developers of wxWidgets which keep
it running and have provided an invaluable, extensive and high-quality amount of
changes over the many of years of wxWidgets' life:

@li Julian Smart
@li Vadim Zeitlin
@li Robert Roebling
@li Robin Dunn
@li Stefan Csomor
@li Vaclav Slavik
@li Paul Cornett
@li Wlodzimierz `ABX' Skiba
@li Chris Elliott
@li David Elliott
@li Kevin Hock
@li Stefan Neis
@li Michael Wetherell

We would particularly like to thank the following peoples for their contributions
to wxWidgets, and the many others who have been involved in the project over the years.
Apologies for any unintentional omissions from this alphabetic list:

Yiorgos Adamopoulos, Jamshid Afshar, Alejandro Aguilar-Sierra, AIAI,
Patrick Albert, Karsten Ballueder, Mattia Barbon, Michael Bedward,
Kai Bendorf, Yura Bidus, Keith Gary Boyce, Chris Breeze, Pete Britton,
Ian Brown, C. Buckley, Marco Cavallini, Dmitri Chubraev, Robin Corbet, Cecil Coupe,
Andrew Davison, Gilles Depeyrot, Neil Dudman, Hermann Dunkel, Jos van Eijndhoven,
Tom Felici, Thomas Fettig, Matthew Flatt, Pasquale Foggia, Josep Fortiana, Todd Fries,
Dominic Gallagher, Guillermo Rodriguez Garcia, Wolfram Gloger, Norbert Grotz,
Stefan Gunter, Bill Hale, Patrick Halke, Stefan Hammes, Guillaume Helle,
Harco de Hilster, Cord Hockemeyer, Markus Holzem, Olaf Klein, Leif Jensen,
Bart Jourquin, Guilhem Lavaux, Ron Lee, Jan Lessner, Nicholas Liebmann,
Torsten Liermann, Per Lindqvist, Francesco Montorsi, Thomas Runge, Tatu M&auml;nnist&ouml;,
Scott Maxwell, Thomas Myers, Oliver Niedung, Ryan Norton, Hernan Otero,
Ian Perrigo, Timothy Peters, Giordano Pezzoli, Harri Pasanen, Thomaso Paoletti,
Garrett Potts, Marcel Rasche, Dino Scaringella, Jobst Schmalenbach, Arthur Seaton,
Paul Shirley, Stein Somers, Petr Smilauer, Neil Smith, Kari Syst&auml;, George Tasker,
Arthur Tetzlaff-Deas, Jonathan Tonberg, Jyrki Tuomi, Janos Vegh, Andrea Venturoli,
David Webster, Otto Wyss, Xiaokun Zhu, Edward Zimmermann.

Many thanks also to AIAI for being willing to release the original version of
wxWidgets into the public domain, and to our patient partners.

`Graphplace', the basis for the wxGraphLayout library, is copyright Dr. Jos
T.J. van Eijndhoven of Eindhoven University of Technology. The code has
been used in wxGraphLayout (not in wxWidgets anymore) with his permission.

We also acknowledge the author of XFIG, the excellent Unix drawing tool,
from the source of which we have borrowed some spline drawing code.
His copyright is included below.

<em>
XFig2.1 is copyright (c) 1985 by Supoj Sutanthavibul. Permission to
use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided
that the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation, and that the name of M.I.T. not be used in advertising or
publicity pertaining to distribution of the software without specific,
written prior permission.  M.I.T. makes no representations about the
suitability of this software for any purpose.  It is provided ``as is''
without express or implied warranty.
</em>

*/
