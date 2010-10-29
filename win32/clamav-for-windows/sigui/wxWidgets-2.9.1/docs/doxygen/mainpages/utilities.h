/////////////////////////////////////////////////////////////////////////////
// Name:        utilities.h
// Purpose:     Utilities page of the Doxygen manual
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page page_utils Utilities Overview

In addition to the wxWidgets libraries (see @ref page_libs), some utilities
are available to the users in the @c utils hierarchy (even if some of them are
explicitely coinceived for wxWidgets maintainance and will probably be of
little use to others).

Please note that these utilities do represent only the utilities developed
and maintained by the wxWidgets team.
There are lots of other user-contributed and user-maintained packages;
see the wxWidgets download page: http://www.wxwidgets.org/downloads
or directly http://wxcode.sourceforge.net or http://www.wxcommunity.com/ .

@li @ref page_utils_emulator
@li @ref page_utils_helpview
@li @ref page_utils_hhp2cached
@li @ref page_utils_ifacecheck
@li @ref page_utils_wxrc


<hr>


@section page_utils_emulator Emulator

Xnest-based display emulator for X11-based PDA applications.

<!-- On some systems, the Xnest window does not synchronise with the
'skin' window. THIS ISN'T THE PLACE FOR THIS STATEMENT I THINK -->

This program can be found in @c utils/emulator.


@section page_utils_helpview Help Viewer

Helpview is a program for displaying wxWidgets HTML Help files.
In many cases, you may wish to use the wxWidgets HTML
Help classes from within your application, but this provides a
handy stand-alone viewer. See @ref overview_html for more details.

You can find Helpview in @c utils/helpview.


@section page_utils_hhp2cached HHP2Cached

This utility creates a "cached" version of a @c .hhp file; using cached @c .hhp
files in wxHtmlHelpController can drammatically improve the performances
of the help viewer. See wxHtmlHelpController for more details.

You can find HHP2Cached in @c utils/hhp2cached.


@section page_utils_ifacecheck Interface checker

This utility compares the wxWidgets real interface contained in the @c include
hierarchy with the wxWidgets interface used for documentation purposes and
kept in the @c interface hierarchy.

Ifacecheck warns about incoherences (mainly wrong prototype signatures) and
can even correct them automatically. It uses the XML outputs of the gccxml utility
(see http://www.gccxml.org) and of the Doxygen utility (see http://www.doxygen.org)
to do the comparisons.

It's explicitely designed for wxWidgets documentation needs and is probably of little
use for anything else than wxWidgets docs reviewing.

You can find it in @c utils/ifacecheck.


@section page_utils_wxrc wxWidgets XML Resource Compiler

This utility allows the user to compile @e binary versions of their XRC files,
which are compressed and can be loaded faster than plain XRC files.
See @ref overview_xrc for more info.

You can find it under @c utils/wxrc.

*/

