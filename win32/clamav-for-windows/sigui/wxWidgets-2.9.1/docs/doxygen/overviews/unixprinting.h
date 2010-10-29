/////////////////////////////////////////////////////////////////////////////
// Name:        unixprinting.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_unixprinting Printing Under Unix (GTK+)

Printing under Unix has always been a cause of problems as Unix does not
provide a standard way to display text and graphics on screen and print it to a
printer using the same application programming interface - instead, displaying
on screen is done via the X11 library while printing has to be done with using
PostScript commands. This was particularly difficult to handle for the case of
fonts with the result that only a selected number of application could offer
WYSIWYG under Unix. Equally, wxWidgets offered its own printing implementation
using PostScript which never really matched the screen display.

Starting with version 2.8.X, the GNOME project provides printing support
through the libgnomeprint and libgnomeprintui libraries by which especially the
font problem is mostly solved. Beginning with version 2.5.4, the GTK+ port of
wxWidgets can make use of these libraries if wxWidgets is configured
accordingly and if the libraries are present. You need to configure wxWidgets
with the <tt>configure --with-gnomeprint</tt> switch and your application will
then search for the GNOME print libraries at runtime. If they are found,
printing will be done through these, otherwise the application will fall back
to the old PostScript printing code. Note that the application will not require
the GNOME print libraries to be installed in order to run (there will be no
dependency on these libraries).

In version GTK+ 2.10, support for printing has been added to GTK+ itself.
Beginning with version wxWidgets 2.9.X, the GTK+ port of wxWidgets can make use
of this feature if wxWidgets is configured accordingly and if the GTK+ version
is = 2.10. You need to configure wxWidgets with the
<tt>configure --with-gtkprint</tt> switch and your application will then search
for the GTK+ print support at runtime. If it is found, printing will be done
through GTK+, otherwise the application will fall back to GNOME printing
support if it is available or, if it isn't, to the old PostScript printing
code. Note that the application will not require a GTK+ version = 2.10 to be
installed in order to run (there will be no dependency on this version).

*/

