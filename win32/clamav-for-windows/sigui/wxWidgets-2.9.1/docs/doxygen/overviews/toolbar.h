/////////////////////////////////////////////////////////////////////////////
// Name:        toolbar.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_toolbar Toolbar Overview

Classes: wxToolBar

@li @ref overview_toolbar_intro
@li @ref overview_toolbar_library


<hr>


@section overview_toolbar_intro Introduction

The toolbar family of classes allows an application to use toolbars in a
variety of configurations and styles.

The toolbar is a popular user interface component and contains a set of bitmap
buttons or toggles. A toolbar gives faster access to an application's
facilities than menus, which have to be popped up and selected rather
laboriously.

Instead of supplying one toolbar class with a number of different
implementations depending on platform, wxWidgets separates out the classes.
This is because there are a number of different toolbar styles that you may
wish to use simultaneously, and also, future toolbar implementations will
emerge which cannot all be shoe-horned into the one class.

For each platform, the symbol wxToolBar is defined to be one of the specific
toolbar classes.

The following is a summary of the toolbar classes and their differences:

@li wxToolBarBase: This is a base class with pure virtual functions, and should
    not be used directly.
@li wxToolBarSimple: A simple toolbar class written entirely with generic
    wxWidgets functionality. A simple 3D effect for buttons is possible, but it
    is not consistent with the Windows look and feel. This toolbar can scroll,
    and you can have arbitrary numbers of rows and columns.
@li wxToolBarMSW: This class implements an old-style Windows toolbar, only on
    Windows. There are small, three-dimensional buttons, which do not
    (currently) reflect the current Windows colour settings: the buttons are
    grey. This is the default wxToolBar on 16-bit windows.
@li wxToolBar95: Uses the native Windows 95 toolbar class. It dynamically
    adjusts it's background and button colours according to user colour
    settings. CreateTools must be called after the tools have been added. No
    absolute positioning is supported but you can specify the number of rows,
    and add tool separators with @c AddSeparator. Tooltips are supported.
    @c OnRightClick is not supported. This is the default wxToolBar on Windows
    95, Windows NT 4 and above. With the style wxTB_FLAT, the flat toolbar look
    is used, with a border that is highlighted when the cursor moves over the
    buttons.

A toolbar might appear as a single row of images under the menubar, or it might
be in a separate frame layout in several rows and columns. The class handles
the layout of the images, unless explicit positioning is requested.

A tool is a bitmap which can either be a button (there is no 'state', it just
generates an event when clicked) or it can be a toggle. If a toggle, a second
bitmap can be provided to depict the 'on' state; if the second bitmap is
omitted, either the inverse of the first bitmap will be used (for monochrome
displays) or a thick border is drawn around the bitmap (for colour displays
where inverting will not have the desired result).

The Windows-specific toolbar classes expect 16-colour bitmaps that are 16
pixels wide and 15 pixels high. If you want to use a different size, call
@c SetToolBitmapSize as the demo shows, before adding tools to the button bar.
Don't supply more than one bitmap for each tool, because the toolbar generates
all three images (normal, depressed, and checked) from the single bitmap you
give it.


@section overview_toolbar_library Using the Toolbar Library

Include @c "wx/toolbar.h", or if using a class directly, one of:

- @c "wx/msw/tbarmsw.h" for wxToolBarMSW
- @c "wx/msw/tbar95.h" for wxToolBar95
- @c "wx/tbarsmpl.h" for wxToolBarSimple

An example of using a toolbar is given in the "toolbar" sample.

*/

