/////////////////////////////////////////////////////////////////////////////
// Name:        sizer.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_sizer Sizers Overview

Classes: wxSizer, wxBoxSizer, wxStaticBoxSizer, wxGridSizer, wxFlexGridSizer,
         wxGridBagSizer

Sizers, as represented by the wxSizer class and its descendants in the
wxWidgets class hierarchy, have become the method of choice to define the
layout of controls in dialogs in wxWidgets because of their ability to create
visually appealing dialogs independent of the platform, taking into account
the differences in size and style of the individual controls. Unlike the
original wxWidgets Dialog Editor, editors such as wxDesigner, DialogBlocks,
XRCed and wxWorkshop create dialogs based exclusively on sizers, practically
forcing the user to create platform independent layouts without compromises.

The next section describes and shows what can be done with sizers. The
following sections briefly describe how to program with individual sizer
classes.

For information about the wxWidgets resource system, which can describe
sizer-based dialogs, see the @ref overview_xrc.

@li @ref overview_sizer_idea
@li @ref overview_sizer_features
@li @ref overview_sizer_hiding
@li @ref overview_sizer_box
@li @ref overview_sizer_types
@li @ref overview_sizer_button


<hr>


@section overview_sizer_idea The Idea Behind Sizers

The layout algorithm used by sizers in wxWidgets is closely related to layout
systems in other GUI toolkits, such as Java's AWT, the GTK toolkit or the Qt
toolkit. It is based upon the idea of individual subwindows reporting their
minimal required size and their ability to get stretched if the size of the
parent window has changed. This will most often mean that the programmer does
not set the start-up size of a dialog, the dialog will rather be assigned a
sizer and this sizer will be queried about the recommended size. This sizer in
turn will query its children (which can be normal windows, empty space or other
sizers) so that a hierarchy of sizers can be constructed. Note that wxSizer
does not derive from wxWindow and thus does not interfere with tab ordering and
requires very few resources compared to a real window on screen.

What makes sizers so well fitted for use in wxWidgets is the fact that every
control reports its own minimal size and the algorithm can handle differences
in font sizes or different window (dialog item) sizes on different platforms
without problems. For example, if the standard font as well as the overall
design of Linux/GTK widgets requires more space than on Windows, the initial
dialog size will automatically be bigger on Linux/GTK than on Windows.

There are currently five different kinds of sizers available in wxWidgets. Each
represents either a certain way to lay out dialog items in a dialog or it
fulfills a special task such as wrapping a static box around a dialog item (or
another sizer). These sizers will be discussed one by one in the text below.
For more detailed information on how to use sizers programmatically, please
refer to the section @ref overview_sizer_box.


@section overview_sizer_features Common Features

All sizers are containers, that is, they are used to lay out one dialog item
(or several dialog items), which they contain. Such items are sometimes
referred to as the children of the sizer. Independent of how the individual
sizers lay out their children, all children have certain features in common:

<b>A minimal size</b>: This minimal size is usually identical to the initial
size of the controls and may either be set explicitly in the wxSize field of
the control constructor or may be calculated by wxWidgets, typically by setting
the height and/or the width of the item to -1. Note that only some controls can
calculate their size (such as a checkbox) whereas others (such as a listbox)
don't have any natural width or height and thus require an explicit size. Some
controls can calculate their height, but not their width (e.g. a single line
text control):

@image html overview_sizer_03.png

@image html overview_sizer_04.png

@image html overview_sizer_05.png

<b>A border</b>: The border is just empty space and is used to separate dialog
items in a dialog. This border can either be all around, or at any combination
of sides such as only above and below the control. The thickness of this border
must be set explicitly, typically 5 points. The following samples show dialogs
with only one dialog item (a button) and a border of 0, 5, and 10 pixels around
the button:

@image html overview_sizer_00.png

@image html overview_sizer_01.png

@image html overview_sizer_02.png

<b>An alignment</b>: Often, a dialog item is given more space than its minimal
size plus its border. Depending on what flags are used for the respective
dialog item, the dialog item can be made to fill out the available space
entirely, i.e. it will grow to a size larger than the minimal size, or it will
be moved to either the centre of the available space or to either side of the
space. The following sample shows a listbox and three buttons in a horizontal
box sizer; one button is centred, one is aligned at the top, one is aligned at
the bottom:

@image html overview_sizer_06.png

<b>A stretch factor</b>: If a sizer contains more than one child and it is
offered more space than its children and their borders need, the question
arises how to distribute the surplus space among the children. For this
purpose, a stretch factor may be assigned to each child, where the default
value of 0 indicates that the child will not get more space than its requested
minimum size. A value of more than zero is interpreted in relation to the sum
of all stretch factors in the children of the respective sizer, i.e. if two
children get a stretch factor of 1, they will get half the extra space each
<em>independent of whether one control has a minimal sizer inferior to the
other or not</em>. The following sample shows a dialog with three buttons, the
first one has a stretch factor of 1 and thus gets stretched, whereas the other
two buttons have a stretch factor of zero and keep their initial width:

@image html overview_sizer_07.png

Within wxDesigner, this stretch factor gets set from the @e Option menu.


@section overview_sizer_hiding Hiding Controls Using Sizers

You can hide controls contained in sizers the same way you would hide any
control, using the wxWindow::Show method. However, wxSizer also offers a
separate method which can tell the sizer not to consider that control in its
size calculations. To hide a window using the sizer, call wxSizer::Show. You
must then call Layout on the sizer to force an update.

This is useful when hiding parts of the interface, since you can avoid removing
the controls from the sizer and having to add them back later.

@note This is supported only by wxBoxSizer and wxFlexGridSizer.

@subsection overview_sizer_hiding_box wxBoxSizer

wxBoxSizer can lay out its children either vertically or horizontally,
depending on what flag is being used in its constructor. When using a vertical
sizer, each child can be centered, aligned to the right or aligned to the left.
Correspondingly, when using a horizontal sizer, each child can be centered,
aligned at the bottom or aligned at the top. The stretch factor described in
the last paragraph is used for the main orientation, i.e. when using a
horizontal box sizer, the stretch factor determines how much the child can be
stretched horizontally. The following sample shows the same dialog as in the
last sample, only the box sizer is a vertical box sizer now:

@image html overview_sizer_08.png

@subsection overview_sizer_hiding_static wxStaticBoxSizer

wxStaticBoxSixer is the same as a wxBoxSizer, but surrounded by a static box.
Here is a sample:

@image html overview_sizer_09.png

@subsection overview_sizer_hiding_grid wxGridSizer

wxGridSizer is a two-dimensional sizer. All children are given the same size,
which is the minimal size required by the biggest child, in this case the text
control in the left bottom border. Either the number of columns or the number
or rows is fixed and the grid sizer will grow in the respectively other
orientation if new children are added:

@image html overview_sizer_10.png

For programming information, see wxGridSizer.

@subsection overview_sizer_hiding_flexgrid wxFlexGridSizer

Another two-dimensional sizer derived from wxGridSizer. The width of each
column and the height of each row are calculated individually according to the
minimal requirements from the respectively biggest child. Additionally, columns
and rows can be declared to be stretchable if the sizer is assigned a size
different from the one it requested. The following sample shows the same dialog
as the one above, but using a flex grid sizer:

@image html overview_sizer_11.png


@section overview_sizer_box Programming with wxBoxSizer

The basic idea behind a wxBoxSizer is that windows will most often be laid out
in rather simple basic geometry, typically in a row or a column or several
hierarchies of either.

As an example, we will construct a dialog that will contain a text field at the
top and two buttons at the bottom. This can be seen as a top-hierarchy column
with the text at the top and buttons at the bottom and a low-hierarchy row with
an OK button to the left and a Cancel button to the right. In many cases
(particularly dialogs under Unix and normal frames) the main window will be
resizable by the user and this change of size will have to get propagated to
its children. In our case, we want the text area to grow with the dialog,
whereas the button shall have a fixed size. In addition, there will be a thin
border around all controls to make the dialog look nice and - to make matter
worse - the buttons shall be centred as the width of the dialog changes.

It is the unique feature of a box sizer, that it can grow in both directions
(height and width) but can distribute its growth in the main direction
(horizontal for a row) @e unevenly among its children. In our example case, the
vertical sizer is supposed to propagate all its height changes to only the text
area, not to the button area. This is determined by the @e proportion parameter
when adding a window (or another sizer) to a sizer. It is interpreted as a
weight factor, i.e. it can be zero, indicating that the window may not be
resized at all, or above zero. If several windows have a value above zero, the
value is interpreted relative to the sum of all weight factors of the sizer, so
when adding two windows with a value of 1, they will both get resized equally
much and each half as much as the sizer owning them. Then what do we do when a
column sizer changes its width? This behaviour is controlled by @e flags (the
second parameter of the Add() function): Zero or no flag indicates that the
window will preserve it is original size, wxGROW flag (same as wxEXPAND) forces
the window to grow with the sizer, and wxSHAPED flag tells the window to change
it is size proportionally, preserving original aspect ratio.  When wxGROW flag
is not used, the item can be aligned within available space.  wxALIGN_LEFT,
wxALIGN_TOP, wxALIGN_RIGHT, wxALIGN_BOTTOM, wxALIGN_CENTER_HORIZONTAL and
wxALIGN_CENTER_VERTICAL do what they say. wxALIGN_CENTRE (same as
wxALIGN_CENTER) is defined as (wxALIGN_CENTER_HORIZONTAL |
wxALIGN_CENTER_VERTICAL). Default alignment is wxALIGN_LEFT | wxALIGN_TOP.

As mentioned above, any window belonging to a sizer may have a border, and it
can be specified which of the four sides may have this border, using the wxTOP,
wxLEFT, wxRIGHT and wxBOTTOM constants or wxALL for all directions (and you may
also use wxNORTH, wxWEST etc instead). These flags can be used in combination
with the alignment flags above as the second parameter of the Add() method
using the binary or operator |. The sizer of the border also must be made
known, and it is the third parameter in the Add() method. This means, that the
entire behaviour of a sizer and its children can be controlled by the three
parameters of the Add() method.

@code
// We want to get a dialog that is stretchable because it
// has a text ctrl at the top and two buttons at the bottom.

MyDialog::MyDialog(wxFrame *parent, wxWindowID id, const wxString &title )
: wxDialog(parent, id, title, wxDefaultPosition, wxDefaultSize,
           wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER)
{
    wxBoxSizer *topsizer = new wxBoxSizer( wxVERTICAL );

    // create text ctrl with minimal size 100x60
    topsizer->Add(
        new wxTextCtrl( this, -1, "My text.", wxDefaultPosition, wxSize(100,60), wxTE_MULTILINE),
        1,            // make vertically stretchable
        wxEXPAND |    // make horizontally stretchable
        wxALL,        //   and make border all around
        10 );         // set border width to 10

    wxBoxSizer *button_sizer = new wxBoxSizer( wxHORIZONTAL );
    button_sizer->Add(
        new wxButton( this, wxID_OK, "OK" ),
        0,           // make horizontally unstretchable
        wxALL,       // make border all around (implicit top alignment)
        10 );        // set border width to 10
    button_sizer->Add(
        new wxButton( this, wxID_CANCEL, "Cancel" ),
        0,           // make horizontally unstretchable
        wxALL,       // make border all around (implicit top alignment)
        10 );        // set border width to 10

    topsizer->Add(
        button_sizer,
        0,                // make vertically unstretchable
        wxALIGN_CENTER ); // no border and centre horizontally

    SetSizerAndFit(topsizer); // use the sizer for layout and size window
                              // accordingly and prevent it from being resized
                              // to smaller size
}
@endcode

Note that the new way of specifying flags to wxSizer is via wxSizerFlags. This
class greatly eases the burden of passing flags to a wxSizer.

Here's how you'd do the previous example with wxSizerFlags:

@code
// We want to get a dialog that is stretchable because it
// has a text ctrl at the top and two buttons at the bottom.

MyDialog::MyDialog(wxFrame *parent, wxWindowID id, const wxString &title )
: wxDialog(parent, id, title, wxDefaultPosition, wxDefaultSize,
           wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER)
{
    wxBoxSizer *topsizer = new wxBoxSizer( wxVERTICAL );

    // create text ctrl with minimal size 100x60 that is horizontally and
    // vertically stretchable with a border width of 10
    topsizer->Add(
        new wxTextCtrl( this, -1, "My text.", wxDefaultPosition, wxSize(100,60), wxTE_MULTILINE),
        wxSizerFlags(1).Align().Expand().Border(wxALL, 10));

    wxBoxSizer *button_sizer = new wxBoxSizer( wxHORIZONTAL );

    //create two buttons that are horizontally unstretchable,
    // with an all-around border with a width of 10 and implicit top alignment
    button_sizer->Add(
        new wxButton( this, wxID_OK, "OK" ),
        wxSizerFlags(0).Align().Border(wxALL, 10));

    button_sizer->Add(
        new wxButton( this, wxID_CANCEL, "Cancel" ),
        wxSizerFlags(0).Align().Border(wxALL, 10));

    //create a sizer with no border and centered horizontally
    topsizer->Add(
        button_sizer,
        wxSizerFlags(0).Center() );

    SetSizerAndFit(topsizer); // use the sizer for layout and set size and hints
}
@endcode



@section overview_sizer_types Other Types of Sizers

wxGridSizer is a sizer which lays out its children in a two-dimensional table
with all table fields having the same size, i.e. the width of each field is the
width of the widest child, the height of each field is the height of the
tallest child.

wxFlexGridSizer is a sizer which lays out its children in a two-dimensional
table with all table fields in one row having the same height and all fields in
one column having the same width, but all rows or all columns are not
necessarily the same height or width as in the wxGridSizer.

wxStaticBoxSizer is a sizer derived from wxBoxSizer but adds a static box
around the sizer. Note that this static box has to be created separately.

wxGridBagSizer is a rather special kind of sizer which, unlike the other
classes, allows to directly put the elements at the given position in the
sizer. Please see its documentation for more details.

@section overview_sizer_button CreateButtonSizer

As a convenience, wxDialog::CreateButtonSizer(long flags) can be used to create a
standard button sizer in which standard buttons are displayed. The following
flags can be passed to this function:

@code
wxYES_NO     // Add Yes/No subpanel
wxYES        // return wxID_YES
wxNO         // return wxID_NO
wxNO_DEFAULT // make the wxNO button the default,
             // otherwise wxYES or wxOK button will be default

wxOK     // return wxID_OK
wxCANCEL // return wxID_CANCEL
wxHELP   // return wxID_HELP

wxFORWARD   // return wxID_FORWARD
wxBACKWARD  // return wxID_BACKWARD
wxSETUP     // return wxID_SETUP
wxMORE      // return wxID_MORE
@endcode

*/

