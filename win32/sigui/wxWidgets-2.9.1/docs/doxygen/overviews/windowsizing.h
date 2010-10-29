/////////////////////////////////////////////////////////////////////////////
// Name:        windowsizing.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_windowsizing Window Sizing Overview

It can sometimes be confusing to keep track of the various size-related
attributes of a wxWindow, how they relate to each other, and how they interact
with sizers. This document will attempt to clear the fog a little, and give
some simple explanations of things.

@li @ref overview_windowsizing_glossary
@li @ref overview_windowsizing_func


<hr>


@section overview_windowsizing_glossary Glossary

@li @b "Best Size": the best size of a widget depends on what kind of widget it is,
    and usually also on the contents of the widget. For example a wxListBox's best
    size will be calculated based on how many items it has, up to a certain limit,
    or a wxButton's best size will be calculated based on its label size, but
    normally won't be smaller than the platform default button size (unless a style
    flag overrides that).
    There is a special virtual method in the C++ window classes called
    wxWindow::DoGetBestSize() that a class needs to override if it wants to calculate
    its own best size based on its content.

@li @b "Minimal Size": the minimal size of a widget is a size that is normally explicitly
    set by the programmer either with the wxWindow::SetMinSize() method or with the
    wxWindow::SetSizeHints() method.
    Most controls will also set the minimal size to the size given in the control's
    constructor if a non-default value is passed.
    Top-level windows such as wxFrame will not allow the user to resize the frame below
    the minimal size.

@li @b "Maximum Size": just like for the minimal size, the maximum size is normally
    explicitely set by the programmer with the wxWindow::SetMaxSize() method or
    with wxWindow::SetSizeHints().
    Top-level windows such as wxFrame will not allow the user to resize the frame above
    the maximum size.

@li @b "Size": the size of a widget can be explicitly set or fetched with the
    wxWindow::SetSize() or wxWindow::GetSize() methods.
    This size value is the size that the widget is currently using on screen and is
    the way to change the size of something that is not being managed by a sizer.

@li @b "Client Size": the client size represents the widget's area inside of any
    borders belonging to the widget and is the area that can be drawn upon in a
    @c EVT_PAINT event. If a widget doesn't have a border then its client size is
    the same as its size.

@li @b "Initial Size": the initial size of a widget is the size given to the
    constructor of the widget, if any.
    As mentioned above most controls will also set this size value as the control's
    minimal size. If the size passed to the constructor is the default ::wxDefaultSize,
    or if the size is not fully specified (such as wxSize(150,-1)) then most controls
    will fill in the missing size components using the best size and will set the
    initial size of the control to the resulting size.

@li @b "Virtual Size": the virtual size is the size of the potentially viewable
    area of the widget.
    The virtual size of a widget may be larger than its actual size and in this
    case scrollbars will appear to the let the user 'explore' the full contents
    of the widget.
    See wxScrolled for more info.


@section overview_windowsizing_func Functions related to sizing

@li wxWindow::GetEffectiveMinSize(): returns a blending of the widget's minimal size
    and best size, giving precedence to the minimal size.
    For example, if a widget's min size is set to (150, -1) and the best size is
    (80, 22) then the best fitting size is (150, 22). If the min size is (50, 20)
    then the best fitting size is (50, 20). This method is what is called by the
    sizers when determining what the requirements of each item in the sizer is,
    and is used for calculating the overall minimum needs of the sizer.

@li wxWindow::SetInitialSize(): this is a little different than the typical size
    setters. Rather than just setting an "initial size" attribute it actually sets
    the minimal size to the value passed in, blends that value with the best size,
    and then sets the size of the widget to be the result.
    So you can consider this method to be a "Smart SetSize". This method is what is
    called by the constructor of most controls to set the minimal size and the initial
    size of the control.

@li wxWindow::Fit(): this method sets the size of a window to fit around its children.
    If it has no children then nothing is done, if it does have children then the size
    of the window is set to the window's best size.

@li wxSizer::Fit(): this sets the size of the window to be large enough to
    accommodate the minimum size needed by the sizer, (along with a few other
    constraints...). If the sizer is the one that is assigned to the window then
    this should be equivalent to wxWindow::Fit().

@li wxSizer::Layout(): recalculates the minimum space needed by each item in the
    sizer, and then lays out the items within the space currently allotted to the sizer.

@li wxWindow::Layout(): if the window has a sizer then it sets the space given to
    the sizer to the current size of the window, which results in a call to
    wxSizer::Layout(). If the window has layout constraints instead of a sizer then
    the constraints algorithm is run. The @c Layout() method is what is called by
    the default @c EVT_SIZE handler for container windows.

*/

