/////////////////////////////////////////////////////////////////////////////
// Name:        scrolling.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_scrolling Scrolled Windows

Classes: wxWindow, wxScrolledWindow, wxScrollBar

@li @ref overview_scrolling_model
@li @ref overview_scrolling_example

<hr>


Scrollbars come in various guises in wxWidgets. All windows have the potential
to show a vertical scrollbar and/or a horizontal scrollbar: it is a basic
capability of a window. However, in practice, not all windows do make use of
scrollbars, such as a single-line wxTextCtrl.

Because any class derived from wxWindow may have scrollbars, there are
functions to manipulate the scrollbars and event handlers to intercept scroll
events. But just because a window generates a scroll event, doesn't mean that
the window necessarily handles it and physically scrolls the window. The base
class wxWindow in fact doesn't have any default functionality to handle scroll
events. If you created a wxWindow object with scrollbars, and then clicked on
the scrollbars, nothing at all would happen. This is deliberate, because the
@e interpretation of scroll events varies from one window class to another.

::wxScrolledWindow (formerly wxCanvas) is an example of a window that adds
functionality to make scrolling really work. It assumes that scrolling happens
in consistent units, not different-sized jumps, and that page size is
represented by the visible portion of the window. It is suited to drawing
applications, but perhaps not so suitable for a sophisticated editor in which
the amount scrolled may vary according to the size of text on a given line. For
this, you would derive from wxWindow and implement scrolling yourself. wxGrid
is an example of a class that implements its own scrolling, largely because
columns and rows can vary in size.


@section overview_scrolling_model The Scrollbar Model

The function wxWindow::SetScrollbar gives a clue about the way a scrollbar is
modeled. This function takes the following arguments:

@beginTable
@row2col{ @c orientation , Which scrollbar: wxVERTICAL or wxHORIZONTAL. }
@row2col{ @c position , The position of the scrollbar in scroll units. }
@row2col{ @c visible , The size of the visible portion of the scrollbar,
                       in scroll units. }
@row2col{ @c range , The maximum position of the scrollbar. }
@row2col{ @c refresh , Whether the scrollbar should be repainted. }
@endTable

@c orientation determines whether we're talking about the built-in horizontal
or vertical scrollbar.

@c position is simply the position of the 'thumb' (the bit you drag to scroll
around). It is given in scroll units, and so is relative to the total range of
the scrollbar.

@c visible gives the number of scroll units that represents the portion of the
window currently visible. Normally, a scrollbar is capable of indicating this
visually by showing a different length of thumb.

@c range is the maximum value of the scrollbar, where zero is the start
position. You choose the units that suit you, so if you wanted to display text
that has 100 lines, you would set this to 100. Note that this doesn't have to
correspond to the number of pixels scrolled - it is up to you how you actually
show the contents of the window.

@c refresh just indicates whether the scrollbar should be repainted immediately
or not.


@section overview_scrolling_example An Example

Let's say you wish to display 50 lines of text, using the same font. The window
is sized so that you can only see 16 lines at a time. You would use:

@code
SetScrollbar(wxVERTICAL, 0, 16, 50);
@endcode

Note that with the window at this size, the thumb position can never go above
50 minus 16, or 34. You can determine how many lines are currently visible by
dividing the current view size by the character height in pixels.

When defining your own scrollbar behaviour, you will always need to recalculate
the scrollbar settings when the window size changes. You could therefore put
your scrollbar calculations and SetScrollbar call into a function named
AdjustScrollbars, which can be called initially and also from your wxSizeEvent
handler function.

*/

