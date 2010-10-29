/////////////////////////////////////////////////////////////////////////////
// Name:        dc.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_dc Device Contexts

Classes: wxBufferedDC, wxBufferedPaintDC, wxDC, wxPostScriptDC,
        wxMetafileDC, wxMemoryDC, wxPrinterDC, wxScreenDC, wxClientDC,
        wxPaintDC, wxWindowDC.

A wxDC is a @e device context onto which graphics and text can be drawn.
The device context is intended to represent a number of output devices in a
generic way, with the same API being used throughout.

Some device contexts are created temporarily in order to draw on a window.
This is @true of wxScreenDC, wxClientDC, wxPaintDC, and wxWindowDC.
The following describes the differences between these device contexts and
when you should use them.

@li @b wxScreenDC. Use this to paint on the screen, as opposed to an individual window.
@li @b wxClientDC. Use this to paint on the client area of window (the part without
    borders and other decorations), but do not use it from within an wxPaintEvent.
@li @b wxPaintDC. Use this to paint on the client area of a window, but @e only from
    within a wxPaintEvent.
@li @b wxWindowDC. Use this to paint on the whole area of a window, including decorations.
    This may not be available on non-Windows platforms.

To use a client, paint or window device context, create an object on the stack with
the window as argument, for example:

@code
void MyWindow::OnMyCmd(wxCommandEvent& event)
{
    wxClientDC dc(window);
    DrawMyPicture(dc);
}
@endcode

Try to write code so it is parameterised by wxDC - if you do this, the same piece of code may
write to a number of different devices, by passing a different device context. This doesn't
work for everything (for example not all device contexts support bitmap drawing) but
will work most of the time.

*/

