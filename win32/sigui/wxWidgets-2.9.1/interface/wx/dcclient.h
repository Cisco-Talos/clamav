/////////////////////////////////////////////////////////////////////////////
// Name:        dcclient.h
// Purpose:     interface of wxClientDC and wxPaintDC
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxPaintDC

    A wxPaintDC must be constructed if an application wishes to paint on the
    client area of a window from within an EVT_PAINT() event handler. This
    should normally be constructed as a temporary stack object; don't store a
    wxPaintDC object. If you have an EVT_PAINT() handler, you @e must create a
    wxPaintDC object within it even if you don't actually use it.

    Using wxPaintDC within your EVT_PAINT() handler is important because it
    automatically sets the clipping area to the damaged area of the window.
    Attempts to draw outside this area do not appear.

    To draw on a window from outside your EVT_PAINT() handler, construct a
    wxClientDC object.

    To draw on the whole window including decorations, construct a wxWindowDC
    object (Windows only).

    A wxPaintDC object is initialized to use the same font and colours as the
    window it is associated with.

    @library{wxcore}
    @category{dc}

    @see wxDC, wxClientDC, wxMemoryDC, wxWindowDC, wxScreenDC
*/
class wxPaintDC : public wxWindowDC
{
public:
    /**
        Constructor. Pass a pointer to the window on which you wish to paint.
    */
    wxPaintDC(wxWindow* window);
};



/**
    @class wxClientDC

    A wxClientDC must be constructed if an application wishes to paint on the
    client area of a window from outside an EVT_PAINT() handler. This should
    normally be constructed as a temporary stack object; don't store a
    wxClientDC object.

    To draw on a window from within an EVT_PAINT() handler, construct a
    wxPaintDC object instead.

    To draw on the whole window including decorations, construct a wxWindowDC
    object (Windows only).

    A wxClientDC object is initialized to use the same font and colours as the
    window it is associated with.

    @library{wxcore}
    @category{dc}

    @see wxDC, wxMemoryDC, wxPaintDC, wxWindowDC, wxScreenDC
*/
class wxClientDC : public wxWindowDC
{
public:
    /**
        Constructor. Pass a pointer to the window on which you wish to paint.
    */
    wxClientDC(wxWindow* window);
};



/**
    @class wxWindowDC

    A wxWindowDC must be constructed if an application wishes to paint on the
    whole area of a window (client and decorations). This should normally be
    constructed as a temporary stack object; don't store a wxWindowDC object.

    To draw on a window from inside an EVT_PAINT() handler, construct a
    wxPaintDC object instead.

    To draw on the client area of a window from outside an EVT_PAINT() handler,
    construct a wxClientDC object.

    A wxWindowDC object is initialized to use the same font and colours as the
    window it is associated with.

    @library{wxcore}
    @category{dc}

    @see wxDC, wxMemoryDC, wxPaintDC, wxClientDC, wxScreenDC
*/
class wxWindowDC : public wxDC
{
public:
    /**
        Constructor. Pass a pointer to the window on which you wish to paint.
    */
    wxWindowDC(wxWindow* window);
};

