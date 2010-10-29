/////////////////////////////////////////////////////////////////////////////
// Name:        display.h
// Purpose:     interface of wxDisplay
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxDisplay

    Determines the sizes and locations of displays connected to the system.

    @library{wxcore}
    @category{cfg}

    @see wxClientDisplayRect(), wxDisplaySize(), wxDisplaySizeMM()
*/
class wxDisplay
{
public:
    /**
        Constructor, setting up a wxDisplay instance with the specified
        display.

        @param index
            The index of the display to use. This must be non-negative and
            lower than the value returned by GetCount().
    */
    wxDisplay(unsigned int index = 0);

    /**
        Destructor.
    */
    ~wxDisplay();

    /**
        Changes the video mode of this display to the mode specified in the
        mode parameter.

        If wxDefaultVideoMode is passed in as the mode parameter, the defined
        behaviour is that wxDisplay will reset the video mode to the default
        mode used by the display. On Windows, the behavior is normal. However,
        there are differences on other platforms. On Unix variations using X11
        extensions it should behave as defined, but some irregularities may
        occur.

        On wxMac passing in wxDefaultVideoMode as the mode parameter does
        nothing. This happens because carbon no longer has access to
        @c DMUseScreenPrefs(), an undocumented function that changed the video
        mode to the system default by using the system's "scrn" resource.
    */
    bool ChangeMode(const wxVideoMode& mode = wxDefaultVideoMode);

    /**
        Returns the client area of the display. The client area is the part of
        the display available for the normal (non full screen) windows, usually
        it is the same as GetGeometry() but it could be less if there is a
        taskbar (or equivalent) on this display.
    */
    wxRect GetClientArea() const;

    /**
        Returns the number of connected displays.
    */
    static unsigned int GetCount();

    /**
        Returns the current video mode that this display is in.
    */
    wxVideoMode GetCurrentMode() const;

    /**
        Returns the index of the display on which the given point lies, or
        @c wxNOT_FOUND if the point is not on any connected display.

        @param pt
            The point to locate.
    */
    static int GetFromPoint(const wxPoint& pt);

    /**
        Returns the index of the display on which the given window lies.

        If the window is on more than one display it gets the display that
        overlaps the window the most.

        Returns @c wxNOT_FOUND if the window is not on any connected display.

        @param win
            The window to locate.
    */
    static int GetFromWindow(const wxWindow* win);

    /**
        Returns the bounding rectangle of the display whose index was passed to
        the constructor.

        @see GetClientArea(), wxDisplaySize()
    */
    wxRect GetGeometry() const;

    /**
        Fills and returns an array with all the video modes that are supported
        by this display, or video modes that are supported by this display and
        match the mode parameter (if mode is not wxDefaultVideoMode).
    */
    wxArrayVideoModes GetModes(const wxVideoMode& mode = wxDefaultVideoMode) const;

    /**
        Returns the display's name. A name is not available on all platforms.
    */
    wxString GetName() const;

    /**
        Returns @true if the display is the primary display. The primary
        display is the one whose index is 0.
    */
    bool IsPrimary() const;
};

