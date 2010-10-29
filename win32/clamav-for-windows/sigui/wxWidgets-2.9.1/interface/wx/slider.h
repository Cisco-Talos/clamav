/////////////////////////////////////////////////////////////////////////////
// Name:        slider.h
// Purpose:     interface of wxSlider
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxSlider

    A slider is a control with a handle which can be pulled back and forth to
    change the value.

    On Windows, the track bar control is used.

    Slider events are handled in the same way as a scrollbar.

    @beginStyleTable
    @style{wxSL_HORIZONTAL}
           Displays the slider horizontally (this is the default).
    @style{wxSL_VERTICAL}
           Displays the slider vertically.
    @style{wxSL_AUTOTICKS}
           Displays tick marks. Windows only.
    @style{wxSL_MIN_MAX_LABELS}
           Displays minimum, maximum labels (new since wxWidgets 2.9.1).
    @style{wxSL_VALUE_LABEL}
           Displays value label (new since wxWidgets 2.9.1).
    @style{wxSL_LABELS}
           Displays minimum, maximum and value labels (same as wxSL_VALUE_LABEL
           and wxSL_MIN_MAX_LABELS together).
    @style{wxSL_LEFT}
           Displays ticks on the left and forces the slider to be vertical.
    @style{wxSL_RIGHT}
           Displays ticks on the right and forces the slider to be vertical.
    @style{wxSL_TOP}
           Displays ticks on the top.
    @style{wxSL_BOTTOM}
           Displays ticks on the bottom (this is the default).
    @style{wxSL_SELRANGE}
           Allows the user to select a range on the slider. Windows only.
    @style{wxSL_INVERSE}
           Inverses the mininum and maximum endpoints on the slider. Not
           compatible with wxSL_SELRANGE.
    @endStyleTable

    Notice that @c wxSL_LEFT, @c wxSL_TOP, @c wxSL_RIGHT and @c wxSL_BOTTOM
    specify the position of the slider ticks in MSW implementation and that the
    slider labels, if any, are positioned on the opposite side. So, to have a
    label on the left side of a vertical slider, @b wxSL_RIGHT must be used (or
    none of these styles at all should be specified as left and top are default
    positions for the vertical and horizontal sliders respectively).

    @beginEventEmissionTable{wxScrollEvent}
    You can use EVT_COMMAND_SCROLL... macros with window IDs for when intercepting
    scroll events from controls, or EVT_SCROLL... macros without window IDs for
    intercepting scroll events from the receiving window -- except for this,
    the macros behave exactly the same.
    @event{EVT_SCROLL(func)}
        Process all scroll events.
    @event{EVT_SCROLL_TOP(func)}
        Process wxEVT_SCROLL_TOP scroll-to-top events (minimum position).
    @event{EVT_SCROLL_BOTTOM(func)}
        Process wxEVT_SCROLL_BOTTOM scroll-to-bottom events (maximum position).
    @event{EVT_SCROLL_LINEUP(func)}
        Process wxEVT_SCROLL_LINEUP line up events.
    @event{EVT_SCROLL_LINEDOWN(func)}
        Process wxEVT_SCROLL_LINEDOWN line down events.
    @event{EVT_SCROLL_PAGEUP(func)}
        Process wxEVT_SCROLL_PAGEUP page up events.
    @event{EVT_SCROLL_PAGEDOWN(func)}
        Process wxEVT_SCROLL_PAGEDOWN page down events.
    @event{EVT_SCROLL_THUMBTRACK(func)}
        Process wxEVT_SCROLL_THUMBTRACK thumbtrack events
        (frequent events sent as the user drags the thumbtrack).
    @event{EVT_SCROLL_THUMBRELEASE(func)}
        Process wxEVT_SCROLL_THUMBRELEASE thumb release events.
    @event{EVT_SCROLL_CHANGED(func)}
        Process wxEVT_SCROLL_CHANGED end of scrolling events (MSW only).
    @event{EVT_COMMAND_SCROLL(id, func)}
        Process all scroll events.
    @event{EVT_COMMAND_SCROLL_TOP(id, func)}
        Process wxEVT_SCROLL_TOP scroll-to-top events (minimum position).
    @event{EVT_COMMAND_SCROLL_BOTTOM(id, func)}
        Process wxEVT_SCROLL_BOTTOM scroll-to-bottom events (maximum position).
    @event{EVT_COMMAND_SCROLL_LINEUP(id, func)}
        Process wxEVT_SCROLL_LINEUP line up events.
    @event{EVT_COMMAND_SCROLL_LINEDOWN(id, func)}
        Process wxEVT_SCROLL_LINEDOWN line down events.
    @event{EVT_COMMAND_SCROLL_PAGEUP(id, func)}
        Process wxEVT_SCROLL_PAGEUP page up events.
    @event{EVT_COMMAND_SCROLL_PAGEDOWN(id, func)}
        Process wxEVT_SCROLL_PAGEDOWN page down events.
    @event{EVT_COMMAND_SCROLL_THUMBTRACK(id, func)}
        Process wxEVT_SCROLL_THUMBTRACK thumbtrack events
        (frequent events sent as the user drags the thumbtrack).
    @event{EVT_COMMAND_SCROLL_THUMBRELEASE(func)}
        Process wxEVT_SCROLL_THUMBRELEASE thumb release events.
    @event{EVT_COMMAND_SCROLL_CHANGED(func)}
        Process wxEVT_SCROLL_CHANGED end of scrolling events (MSW only).
    @endEventTable

    @section slider_diff The difference between EVT_SCROLL_THUMBRELEASE and EVT_SCROLL_CHANGED

    The EVT_SCROLL_THUMBRELEASE event is only emitted when actually dragging the
    thumb using the mouse and releasing it (This EVT_SCROLL_THUMBRELEASE event
    is also followed by an EVT_SCROLL_CHANGED event).

    The EVT_SCROLL_CHANGED event also occurs when using the keyboard to change
    the thumb position, and when clicking next to the thumb
    (In all these cases the EVT_SCROLL_THUMBRELEASE event does not happen).
    In short, the EVT_SCROLL_CHANGED event is triggered when scrolling/ moving
    has finished independently of the way it had started.
    Please see the widgets sample ("Slider" page) to see the difference between
    EVT_SCROLL_THUMBRELEASE and EVT_SCROLL_CHANGED in action.

    @library{wxcore}
    @category{ctrl}
    @appearance{slider.png}

    @see @ref overview_events, wxScrollBar
*/
class wxSlider : public wxControl
{
public:
    /**
       Default constructor
    */
    wxSlider();

    /**
        Constructor, creating and showing a slider.

        @param parent
            Parent window. Must not be @NULL.
        @param id
            Window identifier. The value wxID_ANY indicates a default value.
        @param value
            Initial position for the slider.
        @param minValue
            Minimum slider position.
        @param maxValue
            Maximum slider position.
        @param pos
            Window position. 
            If ::wxDefaultPosition is specified then a default position is chosen.
        @param size
            Window size. 
            If ::wxDefaultSize is specified then a default size is chosen.
        @param style
            Window style. See wxSlider.
        @param validator
            Window validator.
        @param name
            Window name.

        @see Create(), wxValidator
    */
    wxSlider(wxWindow* parent, wxWindowID id, int value,
             int minValue, int maxValue,
             const wxPoint& pos = wxDefaultPosition,
             const wxSize& size = wxDefaultSize,
             long style = wxSL_HORIZONTAL,
             const wxValidator& validator = wxDefaultValidator,
             const wxString& name = wxSliderNameStr);

    /**
        Destructor, destroying the slider.
    */
    virtual ~wxSlider();

    /**
        Clears the selection, for a slider with the @b wxSL_SELRANGE style.

        @onlyfor{wxmsw}
    */
    virtual void ClearSel();

    /**
        Clears the ticks.

        @onlyfor{wxmsw}
    */
    virtual void ClearTicks();

    /**
        Used for two-step slider construction.
        See wxSlider() for further details.
    */
    bool Create(wxWindow* parent, wxWindowID id, int value, int minValue,
                int maxValue, const wxPoint& point = wxDefaultPosition,
                const wxSize& size = wxDefaultSize, long style = wxSL_HORIZONTAL,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxSliderNameStr);

    /**
        Returns the line size.

        @see SetLineSize()
    */
    virtual int GetLineSize() const;

    /**
        Gets the maximum slider value.

        @see GetMin(), SetRange()
    */
    virtual int GetMax() const;

    /**
        Gets the minimum slider value.

        @see GetMin(), SetRange()
    */
    virtual int GetMin() const;

    /**
        Returns the page size.

        @see SetPageSize()
    */
    virtual int GetPageSize() const;

    /**
        Returns the selection end point.

        @onlyfor{wxmsw}

        @see GetSelStart(), SetSelection()
    */
    virtual int GetSelEnd() const;

    /**
        Returns the selection start point.

        @onlyfor{wxmsw}

        @see GetSelEnd(), SetSelection()
    */
    virtual int GetSelStart() const;

    /**
        Returns the thumb length.

        @onlyfor{wxmsw}

        @see SetThumbLength()
    */
    virtual int GetThumbLength() const;

    /**
        Returns the tick frequency.

        @onlyfor{wxmsw}

        @see SetTickFreq()
    */
    virtual int GetTickFreq() const;

    /**
        Gets the current slider value.

        @see GetMin(), GetMax(), SetValue()
    */
    virtual int GetValue() const;

    /**
        Sets the line size for the slider.

        @param lineSize
            The number of steps the slider moves when the user moves it up
            or down a line.

        @see GetLineSize()
    */
    virtual void SetLineSize(int lineSize);

    /**
        Sets the page size for the slider.

        @param pageSize
            The number of steps the slider moves when the user pages up or down.

        @see GetPageSize()
    */
    virtual void SetPageSize(int pageSize);

    /**
        Sets the minimum and maximum slider values.

        @see GetMin(), GetMax()
    */
    virtual void SetRange(int minValue, int maxValue);

    /**
        Sets the selection.

        @param startPos
            The selection start position.
        @param endPos
            The selection end position.

        @onlyfor{wxmsw}

        @see GetSelStart(), GetSelEnd()
    */
    virtual void SetSelection(int startPos, int endPos);

    /**
        Sets the slider thumb length.

        @param len
            The thumb length.

        @onlyfor{wxmsw}

        @see GetThumbLength()
    */
    virtual void SetThumbLength(int len);

    /**
        Sets a tick position.

        @param tickPos
            The tick position.

        @onlyfor{wxmsw}

        @see SetTickFreq()
    */
    virtual void SetTick(int tickPos);

    /**
        Sets the tick mark frequency and position.

        @param n
            Frequency. For example, if the frequency is set to two, a tick mark is
            displayed for every other increment in the slider's range.
        @param pos
            Position. Must be greater than zero. @todo: what is this for?

        @onlyfor{wxmsw}

        @see GetTickFreq()
    */
    virtual void SetTickFreq(int n, int pos);

    /**
        Sets the slider position.

        @param value
            The slider position.
    */
    virtual void SetValue(int value);
};

