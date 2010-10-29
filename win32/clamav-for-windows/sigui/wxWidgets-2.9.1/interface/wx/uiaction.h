/////////////////////////////////////////////////////////////////////////////
// Name:        uiaction.h
// Purpose:     interface of wxUIActionSimulator
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxUIActionSimulator

    wxUIActionSimulator is a class used to simulate user interface actions
    such as a mouse click or a key press.

    @note that this class is currently experimental and disabled by default,
    you must set @c wxUSE_UIACTIONSIMULATOR to 1 in your setup.h file or use
    configure @c --enable-uiactionsim option to enable it.

    Common usages for this class would be to provide playback and record (aka macro recording)
    functionality for users, or to drive unit tests by simulating user sessions.

    See the uiaction sample for example usage of this class.

    NOTE: For keyboard operations, currently you must pass the keycode of the actual
    key on the keyboard. To simulate, e.g. IME actions, you'd need to simulate the actual
    keypresses needed to active the IME, then the keypresses needed to type and select
    the desired character.

    @library{wxcore}
*/

class wxUIActionSimulator
{
  public:
    /**
        Constructor.
    */
    wxUIActionSimulator();
    ~wxUIActionSimulator();

    /**
        Move the mouse to the specified coordinates.

        @param x
            x coordinate to move to, in screen coordinates.

        @param y
            y coordinate to move to, in screen coordinates.
    */
    bool        MouseMove(long x, long y);

    /**
        Press a mouse button.

        @param button
            Button to press. Valid constants are wxMOUSE_BTN_LEFT, wxMOUSE_BTN_MIDDLE, and wxMOUSE_BTN_RIGHT.
    */
    bool        MouseDown(int button = wxMOUSE_BTN_LEFT);

    /**
        Release a mouse button.

        @param button
            Button to press. See wxUIActionSimulator::MouseDown for a list of valid constants.
    */
    bool        MouseUp(int button = wxMOUSE_BTN_LEFT);
    /**
        Click a mouse button.

        @param button
            Button to press. See wxUIActionSimulator::MouseDown for a list of valid constants.
    */
    bool        MouseClick(int button = wxMOUSE_BTN_LEFT);
    /**
        Double-click a mouse button.

        @param button
            Button to press. See wxUIActionSimulator::MouseDown for a list of valid constants.
    */
    bool        MouseDblClick(int button = wxMOUSE_BTN_LEFT);

    /**
        Perform a drag and drop operation.

        @param x1
            x start coordinate, in screen coordinates.

        @param y1
            y start coordinate, in screen coordinates.

        @param x2
            x desintation coordinate, in screen coordinates.

        @param y2
            y destination coordinate, in screen coordinates.

        @param button
            Button to press. See wxUIActionSimulator::MouseDown for a list of valid constants.
    */
    bool        MouseDragDrop(long x1, long y1, long x2, long y2, int button = wxMOUSE_BTN_LEFT);

    /**
        Press a key.

        @param keycode
            key to operate on, as an integer.

        @param shiftDown
            true if the shift key should be pressed, false otherwise.

        @param cmdDown
            true if the cmd key should be pressed, false otherwise.

        @param altDown
            true if the alt key should be pressed, false otherwise.
    */
    bool        KeyDown(int keycode, bool shiftDown=false, bool cmdDown=false, bool altDown=false);

    /**
        Release a key.

        @param keycode
            key to operate on, as an integer.

        @param shiftDown
            true if the shift key should be pressed, false otherwise.

        @param cmdDown
            true if the cmd key should be pressed, false otherwise.

        @param altDown
            true if the alt key should be pressed, false otherwise.
    */
    bool        KeyUp(int keycode, bool shiftDown=false, bool cmdDown=false, bool altDown=false);

    /**
        Press and release a key.

        @param keycode
            key to operate on, as an integer.

        @param shiftDown
            true if the shift key should be pressed, false otherwise.

        @param cmdDown
            true if the cmd key should be pressed, false otherwise.

        @param altDown
            true if the alt key should be pressed, false otherwise.
    */
    bool        Char(int keycode, bool shiftDown=false, bool cmdDown=false, bool altDown=false);
};

