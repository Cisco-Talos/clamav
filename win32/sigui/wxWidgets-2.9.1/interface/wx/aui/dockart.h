/////////////////////////////////////////////////////////////////////////////
// Name:        aui/dockart.h
// Purpose:     interface of wxAuiDockArt
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**
    @todo TOWRITE
*/
enum wxAuiPaneDockArtSetting
{
    wxAUI_DOCKART_SASH_SIZE = 0,
    wxAUI_DOCKART_CAPTION_SIZE = 1,
    wxAUI_DOCKART_GRIPPER_SIZE = 2,
    wxAUI_DOCKART_PANE_BORDER_SIZE = 3,
    wxAUI_DOCKART_PANE_BUTTON_SIZE = 4,
    wxAUI_DOCKART_BACKGROUND_COLOUR = 5,
    wxAUI_DOCKART_SASH_COLOUR = 6,
    wxAUI_DOCKART_ACTIVE_CAPTION_COLOUR = 7,
    wxAUI_DOCKART_ACTIVE_CAPTION_GRADIENT_COLOUR = 8,
    wxAUI_DOCKART_INACTIVE_CAPTION_COLOUR = 9,
    wxAUI_DOCKART_INACTIVE_CAPTION_GRADIENT_COLOUR = 10,
    wxAUI_DOCKART_ACTIVE_CAPTION_TEXT_COLOUR = 11,
    wxAUI_DOCKART_INACTIVE_CAPTION_TEXT_COLOUR = 12,
    wxAUI_DOCKART_BORDER_COLOUR = 13,
    wxAUI_DOCKART_GRIPPER_COLOUR = 14,
    wxAUI_DOCKART_CAPTION_FONT = 15,
    wxAUI_DOCKART_GRADIENT_TYPE = 16
};

/**
    @todo TOWRITE
*/
enum wxAuiPaneDockArtGradients
{
    wxAUI_GRADIENT_NONE = 0,
    wxAUI_GRADIENT_VERTICAL = 1,
    wxAUI_GRADIENT_HORIZONTAL = 2
};

/**
    @todo TOWRITE
*/
enum wxAuiPaneButtonState
{
    wxAUI_BUTTON_STATE_NORMAL = 0,
    wxAUI_BUTTON_STATE_HOVER = 1,
    wxAUI_BUTTON_STATE_PRESSED = 2
};

/**
    @todo TOWRITE
*/
enum wxAuiButtonId
{
    wxAUI_BUTTON_CLOSE = 101,
    wxAUI_BUTTON_MAXIMIZE_RESTORE = 102,
    wxAUI_BUTTON_MINIMIZE = 103,
    wxAUI_BUTTON_PIN = 104,
    wxAUI_BUTTON_OPTIONS = 105,
    wxAUI_BUTTON_WINDOWLIST = 106,
    wxAUI_BUTTON_LEFT = 107,
    wxAUI_BUTTON_RIGHT = 108,
    wxAUI_BUTTON_UP = 109,
    wxAUI_BUTTON_DOWN = 110,
    wxAUI_BUTTON_CUSTOM1 = 201,
    wxAUI_BUTTON_CUSTOM2 = 202,
    wxAUI_BUTTON_CUSTOM3 = 203
};

/**
    @class wxAuiDockArt

    wxAuiDockArt is part of the wxAUI class framework.
    See also @ref overview_aui.

    wxAuiDockArt is the art provider: provides all drawing functionality to the
    wxAui dock manager. This allows the dock manager to have a plugable look-and-feel.

    By default, a wxAuiManager uses an instance of this class called
    wxAuiDefaultDockArt which provides bitmap art and a colour scheme that is
    adapted to the major platforms' look. You can either derive from that class
    to alter its behaviour or write a completely new dock art class.
    Call wxAuiManager::SetArtProvider to force wxAUI to use your new dock art provider.

    @library{wxaui}
    @category{aui}

    @see wxAuiManager, wxAuiPaneInfo
*/
class wxAuiDockArt
{
public:
    /**
        Constructor.
    */
    wxAuiDockArt();

    /**
        Destructor.
    */
    virtual ~wxAuiDockArt();

    /**
        Draws a background.
    */
    virtual void DrawBackground(wxDC& dc, wxWindow* window, int orientation,
                                const wxRect& rect) = 0;

    /**
        Draws a border.
    */
    virtual void DrawBorder(wxDC& dc, wxWindow* window, const wxRect& rect,
                            wxAuiPaneInfo& pane) = 0;

    /**
        Draws a caption.
    */
    virtual void DrawCaption(wxDC& dc, wxWindow* window, const wxString& text,
                             const wxRect& rect, wxAuiPaneInfo& pane) = 0;

    /**
        Draws a gripper.
    */
    virtual void DrawGripper(wxDC& dc, wxWindow* window, const wxRect& rect,
                             wxAuiPaneInfo& pane) = 0;

    /**
        Draws a button in the pane's title bar.
        @a button can be one of the values of @b wxAuiButtonId.
        @a button_state can be one of the values of @b wxAuiPaneButtonState.
    */
    virtual void DrawPaneButton(wxDC& dc, wxWindow* window, int button,
                                int button_state, const wxRect& rect,
                                wxAuiPaneInfo& pane) = 0;

    /**
        Draws a sash between two windows.
    */
    virtual void DrawSash(wxDC& dc, wxWindow* window, int orientation,
                          const wxRect& rect) = 0;
    /**
        Get the colour of a certain setting.
        @a id can be one of the colour values of @b wxAuiPaneDockArtSetting.
    */
    virtual wxColour GetColour(int id) = 0;

    /**
        Get a font setting.
    */
    virtual wxFont GetFont(int id) = 0;

    /**
        Get the value of a certain setting.
        @a id can be one of the size values of @b wxAuiPaneDockArtSetting.
    */
    virtual int GetMetric(int id) = 0;

    /**
        Set a certain setting with the value @e colour.
        @a id can be one of the colour values of @b wxAuiPaneDockArtSetting.
    */
    virtual void SetColour(int id, const wxColour& colour) = 0;

    /**
        Set a font setting.
    */
    virtual void SetFont(int id, const wxFont& font) = 0;

    /**
        Set a certain setting with the value @e new_val.
        @a id can be one of the size values of @b wxAuiPaneDockArtSetting.
    */
    virtual void SetMetric(int id, int new_val) = 0;
};

