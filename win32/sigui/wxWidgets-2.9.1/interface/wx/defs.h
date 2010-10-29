/////////////////////////////////////////////////////////////////////////////
// Name:        wx/defs.h
// Purpose:     interface of global functions
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


// ----------------------------------------------------------------------------
// enumerations
// ----------------------------------------------------------------------------

/**
    Generic flags.
*/
enum wxGeometryCentre
{
    wxCENTRE                  = 0x0001,
    wxCENTER                  = wxCENTRE
};

/**
    A generic orientation value.
*/
enum wxOrientation
{
    wxHORIZONTAL              = 0x0004,
    wxVERTICAL                = 0x0008,

    /**
        A mask value to indicate both vertical and horizontal orientations.
    */
    wxBOTH                    = wxVERTICAL | wxHORIZONTAL,

    /// A synonim for @c wxBOTH.
    wxORIENTATION_MASK        = wxBOTH
};

/**
    A generic direction value.
*/
enum wxDirection
{
    wxLEFT                    = 0x0010,
    wxRIGHT                   = 0x0020,
    wxUP                      = 0x0040,
    wxDOWN                    = 0x0080,

    wxTOP                     = wxUP,
    wxBOTTOM                  = wxDOWN,

    wxNORTH                   = wxUP,
    wxSOUTH                   = wxDOWN,
    wxWEST                    = wxLEFT,
    wxEAST                    = wxRIGHT,

    wxALL                     = (wxUP | wxDOWN | wxRIGHT | wxLEFT),

    /** A mask to extract direction from the combination of flags. */
    wxDIRECTION_MASK           = wxALL
};

/**
    Generic alignment values. Can be combined together.
*/
enum wxAlignment
{
    /**
        A value different from any valid alignment value.

        Note that you shouldn't use 0 for this as it's the value of (valid)
        alignments wxALIGN_LEFT and wxALIGN_TOP.

        @since 2.9.1
     */
    wxALIGN_INVALID           = -1,

    wxALIGN_NOT               = 0x0000,
    wxALIGN_CENTER_HORIZONTAL = 0x0100,
    wxALIGN_CENTRE_HORIZONTAL = wxALIGN_CENTER_HORIZONTAL,
    wxALIGN_LEFT              = wxALIGN_NOT,
    wxALIGN_TOP               = wxALIGN_NOT,
    wxALIGN_RIGHT             = 0x0200,
    wxALIGN_BOTTOM            = 0x0400,
    wxALIGN_CENTER_VERTICAL   = 0x0800,
    wxALIGN_CENTRE_VERTICAL   = wxALIGN_CENTER_VERTICAL,

    wxALIGN_CENTER            = (wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL),
    wxALIGN_CENTRE            = wxALIGN_CENTER,

    /** A mask to extract alignment from the combination of flags. */
    wxALIGN_MASK              = 0x0f00
};

/**
    Miscellaneous flags for wxSizer items.
*/
enum wxSizerFlagBits
{
    wxFIXED_MINSIZE                = 0x8000,
    wxRESERVE_SPACE_EVEN_IF_HIDDEN = 0x0002,

    /*  a mask to extract wxSizerFlagBits from combination of flags */
    wxSIZER_FLAG_BITS_MASK         = 0x8002
};

/**
    Generic stretch values.
*/
enum wxStretch
{
    wxSTRETCH_NOT             = 0x0000,
    wxSHRINK                  = 0x1000,
    wxGROW                    = 0x2000,
    wxEXPAND                  = wxGROW,
    wxSHAPED                  = 0x4000,
    wxTILE                    = wxSHAPED | wxFIXED_MINSIZE,

    /*  a mask to extract stretch from the combination of flags */
    wxSTRETCH_MASK            = 0x7000 /* sans wxTILE */
};

/**
    Border flags for wxWindow.
*/
enum wxBorder
{
    /**
        This is different from wxBORDER_NONE as by default the controls do have
        a border.
    */
    wxBORDER_DEFAULT = 0,

    wxBORDER_NONE   = 0x00200000,
    wxBORDER_STATIC = 0x01000000,
    wxBORDER_SIMPLE = 0x02000000,
    wxBORDER_RAISED = 0x04000000,
    wxBORDER_SUNKEN = 0x08000000,
    wxBORDER_DOUBLE = 0x10000000, /* deprecated */
    wxBORDER_THEME  = wxBORDER_DOUBLE,

    /*  a mask to extract border style from the combination of flags */
    wxBORDER_MASK   = 0x1f200000
};


/**
    Background styles.

    @see wxWindow::SetBackgroundStyle()
*/
enum wxBackgroundStyle
{
    /**
        Default background style value indicating that the background may be
        erased in the user-defined EVT_ERASE_BACKGROUND handler.

        If no such handler is defined (or if it skips the event), the effect of
        this style is the same as wxBG_STYLE_SYSTEM. If an empty handler (@em
        not skipping the event) is defined, the effect is the same as
        wxBG_STYLE_PAINT, i.e. the background is not erased at all until
        EVT_PAINT handler is executed.

        This is the only background style value for which erase background
        events are generated at all.
     */
    wxBG_STYLE_ERASE,

    /**
        Use the default background, as determined by the system or the current
        theme.

        If the window has been assigned a non-default background colour, it
        will be used for erasing its background. Otherwise the default
        background (which might be a gradient or a pattern) will be used.

        EVT_ERASE_BACKGROUND event will not be generated at all for windows
        with this style.
     */
    wxBG_STYLE_SYSTEM,

    /**
        Indicates that the background is only erased in the user-defined
        EVT_PAINT handler.

        Using this style avoids flicker which would result from redrawing the
        background twice if the EVT_PAINT handler entirely overwrites it. It
        must not be used however if the paint handler leaves any parts of the
        window unpainted as their contents is then undetermined. Only use it if
        you repaint the whole window in your handler.

        EVT_ERASE_BACKGROUND event will not be generated at all for windows
        with this style.
     */
    wxBG_STYLE_PAINT
};


/**
    Standard menu IDs.
*/
enum wxStandardID
{
    /**
       This id delimits the lower bound of the range used by automatically-generated ids
       (i.e. those used when wxID_ANY is specified during construction).
     */
    wxID_AUTO_LOWEST,

    /**
       This id delimits the upper bound of the range used by automatically-generated ids
       (i.e. those used when wxID_ANY is specified during construction).
     */
    wxID_AUTO_HIGHEST,

    /**
        No id matches this one when compared to it.
    */
    wxID_NONE = -3,

    /**
        Id for a separator line in the menu (invalid for normal item).
    */
    wxID_SEPARATOR = -2,

    /**
        Any id: means that we don't care about the id, whether when installing
        an event handler or when creating a new window.
    */
    wxID_ANY = -1,

    wxID_LOWEST = 4999,

    wxID_OPEN,
    wxID_CLOSE,
    wxID_NEW,
    wxID_SAVE,
    wxID_SAVEAS,
    wxID_REVERT,
    wxID_EXIT,
    wxID_UNDO,
    wxID_REDO,
    wxID_HELP,
    wxID_PRINT,
    wxID_PRINT_SETUP,
    wxID_PAGE_SETUP,
    wxID_PREVIEW,
    wxID_ABOUT,
    wxID_HELP_CONTENTS,
    wxID_HELP_INDEX,
    wxID_HELP_SEARCH,
    wxID_HELP_COMMANDS,
    wxID_HELP_PROCEDURES,
    wxID_HELP_CONTEXT,
    wxID_CLOSE_ALL,
    wxID_PREFERENCES,

    wxID_EDIT = 5030,
    wxID_CUT,
    wxID_COPY,
    wxID_PASTE,
    wxID_CLEAR,
    wxID_FIND,
    wxID_DUPLICATE,
    wxID_SELECTALL,
    wxID_DELETE,
    wxID_REPLACE,
    wxID_REPLACE_ALL,
    wxID_PROPERTIES,

    wxID_VIEW_DETAILS,
    wxID_VIEW_LARGEICONS,
    wxID_VIEW_SMALLICONS,
    wxID_VIEW_LIST,
    wxID_VIEW_SORTDATE,
    wxID_VIEW_SORTNAME,
    wxID_VIEW_SORTSIZE,
    wxID_VIEW_SORTTYPE,

    wxID_FILE = 5050,
    wxID_FILE1,
    wxID_FILE2,
    wxID_FILE3,
    wxID_FILE4,
    wxID_FILE5,
    wxID_FILE6,
    wxID_FILE7,
    wxID_FILE8,
    wxID_FILE9,

    /** Standard button and menu IDs */
    wxID_OK = 5100,
    wxID_CANCEL,
    wxID_APPLY,
    wxID_YES,
    wxID_NO,
    wxID_STATIC,
    wxID_FORWARD,
    wxID_BACKWARD,
    wxID_DEFAULT,
    wxID_MORE,
    wxID_SETUP,
    wxID_RESET,
    wxID_CONTEXT_HELP,
    wxID_YESTOALL,
    wxID_NOTOALL,
    wxID_ABORT,
    wxID_RETRY,
    wxID_IGNORE,
    wxID_ADD,
    wxID_REMOVE,

    wxID_UP,
    wxID_DOWN,
    wxID_HOME,
    wxID_REFRESH,
    wxID_STOP,
    wxID_INDEX,

    wxID_BOLD,
    wxID_ITALIC,
    wxID_JUSTIFY_CENTER,
    wxID_JUSTIFY_FILL,
    wxID_JUSTIFY_RIGHT,
    wxID_JUSTIFY_LEFT,
    wxID_UNDERLINE,
    wxID_INDENT,
    wxID_UNINDENT,
    wxID_ZOOM_100,
    wxID_ZOOM_FIT,
    wxID_ZOOM_IN,
    wxID_ZOOM_OUT,
    wxID_UNDELETE,
    wxID_REVERT_TO_SAVED,
    wxID_CDROM,
    wxID_CONVERT,
    wxID_EXECUTE,
    wxID_FLOPPY,
    wxID_HARDDISK,
    wxID_BOTTOM,
    wxID_FIRST,
    wxID_LAST,
    wxID_TOP,
    wxID_INFO,
    wxID_JUMP_TO,
    wxID_NETWORK,
    wxID_SELECT_COLOR,
    wxID_SELECT_FONT,
    wxID_SORT_ASCENDING,
    wxID_SORT_DESCENDING,
    wxID_SPELL_CHECK,
    wxID_STRIKETHROUGH,

    /** System menu IDs (used by wxUniv): */
    wxID_SYSTEM_MENU = 5200,
    wxID_CLOSE_FRAME,
    wxID_MOVE_FRAME,
    wxID_RESIZE_FRAME,
    wxID_MAXIMIZE_FRAME,
    wxID_ICONIZE_FRAME,
    wxID_RESTORE_FRAME,

    /** MDI window menu ids */
    wxID_MDI_WINDOW_FIRST = 5230,
    wxID_MDI_WINDOW_CASCADE = wxID_MDI_WINDOW_FIRST,
    wxID_MDI_WINDOW_TILE_HORZ,
    wxID_MDI_WINDOW_TILE_VERT,
    wxID_MDI_WINDOW_ARRANGE_ICONS,
    wxID_MDI_WINDOW_PREV,
    wxID_MDI_WINDOW_NEXT,
    wxID_MDI_WINDOW_LAST = wxID_MDI_WINDOW_NEXT,

    /** IDs used by generic file dialog (13 consecutive starting from this value) */
    wxID_FILEDLGG = 5900,

    /** IDs used by generic file ctrl (4 consecutive starting from this value) */
    wxID_FILECTRL = 5950,

    wxID_HIGHEST = 5999
};

/**
    Item kinds for use with wxMenu, wxMenuItem, and wxToolBar.

    @see wxMenu::Append(), wxMenuItem::wxMenuItem(), wxToolBar::AddTool()
*/
enum wxItemKind
{
    wxITEM_SEPARATOR = -1,

    /**
        Normal tool button / menu item.

        @see wxToolBar::AddTool(), wxMenu::AppendItem().
    */
    wxITEM_NORMAL,

    /**
        Check (or toggle) tool button / menu item.

        @see wxToolBar::AddCheckTool(), wxMenu::AppendCheckItem().
    */
    wxITEM_CHECK,

    /**
        Radio tool button / menu item.

        @see wxToolBar::AddRadioTool(), wxMenu::AppendRadioItem().
    */
    wxITEM_RADIO,

    /**
        Normal tool button with a dropdown arrow next to it. Clicking the
        dropdown arrow sends a @c wxEVT_COMMAND_TOOL_DROPDOWN_CLICKED event and may
        also display the menu previously associated with the item with
        wxToolBar::SetDropdownMenu(). Currently this type of tools is supported
        under MSW and GTK.
    */
    wxITEM_DROPDOWN,

    wxITEM_MAX
};

/**
    Generic hit test results.
*/
enum wxHitTest
{
    wxHT_NOWHERE,

    /*  scrollbar */
    wxHT_SCROLLBAR_FIRST = wxHT_NOWHERE,
    wxHT_SCROLLBAR_ARROW_LINE_1,    /**< left or upper arrow to scroll by line */
    wxHT_SCROLLBAR_ARROW_LINE_2,    /**< right or down */
    wxHT_SCROLLBAR_ARROW_PAGE_1,    /**< left or upper arrow to scroll by page */
    wxHT_SCROLLBAR_ARROW_PAGE_2,    /**< right or down */
    wxHT_SCROLLBAR_THUMB,           /**< on the thumb */
    wxHT_SCROLLBAR_BAR_1,           /**< bar to the left/above the thumb */
    wxHT_SCROLLBAR_BAR_2,           /**< bar to the right/below the thumb */
    wxHT_SCROLLBAR_LAST,

    /*  window */
    wxHT_WINDOW_OUTSIDE,            /**< not in this window at all */
    wxHT_WINDOW_INSIDE,             /**< in the client area */
    wxHT_WINDOW_VERT_SCROLLBAR,     /**< on the vertical scrollbar */
    wxHT_WINDOW_HORZ_SCROLLBAR,     /**< on the horizontal scrollbar */
    wxHT_WINDOW_CORNER,             /**< on the corner between 2 scrollbars */

    wxHT_MAX
};

/**
    Data format IDs used by wxDataFormat.
*/
enum wxDataFormatId
{
    wxDF_INVALID =          0,
    wxDF_TEXT =             1,  /* CF_TEXT */
    wxDF_BITMAP =           2,  /* CF_BITMAP */
    wxDF_METAFILE =         3,  /* CF_METAFILEPICT */
    wxDF_SYLK =             4,
    wxDF_DIF =              5,
    wxDF_TIFF =             6,
    wxDF_OEMTEXT =          7,  /* CF_OEMTEXT */
    wxDF_DIB =              8,  /* CF_DIB */
    wxDF_PALETTE =          9,
    wxDF_PENDATA =          10,
    wxDF_RIFF =             11,
    wxDF_WAVE =             12,
    wxDF_UNICODETEXT =      13,
    wxDF_ENHMETAFILE =      14,
    wxDF_FILENAME =         15, /* CF_HDROP */
    wxDF_LOCALE =           16,
    wxDF_PRIVATE =          20,
    wxDF_HTML =             30, /* Note: does not correspond to CF_ constant */
    wxDF_MAX
};

/**
    Virtual keycodes used by wxKeyEvent and some other wxWidgets functions.

    Note that the range @c 33 - @c 126 is reserved for the standard ASCII
    characters and that the range @c 128 - @c 255 is reserved for the
    extended ASCII characters (which are not really standard and thus should
    be avoid in portable apps!).
*/
enum wxKeyCode
{
    WXK_BACK    =    8,     //!< Backspace.
    WXK_TAB     =    9,
    WXK_RETURN  =    13,
    WXK_ESCAPE  =    27,
    WXK_SPACE   =    32,

    WXK_DELETE  =    127,

    /**
        These are, by design, not compatible with unicode characters.
        If you want to get a unicode character from a key event, use
        wxKeyEvent::GetUnicodeKey instead.
    */
    WXK_START   = 300,
    WXK_LBUTTON,
    WXK_RBUTTON,
    WXK_CANCEL,
    WXK_MBUTTON,
    WXK_CLEAR,
    WXK_SHIFT,
    WXK_ALT,
    WXK_CONTROL,
    WXK_MENU,
    WXK_PAUSE,
    WXK_CAPITAL,
    WXK_END,
    WXK_HOME,
    WXK_LEFT,
    WXK_UP,
    WXK_RIGHT,
    WXK_DOWN,
    WXK_SELECT,
    WXK_PRINT,
    WXK_EXECUTE,
    WXK_SNAPSHOT,
    WXK_INSERT,
    WXK_HELP,
    WXK_NUMPAD0,
    WXK_NUMPAD1,
    WXK_NUMPAD2,
    WXK_NUMPAD3,
    WXK_NUMPAD4,
    WXK_NUMPAD5,
    WXK_NUMPAD6,
    WXK_NUMPAD7,
    WXK_NUMPAD8,
    WXK_NUMPAD9,
    WXK_MULTIPLY,
    WXK_ADD,
    WXK_SEPARATOR,
    WXK_SUBTRACT,
    WXK_DECIMAL,
    WXK_DIVIDE,
    WXK_F1,
    WXK_F2,
    WXK_F3,
    WXK_F4,
    WXK_F5,
    WXK_F6,
    WXK_F7,
    WXK_F8,
    WXK_F9,
    WXK_F10,
    WXK_F11,
    WXK_F12,
    WXK_F13,
    WXK_F14,
    WXK_F15,
    WXK_F16,
    WXK_F17,
    WXK_F18,
    WXK_F19,
    WXK_F20,
    WXK_F21,
    WXK_F22,
    WXK_F23,
    WXK_F24,
    WXK_NUMLOCK,
    WXK_SCROLL,
    WXK_PAGEUP,
    WXK_PAGEDOWN,

    WXK_NUMPAD_SPACE,
    WXK_NUMPAD_TAB,
    WXK_NUMPAD_ENTER,
    WXK_NUMPAD_F1,
    WXK_NUMPAD_F2,
    WXK_NUMPAD_F3,
    WXK_NUMPAD_F4,
    WXK_NUMPAD_HOME,
    WXK_NUMPAD_LEFT,
    WXK_NUMPAD_UP,
    WXK_NUMPAD_RIGHT,
    WXK_NUMPAD_DOWN,
    WXK_NUMPAD_PAGEUP,
    WXK_NUMPAD_PAGEDOWN,
    WXK_NUMPAD_END,
    WXK_NUMPAD_BEGIN,
    WXK_NUMPAD_INSERT,
    WXK_NUMPAD_DELETE,
    WXK_NUMPAD_EQUAL,
    WXK_NUMPAD_MULTIPLY,
    WXK_NUMPAD_ADD,
    WXK_NUMPAD_SEPARATOR,
    WXK_NUMPAD_SUBTRACT,
    WXK_NUMPAD_DECIMAL,
    WXK_NUMPAD_DIVIDE,

    /** The following key codes are only generated under Windows currently */
    WXK_WINDOWS_LEFT,
    WXK_WINDOWS_RIGHT,
    WXK_WINDOWS_MENU ,
    WXK_COMMAND,

    /** Hardware-specific buttons */
    WXK_SPECIAL1 = 193,
    WXK_SPECIAL2,
    WXK_SPECIAL3,
    WXK_SPECIAL4,
    WXK_SPECIAL5,
    WXK_SPECIAL6,
    WXK_SPECIAL7,
    WXK_SPECIAL8,
    WXK_SPECIAL9,
    WXK_SPECIAL10,
    WXK_SPECIAL11,
    WXK_SPECIAL12,
    WXK_SPECIAL13,
    WXK_SPECIAL14,
    WXK_SPECIAL15,
    WXK_SPECIAL16,
    WXK_SPECIAL17,
    WXK_SPECIAL18,
    WXK_SPECIAL19,
    WXK_SPECIAL20
};

/**
    This enum contains bit mask constants used in wxKeyEvent.
*/
enum wxKeyModifier
{
    wxMOD_NONE      = 0x0000,
    wxMOD_ALT       = 0x0001,
    wxMOD_CONTROL   = 0x0002,
    wxMOD_ALTGR     = wxMOD_ALT | wxMOD_CONTROL,
    wxMOD_SHIFT     = 0x0004,
    wxMOD_META      = 0x0008,
    wxMOD_WIN       = wxMOD_META,

    /**
        Notice that @c wxMOD_CMD should be used instead of @c wxMOD_CONTROL
        in portable code to account for the fact that although
        @c Control modifier exists under Mac OS, it is not used for the same
        purpose as under Windows or Unix there while the special Mac-specific
        @c Command modifier is used in exactly the same way.
    */
    wxMOD_CMD       = wxMOD_META,
    wxMOD_ALL       = 0xffff
};

/**
    Paper size types for use with the printing framework.

    @see overview_printing, wxPrintData::SetPaperId()
*/
enum wxPaperSize
{
    wxPAPER_NONE,               ///<  Use specific dimensions
    wxPAPER_LETTER,             ///<  Letter, 8 1/2 by 11 inches
    wxPAPER_LEGAL,              ///<  Legal, 8 1/2 by 14 inches
    wxPAPER_A4,                 ///<  A4 Sheet, 210 by 297 millimeters
    wxPAPER_CSHEET,             ///<  C Sheet, 17 by 22 inches
    wxPAPER_DSHEET,             ///<  D Sheet, 22 by 34 inches
    wxPAPER_ESHEET,             ///<  E Sheet, 34 by 44 inches
    wxPAPER_LETTERSMALL,        ///<  Letter Small, 8 1/2 by 11 inches
    wxPAPER_TABLOID,            ///<  Tabloid, 11 by 17 inches
    wxPAPER_LEDGER,             ///<  Ledger, 17 by 11 inches
    wxPAPER_STATEMENT,          ///<  Statement, 5 1/2 by 8 1/2 inches
    wxPAPER_EXECUTIVE,          ///<  Executive, 7 1/4 by 10 1/2 inches
    wxPAPER_A3,                 ///<  A3 sheet, 297 by 420 millimeters
    wxPAPER_A4SMALL,            ///<  A4 small sheet, 210 by 297 millimeters
    wxPAPER_A5,                 ///<  A5 sheet, 148 by 210 millimeters
    wxPAPER_B4,                 ///<  B4 sheet, 250 by 354 millimeters
    wxPAPER_B5,                 ///<  B5 sheet, 182-by-257-millimeter paper
    wxPAPER_FOLIO,              ///<  Folio, 8-1/2-by-13-inch paper
    wxPAPER_QUARTO,             ///<  Quarto, 215-by-275-millimeter paper
    wxPAPER_10X14,              ///<  10-by-14-inch sheet
    wxPAPER_11X17,              ///<  11-by-17-inch sheet
    wxPAPER_NOTE,               ///<  Note, 8 1/2 by 11 inches
    wxPAPER_ENV_9,              ///<  #9 Envelope, 3 7/8 by 8 7/8 inches
    wxPAPER_ENV_10,             ///<  #10 Envelope, 4 1/8 by 9 1/2 inches
    wxPAPER_ENV_11,             ///<  #11 Envelope, 4 1/2 by 10 3/8 inches
    wxPAPER_ENV_12,             ///<  #12 Envelope, 4 3/4 by 11 inches
    wxPAPER_ENV_14,             ///<  #14 Envelope, 5 by 11 1/2 inches
    wxPAPER_ENV_DL,             ///<  DL Envelope, 110 by 220 millimeters
    wxPAPER_ENV_C5,             ///<  C5 Envelope, 162 by 229 millimeters
    wxPAPER_ENV_C3,             ///<  C3 Envelope, 324 by 458 millimeters
    wxPAPER_ENV_C4,             ///<  C4 Envelope, 229 by 324 millimeters
    wxPAPER_ENV_C6,             ///<  C6 Envelope, 114 by 162 millimeters
    wxPAPER_ENV_C65,            ///<  C65 Envelope, 114 by 229 millimeters
    wxPAPER_ENV_B4,             ///<  B4 Envelope, 250 by 353 millimeters
    wxPAPER_ENV_B5,             ///<  B5 Envelope, 176 by 250 millimeters
    wxPAPER_ENV_B6,             ///<  B6 Envelope, 176 by 125 millimeters
    wxPAPER_ENV_ITALY,          ///<  Italy Envelope, 110 by 230 millimeters
    wxPAPER_ENV_MONARCH,        ///<  Monarch Envelope, 3 7/8 by 7 1/2 inches
    wxPAPER_ENV_PERSONAL,       ///<  6 3/4 Envelope, 3 5/8 by 6 1/2 inches
    wxPAPER_FANFOLD_US,         ///<  US Std Fanfold, 14 7/8 by 11 inches
    wxPAPER_FANFOLD_STD_GERMAN, ///<  German Std Fanfold, 8 1/2 by 12 inches
    wxPAPER_FANFOLD_LGL_GERMAN, ///<  German Legal Fanfold, 8 1/2 by 13 inches

    // wxMSW Only

    wxPAPER_ISO_B4,             ///<  B4 (ISO) 250 x 353 mm
    wxPAPER_JAPANESE_POSTCARD,  ///<  Japanese Postcard 100 x 148 mm
    wxPAPER_9X11,               ///<  9 x 11 in
    wxPAPER_10X11,              ///<  10 x 11 in
    wxPAPER_15X11,              ///<  15 x 11 in
    wxPAPER_ENV_INVITE,         ///<  Envelope Invite 220 x 220 mm
    wxPAPER_LETTER_EXTRA,       ///<  Letter Extra 9.5 x 12 in
    wxPAPER_LEGAL_EXTRA,        ///<  Legal Extra 9.5 x 15 in
    wxPAPER_TABLOID_EXTRA,      ///<  Tabloid Extra 11.69 x 18 in
    wxPAPER_A4_EXTRA,           ///<  A4 Extra 9.27 x 12.69 in
    wxPAPER_LETTER_TRANSVERSE,  ///<  Letter Transverse 8.5 x 11 in
    wxPAPER_A4_TRANSVERSE,      ///<  A4 Transverse 210 x 297 mm
    wxPAPER_LETTER_EXTRA_TRANSVERSE, ///<  Letter Extra Transverse 9.5 x 12 in
    wxPAPER_A_PLUS,             ///<  SuperA/SuperA/A4 227 x 356 mm
    wxPAPER_B_PLUS,             ///<  SuperB/SuperB/A3 305 x 487 mm
    wxPAPER_LETTER_PLUS,        ///<  Letter Plus 8.5 x 12.69 in
    wxPAPER_A4_PLUS,            ///<  A4 Plus 210 x 330 mm
    wxPAPER_A5_TRANSVERSE,      ///<  A5 Transverse 148 x 210 mm
    wxPAPER_B5_TRANSVERSE,      ///<  B5 (JIS) Transverse 182 x 257 mm
    wxPAPER_A3_EXTRA,           ///<  A3 Extra 322 x 445 mm
    wxPAPER_A5_EXTRA,           ///<  A5 Extra 174 x 235 mm
    wxPAPER_B5_EXTRA,           ///<  B5 (ISO) Extra 201 x 276 mm
    wxPAPER_A2,                 ///<  A2 420 x 594 mm
    wxPAPER_A3_TRANSVERSE,      ///<  A3 Transverse 297 x 420 mm
    wxPAPER_A3_EXTRA_TRANSVERSE, ///<  A3 Extra Transverse 322 x 445 mm

    wxPAPER_DBL_JAPANESE_POSTCARD, ///< Japanese Double Postcard 200 x 148 mm
    wxPAPER_A6,                 ///< A6 105 x 148 mm
    wxPAPER_JENV_KAKU2,         ///< Japanese Envelope Kaku #2
    wxPAPER_JENV_KAKU3,         ///< Japanese Envelope Kaku #3
    wxPAPER_JENV_CHOU3,         ///< Japanese Envelope Chou #3
    wxPAPER_JENV_CHOU4,         ///< Japanese Envelope Chou #4
    wxPAPER_LETTER_ROTATED,     ///< Letter Rotated 11 x 8 1/2 in
    wxPAPER_A3_ROTATED,         ///< A3 Rotated 420 x 297 mm
    wxPAPER_A4_ROTATED,         ///< A4 Rotated 297 x 210 mm
    wxPAPER_A5_ROTATED,         ///< A5 Rotated 210 x 148 mm
    wxPAPER_B4_JIS_ROTATED,     ///< B4 (JIS) Rotated 364 x 257 mm
    wxPAPER_B5_JIS_ROTATED,     ///< B5 (JIS) Rotated 257 x 182 mm
    wxPAPER_JAPANESE_POSTCARD_ROTATED, ///< Japanese Postcard Rotated 148 x 100 mm
    wxPAPER_DBL_JAPANESE_POSTCARD_ROTATED, ///< Double Japanese Postcard Rotated 148 x 200 mm
    wxPAPER_A6_ROTATED,         ///< A6 Rotated 148 x 105 mm
    wxPAPER_JENV_KAKU2_ROTATED, ///< Japanese Envelope Kaku #2 Rotated
    wxPAPER_JENV_KAKU3_ROTATED, ///< Japanese Envelope Kaku #3 Rotated
    wxPAPER_JENV_CHOU3_ROTATED, ///< Japanese Envelope Chou #3 Rotated
    wxPAPER_JENV_CHOU4_ROTATED, ///< Japanese Envelope Chou #4 Rotated
    wxPAPER_B6_JIS,             ///< B6 (JIS) 128 x 182 mm
    wxPAPER_B6_JIS_ROTATED,     ///< B6 (JIS) Rotated 182 x 128 mm
    wxPAPER_12X11,              ///< 12 x 11 in
    wxPAPER_JENV_YOU4,          ///< Japanese Envelope You #4
    wxPAPER_JENV_YOU4_ROTATED,  ///< Japanese Envelope You #4 Rotated
    wxPAPER_P16K,               ///< PRC 16K 146 x 215 mm
    wxPAPER_P32K,               ///< PRC 32K 97 x 151 mm
    wxPAPER_P32KBIG,            ///< PRC 32K(Big) 97 x 151 mm
    wxPAPER_PENV_1,             ///< PRC Envelope #1 102 x 165 mm
    wxPAPER_PENV_2,             ///< PRC Envelope #2 102 x 176 mm
    wxPAPER_PENV_3,             ///< PRC Envelope #3 125 x 176 mm
    wxPAPER_PENV_4,             ///< PRC Envelope #4 110 x 208 mm
    wxPAPER_PENV_5,             ///< PRC Envelope #5 110 x 220 mm
    wxPAPER_PENV_6,             ///< PRC Envelope #6 120 x 230 mm
    wxPAPER_PENV_7,             ///< PRC Envelope #7 160 x 230 mm
    wxPAPER_PENV_8,             ///< PRC Envelope #8 120 x 309 mm
    wxPAPER_PENV_9,             ///< PRC Envelope #9 229 x 324 mm
    wxPAPER_PENV_10,            ///< PRC Envelope #10 324 x 458 mm
    wxPAPER_P16K_ROTATED,       ///< PRC 16K Rotated
    wxPAPER_P32K_ROTATED,       ///< PRC 32K Rotated
    wxPAPER_P32KBIG_ROTATED,    ///< PRC 32K(Big) Rotated
    wxPAPER_PENV_1_ROTATED,     ///< PRC Envelope #1 Rotated 165 x 102 mm
    wxPAPER_PENV_2_ROTATED,     ///< PRC Envelope #2 Rotated 176 x 102 mm
    wxPAPER_PENV_3_ROTATED,     ///< PRC Envelope #3 Rotated 176 x 125 mm
    wxPAPER_PENV_4_ROTATED,     ///< PRC Envelope #4 Rotated 208 x 110 mm
    wxPAPER_PENV_5_ROTATED,     ///< PRC Envelope #5 Rotated 220 x 110 mm
    wxPAPER_PENV_6_ROTATED,     ///< PRC Envelope #6 Rotated 230 x 120 mm
    wxPAPER_PENV_7_ROTATED,     ///< PRC Envelope #7 Rotated 230 x 160 mm
    wxPAPER_PENV_8_ROTATED,     ///< PRC Envelope #8 Rotated 309 x 120 mm
    wxPAPER_PENV_9_ROTATED,     ///< PRC Envelope #9 Rotated 324 x 229 mm
    wxPAPER_PENV_10_ROTATED     ///< PRC Envelope #10 Rotated 458 x 324 m
};

/**
    Printing orientation
*/

enum wxPrintOrientation
{
   wxPORTRAIT,
   wxLANDSCAPE
};

/**
    Duplex printing modes.
*/
enum wxDuplexMode
{
    wxDUPLEX_SIMPLEX, /**< Non-duplex */
    wxDUPLEX_HORIZONTAL,
    wxDUPLEX_VERTICAL
};

/**
    Print mode (currently PostScript only).
*/
enum wxPrintMode
{
    wxPRINT_MODE_NONE =    0,
    wxPRINT_MODE_PREVIEW = 1,   /**< Preview in external application */
    wxPRINT_MODE_FILE =    2,   /**< Print to file */
    wxPRINT_MODE_PRINTER = 3,   /**< Send to printer */
    wxPRINT_MODE_STREAM =  4    /**< Send postscript data into a stream */
};

/**
    Flags which can be used in wxWindow::UpdateWindowUI().
*/
enum wxUpdateUI
{
    wxUPDATE_UI_NONE,
    wxUPDATE_UI_RECURSE,
    wxUPDATE_UI_FROMIDLE  /**<  Invoked from On(Internal)Idle */
};


// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

/**
    C99-like sized MIN/MAX constants for all integer types.

    For each @c n in the set 8, 16, 32, 64 we define @c wxINTn_MIN, @c
    wxINTn_MAX and @c wxUINTc_MAX (@c wxUINTc_MIN is always 0 and so is not
    defined).
 */
//@{
#define wxINT8_MIN CHAR_MIN
#define wxINT8_MAX CHAR_MAX
#define wxUINT8_MAX UCHAR_MAX

#define wxINT16_MIN SHRT_MIN
#define wxINT16_MAX SHRT_MAX
#define wxUINT16_MAX USHRT_MAX

#define wxINT32_MIN INT_MIN-or-LONG_MIN
#define wxINT32_MAX INT_MAX-or-LONG_MAX
#define wxUINT32_MAX UINT_MAX-or-LONG_MAX

#define wxINT64_MIN LLONG_MIN
#define wxINT64_MAX LLONG_MAX
#define wxUINT64_MAX ULLONG_MAX
//@}

// ----------------------------------------------------------------------------
// types
// ----------------------------------------------------------------------------

/** The type for screen and DC coordinates. */
typedef int wxCoord;

/** A special value meaning "use default coordinate". */
wxCoord wxDefaultCoord = -1;

//@{
/** 8 bit type (the mapping is more complex than a simple @c typedef and is not shown here). */
typedef signed char wxInt8;
typedef unsigned char wxUint8;
typedef wxUint8 wxByte;
//@}

//@{
/** 16 bit type (the mapping is more complex than a simple @c typedef and is not shown here). */
typedef signed short wxInt16;
typedef unsigned short wxUint16;
typedef wxUint16 wxWord;
typedef wxUint16 wxChar16;
//@}

//@{
/** 32 bit type (the mapping is more complex than a simple @c typedef and is not shown here). */
typedef int wxInt32;
typedef unsigned int wxUint32;
typedef wxUint32 wxDword;
typedef wxUint32 wxChar32;
//@}

//@{
/** 64 bit type (the mapping is more complex than a simple @c typedef and is not shown here). */
typedef wxLongLong_t wxInt64;
typedef wxULongLong_t wxUint64;
//@}

//@{
/**
    Signed and unsigned integral types big enough to contain all of @c long,
    @c size_t and @c void*.
    (The mapping is more complex than a simple @c typedef and is not shown here).
*/
typedef ssize_t wxIntPtr;
typedef size_t wxUIntPtr;
//@}


/**
    32 bit IEEE float ( 1 sign, 8 exponent bits, 23 fraction bits ).
    (The mapping is more complex than a simple @c typedef and is not shown here).
*/
typedef float wxFloat32;


/**
    64 bit IEEE float ( 1 sign, 11 exponent bits, 52 fraction bits ).
    (The mapping is more complex than a simple @c typedef and is not shown here).
*/
typedef double wxFloat64;

/**
    Native fastest representation that has at least wxFloat64 precision, so use
    the IEEE types for storage, and this for calculations.
    (The mapping is more complex than a simple @c typedef and is not shown here).
*/
typedef double wxDouble;



// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------


/** @addtogroup group_funcmacro_byteorder */
//@{

/**
    This macro will swap the bytes of the @a value variable from little endian
    to big endian or vice versa unconditionally, i.e. independently of the
    current platform.

    @header{wx/defs.h}
*/
#define wxINT32_SWAP_ALWAYS( wxInt32_value )
#define wxUINT32_SWAP_ALWAYS( wxUint32_value )
#define wxINT16_SWAP_ALWAYS( wxInt16_value )
#define wxUINT16_SWAP_ALWAYS( wxUint16_value )

//@}

/** @addtogroup group_funcmacro_byteorder */
//@{

/**
    This macro will swap the bytes of the @a value variable from little endian
    to big endian or vice versa if the program is compiled on a big-endian
    architecture (such as Sun work stations). If the program has been compiled
    on a little-endian architecture, the value will be unchanged.

    Use these macros to read data from and write data to a file that stores
    data in little-endian (for example Intel i386) format.

    @header{wx/defs.h}
*/
#define wxINT32_SWAP_ON_BE( wxInt32_value )
#define wxUINT32_SWAP_ON_BE( wxUint32_value )
#define wxINT16_SWAP_ON_BE( wxInt16_value )
#define wxUINT16_SWAP_ON_BE( wxUint16_value )

//@}

/** @addtogroup group_funcmacro_byteorder */
//@{

/**
    This macro will swap the bytes of the @a value variable from little endian
    to big endian or vice versa if the program is compiled on a little-endian
    architecture (such as Intel PCs). If the program has been compiled on a
    big-endian architecture, the value will be unchanged.

    Use these macros to read data from and write data to a file that stores
    data in big-endian format.

    @header{wx/defs.h}
*/
#define wxINT32_SWAP_ON_LE( wxInt32_value )
#define wxUINT32_SWAP_ON_LE( wxUint32_value )
#define wxINT16_SWAP_ON_LE( wxInt16_value )
#define wxUINT16_SWAP_ON_LE( wxUint16_value )

//@}



/** @addtogroup group_funcmacro_misc */
//@{

/**
    This macro can be used in a class declaration to disable the generation of
    default assignment operator.

    Some classes have a well-defined copy constructor but cannot have an
    assignment operator, typically because they can't be modified once created.
    In such case, this macro can be used to disable the automatic assignment
    operator generation.

    @see wxDECLARE_NO_COPY_CLASS()
 */
#define wxDECLARE_NO_ASSIGN_CLASS(classname)

/**
    This macro can be used in a class declaration to disable the generation of
    default copy ctor and assignment operator.

    Some classes don't have a well-defined copying semantics. In this case the
    standard C++ convention is to not allow copying them. One way of achieving
    it is to use this macro which simply defines a private copy constructor and
    assignment operator.

    Beware that simply not defining copy constructor and assignment operator is
    @em not enough as the compiler would provide its own automatically-generated
    versions of them -- hence the usefulness of this macro.

    Example of use:
    @code
    class FooWidget
    {
    public:
        FooWidget();
        ...

    private:
        // widgets can't be copied
        wxDECLARE_NO_COPY_CLASS(FooWidget);
    };
    @endcode

    Notice that a semicolon must be used after this macro and that it changes
    the access specifier to private internally so it is better to use it at the
    end of the class declaration.

    @see wxDECLARE_NO_ASSIGN_CLASS(), wxDECLARE_NO_COPY_TEMPLATE_CLASS()
 */
#define wxDECLARE_NO_COPY_CLASS(classname)

/**
    Analog of wxDECLARE_NO_COPY_CLASS() for template classes.

    This macro can be used for template classes (with a single template
    parameter) for the same purpose as wxDECLARE_NO_COPY_CLASS() is used with the
    non-template classes.

    @param classname The name of the template class.
    @param arg The name of the template parameter.

    @see wxDECLARE_NO_COPY_TEMPLATE_CLASS_2
 */
#define wxDECLARE_NO_COPY_TEMPLATE_CLASS(classname, arg)

/**
    Analog of wxDECLARE_NO_COPY_TEMPLATE_CLASS() for templates with 2
    parameters.

    This macro can be used for template classes with two template
    parameters for the same purpose as wxDECLARE_NO_COPY_CLASS() is used with
    the non-template classes.

    @param classname The name of the template class.
    @param arg1 The name of the first template parameter.
    @param arg2 The name of the second template parameter.

    @see wxDECLARE_NO_COPY_TEMPLATE_CLASS
 */
#define wxDECLARE_NO_COPY_TEMPLATE_CLASS_2(classname, arg1, arg2)

/**
    A function which deletes and nulls the pointer.

    This function uses operator delete to free the pointer and also sets it to
    @NULL. Notice that this does @em not work for arrays, use wxDELETEA() for
    them.

    @code
        MyClass *ptr = new MyClass;
        ...
        wxDELETE(ptr);
        wxASSERT(!ptr);
    @endcode

    @header{wx/defs.h}
*/
template <typename T> wxDELETE(T*& ptr);

/**
    A function which deletes and nulls the pointer.

    This function uses vector operator delete (@c delete[]) to free the array
    pointer and also sets it to @NULL. Notice that this does @em not work for
    non-array pointers, use wxDELETE() for them.

    @code
        MyClass *array = new MyClass[17];
        ...
        wxDELETEA(array);
        wxASSERT(!array);
    @endcode

    @see wxDELETE()

    @header{wx/defs.h}
*/
template <typename T> wxDELETEA(T*& array);

/**
    This macro can be used around a function declaration to generate warnings
    indicating that this function is deprecated (i.e. obsolete and planned to
    be removed in the future) when it is used. Only Visual C++ 7 and higher and
    g++ compilers currently support this functionality.

    Example of use:

    @code
    // old function, use wxString version instead
    wxDEPRECATED( void wxGetSomething(char *buf, size_t len) );

    // ...
    wxString wxGetSomething();
    @endcode

    @header{wx/defs.h}
*/
#define wxDEPRECATED(function)

/**
    This is a special version of wxDEPRECATED() macro which only does something
    when the deprecated function is used from the code outside wxWidgets itself
    but doesn't generate warnings when it is used from wxWidgets.

    It is used with the virtual functions which are called by the library
    itself -- even if such function is deprecated the library still has to call
    it to ensure that the existing code overriding it continues to work, but
    the use of this macro ensures that a deprecation warning will be generated
    if this function is used from the user code or, in case of Visual C++, even
    when it is simply overridden.

    @header{wx/defs.h}
*/
#define wxDEPRECATED_BUT_USED_INTERNALLY(function)

/**
    This macro is similar to wxDEPRECATED() but can be used to not only declare
    the function @a function as deprecated but to also provide its (inline)
    implementation @a body.

    It can be used as following:

    @code
    class wxFoo
    {
    public:
        // OldMethod() is deprecated, use NewMethod() instead
        void NewMethod();
        wxDEPRECATED_INLINE( void OldMethod(), NewMethod(); )
    };
    @endcode

    @header{wx/defs.h}
*/
#define wxDEPRECATED_INLINE(func, body)

/**
    A helper macro allowing to easily define a simple deprecated accessor.

    Compared to wxDEPRECATED_INLINE() it saves a @c return statement and,
    especially, a strangely looking semicolon inside a macro.

    Example of use
    @code
    class wxFoo
    {
    public:
        int GetValue() const { return m_value; }

        // this one is deprecated because it was erroneously non-const
        wxDEPRECATED_ACCESSOR( int GetValue(), m_value )

    private:
        int m_value;
    };
    @endcode
 */
#define wxDEPRECATED_ACCESSOR(func, what)

/**
    Combination of wxDEPRECATED_BUT_USED_INTERNALLY() and wxDEPRECATED_INLINE().

    This macro should be used for deprecated functions called by the library
    itself (usually for backwards compatibility reasons) and which are defined
    inline.

    @header{wx/defs.h}
*/
#define wxDEPRECATED_BUT_USED_INTERNALLY_INLINE(func, body)

/**
    @c wxEXPLICIT is a macro which expands to the C++ @c explicit keyword if
    the compiler supports it or nothing otherwise. Thus, it can be used even in
    the code which might have to be compiled with an old compiler without
    support for this language feature but still take advantage of it when it is
    available.

    @header{wx/defs.h}
*/
#define wxEXPLICIT

/**
    GNU C++ compiler gives a warning for any class whose destructor is private
    unless it has a friend. This warning may sometimes be useful but it doesn't
    make sense for reference counted class which always delete themselves
    (hence destructor should be private) but don't necessarily have any
    friends, so this macro is provided to disable the warning in such case. The
    @a name parameter should be the name of the class but is only used to
    construct a unique friend class name internally.

    Example of using the macro:

    @code
    class RefCounted
    {
    public:
        RefCounted() { m_nRef = 1; }
        void IncRef() { m_nRef++ ; }
        void DecRef() { if ( !--m_nRef ) delete this; }

    private:
        ~RefCounted() { }

        wxSUPPRESS_GCC_PRIVATE_DTOR(RefCounted)
    };
    @endcode

    Notice that there should be no semicolon after this macro.

    @header{wx/defs.h}
*/
#define wxSUPPRESS_GCC_PRIVATE_DTOR_WARNING(name)

/**
    Swaps the contents of two variables.

    This is similar to std::swap() but can be used even on the platforms where
    the standard C++ library is not available (if you don't target such
    platforms, please use std::swap() instead).

    The function relies on type T being copy constructible and assignable.

    Example of use:
    @code
        int x = 3,
            y = 4;
        wxSwap(x, y);
        wxASSERT( x == 4 && y == 3 );
    @endcode
 */
template <typename T> wxSwap(T& first, T& second);

/**
    This macro is the same as the standard C99 @c va_copy for the compilers
    which support it or its replacement for those that don't. It must be used
    to preserve the value of a @c va_list object if you need to use it after
    passing it to another function because it can be modified by the latter.

    As with @c va_start, each call to @c wxVaCopy must have a matching
    @c va_end.

    @header{wx/defs.h}
*/
void wxVaCopy(va_list argptrDst, va_list argptrSrc);

//@}


