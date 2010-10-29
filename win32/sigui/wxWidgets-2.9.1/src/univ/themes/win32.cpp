///////////////////////////////////////////////////////////////////////////////
// Name:        src/univ/themes/win32.cpp
// Purpose:     wxUniversal theme implementing Win32-like LNF
// Author:      Vadim Zeitlin
// Modified by:
// Created:     06.08.00
// RCS-ID:      $Id$
// Copyright:   (c) 2000 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/univ/theme.h"

#if wxUSE_THEME_WIN32

#ifndef WX_PRECOMP
    #include "wx/timer.h"
    #include "wx/intl.h"
    #include "wx/dc.h"
    #include "wx/window.h"

    #include "wx/dcmemory.h"
    #include "wx/dcclient.h"

    #include "wx/button.h"
    #include "wx/bmpbuttn.h"
    #include "wx/listbox.h"
    #include "wx/checklst.h"
    #include "wx/combobox.h"
    #include "wx/scrolbar.h"
    #include "wx/slider.h"
    #include "wx/textctrl.h"
    #include "wx/toolbar.h"
    #include "wx/statusbr.h"

    #ifdef __WXMSW__
        // for COLOR_* constants
        #include "wx/msw/private.h"
    #endif
    #include "wx/menu.h"
    #include "wx/settings.h"
    #include "wx/toplevel.h"
    #include "wx/image.h"
#endif // WX_PRECOMP

#include "wx/notebook.h"
#include "wx/spinbutt.h"
#include "wx/artprov.h"
#ifdef wxUSE_TOGGLEBTN
#include "wx/tglbtn.h"
#endif // wxUSE_TOGGLEBTN

#include "wx/univ/scrtimer.h"
#include "wx/univ/stdrend.h"
#include "wx/univ/inpcons.h"
#include "wx/univ/inphand.h"
#include "wx/univ/colschem.h"

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

static const int BORDER_THICKNESS = 2;

static const size_t NUM_STATUSBAR_GRIP_BANDS = 3;
static const size_t WIDTH_STATUSBAR_GRIP_BAND = 4;
static const size_t STATUSBAR_GRIP_SIZE =
    WIDTH_STATUSBAR_GRIP_BAND*NUM_STATUSBAR_GRIP_BANDS;

static const wxCoord SLIDER_MARGIN = 6; // margin around slider
static const wxCoord SLIDER_THUMB_LENGTH = 18;
static const wxCoord SLIDER_TICK_LENGTH = 6;

// wxWin32Renderer: draw the GUI elements in Win32 style
// ----------------------------------------------------------------------------

class wxWin32Renderer : public wxStdRenderer
{
public:
    // ctor
    wxWin32Renderer(const wxColourScheme *scheme);

    // reimplement the renderer methods which are different for this theme
    virtual void DrawLabel(wxDC& dc,
                           const wxString& label,
                           const wxRect& rect,
                           int flags = 0,
                           int alignment = wxALIGN_LEFT | wxALIGN_TOP,
                           int indexAccel = -1,
                           wxRect *rectBounds = NULL);
    virtual void DrawButtonLabel(wxDC& dc,
                                 const wxString& label,
                                 const wxBitmap& image,
                                 const wxRect& rect,
                                 int flags = 0,
                                 int alignment = wxALIGN_LEFT | wxALIGN_TOP,
                                 int indexAccel = -1,
                                 wxRect *rectBounds = NULL);
    virtual void DrawButtonBorder(wxDC& dc,
                                  const wxRect& rect,
                                  int flags = 0,
                                  wxRect *rectIn = NULL);

    virtual void DrawArrow(wxDC& dc,
                           wxDirection dir,
                           const wxRect& rect,
                           int flags = 0);
    virtual void DrawScrollbarThumb(wxDC& dc,
                                    wxOrientation orient,
                                    const wxRect& rect,
                                    int flags = 0);
    virtual void DrawScrollbarShaft(wxDC& dc,
                                    wxOrientation orient,
                                    const wxRect& rect,
                                    int flags = 0);

#if wxUSE_TOOLBAR
    virtual void DrawToolBarButton(wxDC& dc,
                                   const wxString& label,
                                   const wxBitmap& bitmap,
                                   const wxRect& rect,
                                   int flags = 0,
                                   long style = 0,
                                   int tbarStyle = 0);
#endif // wxUSE_TOOLBAR

#if wxUSE_NOTEBOOK
    virtual void DrawTab(wxDC& dc,
                         const wxRect& rect,
                         wxDirection dir,
                         const wxString& label,
                         const wxBitmap& bitmap = wxNullBitmap,
                         int flags = 0,
                         int indexAccel = -1);
#endif // wxUSE_NOTEBOOK

#if wxUSE_SLIDER
    virtual void DrawSliderShaft(wxDC& dc,
                                 const wxRect& rect,
                                 int lenThumb,
                                 wxOrientation orient,
                                 int flags = 0,
                                 long style = 0,
                                 wxRect *rectShaft = NULL);
    virtual void DrawSliderThumb(wxDC& dc,
                                 const wxRect& rect,
                                 wxOrientation orient,
                                 int flags = 0,
                                 long style = 0);
    virtual void DrawSliderTicks(wxDC& dc,
                                 const wxRect& rect,
                                 int lenThumb,
                                 wxOrientation orient,
                                 int start,
                                 int end,
                                 int step = 1,
                                 int flags = 0,
                                 long style = 0);
#endif // wxUSE_SLIDER

#if wxUSE_MENUS
    virtual void DrawMenuBarItem(wxDC& dc,
                                 const wxRect& rect,
                                 const wxString& label,
                                 int flags = 0,
                                 int indexAccel = -1);
    virtual void DrawMenuItem(wxDC& dc,
                              wxCoord y,
                              const wxMenuGeometryInfo& geometryInfo,
                              const wxString& label,
                              const wxString& accel,
                              const wxBitmap& bitmap = wxNullBitmap,
                              int flags = 0,
                              int indexAccel = -1);
    virtual void DrawMenuSeparator(wxDC& dc,
                                   wxCoord y,
                                   const wxMenuGeometryInfo& geomInfo);
#endif // wxUSE_MENUS

#if wxUSE_STATUSBAR
    virtual void DrawStatusField(wxDC& dc,
                                 const wxRect& rect,
                                 const wxString& label,
                                 int flags = 0, int style = 0);
#endif // wxUSE_STATUSBAR

    virtual void GetComboBitmaps(wxBitmap *bmpNormal,
                                 wxBitmap *bmpFocus,
                                 wxBitmap *bmpPressed,
                                 wxBitmap *bmpDisabled);

    virtual void AdjustSize(wxSize *size, const wxWindow *window);
    virtual bool AreScrollbarsInsideBorder() const;

    virtual wxSize GetScrollbarArrowSize() const
        { return m_sizeScrollbarArrow; }

    virtual wxSize GetCheckBitmapSize() const
        { return wxSize(13, 13); }
    virtual wxSize GetRadioBitmapSize() const
        { return wxSize(12, 12); }
    virtual wxCoord GetCheckItemMargin() const
        { return 0; }

#if wxUSE_TOOLBAR
    virtual wxSize GetToolBarButtonSize(wxCoord *separator) const
        { if ( separator ) *separator = 5; return wxSize(16, 15); }
    virtual wxSize GetToolBarMargin() const
        { return wxSize(4, 4); }
#endif // wxUSE_TOOLBAR

#if wxUSE_TEXTCTRL
    virtual wxRect GetTextTotalArea(const wxTextCtrl *text,
                                    const wxRect& rect) const;
    virtual wxRect GetTextClientArea(const wxTextCtrl *text,
                                     const wxRect& rect,
                                     wxCoord *extraSpaceBeyond) const;
#endif // wxUSE_TEXTCTRL

#if wxUSE_NOTEBOOK
    virtual wxSize GetTabIndent() const { return wxSize(2, 2); }
    virtual wxSize GetTabPadding() const { return wxSize(6, 5); }
#endif // wxUSE_NOTEBOOK

#if wxUSE_SLIDER

    virtual wxCoord GetSliderDim() const { return SLIDER_THUMB_LENGTH + 2*BORDER_THICKNESS; }
    virtual wxCoord GetSliderTickLen() const { return SLIDER_TICK_LENGTH; }
    virtual wxRect GetSliderShaftRect(const wxRect& rect,
                                      int lenThumb,
                                      wxOrientation orient,
                                      long style = 0) const;
    virtual wxSize GetSliderThumbSize(const wxRect& rect,
                                      int lenThumb,
                                      wxOrientation orient) const;
#endif // wxUSE_SLIDER

    virtual wxSize GetProgressBarStep() const { return wxSize(16, 32); }

#if wxUSE_MENUS
    virtual wxSize GetMenuBarItemSize(const wxSize& sizeText) const;
    virtual wxMenuGeometryInfo *GetMenuGeometry(wxWindow *win,
                                                const wxMenu& menu) const;
#endif // wxUSE_MENUS

protected:
    // overridden wxStdRenderer methods
    virtual void DrawFrameWithLabel(wxDC& dc,
                                    const wxString& label,
                                    const wxRect& rectFrame,
                                    const wxRect& rectText,
                                    int flags,
                                    int alignment,
                                    int indexAccel);

    virtual void DrawCheckItemBitmap(wxDC& dc,
                                     const wxBitmap& bitmap,
                                     const wxRect& rect,
                                     int flags);


    // draw the border used for scrollbar arrows
    void DrawArrowBorder(wxDC& dc, wxRect *rect, bool isPressed = false);

    // public DrawArrow()s helper
    void DrawArrow(wxDC& dc, const wxRect& rect,
                   ArrowDirection arrowDir, ArrowStyle arrowStyle);

    // DrawArrowButton is used by DrawScrollbar and DrawComboButton
    void DrawArrowButton(wxDC& dc, const wxRect& rect,
                         ArrowDirection arrowDir,
                         ArrowStyle arrowStyle);

    // draw a normal or transposed line (useful for using the same code fo both
    // horizontal and vertical widgets)
    void DrawLine(wxDC& dc,
                  wxCoord x1, wxCoord y1,
                  wxCoord x2, wxCoord y2,
                  bool transpose = false)
    {
        if ( transpose )
            dc.DrawLine(y1, x1, y2, x2);
        else
            dc.DrawLine(x1, y1, x2, y2);
    }

    // get the standard check/radio button bitmap
    wxBitmap GetIndicator(IndicatorType indType, int flags);
    virtual wxBitmap GetCheckBitmap(int flags)
        { return GetIndicator(IndicatorType_Check, flags); }
    virtual wxBitmap GetRadioBitmap(int flags)
        { return GetIndicator(IndicatorType_Radio, flags); }

    virtual wxBitmap GetFrameButtonBitmap(FrameButtonType type);

#if wxUSE_SLIDER
    // Fill the arguments with true or false if this slider has labels on
    // left/right side (or top/bottom for horizontal sliders) respectively
    static
    void GetSliderLabelsSides(wxOrientation orient, long style,
                              bool *left, bool *right)
    {
        // should we draw ticks at all?
        if ( !(style & wxSL_AUTOTICKS) )
        {
            *left =
            *right = false;
            return;
        }

        // should we draw them on both sides?
        if ( style & wxSL_BOTH )
        {
            *left =
            *right = true;
            return;
        }

        // we draw them on one side only, determine which one
        if ( ((style & wxSL_TOP) && (orient == wxHORIZONTAL)) ||
                ((style & wxSL_LEFT) && (orient == wxVERTICAL)) )
        {
            *left = true;
            *right = false;
        }
        else if ( ((style & wxSL_BOTTOM) && (orient == wxHORIZONTAL)) ||
                    ((style & wxSL_RIGHT) && (orient == wxVERTICAL)) )
        {
            *left = false;
            *right = true;
        }
        else
        {
            wxFAIL_MSG( "inconsistent wxSlider flags" );

            *left =
            *right = false;
        }
    }
#endif // wxUSE_SLIDER

private:
    // the sizing parameters (TODO make them changeable)
    wxSize m_sizeScrollbarArrow;

    // the checked and unchecked bitmaps for DrawCheckItemBitmap()
    wxBitmap m_bmpCheckBitmaps[IndicatorStatus_Max];

    // the bitmaps returned by GetIndicator()
    wxBitmap m_bmpIndicators[IndicatorType_Max]
                            [IndicatorState_MaxMenu]
                            [IndicatorStatus_Max];

    // titlebar icons:
    wxBitmap m_bmpFrameButtons[FrameButton_Max];

    // standard defaults for the above bitmaps
    static const char **ms_xpmChecked[IndicatorStatus_Max];
    static const char **ms_xpmIndicators[IndicatorType_Max]
                                        [IndicatorState_MaxMenu]
                                        [IndicatorStatus_Max];
    static const char **ms_xpmFrameButtons[FrameButton_Max];

    // first row is for the normal state, second - for the disabled
    wxBitmap m_bmpArrows[Arrow_StateMax][Arrow_Max];
};

// ----------------------------------------------------------------------------
// wxWin32InputHandler and derived classes: process the keyboard and mouse
// messages according to Windows standards
// ----------------------------------------------------------------------------

class wxWin32InputHandler : public wxInputHandler
{
public:
    wxWin32InputHandler() { }

    virtual bool HandleKey(wxInputConsumer *control,
                           const wxKeyEvent& event,
                           bool pressed);
    virtual bool HandleMouse(wxInputConsumer *control,
                             const wxMouseEvent& event);
};

#if wxUSE_SCROLLBAR
class wxWin32ScrollBarInputHandler : public wxStdScrollBarInputHandler
{
public:
    wxWin32ScrollBarInputHandler(wxRenderer *renderer,
                                 wxInputHandler *handler);

    virtual bool HandleMouse(wxInputConsumer *control,
                             const wxMouseEvent& event);
    virtual bool HandleMouseMove(wxInputConsumer *control,
                                 const wxMouseEvent& event);

    virtual bool OnScrollTimer(wxScrollBar *scrollbar,
                               const wxControlAction& action);

protected:
    virtual void Highlight(wxScrollBar * WXUNUSED(scrollbar),
                           bool WXUNUSED(doIt))
    {
        // we don't highlight anything
    }

    // the first and last event which caused the thumb to move
    wxMouseEvent m_eventStartDrag,
                 m_eventLastDrag;

    // have we paused the scrolling because the mouse moved?
    bool m_scrollPaused;

    // we remember the interval of the timer to be able to restart it
    int m_interval;
};
#endif // wxUSE_SCROLLBAR

#if wxUSE_CHECKBOX
class wxWin32CheckboxInputHandler : public wxStdInputHandler
{
public:
    wxWin32CheckboxInputHandler(wxInputHandler *handler)
        : wxStdInputHandler(handler) { }

    virtual bool HandleKey(wxInputConsumer *control,
                           const wxKeyEvent& event,
                           bool pressed);
};
#endif // wxUSE_CHECKBOX

#if wxUSE_TEXTCTRL
class wxWin32TextCtrlInputHandler : public wxStdInputHandler
{
public:
    wxWin32TextCtrlInputHandler(wxInputHandler *handler)
        : wxStdInputHandler(handler) { }

    virtual bool HandleKey(wxInputConsumer *control,
                           const wxKeyEvent& event,
                           bool pressed);
};
#endif // wxUSE_TEXTCTRL

class wxWin32StatusBarInputHandler : public wxStdInputHandler
{
public:
    wxWin32StatusBarInputHandler(wxInputHandler *handler);

    virtual bool HandleMouse(wxInputConsumer *consumer,
                             const wxMouseEvent& event);

    virtual bool HandleMouseMove(wxInputConsumer *consumer,
                                 const wxMouseEvent& event);

protected:
    // is the given point over the statusbar grip?
    bool IsOnGrip(wxWindow *statbar, const wxPoint& pt) const;

private:
    // the cursor we had replaced with the resize one
    wxCursor m_cursorOld;

    // was the mouse over the grip last time we checked?
    bool m_isOnGrip;
};

class wxWin32SystemMenuEvtHandler;

class wxWin32FrameInputHandler : public wxStdInputHandler
{
public:
    wxWin32FrameInputHandler(wxInputHandler *handler);
    virtual ~wxWin32FrameInputHandler();

    virtual bool HandleMouse(wxInputConsumer *control,
                             const wxMouseEvent& event);

    virtual bool HandleActivation(wxInputConsumer *consumer, bool activated);

#if wxUSE_MENUS
    void PopupSystemMenu(wxTopLevelWindow *window) const;
#endif // wxUSE_MENUS

private:
    // was the mouse over the grip last time we checked?
    wxWin32SystemMenuEvtHandler *m_menuHandler;
};

// ----------------------------------------------------------------------------
// wxWin32ColourScheme: uses (default) Win32 colours
// ----------------------------------------------------------------------------

class wxWin32ColourScheme : public wxColourScheme
{
public:
    virtual wxColour Get(StdColour col) const;
    virtual wxColour GetBackground(wxWindow *win) const;
};

// ----------------------------------------------------------------------------
// wxWin32ArtProvider
// ----------------------------------------------------------------------------

class wxWin32ArtProvider : public wxArtProvider
{
protected:
    virtual wxBitmap CreateBitmap(const wxArtID& id,
                                  const wxArtClient& client,
                                  const wxSize& size);
};

// ----------------------------------------------------------------------------
// wxWin32Theme
// ----------------------------------------------------------------------------

WX_DEFINE_ARRAY_PTR(wxInputHandler *, wxArrayHandlers);

class wxWin32Theme : public wxTheme
{
public:
    wxWin32Theme();
    virtual ~wxWin32Theme();

    virtual wxRenderer *GetRenderer();
    virtual wxArtProvider *GetArtProvider();
    virtual wxInputHandler *GetInputHandler(const wxString& control,
                                            wxInputConsumer *consumer);
    virtual wxColourScheme *GetColourScheme();

private:
    wxWin32Renderer *m_renderer;

    wxWin32ArtProvider *m_artProvider;

    // the names of the already created handlers and the handlers themselves
    // (these arrays are synchronized)
    wxSortedArrayString m_handlerNames;
    wxArrayHandlers m_handlers;

    wxWin32ColourScheme *m_scheme;

    WX_DECLARE_THEME(win32)
};

// ----------------------------------------------------------------------------
// standard bitmaps
// ----------------------------------------------------------------------------

// frame buttons bitmaps
static const char *frame_button_close_xpm[] = {
"12 10 2 1",
"         c None",
"X        c black",
"            ",
"  XX    XX  ",
"   XX  XX   ",
"    XXXX    ",
"     XX     ",
"    XXXX    ",
"   XX  XX   ",
"  XX    XX  ",
"            ",
"            "};

static const char *frame_button_help_xpm[] = {
"12 10 2 1",
"         c None",
"X        c #000000",
"    XXXX    ",
"   XX  XX   ",
"   XX  XX   ",
"      XX    ",
"     XX     ",
"     XX     ",
"            ",
"     XX     ",
"     XX     ",
"            "};

static const char *frame_button_maximize_xpm[] = {
"12 10 2 1",
"         c None",
"X        c #000000",
" XXXXXXXXX  ",
" XXXXXXXXX  ",
" X       X  ",
" X       X  ",
" X       X  ",
" X       X  ",
" X       X  ",
" X       X  ",
" XXXXXXXXX  ",
"            "};

static const char *frame_button_minimize_xpm[] = {
"12 10 2 1",
"         c None",
"X        c #000000",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"  XXXXXX    ",
"  XXXXXX    ",
"            "};

static const char *frame_button_restore_xpm[] = {
"12 10 2 1",
"         c None",
"X        c #000000",
"   XXXXXX   ",
"   XXXXXX   ",
"   X    X   ",
" XXXXXX X   ",
" XXXXXX X   ",
" X    XXX   ",
" X    X     ",
" X    X     ",
" XXXXXX     ",
"            "};

const char **wxWin32Renderer::ms_xpmFrameButtons[FrameButton_Max] =
{
    frame_button_close_xpm,
    frame_button_minimize_xpm,
    frame_button_maximize_xpm,
    frame_button_restore_xpm,
    frame_button_help_xpm,
};

// menu bitmaps

static const char *checked_menu_xpm[] = {
/* columns rows colors chars-per-pixel */
"9 9 2 1",
"w c None",
"b c black",
/* pixels */
"wwwwwwwww",
"wwwwwwwbw",
"wwwwwwbbw",
"wbwwwbbbw",
"wbbwbbbww",
"wbbbbbwww",
"wwbbbwwww",
"wwwbwwwww",
"wwwwwwwww"
};

static const char *selected_checked_menu_xpm[] = {
/* columns rows colors chars-per-pixel */
"9 9 2 1",
"w c None",
"b c white",
/* pixels */
"wwwwwwwww",
"wwwwwwwbw",
"wwwwwwbbw",
"wbwwwbbbw",
"wbbwbbbww",
"wbbbbbwww",
"wwbbbwwww",
"wwwbwwwww",
"wwwwwwwww"
};

static const char *disabled_checked_menu_xpm[] = {
/* columns rows colors chars-per-pixel */
"9 9 3 1",
"w c None",
"b c #7f7f7f",
"W c #e0e0e0",
/* pixels */
"wwwwwwwww",
"wwwwwwwbw",
"wwwwwwbbW",
"wbwwwbbbW",
"wbbwbbbWW",
"wbbbbbWWw",
"wwbbbWWww",
"wwwbWWwww",
"wwwwWwwww"
};

static const char *selected_disabled_checked_menu_xpm[] = {
/* columns rows colors chars-per-pixel */
"9 9 2 1",
"w c None",
"b c #7f7f7f",
/* pixels */
"wwwwwwwww",
"wwwwwwwbw",
"wwwwwwbbw",
"wbwwwbbbw",
"wbbwbbbww",
"wbbbbbwww",
"wwbbbwwww",
"wwwbwwwww",
"wwwwwwwww"
};

// checkbox and radiobox bitmaps below

static const char *checked_xpm[] = {
/* columns rows colors chars-per-pixel */
"13 13 5 1",
"w c white",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"ddddddddddddh",
"dbbbbbbbbbbgh",
"dbwwwwwwwwwgh",
"dbwwwwwwwbwgh",
"dbwwwwwwbbwgh",
"dbwbwwwbbbwgh",
"dbwbbwbbbwwgh",
"dbwbbbbbwwwgh",
"dbwwbbbwwwwgh",
"dbwwwbwwwwwgh",
"dbwwwwwwwwwgh",
"dgggggggggggh",
"hhhhhhhhhhhhh"
};

static const char *pressed_checked_xpm[] = {
/* columns rows colors chars-per-pixel */
"13 13 4 1",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"ddddddddddddh",
"dbbbbbbbbbbgh",
"dbggggggggggh",
"dbgggggggbggh",
"dbggggggbbggh",
"dbgbgggbbbggh",
"dbgbbgbbbgggh",
"dbgbbbbbggggh",
"dbggbbbgggggh",
"dbgggbggggggh",
"dbggggggggggh",
"dgggggggggggh",
"hhhhhhhhhhhhh"
};

static const char *pressed_disabled_checked_xpm[] = {
/* columns rows colors chars-per-pixel */
"13 13 4 1",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"ddddddddddddh",
"dbbbbbbbbbbgh",
"dbggggggggggh",
"dbgggggggdggh",
"dbggggggddggh",
"dbgdgggdddggh",
"dbgddgdddgggh",
"dbgdddddggggh",
"dbggdddgggggh",
"dbgggdggggggh",
"dbggggggggggh",
"dgggggggggggh",
"hhhhhhhhhhhhh"
};

static const char *checked_item_xpm[] = {
/* columns rows colors chars-per-pixel */
"13 13 3 1",
"w c white",
"b c black",
"d c #808080",
/* pixels */
"wwwwwwwwwwwww",
"wdddddddddddw",
"wdwwwwwwwwwdw",
"wdwwwwwwwbwdw",
"wdwwwwwwbbwdw",
"wdwbwwwbbbwdw",
"wdwbbwbbbwwdw",
"wdwbbbbbwwwdw",
"wdwwbbbwwwwdw",
"wdwwwbwwwwwdw",
"wdwwwwwwwwwdw",
"wdddddddddddw",
"wwwwwwwwwwwww"
};

static const char *unchecked_xpm[] = {
/* columns rows colors chars-per-pixel */
"13 13 5 1",
"w c white",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"ddddddddddddh",
"dbbbbbbbbbbgh",
"dbwwwwwwwwwgh",
"dbwwwwwwwwwgh",
"dbwwwwwwwwwgh",
"dbwwwwwwwwwgh",
"dbwwwwwwwwwgh",
"dbwwwwwwwwwgh",
"dbwwwwwwwwwgh",
"dbwwwwwwwwwgh",
"dbwwwwwwwwwgh",
"dgggggggggggh",
"hhhhhhhhhhhhh"
};

static const char *pressed_unchecked_xpm[] = {
/* columns rows colors chars-per-pixel */
"13 13 4 1",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"ddddddddddddh",
"dbbbbbbbbbbgh",
"dbggggggggggh",
"dbggggggggggh",
"dbggggggggggh",
"dbggggggggggh",
"dbggggggggggh",
"dbggggggggggh",
"dbggggggggggh",
"dbggggggggggh",
"dbggggggggggh",
"dbggggggggggh",
"hhhhhhhhhhhhh"
};

static const char *unchecked_item_xpm[] = {
/* columns rows colors chars-per-pixel */
"13 13 2 1",
"w c white",
"d c #808080",
/* pixels */
"wwwwwwwwwwwww",
"wdddddddddddw",
"wdwwwwwwwwwdw",
"wdwwwwwwwwwdw",
"wdwwwwwwwwwdw",
"wdwwwwwwwwwdw",
"wdwwwwwwwwwdw",
"wdwwwwwwwwwdw",
"wdwwwwwwwwwdw",
"wdwwwwwwwwwdw",
"wdwwwwwwwwwdw",
"wdddddddddddw",
"wwwwwwwwwwwww"
};

static const char *undetermined_xpm[] = {
/* columns rows colors chars-per-pixel */
"13 13 5 1",
"A c #030303",
"B c #838383",
"C c #C3C3C3",
"D c #FBFBFB",
"E c #DBDBDB",
/* pixels */
"BBBBBBBBBBBBD",
"BAAAAAAAAAAED",
"BACDCDCDCDCED",
"BADCDCDCDBDED",
"BACDCDCDBBCED",
"BADBDCEBBBDED",
"BACBBDBBBDCED",
"BADBBBBBDCDED",
"BACDBBBDCDCED",
"BADCDBDCDCDED",
"BACDCDCDCDCED",
"BEEEEEEEEEEED",
"DDDDDDDDDDDDD"
};

static const char *pressed_undetermined_xpm[] = {
/* columns rows colors chars-per-pixel */
"13 13 5 1",
"A c #040404",
"B c #848484",
"C c #C4C4C4",
"D c #FCFCFC",
"E c #DCDCDC",
/* pixels */
"BBBBBBBBBBBBD",
"BAAAAAAAAAAED",
"BACCCCCCCCCCD",
"BACCCCCCCACED",
"BACCCCCCAACED",
"BACACCCAAACED",
"BACAACAAACCED",
"BACAAAAACCCED",
"BACCAAACCCCCD",
"BACCCACCCCCED",
"BACCCCCCCCCED",
"BEEEEEEEEEEED",
"DDDDDDDDDDDDD"
};

static const char *checked_radio_xpm[] = {
/* columns rows colors chars-per-pixel */
"12 12 6 1",
"  c None",
"w c white",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"    dddd    ",
"  ddbbbbdd  ",
" dbbwwwwbbh ",
" dbwwwwwwgh ",
"dbwwwbbwwwgh",
"dbwwbbbbwwgh",
"dbwwbbbbwwgh",
"dbwwwbbwwwgh",
" dbwwwwwwgh ",
" dggwwwwggh ",
"  hhgggghh  ",
"    hhhh    "
};

static const char *pressed_checked_radio_xpm[] = {
/* columns rows colors chars-per-pixel */
"12 12 6 1",
"  c None",
"w c white",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"    dddd    ",
"  ddbbbbdd  ",
" dbbggggbbh ",
" dbgggggggh ",
"dbgggbbggggh",
"dbggbbbbgggh",
"dbggbbbbgggh",
"dbgggbbggggh",
" dbgggggggh ",
" dggggggggh ",
"  hhgggghh  ",
"    hhhh    "
};

static const char *pressed_disabled_checked_radio_xpm[] = {
/* columns rows colors chars-per-pixel */
"12 12 6 1",
"  c None",
"w c white",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"    dddd    ",
"  ddbbbbdd  ",
" dbbggggbbh ",
" dbgggggggh ",
"dbgggddggggh",
"dbggddddgggh",
"dbggddddgggh",
"dbgggddggggh",
" dbgggggggh ",
" dggggggggh ",
"  hhgggghh  ",
"    hhhh    ",
};

static const char *unchecked_radio_xpm[] = {
/* columns rows colors chars-per-pixel */
"12 12 6 1",
"  c None",
"w c white",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"    dddd    ",
"  ddbbbbdd  ",
" dbbwwwwbbh ",
" dbwwwwwwgh ",
"dbwwwwwwwwgh",
"dbwwwwwwwwgh",
"dbwwwwwwwwgh",
"dbwwwwwwwwgh",
" dbwwwwwwgh ",
" dggwwwwggh ",
"  hhgggghh  ",
"    hhhh    "
};

static const char *pressed_unchecked_radio_xpm[] = {
/* columns rows colors chars-per-pixel */
"12 12 6 1",
"  c None",
"w c white",
"b c black",
"d c #7f7f7f",
"g c #c0c0c0",
"h c #e0e0e0",
/* pixels */
"    dddd    ",
"  ddbbbbdd  ",
" dbbggggbbh ",
" dbgggggggh ",
"dbgggggggggh",
"dbgggggggggh",
"dbgggggggggh",
"dbgggggggggh",
" dbgggggggh ",
" dggggggggh ",
"  hhgggghh  ",
"    hhhh    "
};

const char **wxWin32Renderer::ms_xpmIndicators[IndicatorType_Max]
                                              [IndicatorState_MaxMenu]
                                              [IndicatorStatus_Max] =
{
    // checkboxes first
    {
        // normal state
        { checked_xpm, unchecked_xpm, undetermined_xpm },

        // pressed state
        { pressed_checked_xpm, pressed_unchecked_xpm, pressed_undetermined_xpm },

        // disabled state
        { pressed_disabled_checked_xpm, pressed_unchecked_xpm, pressed_disabled_checked_xpm },
    },

    // radio
    {
        // normal state
        { checked_radio_xpm, unchecked_radio_xpm, NULL },

        // pressed state
        { pressed_checked_radio_xpm, pressed_unchecked_radio_xpm, NULL },

        // disabled state
        { pressed_disabled_checked_radio_xpm, pressed_unchecked_radio_xpm, NULL },
    },

    // menu
    {
        // normal state
        { checked_menu_xpm, NULL, NULL },

        // selected state
        { selected_checked_menu_xpm, NULL, NULL },

        // disabled state
        { disabled_checked_menu_xpm, NULL, NULL },

        // disabled selected state
        { selected_disabled_checked_menu_xpm, NULL, NULL },
    }
};

const char **wxWin32Renderer::ms_xpmChecked[IndicatorStatus_Max] =
{
    checked_item_xpm,
    unchecked_item_xpm
};

// ============================================================================
// implementation
// ============================================================================

WX_IMPLEMENT_THEME(wxWin32Theme, win32, wxTRANSLATE("Win32 theme"));

// ----------------------------------------------------------------------------
// wxWin32Theme
// ----------------------------------------------------------------------------

wxWin32Theme::wxWin32Theme()
{
    m_scheme = NULL;
    m_renderer = NULL;
    m_artProvider = NULL;
}

wxWin32Theme::~wxWin32Theme()
{
    delete m_renderer;
    delete m_scheme;
    delete m_artProvider;
}

wxRenderer *wxWin32Theme::GetRenderer()
{
    if ( !m_renderer )
    {
        m_renderer = new wxWin32Renderer(GetColourScheme());
    }

    return m_renderer;
}

wxArtProvider *wxWin32Theme::GetArtProvider()
{
    if ( !m_artProvider )
    {
        m_artProvider = new wxWin32ArtProvider;
    }

    return m_artProvider;
}

wxInputHandler *
wxWin32Theme::GetInputHandler(const wxString& control,
                              wxInputConsumer *consumer)
{
    wxInputHandler *handler = NULL;
    int n = m_handlerNames.Index(control);
    if ( n == wxNOT_FOUND )
    {
        static wxWin32InputHandler s_handlerDef;

        wxInputHandler * const
          handlerStd = consumer->DoGetStdInputHandler(&s_handlerDef);

        // create a new handler
        if ( control == wxINP_HANDLER_TOPLEVEL )
        {
            static wxWin32FrameInputHandler s_handler(handlerStd);

            handler = &s_handler;
        }
#if wxUSE_CHECKBOX
        else if ( control == wxINP_HANDLER_CHECKBOX )
        {
            static wxWin32CheckboxInputHandler s_handler(handlerStd);

            handler = &s_handler;
        }
#endif // wxUSE_CHECKBOX
#if wxUSE_SCROLLBAR
        else if ( control == wxINP_HANDLER_SCROLLBAR )
        {
            static wxWin32ScrollBarInputHandler
                s_handler(GetRenderer(), handlerStd);

            handler = &s_handler;
        }
#endif // wxUSE_SCROLLBAR
#if wxUSE_STATUSBAR
        else if ( control == wxINP_HANDLER_STATUSBAR )
        {
            static wxWin32StatusBarInputHandler s_handler(handlerStd);

            handler = &s_handler;
        }
#endif // wxUSE_STATUSBAR
#if wxUSE_TEXTCTRL
        else if ( control == wxINP_HANDLER_TEXTCTRL )
        {
            static wxWin32TextCtrlInputHandler s_handler(handlerStd);

            handler = &s_handler;
        }
#endif // wxUSE_TEXTCTRL
        else // no special handler for this control
        {
            handler = handlerStd;
        }

        n = m_handlerNames.Add(control);
        m_handlers.Insert(handler, n);
    }
    else // we already have it
    {
        handler = m_handlers[n];
    }

    return handler;
}

wxColourScheme *wxWin32Theme::GetColourScheme()
{
    if ( !m_scheme )
    {
        m_scheme = new wxWin32ColourScheme;
    }
    return m_scheme;
}

// ============================================================================
// wxWin32ColourScheme
// ============================================================================

wxColour wxWin32ColourScheme::GetBackground(wxWindow *win) const
{
    wxColour col;
    if ( win->UseBgCol() )
    {
        // use the user specified colour
        col = win->GetBackgroundColour();
    }

    if ( !win->ShouldInheritColours() )
    {
#if wxUSE_TEXTCTRL
        wxTextCtrl *text = wxDynamicCast(win, wxTextCtrl);
#endif // wxUSE_TEXTCTRL
#if wxUSE_LISTBOX
        wxListBox* listBox = wxDynamicCast(win, wxListBox);
#endif // wxUSE_LISTBOX

#if wxUSE_TEXTCTRL
        if ( text
#if wxUSE_LISTBOX
         || listBox
#endif
          )
        {
            if ( !win->IsEnabled() ) // not IsEditable()
                col = Get(CONTROL);
            else
            {
                if ( !col.Ok() )
                {
                    // doesn't depend on the state
                    col = Get(WINDOW);
                }
            }
        }
#endif // wxUSE_TEXTCTRL

        if (!col.Ok())
            col = Get(CONTROL); // Most controls should be this colour, not WINDOW
    }
    else
    {
        int flags = win->GetStateFlags();

        // the colour set by the user should be used for the normal state
        // and for the states for which we don't have any specific colours
        if ( !col.Ok() || (flags & wxCONTROL_PRESSED) != 0 )
        {
#if wxUSE_SCROLLBAR
            if ( wxDynamicCast(win, wxScrollBar) )
                col = Get(flags & wxCONTROL_PRESSED ? SCROLLBAR_PRESSED
                                                    : SCROLLBAR);
            else
#endif // wxUSE_SCROLLBAR
                col = Get(CONTROL);
        }
    }

    return col;
}

wxColour wxWin32ColourScheme::Get(wxWin32ColourScheme::StdColour col) const
{
    switch ( col )
    {
        // use the system colours under Windows
#if defined(__WXMSW__)
        case WINDOW:            return wxColour(GetSysColor(COLOR_WINDOW));

        case CONTROL_PRESSED:
        case CONTROL_CURRENT:
        case CONTROL:           return wxColour(GetSysColor(COLOR_BTNFACE));

        case CONTROL_TEXT:      return wxColour(GetSysColor(COLOR_BTNTEXT));

#if defined(COLOR_3DLIGHT)
        case SCROLLBAR:         return wxColour(GetSysColor(COLOR_3DLIGHT));
#else
        case SCROLLBAR:         return wxColour(0xe0e0e0);
#endif
        case SCROLLBAR_PRESSED: return wxColour(GetSysColor(COLOR_BTNTEXT));

        case HIGHLIGHT:         return wxColour(GetSysColor(COLOR_HIGHLIGHT));
        case HIGHLIGHT_TEXT:    return wxColour(GetSysColor(COLOR_HIGHLIGHTTEXT));

#if defined(COLOR_3DDKSHADOW)
        case SHADOW_DARK:       return wxColour(GetSysColor(COLOR_3DDKSHADOW));
#else
        case SHADOW_DARK:       return wxColour(GetSysColor(COLOR_3DHADOW));
#endif

        case CONTROL_TEXT_DISABLED:
        case SHADOW_HIGHLIGHT:  return wxColour(GetSysColor(COLOR_BTNHIGHLIGHT));

        case SHADOW_IN:         return wxColour(GetSysColor(COLOR_BTNFACE));

        case CONTROL_TEXT_DISABLED_SHADOW:
        case SHADOW_OUT:        return wxColour(GetSysColor(COLOR_BTNSHADOW));

        case TITLEBAR:          return wxColour(GetSysColor(COLOR_INACTIVECAPTION));
        case TITLEBAR_ACTIVE:   return wxColour(GetSysColor(COLOR_ACTIVECAPTION));
        case TITLEBAR_TEXT:     return wxColour(GetSysColor(COLOR_INACTIVECAPTIONTEXT));
        case TITLEBAR_ACTIVE_TEXT: return wxColour(GetSysColor(COLOR_CAPTIONTEXT));

        case DESKTOP:           return wxColour(0x808000);
        case FRAME:             return wxColour(GetSysColor(COLOR_APPWORKSPACE));
#else // !__WXMSW__
        // use the standard Windows colours elsewhere
        case WINDOW:            return *wxWHITE;

        case CONTROL_PRESSED:
        case CONTROL_CURRENT:
        case CONTROL:           return wxColour(0xc0c0c0);

        case CONTROL_TEXT:      return *wxBLACK;

        case SCROLLBAR:         return wxColour(0xe0e0e0);
        case SCROLLBAR_PRESSED: return *wxBLACK;

        case HIGHLIGHT:         return wxColour(0x800000);
        case HIGHLIGHT_TEXT:    return wxColour(0xffffff);

        case SHADOW_DARK:       return *wxBLACK;

        case CONTROL_TEXT_DISABLED:return wxColour(0xe0e0e0);
        case SHADOW_HIGHLIGHT:  return wxColour(0xffffff);

        case SHADOW_IN:         return wxColour(0xc0c0c0);

        case CONTROL_TEXT_DISABLED_SHADOW:
        case SHADOW_OUT:        return wxColour(0x7f7f7f);

        case TITLEBAR:          return wxColour(0xaeaaae);
        case TITLEBAR_ACTIVE:   return wxColour(0x820300);
        case TITLEBAR_TEXT:     return wxColour(0xc0c0c0);
        case TITLEBAR_ACTIVE_TEXT:return *wxWHITE;

        case DESKTOP:           return wxColour(0x808000);
        case FRAME:             return wxColour(0x808080);
#endif // __WXMSW__

        case GAUGE:             return Get(HIGHLIGHT);

        case MAX:
        default:
            wxFAIL_MSG(wxT("invalid standard colour"));
            return *wxBLACK;
    }
}

// ============================================================================
// wxWin32Renderer
// ============================================================================

// ----------------------------------------------------------------------------
// construction
// ----------------------------------------------------------------------------

wxWin32Renderer::wxWin32Renderer(const wxColourScheme *scheme)
               : wxStdRenderer(scheme)
{
    // init data
    m_sizeScrollbarArrow = wxSize(16, 16);

    // init the arrow bitmaps
    static const size_t ARROW_WIDTH = 7;
    static const size_t ARROW_LENGTH = 4;

    wxMask *mask;
    wxMemoryDC dcNormal,
               dcDisabled,
               dcInverse;
    for ( size_t n = 0; n < Arrow_Max; n++ )
    {
        bool isVertical = n > Arrow_Right;
        int w, h;
        if ( isVertical )
        {
            w = ARROW_WIDTH;
            h = ARROW_LENGTH;
        }
        else
        {
            h = ARROW_WIDTH;
            w = ARROW_LENGTH;
        }

        // disabled arrow is larger because of the shadow
        m_bmpArrows[Arrow_Normal][n].Create(w, h);
        m_bmpArrows[Arrow_Disabled][n].Create(w + 1, h + 1);

        dcNormal.SelectObject(m_bmpArrows[Arrow_Normal][n]);
        dcDisabled.SelectObject(m_bmpArrows[Arrow_Disabled][n]);

        dcNormal.SetBackground(*wxWHITE_BRUSH);
        dcDisabled.SetBackground(*wxWHITE_BRUSH);
        dcNormal.Clear();
        dcDisabled.Clear();

        dcNormal.SetPen(m_penBlack);
        dcDisabled.SetPen(m_penDarkGrey);

        // calculate the position of the point of the arrow
        wxCoord x1, y1;
        if ( isVertical )
        {
            x1 = (ARROW_WIDTH - 1)/2;
            y1 = n == Arrow_Up ? 0 : ARROW_LENGTH - 1;
        }
        else // horizontal
        {
            x1 = n == Arrow_Left ? 0 : ARROW_LENGTH - 1;
            y1 = (ARROW_WIDTH - 1)/2;
        }

        wxCoord x2 = x1,
                y2 = y1;

        if ( isVertical )
            x2++;
        else
            y2++;

        for ( size_t i = 0; i < ARROW_LENGTH; i++ )
        {
            dcNormal.DrawLine(x1, y1, x2, y2);
            dcDisabled.DrawLine(x1, y1, x2, y2);

            if ( isVertical )
            {
                x1--;
                x2++;

                if ( n == Arrow_Up )
                {
                    y1++;
                    y2++;
                }
                else // down arrow
                {
                    y1--;
                    y2--;
                }
            }
            else // left or right arrow
            {
                y1--;
                y2++;

                if ( n == Arrow_Left )
                {
                    x1++;
                    x2++;
                }
                else
                {
                    x1--;
                    x2--;
                }
            }
        }

        // draw the shadow for the disabled one
        dcDisabled.SetPen(m_penHighlight);
        switch ( n )
        {
            case Arrow_Left:
                y1 += 2;
                dcDisabled.DrawLine(x1, y1, x2, y2);
                break;

            case Arrow_Right:
                x1 = ARROW_LENGTH - 1;
                y1 = (ARROW_WIDTH - 1)/2 + 1;
                x2 = 0;
                y2 = ARROW_WIDTH;
                dcDisabled.DrawLine(x1, y1, x2, y2);
                dcDisabled.DrawLine(++x1, y1, x2, ++y2);
                break;

            case Arrow_Up:
                x1 += 2;
                dcDisabled.DrawLine(x1, y1, x2, y2);
                break;

            case Arrow_Down:
                x1 = ARROW_WIDTH - 1;
                y1 = 1;
                x2 = (ARROW_WIDTH - 1)/2;
                y2 = ARROW_LENGTH;
                dcDisabled.DrawLine(x1, y1, x2, y2);
                dcDisabled.DrawLine(++x1, y1, x2, ++y2);
                break;

        }

        // create the inverted bitmap but only for the right arrow as we only
        // use it for the menus
        if ( n == Arrow_Right )
        {
            m_bmpArrows[Arrow_Inverted][n].Create(w, h);
            dcInverse.SelectObject(m_bmpArrows[Arrow_Inverted][n]);
            dcInverse.Clear();
            dcInverse.Blit(0, 0, w, h,
                          &dcNormal, 0, 0,
                          wxXOR);
            dcInverse.SelectObject(wxNullBitmap);

            mask = new wxMask(m_bmpArrows[Arrow_Inverted][n], *wxBLACK);
            m_bmpArrows[Arrow_Inverted][n].SetMask(mask);

            m_bmpArrows[Arrow_InvertedDisabled][n].Create(w, h);
            dcInverse.SelectObject(m_bmpArrows[Arrow_InvertedDisabled][n]);
            dcInverse.Clear();
            dcInverse.Blit(0, 0, w, h,
                          &dcDisabled, 0, 0,
                          wxXOR);
            dcInverse.SelectObject(wxNullBitmap);

            mask = new wxMask(m_bmpArrows[Arrow_InvertedDisabled][n], *wxBLACK);
            m_bmpArrows[Arrow_InvertedDisabled][n].SetMask(mask);
        }

        dcNormal.SelectObject(wxNullBitmap);
        dcDisabled.SelectObject(wxNullBitmap);

        mask = new wxMask(m_bmpArrows[Arrow_Normal][n], *wxWHITE);
        m_bmpArrows[Arrow_Normal][n].SetMask(mask);
        mask = new wxMask(m_bmpArrows[Arrow_Disabled][n], *wxWHITE);
        m_bmpArrows[Arrow_Disabled][n].SetMask(mask);

        m_bmpArrows[Arrow_Pressed][n] = m_bmpArrows[Arrow_Normal][n];
    }
}

bool wxWin32Renderer::AreScrollbarsInsideBorder() const
{
    return true;
}

// ----------------------------------------------------------------------------
// label
// ----------------------------------------------------------------------------

void wxWin32Renderer::DrawLabel(wxDC& dc,
                                const wxString& label,
                                const wxRect& rect,
                                int flags,
                                int alignment,
                                int indexAccel,
                                wxRect *rectBounds)
{
    // the underscores are not drawn for focused controls in wxMSW
    if ( flags & wxCONTROL_FOCUSED )
    {
        indexAccel = -1;
    }

    if ( flags & wxCONTROL_DISABLED )
    {
        // the combination of wxCONTROL_SELECTED and wxCONTROL_DISABLED
        // currently only can happen for a menu item and it seems that Windows
        // doesn't draw the shadow in this case, so we don't do it neither
        if ( flags & wxCONTROL_SELECTED )
        {
            // just make the label text greyed out
            dc.SetTextForeground(m_penDarkGrey.GetColour());

            flags &= ~wxCONTROL_DISABLED;
        }
    }

    wxStdRenderer::DrawLabel(dc, label, rect, flags, alignment,
                             indexAccel, rectBounds);
}

void wxWin32Renderer::DrawFrameWithLabel(wxDC& dc,
                                         const wxString& label,
                                         const wxRect& rectFrame,
                                         const wxRect& rectText,
                                         int flags,
                                         int alignment,
                                         int indexAccel)
{
    wxString label2;
    label2 << wxT(' ') << label << wxT(' ');
    if ( indexAccel != -1 )
    {
        // adjust it as we prepended a space
        indexAccel++;
    }

    wxStdRenderer::DrawFrameWithLabel(dc, label2, rectFrame, rectText,
                                      flags, alignment, indexAccel);
}

void wxWin32Renderer::DrawButtonLabel(wxDC& dc,
                                      const wxString& label,
                                      const wxBitmap& image,
                                      const wxRect& rect,
                                      int flags,
                                      int alignment,
                                      int indexAccel,
                                      wxRect *rectBounds)
{
    // the underscores are not drawn for focused controls in wxMSW
    if ( flags & wxCONTROL_PRESSED )
    {
        indexAccel = -1;
    }

    wxStdRenderer::DrawButtonLabel(dc, label, image, rect, flags, alignment,
                                   indexAccel, rectBounds);
}

void wxWin32Renderer::DrawButtonBorder(wxDC& dc,
                                       const wxRect& rectTotal,
                                       int flags,
                                       wxRect *rectIn)
{
    wxRect rect = rectTotal;

    wxPen penOut(*wxBLACK);
    if ( flags & wxCONTROL_PRESSED )
    {
        // button pressed: draw a double border around it
        DrawRect(dc, &rect, penOut);
        DrawRect(dc, &rect, m_penDarkGrey);
    }
    else // button not pressed
    {
        if ( flags & (wxCONTROL_FOCUSED | wxCONTROL_ISDEFAULT) )
        {
            // button either default or focused (or both): add an extra border
            // around it
            DrawRect(dc, &rect, penOut);
        }

        // now draw a normal button border
        DrawRaisedBorder(dc, &rect);
    }

    if ( rectIn )
        *rectIn = rect;
}

// ----------------------------------------------------------------------------
// (check)listbox items
// ----------------------------------------------------------------------------

void wxWin32Renderer::DrawCheckItemBitmap(wxDC& dc,
                                          const wxBitmap& bitmap,
                                          const wxRect& rect,
                                          int flags)
{
    wxBitmap bmp;
    if ( bitmap.Ok() )
    {
        bmp = bitmap;
    }
    else // use default bitmap
    {
        IndicatorStatus i = flags & wxCONTROL_CHECKED
                                ? IndicatorStatus_Checked
                                : IndicatorStatus_Unchecked;

        if ( !m_bmpCheckBitmaps[i].Ok() )
        {
            m_bmpCheckBitmaps[i] = wxBitmap(ms_xpmChecked[i]);
        }

        bmp = m_bmpCheckBitmaps[i];
    }

    dc.DrawBitmap(bmp, rect.x, rect.y + (rect.height - bmp.GetHeight()) / 2 - 1,
                  true /* use mask */);
}

// ----------------------------------------------------------------------------
// check/radio buttons
// ----------------------------------------------------------------------------

wxBitmap wxWin32Renderer::GetIndicator(IndicatorType indType, int flags)
{
    IndicatorState indState;
    IndicatorStatus indStatus;
    GetIndicatorsFromFlags(flags, indState, indStatus);

    wxBitmap& bmp = m_bmpIndicators[indType][indState][indStatus];
    if ( !bmp.Ok() )
    {
        const char **xpm = ms_xpmIndicators[indType][indState][indStatus];
        if ( xpm )
        {
            // create and cache it
            bmp = wxBitmap(xpm);
        }
    }

    return bmp;
}

// ----------------------------------------------------------------------------
// toolbar stuff
// ----------------------------------------------------------------------------

#if wxUSE_TOOLBAR
void wxWin32Renderer::DrawToolBarButton(wxDC& dc,
                                        const wxString& label,
                                        const wxBitmap& bitmap,
                                        const wxRect& rectOrig,
                                        int flags,
                                        long style,
                                        int tbarStyle)
{
    if (style == wxTOOL_STYLE_BUTTON)
    {
        wxRect rect = rectOrig;
        rect.Deflate(BORDER_THICKNESS);

        if ( flags & wxCONTROL_PRESSED )
        {
            DrawBorder(dc, wxBORDER_SUNKEN, rect, flags);
        }
        else if ( flags & wxCONTROL_CURRENT )
        {
            DrawBorder(dc, wxBORDER_RAISED, rect, flags);
        }

        if(tbarStyle & wxTB_TEXT)
        {
            if(tbarStyle & wxTB_HORIZONTAL)
            {
                dc.DrawLabel(label, bitmap, rect, wxALIGN_CENTRE);
            }
            else
            {
                dc.DrawLabel(label, bitmap, rect, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL);
            }
        }
        else
        {
            int xpoint = (rect.GetLeft() + rect.GetRight() + 1 - bitmap.GetWidth()) / 2;
            int ypoint = (rect.GetTop() + rect.GetBottom() + 1 - bitmap.GetHeight()) / 2;
            dc.DrawBitmap(bitmap, xpoint, ypoint, bitmap.GetMask() != NULL);
        }
    }
    else if (style == wxTOOL_STYLE_SEPARATOR)
    {
        // leave a small gap aroudn the line, also account for the toolbar
        // border itself
        if(rectOrig.height > rectOrig.width)
        {
            // horizontal
            DrawVerticalLine(dc, rectOrig.x + rectOrig.width/2,
                             rectOrig.y + 2*BORDER_THICKNESS,
                             rectOrig.GetBottom() - BORDER_THICKNESS);
        }
        else
        {
            // vertical
            DrawHorizontalLine(dc, rectOrig.y + rectOrig.height/2,
                         rectOrig.x + 2*BORDER_THICKNESS,
                         rectOrig.GetRight() - BORDER_THICKNESS);
        }
    }
    // don't draw wxTOOL_STYLE_CONTROL
}
#endif // wxUSE_TOOLBAR

// ----------------------------------------------------------------------------
// notebook
// ----------------------------------------------------------------------------

#if wxUSE_NOTEBOOK

void wxWin32Renderer::DrawTab(wxDC& dc,
                              const wxRect& rectOrig,
                              wxDirection dir,
                              const wxString& label,
                              const wxBitmap& bitmap,
                              int flags,
                              int indexAccel)
{
    #define SELECT_FOR_VERTICAL(X,Y) ( isVertical ? Y : X )
    #define REVERSE_FOR_VERTICAL(X,Y) \
        SELECT_FOR_VERTICAL(X,Y)      \
        ,                             \
        SELECT_FOR_VERTICAL(Y,X)

    wxRect rect = rectOrig;

    bool isVertical = ( dir == wxLEFT ) || ( dir == wxRIGHT );

    // the current tab is drawn indented (to the top for default case) and
    // bigger than the other ones
    const wxSize indent = GetTabIndent();
    if ( flags & wxCONTROL_SELECTED )
    {
        rect.Inflate( SELECT_FOR_VERTICAL( indent.x , 0),
                      SELECT_FOR_VERTICAL( 0, indent.y ));
        switch ( dir )
        {
            default:
                wxFAIL_MSG(wxT("invaild notebook tab orientation"));
                // fall through

            case wxTOP:
                rect.y -= indent.y;
                // fall through
            case wxBOTTOM:
                rect.height += indent.y;
                break;

            case wxLEFT:
                rect.x -= indent.x;
                // fall through
            case wxRIGHT:
                rect.width += indent.x;
                break;
        }
    }

    // draw the text, image and the focus around them (if necessary)
    wxRect rectLabel( REVERSE_FOR_VERTICAL(rect.x,rect.y),
                      REVERSE_FOR_VERTICAL(rect.width,rect.height)
                    );
    rectLabel.Deflate(1, 1);
    if ( isVertical )
    {
        // draw it horizontally into memory and rotate for screen
        wxMemoryDC dcMem;
        wxBitmap bitmapRotated,
                 bitmapMem( rectLabel.x + rectLabel.width,
                            rectLabel.y + rectLabel.height );
        dcMem.SelectObject(bitmapMem);
        dcMem.SetBackground(dc.GetBackground());
        dcMem.SetFont(dc.GetFont());
        dcMem.SetTextForeground(dc.GetTextForeground());
        dcMem.Clear();
        bitmapRotated =
#if wxUSE_IMAGE
                        wxBitmap( wxImage( bitmap.ConvertToImage() ).Rotate90(dir==wxLEFT) )
#else
                        bitmap
#endif // wxUSE_IMAGE
                        ;
        DrawButtonLabel(dcMem, label, bitmapRotated, rectLabel,
                        flags, wxALIGN_CENTRE, indexAccel);
        dcMem.SelectObject(wxNullBitmap);
        bitmapMem = bitmapMem.GetSubBitmap(rectLabel);
#if wxUSE_IMAGE
        bitmapMem = wxBitmap(wxImage(bitmapMem.ConvertToImage()).Rotate90(dir==wxRIGHT));
#endif // wxUSE_IMAGE
        dc.DrawBitmap(bitmapMem, rectLabel.y, rectLabel.x, false);
    }
    else
    {
        DrawButtonLabel(dc, label, bitmap, rectLabel,
                        flags, wxALIGN_CENTRE, indexAccel);
    }

    // now draw the tab border itself (maybe use DrawRoundedRectangle()?)
    static const wxCoord CUTOFF = 2; // radius of the rounded corner
    wxCoord x = SELECT_FOR_VERTICAL(rect.x,rect.y),
            y = SELECT_FOR_VERTICAL(rect.y,rect.x),
            x2 = SELECT_FOR_VERTICAL(rect.GetRight(),rect.GetBottom()),
            y2 = SELECT_FOR_VERTICAL(rect.GetBottom(),rect.GetRight());

    // FIXME: all this code will break if the tab indent or the border width,
    //        it is tied to the fact that both of them are equal to 2
    switch ( dir )
    {
        default:
            // default is top
        case wxLEFT:
            // left orientation looks like top but IsVertical makes x and y reversed
        case wxTOP:
            // top is not vertical so use coordinates in written order
            dc.SetPen(m_penHighlight);
            dc.DrawLine(REVERSE_FOR_VERTICAL(x, y2),
                        REVERSE_FOR_VERTICAL(x, y + CUTOFF));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x, y + CUTOFF),
                        REVERSE_FOR_VERTICAL(x + CUTOFF, y));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x + CUTOFF, y),
                        REVERSE_FOR_VERTICAL(x2 - CUTOFF + 1, y));

            dc.SetPen(m_penBlack);
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2, y2),
                        REVERSE_FOR_VERTICAL(x2, y + CUTOFF));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2, y + CUTOFF),
                        REVERSE_FOR_VERTICAL(x2 - CUTOFF, y));

            dc.SetPen(m_penDarkGrey);
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2 - 1, y2),
                        REVERSE_FOR_VERTICAL(x2 - 1, y + CUTOFF - 1));

            if ( flags & wxCONTROL_SELECTED )
            {
                dc.SetPen(m_penLightGrey);

                // overwrite the part of the border below this tab
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y2 + 1),
                            REVERSE_FOR_VERTICAL(x2 - 1, y2 + 1));

                // and the shadow of the tab to the left of us
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y + CUTOFF + 1),
                            REVERSE_FOR_VERTICAL(x + 1, y2 + 1));
            }
            break;

        case wxRIGHT:
            // right orientation looks like bottom but IsVertical makes x and y reversed
        case wxBOTTOM:
            // bottom is not vertical so use coordinates in written order
            dc.SetPen(m_penHighlight);
            // we need to continue one pixel further to overwrite the corner of
            // the border for the selected tab
            dc.DrawLine(REVERSE_FOR_VERTICAL(x, y - (flags & wxCONTROL_SELECTED ? 1 : 0)),
                        REVERSE_FOR_VERTICAL(x, y2 - CUTOFF));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x, y2 - CUTOFF),
                        REVERSE_FOR_VERTICAL(x + CUTOFF, y2));

            dc.SetPen(m_penBlack);
            dc.DrawLine(REVERSE_FOR_VERTICAL(x + CUTOFF, y2),
                        REVERSE_FOR_VERTICAL(x2 - CUTOFF + 1, y2));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2, y),
                        REVERSE_FOR_VERTICAL(x2, y2 - CUTOFF));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2, y2 - CUTOFF),
                        REVERSE_FOR_VERTICAL(x2 - CUTOFF, y2));

            dc.SetPen(m_penDarkGrey);
            dc.DrawLine(REVERSE_FOR_VERTICAL(x + CUTOFF, y2 - 1),
                        REVERSE_FOR_VERTICAL(x2 - CUTOFF + 1, y2 - 1));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2 - 1, y),
                        REVERSE_FOR_VERTICAL(x2 - 1, y2 - CUTOFF + 1));

            if ( flags & wxCONTROL_SELECTED )
            {
                dc.SetPen(m_penLightGrey);

                // overwrite the part of the (double!) border above this tab
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y - 1),
                            REVERSE_FOR_VERTICAL(x2 - 1, y - 1));
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y - 2),
                            REVERSE_FOR_VERTICAL(x2 - 1, y - 2));

                // and the shadow of the tab to the left of us
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y2 - CUTOFF),
                            REVERSE_FOR_VERTICAL(x + 1, y - 1));
            }
            break;
    }

    #undef SELECT_FOR_VERTICAL
    #undef REVERSE_FOR_VERTICAL
}

#endif // wxUSE_NOTEBOOK

#if wxUSE_SLIDER

// ----------------------------------------------------------------------------
// slider
// ----------------------------------------------------------------------------

wxSize
wxWin32Renderer::GetSliderThumbSize(const wxRect& WXUNUSED(rect),
                                    int lenThumb,
                                    wxOrientation orient) const
{
    wxSize size;
    wxCoord width  = wxMax (lenThumb, SLIDER_THUMB_LENGTH) / 2;
    wxCoord height = wxMax (lenThumb, SLIDER_THUMB_LENGTH);

    if (orient == wxHORIZONTAL)
    {
        size.x = width;
        size.y = height;
    }
    else
    { // == wxVERTICAL
        size.x = height;
        size.y = width;
    }

    return size;
}

wxRect wxWin32Renderer::GetSliderShaftRect(const wxRect& rectOrig,
                                           int lenThumb,
                                           wxOrientation orient,
                                           long style) const
{
    bool left, right;
    GetSliderLabelsSides(orient, style, &left, &right);

    wxRect rect = rectOrig;

    wxSize sizeThumb = GetSliderThumbSize (rect, lenThumb, orient);

    if (orient == wxHORIZONTAL)
    {
        rect.x += SLIDER_MARGIN;
        if (left & right)
        {
            rect.y += wxMax ((rect.height - 2*BORDER_THICKNESS) / 2, sizeThumb.y/2);
        }
        else if (left)
        {
            rect.y += wxMax ((rect.height - 2*BORDER_THICKNESS - sizeThumb.y/2), sizeThumb.y/2);
        }
        else
        {
            rect.y += sizeThumb.y/2;
        }
        rect.width -= 2*SLIDER_MARGIN;
        rect.height = 2*BORDER_THICKNESS;
    }
    else // == wxVERTICAL
    {
        rect.y += SLIDER_MARGIN;
        if (left & right)
        {
            rect.x += wxMax ((rect.width - 2*BORDER_THICKNESS) / 2, sizeThumb.x/2);
        }
        else if (left)
        {
            rect.x += wxMax ((rect.width - 2*BORDER_THICKNESS - sizeThumb.x/2), sizeThumb.x/2);
        }
        else
        {
            rect.x += sizeThumb.x/2;
        }
        rect.width = 2*BORDER_THICKNESS;
        rect.height -= 2*SLIDER_MARGIN;
    }

    return rect;
}

void wxWin32Renderer::DrawSliderShaft(wxDC& dc,
                                      const wxRect& rectOrig,
                                      int lenThumb,
                                      wxOrientation orient,
                                      int flags,
                                      long style,
                                      wxRect *rectShaft)
{
    /*    show shaft geometry

             shaft
        +-------------+
        |             |
        |     XXX     |  <-- x1
        |     XXX     |
        |     XXX     |
        |     XXX     |
        |     XXX     |  <-- x2
        |             |
        +-------------+

              ^ ^
              | |
             y1 y2
    */

    if (flags & wxCONTROL_FOCUSED)
        DrawFocusRect(NULL, dc, rectOrig);

    wxRect rect = GetSliderShaftRect(rectOrig, lenThumb, orient, style);

    if (rectShaft) *rectShaft = rect;

    DrawSunkenBorder(dc, &rect);
}

void wxWin32Renderer::DrawSliderThumb(wxDC& dc,
                                      const wxRect& rect,
                                      wxOrientation orient,
                                      int flags,
                                      long style)
{
    /*    show thumb geometry

             H       <--- y1
           H H B
         H     H B
       H         H B <--- y3
       H         D B
       H         D B
       H         D B
       H         D B   where H is highlight colour
       H         D B         D    dark grey
       H         D B         B    black
       H         D B
       H         D B
       H         D B <--- y4
         H     D B
           H D B
             B       <--- y2

       ^     ^     ^
       |     |     |
       x1    x3    x2

       The interior of this shape is filled with the hatched brush if the thumb
       is pressed.
    */

    DrawBackground(dc, wxNullColour, rect, flags);

    bool left, right;
    GetSliderLabelsSides(orient, style, &left, &right);

    bool isVertical = orient == wxVERTICAL;

    wxCoord sizeArrow = (isVertical ? rect.height : rect.width) / 2;
    wxCoord c = ((isVertical ? rect.height : rect.width) - 2*sizeArrow);

    wxCoord x1, x2, x3, y1, y2, y3, y4;
    x1 = (isVertical ? rect.y : rect.x);
    x2 = (isVertical ? rect.GetBottom() : rect.GetRight());
    x3 = (x1-1+c) + sizeArrow;
    y1 = (isVertical ? rect.x : rect.y);
    y2 = (isVertical ? rect.GetRight() : rect.GetBottom());
    y3 = (left  ? (y1-1+c) + sizeArrow : y1);
    y4 = (right ? (y2+1-c) - sizeArrow : y2);

    dc.SetPen(m_penBlack);
    if (left)
    {
        DrawLine(dc, x3+1-c, y1, x2, y3, isVertical);
    }
    DrawLine(dc, x2, y3, x2, y4, isVertical);
    if (right)
    {
        DrawLine(dc, x3+1-c, y2, x2, y4, isVertical);
    }
    else
    {
        DrawLine(dc, x1, y2, x2, y2, isVertical);
    }

    dc.SetPen(m_penDarkGrey);
    DrawLine(dc, x2-1, y3+1, x2-1, y4-1, isVertical);
    if (right)
    {
        DrawLine(dc, x3+1-c, y2-1, x2-1, y4, isVertical);
    }
    else
    {
        DrawLine(dc, x1+1, y2-1, x2-1, y2-1, isVertical);
    }

    dc.SetPen(m_penHighlight);
    if (left)
    {
        DrawLine(dc, x1, y3, x3, y1, isVertical);
        DrawLine(dc, x3+1-c, y1+1, x2-1, y3, isVertical);
    }
    else
    {
        DrawLine(dc, x1, y1, x2, y1, isVertical);
    }
    DrawLine(dc, x1, y3, x1, y4, isVertical);
    if (right)
    {
        DrawLine(dc, x1, y4, x3+c, y2+c, isVertical);
    }

    if (flags & wxCONTROL_PRESSED)
    {
        // TODO: MSW fills the entire area inside, not just the rect
        wxRect rectInt = rect;
        if ( isVertical )
        {
            rectInt.SetLeft(y3);
            rectInt.SetRight(y4);
        }
        else
        {
            rectInt.SetTop(y3);
            rectInt.SetBottom(y4);
        }
        rectInt.Deflate(2);

#if !defined(__WXMGL__)
        static const char *stipple_xpm[] = {
            /* columns rows colors chars-per-pixel */
            "2 2 2 1",
            "  c None",
            "w c white",
            /* pixels */
            "w ",
            " w",
        };
#else
        // VS: MGL can only do 8x8 stipple brushes
        static const char *stipple_xpm[] = {
            /* columns rows colors chars-per-pixel */
            "8 8 2 1",
            "  c None",
            "w c white",
            /* pixels */
            "w w w w ",
            " w w w w",
            "w w w w ",
            " w w w w",
            "w w w w ",
            " w w w w",
            "w w w w ",
            " w w w w",
        };
#endif
        dc.SetBrush(wxBrush(stipple_xpm));

        dc.SetTextForeground(wxSCHEME_COLOUR(m_scheme, SHADOW_HIGHLIGHT));
        dc.SetTextBackground(wxSCHEME_COLOUR(m_scheme, CONTROL));
        dc.SetPen(*wxTRANSPARENT_PEN);
        dc.DrawRectangle(rectInt);
    }
}

void wxWin32Renderer::DrawSliderTicks(wxDC& dc,
                                      const wxRect& rect,
                                      int lenThumb,
                                      wxOrientation orient,
                                      int start,
                                      int end,
                                      int step,
                                      int WXUNUSED(flags),
                                      long style)
{
    /*    show ticks geometry

        left        right
        ticks shaft ticks
        ----   XX   ----  <-- x1
        ----   XX   ----
        ----   XX   ----
        ----   XX   ----  <-- x2

        ^  ^        ^  ^
        |  |        |  |
        y3 y1       y2 y4
    */

    // empty slider?
    if ( end == start )
        return;

    bool left, right;
    GetSliderLabelsSides(orient, style, &left, &right);

    bool isVertical = orient == wxVERTICAL;

    // default thumb size
    wxSize sizeThumb = GetSliderThumbSize (rect, 0, orient);
    wxCoord defaultLen = (isVertical ? sizeThumb.x : sizeThumb.y);

    // normal thumb size
    sizeThumb = GetSliderThumbSize (rect, lenThumb, orient);
    wxCoord widthThumb  = (isVertical ? sizeThumb.y : sizeThumb.x);

    wxRect rectShaft = GetSliderShaftRect (rect, lenThumb, orient, style);

    wxCoord x1, x2, y1, y2, y3, y4 , len;
    x1 = (isVertical ? rectShaft.y : rectShaft.x) + widthThumb/2;
    x2 = (isVertical ? rectShaft.GetBottom() : rectShaft.GetRight()) - widthThumb/2;
    y1 = (isVertical ? rectShaft.x : rectShaft.y) - defaultLen/2;
    y2 = (isVertical ? rectShaft.GetRight() : rectShaft.GetBottom()) + defaultLen/2;
    y3 = (isVertical ? rect.x : rect.y);
    y4 = (isVertical ? rect.GetRight() : rect.GetBottom());
    len = x2 - x1;

    dc.SetPen(m_penBlack);

    int range = end - start;
    for ( int n = 0; n < range; n += step )
    {
        wxCoord x = x1 + (len*n) / range;

        if (left & (y1 > y3))
        {
            DrawLine(dc, x, y1, x, y3, orient == wxVERTICAL);
        }
        if (right & (y4 > y2))
        {
            DrawLine(dc, x, y2, x, y4, orient == wxVERTICAL);
        }
    }
    // always draw the line at the end position
    if (left & (y1 > y3))
    {
        DrawLine(dc, x2, y1, x2, y3, orient == wxVERTICAL);
    }
    if (right & (y4 > y2))
    {
        DrawLine(dc, x2, y2, x2, y4, orient == wxVERTICAL);
    }
}

#endif // wxUSE_SLIDER

#if wxUSE_MENUS

// ----------------------------------------------------------------------------
// menu and menubar
// ----------------------------------------------------------------------------

// wxWin32MenuGeometryInfo: the wxMenuGeometryInfo used by wxWin32Renderer
class WXDLLEXPORT wxWin32MenuGeometryInfo : public wxMenuGeometryInfo
{
public:
    virtual wxSize GetSize() const { return m_size; }

    wxCoord GetLabelOffset() const { return m_ofsLabel; }
    wxCoord GetAccelOffset() const { return m_ofsAccel; }

    wxCoord GetItemHeight() const { return m_heightItem; }

private:
    // the total size of the menu
    wxSize m_size;

    // the offset of the start of the menu item label
    wxCoord m_ofsLabel;

    // the offset of the start of the accel label
    wxCoord m_ofsAccel;

    // the height of a normal (not separator) item
    wxCoord m_heightItem;

    friend wxMenuGeometryInfo *
        wxWin32Renderer::GetMenuGeometry(wxWindow *, const wxMenu&) const;
};

// FIXME: all constants are hardcoded but shouldn't be
static const wxCoord MENU_LEFT_MARGIN = 9;
static const wxCoord MENU_RIGHT_MARGIN = 18;
static const wxCoord MENU_VERT_MARGIN = 3;

// the margin around bitmap/check marks (on each side)
static const wxCoord MENU_BMP_MARGIN = 2;

// the margin between the labels and accel strings
static const wxCoord MENU_ACCEL_MARGIN = 8;

// the separator height in pixels: in fact, strangely enough, the real height
// is 2 but Windows adds one extra pixel in the bottom margin, so take it into
// account here
static const wxCoord MENU_SEPARATOR_HEIGHT = 3;

// the size of the standard checkmark bitmap
static const wxCoord MENU_CHECK_SIZE = 9;

void wxWin32Renderer::DrawMenuBarItem(wxDC& dc,
                                      const wxRect& rectOrig,
                                      const wxString& label,
                                      int flags,
                                      int indexAccel)
{
    wxRect rect = rectOrig;
    rect.height--;

    wxDCTextColourChanger colChanger(dc);

    if ( flags & wxCONTROL_SELECTED )
    {
        colChanger.Set(wxSCHEME_COLOUR(m_scheme, HIGHLIGHT_TEXT));

        const wxColour colBg = wxSCHEME_COLOUR(m_scheme, HIGHLIGHT);
        dc.SetBrush(colBg);
        dc.SetPen(colBg);
        dc.DrawRectangle(rect);
    }

    // don't draw the focus rect around menu bar items
    DrawLabel(dc, label, rect, flags & ~wxCONTROL_FOCUSED,
              wxALIGN_CENTRE, indexAccel);
}

void wxWin32Renderer::DrawMenuItem(wxDC& dc,
                                   wxCoord y,
                                   const wxMenuGeometryInfo& gi,
                                   const wxString& label,
                                   const wxString& accel,
                                   const wxBitmap& bitmap,
                                   int flags,
                                   int indexAccel)
{
    const wxWin32MenuGeometryInfo& geometryInfo =
        (const wxWin32MenuGeometryInfo&)gi;

    wxRect rect;
    rect.x = 0;
    rect.y = y;
    rect.width = geometryInfo.GetSize().x;
    rect.height = geometryInfo.GetItemHeight();

    // draw the selected item specially
    wxDCTextColourChanger colChanger(dc);
    if ( flags & wxCONTROL_SELECTED )
    {
        colChanger.Set(wxSCHEME_COLOUR(m_scheme, HIGHLIGHT_TEXT));

        const wxColour colBg = wxSCHEME_COLOUR(m_scheme, HIGHLIGHT);
        dc.SetBrush(colBg);
        dc.SetPen(colBg);
        dc.DrawRectangle(rect);
    }

    // draw the bitmap: use the bitmap provided or the standard checkmark for
    // the checkable items
    wxBitmap bmp = bitmap;
    if ( !bmp.Ok() && (flags & wxCONTROL_CHECKED) )
    {
        bmp = GetIndicator(IndicatorType_Menu, flags);
    }

    if ( bmp.Ok() )
    {
        rect.SetRight(geometryInfo.GetLabelOffset());
        wxControlRenderer::DrawBitmap(dc, bmp, rect);
    }

    // draw the label
    rect.x = geometryInfo.GetLabelOffset();
    rect.SetRight(geometryInfo.GetAccelOffset());

    DrawLabel(dc, label, rect, flags, wxALIGN_CENTRE_VERTICAL, indexAccel);

    // draw the accel string
    rect.x = geometryInfo.GetAccelOffset();
    rect.SetRight(geometryInfo.GetSize().x);

    // NB: no accel index here
    DrawLabel(dc, accel, rect, flags, wxALIGN_CENTRE_VERTICAL);

    // draw the submenu indicator
    if ( flags & wxCONTROL_ISSUBMENU )
    {
        rect.x = geometryInfo.GetSize().x - MENU_RIGHT_MARGIN;
        rect.width = MENU_RIGHT_MARGIN;

        ArrowStyle arrowStyle;
        if ( flags & wxCONTROL_DISABLED )
            arrowStyle = flags & wxCONTROL_SELECTED ? Arrow_InvertedDisabled
                                                    : Arrow_Disabled;
        else if ( flags & wxCONTROL_SELECTED )
            arrowStyle = Arrow_Inverted;
        else
            arrowStyle = Arrow_Normal;

        DrawArrow(dc, rect, Arrow_Right, arrowStyle);
    }
}

void wxWin32Renderer::DrawMenuSeparator(wxDC& dc,
                                        wxCoord y,
                                        const wxMenuGeometryInfo& geomInfo)
{
    DrawHorizontalLine(dc, y + MENU_VERT_MARGIN, 0, geomInfo.GetSize().x);
}

wxSize wxWin32Renderer::GetMenuBarItemSize(const wxSize& sizeText) const
{
    wxSize size = sizeText;

    // FIXME: menubar height is configurable under Windows
    size.x += 12;
    size.y += 6;

    return size;
}

wxMenuGeometryInfo *wxWin32Renderer::GetMenuGeometry(wxWindow *win,
                                                     const wxMenu& menu) const
{
    // prepare the dc: for now we draw all the items with the system font
    wxClientDC dc(win);
    dc.SetFont(wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT));

    // the height of a normal item
    wxCoord heightText = dc.GetCharHeight();

    // the total height
    wxCoord height = 0;

    // the max length of label and accel strings: the menu width is the sum of
    // them, even if they're for different items (as the accels should be
    // aligned)
    //
    // the max length of the bitmap is never 0 as Windows always leaves enough
    // space for a check mark indicator
    wxCoord widthLabelMax = 0,
            widthAccelMax = 0,
            widthBmpMax = MENU_LEFT_MARGIN;

    for ( wxMenuItemList::compatibility_iterator node = menu.GetMenuItems().GetFirst();
          node;
          node = node->GetNext() )
    {
        // height of this item
        wxCoord h;

        wxMenuItem *item = node->GetData();
        if ( item->IsSeparator() )
        {
            h = MENU_SEPARATOR_HEIGHT;
        }
        else // not separator
        {
            h = heightText;

            wxCoord widthLabel;
            dc.GetTextExtent(item->GetItemLabelText(), &widthLabel, NULL);
            if ( widthLabel > widthLabelMax )
            {
                widthLabelMax = widthLabel;
            }

            wxCoord widthAccel;
            dc.GetTextExtent(item->GetAccelString(), &widthAccel, NULL);
            if ( widthAccel > widthAccelMax )
            {
                widthAccelMax = widthAccel;
            }

            const wxBitmap& bmp = item->GetBitmap();
            if ( bmp.Ok() )
            {
                wxCoord widthBmp = bmp.GetWidth();
                if ( widthBmp > widthBmpMax )
                    widthBmpMax = widthBmp;
            }
            //else if ( item->IsCheckable() ): no need to check for this as
            // MENU_LEFT_MARGIN is big enough to show the check mark
        }

        h += 2*MENU_VERT_MARGIN;

        // remember the item position and height
        item->SetGeometry(height, h);

        height += h;
    }

    // bundle the metrics into a struct and return it
    wxWin32MenuGeometryInfo *gi = new wxWin32MenuGeometryInfo;

    gi->m_ofsLabel = widthBmpMax + 2*MENU_BMP_MARGIN;
    gi->m_ofsAccel = gi->m_ofsLabel + widthLabelMax;
    if ( widthAccelMax > 0 )
    {
        // if we actually have any accesl, add a margin
        gi->m_ofsAccel += MENU_ACCEL_MARGIN;
    }

    gi->m_heightItem = heightText + 2*MENU_VERT_MARGIN;

    gi->m_size.x = gi->m_ofsAccel + widthAccelMax + MENU_RIGHT_MARGIN;
    gi->m_size.y = height;

    return gi;
}

#endif // wxUSE_MENUS

#if wxUSE_STATUSBAR

// ----------------------------------------------------------------------------
// status bar
// ----------------------------------------------------------------------------

void wxWin32Renderer::DrawStatusField(wxDC& dc,
                                      const wxRect& rect,
                                      const wxString& label,
                                      int flags,
                                      int style)
{
    wxRect rectIn;

    if ( flags & wxCONTROL_SIZEGRIP )
    {
        // draw the size grip: it is a normal rect except that in the lower
        // right corner we have several bands which may be used for dragging
        // the status bar corner
        //
        // each band consists of 4 stripes: m_penHighlight, double
        // m_penDarkGrey and transparent one
        wxCoord x2 = rect.GetRight(),
                y2 = rect.GetBottom();

        // draw the upper left part of the rect normally
        if (style != wxSB_FLAT)
        {
            if (style == wxSB_RAISED)
                dc.SetPen(m_penHighlight);
            else
                dc.SetPen(m_penDarkGrey);
            dc.DrawLine(rect.GetLeft(), rect.GetTop(), rect.GetLeft(), y2);
            dc.DrawLine(rect.GetLeft() + 1, rect.GetTop(), x2, rect.GetTop());
        }

        // draw the grey stripes of the grip
        size_t n;
        wxCoord ofs = WIDTH_STATUSBAR_GRIP_BAND - 1;
        for ( n = 0; n < NUM_STATUSBAR_GRIP_BANDS; n++, ofs += WIDTH_STATUSBAR_GRIP_BAND )
        {
            dc.DrawLine(x2 - ofs + 1, y2 - 1, x2, y2 - ofs);
            dc.DrawLine(x2 - ofs, y2 - 1, x2, y2 - ofs - 1);
        }

        // draw the white stripes
        dc.SetPen(m_penHighlight);
        ofs = WIDTH_STATUSBAR_GRIP_BAND + 1;
        for ( n = 0; n < NUM_STATUSBAR_GRIP_BANDS; n++, ofs += WIDTH_STATUSBAR_GRIP_BAND )
        {
            dc.DrawLine(x2 - ofs + 1, y2 - 1, x2, y2 - ofs);
        }

        // draw the remaining rect boundaries
        if (style != wxSB_FLAT)
        {
            if (style == wxSB_RAISED)
                dc.SetPen(m_penDarkGrey);
            else
                dc.SetPen(m_penHighlight);
            ofs -= WIDTH_STATUSBAR_GRIP_BAND;
            dc.DrawLine(x2, rect.GetTop(), x2, y2 - ofs + 1);
            dc.DrawLine(rect.GetLeft(), y2, x2 - ofs + 1, y2);
        }

        rectIn = rect;
        rectIn.Deflate(1);

        rectIn.width -= STATUSBAR_GRIP_SIZE;

        // this will prevent the standard version from drawing any borders
        style = wxSB_FLAT;
    }

    wxStdRenderer::DrawStatusField(dc, rect, label, flags, style);
}

#endif // wxUSE_STATUSBAR

// ----------------------------------------------------------------------------
// combobox
// ----------------------------------------------------------------------------

void wxWin32Renderer::GetComboBitmaps(wxBitmap *bmpNormal,
                                      wxBitmap * WXUNUSED(bmpFocus),
                                      wxBitmap *bmpPressed,
                                      wxBitmap *bmpDisabled)
{
    static const wxCoord widthCombo = 16;
    static const wxCoord heightCombo = 17;

    wxMemoryDC dcMem;

    if ( bmpNormal )
    {
        bmpNormal->Create(widthCombo, heightCombo);
        dcMem.SelectObject(*bmpNormal);
        DrawArrowButton(dcMem, wxRect(0, 0, widthCombo, heightCombo),
                        Arrow_Down, Arrow_Normal);
    }

    if ( bmpPressed )
    {
        bmpPressed->Create(widthCombo, heightCombo);
        dcMem.SelectObject(*bmpPressed);
        DrawArrowButton(dcMem, wxRect(0, 0, widthCombo, heightCombo),
                        Arrow_Down, Arrow_Pressed);
    }

    if ( bmpDisabled )
    {
        bmpDisabled->Create(widthCombo, heightCombo);
        dcMem.SelectObject(*bmpDisabled);
        DrawArrowButton(dcMem, wxRect(0, 0, widthCombo, heightCombo),
                        Arrow_Down, Arrow_Disabled);
    }
}

// ----------------------------------------------------------------------------
// scrollbar
// ----------------------------------------------------------------------------

void wxWin32Renderer::DrawArrowBorder(wxDC& dc, wxRect *rect, bool isPressed)
{
    if ( isPressed )
    {
        DrawRect(dc, rect, m_penDarkGrey);

        // the arrow is usually drawn inside border of width 2 and is offset by
        // another pixel in both directions when it's pressed - as the border
        // in this case is more narrow as well, we have to adjust rect like
        // this:
        rect->Inflate(-1);
        rect->x++;
        rect->y++;
    }
    else // !pressed
    {
        DrawAntiSunkenBorder(dc, rect);
    }
}

void wxWin32Renderer::DrawArrow(wxDC& dc,
                                wxDirection dir,
                                const wxRect& rect,
                                int flags)
{
    ArrowStyle arrowStyle;
    if ( flags & wxCONTROL_PRESSED )
    {
        // can't be pressed and disabled
        arrowStyle = Arrow_Pressed;
    }
    else
    {
        arrowStyle = flags & wxCONTROL_DISABLED ? Arrow_Disabled : Arrow_Normal;
    }

    DrawArrowButton(dc, rect, GetArrowDirection(dir), arrowStyle);
}

void wxWin32Renderer::DrawArrow(wxDC& dc,
                                const wxRect& rect,
                                ArrowDirection arrowDir,
                                ArrowStyle arrowStyle)
{
    const wxBitmap& bmp = m_bmpArrows[arrowStyle][arrowDir];

    // under Windows the arrows always have the same size so just centre it in
    // the provided rectangle
    wxCoord x = rect.x + (rect.width - bmp.GetWidth()) / 2,
            y = rect.y + (rect.height - bmp.GetHeight()) / 2;

    // Windows does it like this...
    if ( arrowDir == Arrow_Left )
        x--;

    // draw it
    dc.DrawBitmap(bmp, x, y, true /* use mask */);
}

void wxWin32Renderer::DrawArrowButton(wxDC& dc,
                                      const wxRect& rectAll,
                                      ArrowDirection arrowDir,
                                      ArrowStyle arrowStyle)
{
    wxRect rect = rectAll;
    DrawBackground(dc, wxSCHEME_COLOUR(m_scheme, CONTROL), rect);
    DrawArrowBorder(dc, &rect, arrowStyle == Arrow_Pressed);
    DrawArrow(dc, rect, arrowDir, arrowStyle);
}

void wxWin32Renderer::DrawScrollbarThumb(wxDC& dc,
                                         wxOrientation WXUNUSED(orient),
                                         const wxRect& rect,
                                         int WXUNUSED(flags))
{
    // we don't use the flags, the thumb never changes appearance
    wxRect rectThumb = rect;
    DrawArrowBorder(dc, &rectThumb);
    DrawBackground(dc, wxNullColour, rectThumb);
}

void wxWin32Renderer::DrawScrollbarShaft(wxDC& dc,
                                         wxOrientation WXUNUSED(orient),
                                         const wxRect& rectBar,
                                         int flags)
{
    wxColourScheme::StdColour col = flags & wxCONTROL_PRESSED
                                    ? wxColourScheme::SCROLLBAR_PRESSED
                                    : wxColourScheme::SCROLLBAR;
    DrawBackground(dc, m_scheme->Get(col), rectBar);
}

// ----------------------------------------------------------------------------
// standard icons
// ----------------------------------------------------------------------------

/* Copyright (c) Julian Smart */
static const char *error_xpm[]={
/* columns rows colors chars-per-pixel */
"32 32 70 1",
"- c #BF0101",
"b c #361F1F",
"& c #C08484",
"X c #BF3333",
"# c #C08181",
"% c #C01111",
"d c #C51515",
"s c #551818",
"O c #C07E7E",
": c #C00E0E",
"u c #E28A8A",
"2 c #C81F1F",
"8 c #FFFFFF",
"p c #E59494",
"< c #BB0101",
"y c #DA6A6A",
"A c #4C4C4C",
"9 c #F7DFDF",
"@ c #BF5353",
"w c #FAE9E9",
"F c #272727",
"5 c #D24A4A",
". c #C06363",
"n c #BF8282",
"7 c #F2C9C9",
"t c #C09292",
"M c #3E3E3E",
"x c #4D4D4D",
"4 c #CA2A2A",
"h c #E79F9F",
"* c #C05454",
"D c #711212",
"V c #737373",
"$ c #BF3232",
"N c #900B0B",
"6 c #BD0303",
"3 c #DF7F7F",
"K c #6F1212",
"C c #BD0000",
"m c #950909",
"P c #8A8A8A",
"j c #D75F5F",
"  c None",
"e c #F4D4D4",
"S c #BF2020",
"L c #747474",
"G c #842C2C",
"c c #ECB4B4",
"l c #2E2121",
"g c #BF7E7E",
"k c #9B0808",
"= c #BF0505",
"a c #B10303",
"q c #7E2020",
"1 c #642222",
"J c #676767",
"B c #322020",
"; c #C00303",
"i c #242424",
"o c #C00000",
"> c #BF1F1F",
", c #842B2B",
"f c #701212",
"0 c #BE0000",
"r c #960909",
"H c #686868",
"v c #BC0000",
"Z c #671414",
"+ c #C02020",
"z c #CD3535",
/* pixels */
"                                ",
"                                ",
"            .XoooOO             ",
"         .+ooooooooo@#          ",
"        $oooooooooooo%&         ",
"      *=-ooooooooooooo;:        ",
"     *oooooooooooooooooo>       ",
"     =ooooooooooooooooooo,      ",
"    $-ooooooooooooooooooo<1     ",
"   .oooooo2334ooo533oooooo6     ",
"   +ooooooo789oo2883oooooo0q    ",
"   oooooooo2w83o78eoooooooor    ",
"  toooooooooy88u884oooooooori   ",
"  Xooooooooooe888poooooooooas   ",
"  ooooooooooo4889doooooooooof   ",
"  ooooooooooo588w2oooooooooofi  ",
"  oooooooooodw8887oooooooooofi  ",
"  goooooooooh8w588jooooooookli  ",
"  tooooooooz885op8wdooooooorix  ",
"   oooooood98cood98cooooooori   ",
"   @oooooop8w2ooo5885ooooovbi   ",
"   n%ooooooooooooooooooooomiM   ",
"    &;oooooooooooooooooooNBiV   ",
"     :ooooooooooooooooooCZiA    ",
"     nSooooooooooooooooCDiF     ",
"      nG<oooooooooooooNZiiH     ",
"        160ooooooooovmBiFH      ",
"         nqrraoookrrbiiA        ",
"          nJisKKKliiiML         ",
"             nPiiix             ",
"                                ",
"                                "
};

/* Copyright (c) Julian Smart */
static const char *info_xpm[]={
/* columns rows colors chars-per-pixel */
"32 32 17 1",
"* c #A1A3FB",
"X c #FFFFFF",
"O c #191EF4",
"= c #777AF9",
": c #4D51F7",
"  c None",
"- c #2328F5",
"+ c #4247F6",
"; c #C1C2FC",
". c #C0C0C0",
"& c #E0E1FE",
"% c #242424",
"> c #2D32F5",
"o c #CBCCFD",
"# c #0309F3",
"@ c #8C8FFA",
"$ c #EAEBFE",
/* pixels */
"          .......               ",
"       ...XXXXXXX...            ",
"     ..XXXXXXXXXXXXX..          ",
"    .XXXXXXXXXXXXXXXXX.         ",
"   .XXXXXXXXoO+XXXXXXXX.        ",
"  .XXXXXXXXX@#OXXXXXXXXX.       ",
" .XXXXXXXXXX$@oXXXXXXXXXX.      ",
" .XXXXXXXXXXXXXXXXXXXXXXX.%     ",
" .XXXXXXXXX&*=-XXXXXXXXXX.%%    ",
".XXXXXXXXXX;:#>XXXXXXXXXXX.%    ",
".XXXXXXXXXXX;#+XXXXXXXXXXX.%    ",
".XXXXXXXXXXX;#+XXXXXXXXXXX.%%   ",
" .XXXXXXXXXX;#+XXXXXXXXXX.%%%   ",
" .XXXXXXXXXX;#+XXXXXXXXXX.%%%   ",
" .XXXXXXXXXX;#+XXXXXXXXXX.%%    ",
"  .XXXXXXXX*-##+XXXXXXXX.%%%    ",
"   .XXXXXXXXXXXXXXXXXXX.%%%%    ",
"    .XXXXXXXXXXXXXXXXX.%%%%     ",
"     ..XXXXXXXXXXXXX..%%%%      ",
"      %...XXXXXXXX..%%%%%       ",
"       %%%..XXXXXX.%%%%%        ",
"         %%%.XXXXX.%%%          ",
"            %.XXXX.%%           ",
"              .XXX.%%           ",
"               .XX.%%           ",
"                .X.%%           ",
"                 ..%%           ",
"                  .%%           ",
"                   %%           ",
"                    %           ",
"                                ",
"                                "
};

/* Copyright (c) Julian Smart */
static const char *question_xpm[]={
/* columns rows colors chars-per-pixel */
"32 32 16 1",
"O c #A3A3FF",
"X c #FFFFFF",
"% c #CACAFF",
"- c #4141FF",
"= c #6060FF",
"* c #2B2BFF",
"@ c #B5B5FF",
"  c None",
"# c #1616FF",
"+ c #8181FF",
"$ c #0000FF",
". c #C0C0C0",
"; c #5555FF",
": c #242424",
"o c #E7E7FF",
"& c #7575FF",
/* pixels */
"          .......               ",
"       ...XXXXXXX...            ",
"     ..XXXXXXXXXXXXX..          ",
"    .XXXXXXoO++@XXXXXX.         ",
"   .XXXXXXO#$$$$#%XXXXX.        ",
"  .XXXXXX@$$#&&#$#oXXXXX.       ",
" .XXXXXXX*$$%XX%$$=XXXXXX.      ",
" .XXXXXXX+-;XXXX$$-XXXXXX.:     ",
" .XXXXXXXXXXXXX+$$&XXXXXX.::    ",
".XXXXXXXXXXXXo;$$*oXXXXXXX.:    ",
".XXXXXXXXXXXo*$$*oXXXXXXXX.:    ",
".XXXXXXXXXXX+$$*oXXXXXXXXX.::   ",
" .XXXXXXXXXX-$$oXXXXXXXXX.:::   ",
" .XXXXXXXXXXX--XXXXXXXXXX.:::   ",
" .XXXXXXXXXXXXXXXXXXXXXXX.::    ",
"  .XXXXXXXXX-$$XXXXXXXXX.:::    ",
"   .XXXXXXXX-$$XXXXXXXX.::::    ",
"    .XXXXXXXO++XXXXXXX.::::     ",
"     ..XXXXXXXXXXXXX..::::      ",
"      :...XXXXXXXX..:::::       ",
"       :::..XXXXXX.:::::        ",
"         :::.XXXXX.:::          ",
"            :.XXXX.::           ",
"              .XXX.::           ",
"               .XX.::           ",
"                .X.::           ",
"                 ..::           ",
"                  .::           ",
"                   ::           ",
"                    :           ",
"                                ",
"                                "
};

/* Copyright (c) Julian Smart */
static const char *warning_xpm[]={
/* columns rows colors chars-per-pixel */
"32 32 9 1",
"@ c Black",
"o c #A6A800",
"+ c #8A8C00",
"$ c #B8BA00",
"  c None",
"O c #6E7000",
"X c #DCDF00",
". c #C00000",
"# c #373800",
/* pixels */
"                                ",
"                                ",
"                                ",
"                .               ",
"               ...              ",
"               ...              ",
"              .....             ",
"             ...X..             ",
"             ..XXX..            ",
"            ...XXX...           ",
"            ..XXXXX..           ",
"           ..XXXXXX...          ",
"          ...XXoO+XX..          ",
"          ..XXXO@#XXX..         ",
"         ..XXXXO@#XXX...        ",
"        ...XXXXO@#XXXX..        ",
"        ..XXXXXO@#XXXX...       ",
"       ...XXXXXo@OXXXXX..       ",
"      ...XXXXXXo@OXXXXXX..      ",
"      ..XXXXXXX$@OXXXXXX...     ",
"     ...XXXXXXXX@XXXXXXXX..     ",
"    ...XXXXXXXXXXXXXXXXXX...    ",
"    ..XXXXXXXXXXOXXXXXXXXX..    ",
"   ...XXXXXXXXXO@#XXXXXXXXX..   ",
"   ..XXXXXXXXXXX#XXXXXXXXXX...  ",
"  ...XXXXXXXXXXXXXXXXXXXXXXX..  ",
" ...XXXXXXXXXXXXXXXXXXXXXXXX... ",
" .............................. ",
" .............................. ",
"                                ",
"                                ",
"                                "
};


wxBitmap wxWin32ArtProvider::CreateBitmap(const wxArtID& id,
                                          const wxArtClient& WXUNUSED(client),
                                          const wxSize& WXUNUSED(size))
{
    if ( id == wxART_INFORMATION )
        return wxBitmap(info_xpm);
    if ( id == wxART_ERROR )
        return wxBitmap(error_xpm);
    if ( id == wxART_WARNING )
        return wxBitmap(warning_xpm);
    if ( id == wxART_QUESTION )
        return wxBitmap(question_xpm);
    return wxNullBitmap;
}


#if wxUSE_TEXTCTRL

// ----------------------------------------------------------------------------
// text control geometry
// ----------------------------------------------------------------------------

wxRect
wxWin32Renderer::GetTextTotalArea(const wxTextCtrl *text,
                                  const wxRect& rect) const
{
    wxRect rectTotal = wxStdRenderer::GetTextTotalArea(text, rect);

    // this is strange but it's what Windows does
    rectTotal.height++;

    return rectTotal;
}

wxRect
wxWin32Renderer::GetTextClientArea(const wxTextCtrl *text,
                                   const wxRect& rect,
                                   wxCoord *extraSpaceBeyond) const
{
    wxRect rectText = rect;

    // undo GetTextTotalArea()
    if ( rectText.height > 0 )
        rectText.height--;

    return wxStdRenderer::GetTextClientArea(text, rect, extraSpaceBeyond);
}

#endif // wxUSE_TEXTCTRL

// ----------------------------------------------------------------------------
// size adjustments
// ----------------------------------------------------------------------------

void wxWin32Renderer::AdjustSize(wxSize *size, const wxWindow *window)
{
#if wxUSE_SCROLLBAR
    if ( wxDynamicCast(window, wxScrollBar) )
    {
        // we only set the width of vert scrollbars and height of the
        // horizontal ones
        if ( window->GetWindowStyle() & wxSB_HORIZONTAL )
            size->y = m_sizeScrollbarArrow.y;
        else
            size->x = m_sizeScrollbarArrow.x;

        // skip border width adjustments, they don't make sense for us
        return;
    }
#endif // wxUSE_SCROLLBAR

#if wxUSE_BMPBUTTON
    if ( wxDynamicCast(window, wxBitmapButton) )
    {
        // do nothing
    } else
#endif // wxUSE_BMPBUTTON
#if wxUSE_BUTTON || wxUSE_TOGGLEBTN
    if ( 0
#  if wxUSE_BUTTON
         || wxDynamicCast(window, wxButton)
#  endif // wxUSE_BUTTON
#  if wxUSE_TOGGLEBTN
         || wxDynamicCast(window, wxToggleButton)
#  endif // wxUSE_TOGGLEBTN
        )
    {
        if ( !(window->GetWindowStyle() & wxBU_EXACTFIT) )
        {
            // TODO: don't harcode all this
            size->x += 3*window->GetCharWidth();

            wxCoord heightBtn = (11*(window->GetCharHeight() + 8))/10;
            if ( size->y < heightBtn - 8 )
                size->y = heightBtn;
            else
                size->y += 9;
        }

        // for compatibility with other ports, the buttons default size is never
        // less than the standard one, but not when display not PDAs.
        if (wxSystemSettings::GetScreenType() > wxSYS_SCREEN_PDA)
        {
            if ( !(window->GetWindowStyle() & wxBU_EXACTFIT) )
            {
                wxSize szDef = wxButton::GetDefaultSize();
                if ( size->x < szDef.x )
                    size->x = szDef.x;
            }
        }

        // no border width adjustments for buttons
        return;
    }
#endif // wxUSE_BUTTON || wxUSE_TOGGLEBTN

    wxStdRenderer::AdjustSize(size, window);
}

wxBitmap wxWin32Renderer::GetFrameButtonBitmap(FrameButtonType type)
{
    wxBitmap& bmp = m_bmpFrameButtons[type];
    if ( !bmp.Ok() )
    {
        bmp = wxBitmap(ms_xpmFrameButtons[type]);
    }

    return bmp;
}

// ============================================================================
// wxInputHandler
// ============================================================================

// ----------------------------------------------------------------------------
// wxWin32InputHandler
// ----------------------------------------------------------------------------

bool wxWin32InputHandler::HandleKey(wxInputConsumer * WXUNUSED(control),
                                    const wxKeyEvent& WXUNUSED(event),
                                    bool WXUNUSED(pressed))
{
    return false;
}

bool wxWin32InputHandler::HandleMouse(wxInputConsumer *control,
                                      const wxMouseEvent& event)
{
    // clicking on the control gives it focus
    if ( event.ButtonDown() )
    {
        wxWindow * const win = control->GetInputWindow();

        if ( win->CanAcceptFocus() && wxWindow::FindFocus() != win )
        {
            win->SetFocus();

            return true;
        }
    }

    return false;
}

#if wxUSE_SCROLLBAR

// ----------------------------------------------------------------------------
// wxWin32ScrollBarInputHandler
// ----------------------------------------------------------------------------

wxWin32ScrollBarInputHandler::
wxWin32ScrollBarInputHandler(wxRenderer *renderer, wxInputHandler *handler)
        : wxStdScrollBarInputHandler(renderer, handler)
{
    m_scrollPaused = false;
    m_interval = 0;
}

bool wxWin32ScrollBarInputHandler::OnScrollTimer(wxScrollBar *scrollbar,
                                                 const wxControlAction& action)
{
    // stop if went beyond the position of the original click (this can only
    // happen when we scroll by pages)
    bool stop = false;
    if ( action == wxACTION_SCROLL_PAGE_DOWN )
    {
        stop = scrollbar->HitTestBar(m_ptStartScrolling) != wxHT_SCROLLBAR_BAR_2;
    }
    else if ( action == wxACTION_SCROLL_PAGE_UP )
    {
        stop = scrollbar->HitTestBar(m_ptStartScrolling) != wxHT_SCROLLBAR_BAR_1;
    }

    if ( stop )
    {
        StopScrolling(scrollbar);

        scrollbar->Refresh();

        return false;
    }

    return wxStdScrollBarInputHandler::OnScrollTimer(scrollbar, action);
}

bool wxWin32ScrollBarInputHandler::HandleMouse(wxInputConsumer *control,
                                               const wxMouseEvent& event)
{
    // remember the current state
    bool wasDraggingThumb = m_htLast == wxHT_SCROLLBAR_THUMB;

    // do process the message
    bool rc = wxStdScrollBarInputHandler::HandleMouse(control, event);

    // analyse the changes
    if ( !wasDraggingThumb && (m_htLast == wxHT_SCROLLBAR_THUMB) )
    {
        // we just started dragging the thumb, remember its initial position to
        // be able to restore it if the drag is cancelled later
        m_eventStartDrag = event;
    }

    return rc;
}

bool wxWin32ScrollBarInputHandler::HandleMouseMove(wxInputConsumer *control,
                                                   const wxMouseEvent& event)
{
    // we don't highlight scrollbar elements, so there is no need to process
    // mouse move events normally - only do it while mouse is captured (i.e.
    // when we're dragging the thumb or pressing on something)
    if ( !m_winCapture )
        return false;

    if ( event.Entering() )
    {
        // we're not interested in this at all
        return false;
    }

    wxScrollBar *scrollbar = wxStaticCast(control->GetInputWindow(), wxScrollBar);
    wxHitTest ht;
    if ( m_scrollPaused )
    {
        // check if the mouse returned to its original location

        if ( event.Leaving() )
        {
            // it surely didn't
            return false;
        }

        ht = scrollbar->HitTestBar(event.GetPosition());
        if ( ht == m_htLast )
        {
            // yes it did, resume scrolling
            m_scrollPaused = false;
            if ( m_timerScroll )
            {
                // we were scrolling by line/page, restart timer
                m_timerScroll->Start(m_interval);

                Press(scrollbar, true);
            }
            else // we were dragging the thumb
            {
                // restore its last location
                HandleThumbMove(scrollbar, m_eventLastDrag);
            }

            return true;
        }
    }
    else // normal case, scrolling hasn't been paused
    {
        // if we're scrolling the scrollbar because the arrow or the shaft was
        // pressed, check that the mouse stays on the same scrollbar element

#if 0
        // Always let thumb jump back if we leave the scrollbar
        if ( event.Moving() )
        {
            ht = scrollbar->HitTestBar(event.GetPosition());
        }
        else // event.Leaving()
        {
            ht = wxHT_NOWHERE;
        }
#else
        // Jump back only if we get far away from it
        wxPoint pos = event.GetPosition();
        if (scrollbar->HasFlag( wxVERTICAL ))
        {
            if (pos.x > -40 && pos.x < scrollbar->GetSize().x+40)
               pos.x = 5;
        }
        else
        {
            if (pos.y > -40 && pos.y < scrollbar->GetSize().y+40)
               pos.y = 5;
        }
        ht = scrollbar->HitTestBar(pos);
#endif

        // if we're dragging the thumb and the mouse stays in the scrollbar, it
        // is still ok - we only want to catch the case when the mouse leaves
        // the scrollbar here
        if ( m_htLast == wxHT_SCROLLBAR_THUMB && ht != wxHT_NOWHERE )
        {
            ht = wxHT_SCROLLBAR_THUMB;
        }

        if ( ht != m_htLast )
        {
            // what were we doing? 2 possibilities: either an arrow/shaft was
            // pressed in which case we have a timer and so we just stop it or
            // we were dragging the thumb
            if ( m_timerScroll )
            {
                // pause scrolling
                m_interval = m_timerScroll->GetInterval();
                m_timerScroll->Stop();
                m_scrollPaused = true;

                // unpress the arrow
                Press(scrollbar, false);
            }
            else // we were dragging the thumb
            {
                // remember the current thumb position to be able to restore it
                // if the mouse returns to it later
                m_eventLastDrag = event;

                // and restore the original position (before dragging) of the
                // thumb for now
                HandleThumbMove(scrollbar, m_eventStartDrag);
            }

            return true;
        }
    }

    return wxStdInputHandler::HandleMouseMove(control, event);
}

#endif // wxUSE_SCROLLBAR

#if wxUSE_CHECKBOX

// ----------------------------------------------------------------------------
// wxWin32CheckboxInputHandler
// ----------------------------------------------------------------------------

bool wxWin32CheckboxInputHandler::HandleKey(wxInputConsumer *control,
                                            const wxKeyEvent& event,
                                            bool pressed)
{
    if ( pressed )
    {
        wxControlAction action;
        int keycode = event.GetKeyCode();
        switch ( keycode )
        {
            case WXK_SPACE:
                action = wxACTION_CHECKBOX_TOGGLE;
                break;

            case WXK_SUBTRACT:
            case WXK_NUMPAD_SUBTRACT:
                action = wxACTION_CHECKBOX_CHECK;
                break;

            case WXK_ADD:
            case WXK_NUMPAD_ADD:
            case WXK_NUMPAD_EQUAL:
                action = wxACTION_CHECKBOX_CLEAR;
                break;
        }

        if ( !action.IsEmpty() )
        {
            control->PerformAction(action);

            return true;
        }
    }

    return false;
}

#endif // wxUSE_CHECKBOX

#if wxUSE_TEXTCTRL

// ----------------------------------------------------------------------------
// wxWin32TextCtrlInputHandler
// ----------------------------------------------------------------------------

bool wxWin32TextCtrlInputHandler::HandleKey(wxInputConsumer *control,
                                            const wxKeyEvent& event,
                                            bool pressed)
{
    // handle only MSW-specific text bindings here, the others are handled in
    // the base class
    if ( pressed )
    {
        int keycode = event.GetKeyCode();

        wxControlAction action;
        if ( keycode == WXK_DELETE && event.ShiftDown() )
        {
            action = wxACTION_TEXT_CUT;
        }
        else if ( keycode == WXK_INSERT )
        {
            if ( event.ControlDown() )
                action = wxACTION_TEXT_COPY;
            else if ( event.ShiftDown() )
                action = wxACTION_TEXT_PASTE;
        }

        if ( action != wxACTION_NONE )
        {
            control->PerformAction(action);

            return true;
        }
    }

    return wxStdInputHandler::HandleKey(control, event, pressed);
}

#endif // wxUSE_TEXTCTRL

#if wxUSE_STATUSBAR

// ----------------------------------------------------------------------------
// wxWin32StatusBarInputHandler
// ----------------------------------------------------------------------------

wxWin32StatusBarInputHandler::
wxWin32StatusBarInputHandler(wxInputHandler *handler)
    : wxStdInputHandler(handler)
{
    m_isOnGrip = false;
}

bool wxWin32StatusBarInputHandler::IsOnGrip(wxWindow *statbar,
                                            const wxPoint& pt) const
{
    if ( statbar->HasFlag(wxST_SIZEGRIP) &&
         statbar->GetParent()->HasFlag(wxRESIZE_BORDER) )
    {
        wxTopLevelWindow *
            parentTLW = wxDynamicCast(statbar->GetParent(), wxTopLevelWindow);

        wxCHECK_MSG( parentTLW, false,
                     wxT("the status bar should be a child of a TLW") );

        // a maximized window can't be resized anyhow
        if ( !parentTLW->IsMaximized() )
        {
            // VZ: I think that the standard Windows behaviour is to only
            //     show the resizing cursor when the mouse is on top of the
            //     grip itself but apparently different Windows versions behave
            //     differently (?) and it seems a better UI to allow resizing
            //     the status bar even when the mouse is above the grip
            wxSize sizeSbar = statbar->GetSize();

            int diff = sizeSbar.x - pt.x;
            return diff >= 0 && diff < (wxCoord)STATUSBAR_GRIP_SIZE;
        }
    }

    return false;
}

bool wxWin32StatusBarInputHandler::HandleMouse(wxInputConsumer *consumer,
                                               const wxMouseEvent& event)
{
    if ( event.Button(1) )
    {
        if ( event.ButtonDown(1) )
        {
            wxWindow *statbar = consumer->GetInputWindow();

            if ( IsOnGrip(statbar, event.GetPosition()) )
            {
                wxTopLevelWindow *tlw = wxDynamicCast(statbar->GetParent(),
                                                      wxTopLevelWindow);
                if ( tlw )
                {
                    tlw->PerformAction(wxACTION_TOPLEVEL_RESIZE,
                                       wxHT_TOPLEVEL_BORDER_SE);

                    statbar->SetCursor(m_cursorOld);

                    return true;
                }
            }
        }
    }

    return wxStdInputHandler::HandleMouse(consumer, event);
}

bool wxWin32StatusBarInputHandler::HandleMouseMove(wxInputConsumer *consumer,
                                                   const wxMouseEvent& event)
{
    wxWindow *statbar = consumer->GetInputWindow();

    bool isOnGrip = IsOnGrip(statbar, event.GetPosition());
    if ( isOnGrip != m_isOnGrip )
    {
        m_isOnGrip = isOnGrip;
        if ( isOnGrip )
        {
            m_cursorOld = statbar->GetCursor();
            statbar->SetCursor(wxCURSOR_SIZENWSE);
        }
        else
        {
            statbar->SetCursor(m_cursorOld);
        }
    }

    return wxStdInputHandler::HandleMouseMove(consumer, event);
}

#endif // wxUSE_STATUSBAR

// ----------------------------------------------------------------------------
// wxWin32FrameInputHandler
// ----------------------------------------------------------------------------

class wxWin32SystemMenuEvtHandler : public wxEvtHandler
{
public:
    wxWin32SystemMenuEvtHandler(wxWin32FrameInputHandler *handler);

    void Attach(wxInputConsumer *consumer);
    void Detach();

private:
    DECLARE_EVENT_TABLE()
    void OnSystemMenu(wxCommandEvent &event);
    void OnCloseFrame(wxCommandEvent &event);
    void OnClose(wxCloseEvent &event);

    wxWin32FrameInputHandler *m_inputHnd;
    wxTopLevelWindow         *m_wnd;
#if wxUSE_ACCEL
    wxAcceleratorTable        m_oldAccelTable;
#endif
};

wxWin32SystemMenuEvtHandler::
wxWin32SystemMenuEvtHandler(wxWin32FrameInputHandler *handler)
{
    m_inputHnd = handler;
    m_wnd = NULL;
}

void wxWin32SystemMenuEvtHandler::Attach(wxInputConsumer *consumer)
{
    wxASSERT_MSG( m_wnd == NULL, wxT("can't attach the handler twice!") );

    m_wnd = wxStaticCast(consumer->GetInputWindow(), wxTopLevelWindow);
    m_wnd->PushEventHandler(this);

#if wxUSE_ACCEL
    // VS: This code relies on using generic implementation of
    //     wxAcceleratorTable in wxUniv!
    wxAcceleratorTable table = *m_wnd->GetAcceleratorTable();
    m_oldAccelTable = table;
    table.Add(wxAcceleratorEntry(wxACCEL_ALT, WXK_SPACE, wxID_SYSTEM_MENU));
    table.Add(wxAcceleratorEntry(wxACCEL_ALT, WXK_F4, wxID_CLOSE_FRAME));
    m_wnd->SetAcceleratorTable(table);
#endif
}

void wxWin32SystemMenuEvtHandler::Detach()
{
    if ( m_wnd )
    {
#if wxUSE_ACCEL
        m_wnd->SetAcceleratorTable(m_oldAccelTable);
#endif
        m_wnd->RemoveEventHandler(this);
        m_wnd = NULL;
    }
}

BEGIN_EVENT_TABLE(wxWin32SystemMenuEvtHandler, wxEvtHandler)
    EVT_MENU(wxID_SYSTEM_MENU, wxWin32SystemMenuEvtHandler::OnSystemMenu)
    EVT_MENU(wxID_CLOSE_FRAME, wxWin32SystemMenuEvtHandler::OnCloseFrame)
    EVT_CLOSE(wxWin32SystemMenuEvtHandler::OnClose)
END_EVENT_TABLE()

void wxWin32SystemMenuEvtHandler::OnSystemMenu(wxCommandEvent &WXUNUSED(event))
{
#if wxUSE_ACCEL
    wxAcceleratorTable table = *m_wnd->GetAcceleratorTable();
    m_wnd->SetAcceleratorTable(wxNullAcceleratorTable);
#endif

#if wxUSE_MENUS
    m_inputHnd->PopupSystemMenu(m_wnd);
#endif // wxUSE_MENUS

#if wxUSE_ACCEL
    m_wnd->SetAcceleratorTable(table);
#endif
}

void wxWin32SystemMenuEvtHandler::OnCloseFrame(wxCommandEvent &WXUNUSED(event))
{
    m_wnd->PerformAction(wxACTION_TOPLEVEL_BUTTON_CLICK,
                         wxTOPLEVEL_BUTTON_CLOSE);
}

void wxWin32SystemMenuEvtHandler::OnClose(wxCloseEvent &event)
{
    m_wnd = NULL;
    event.Skip();
}


wxWin32FrameInputHandler::wxWin32FrameInputHandler(wxInputHandler *handler)
                        : wxStdInputHandler(handler)
{
    m_menuHandler = new wxWin32SystemMenuEvtHandler(this);
}

wxWin32FrameInputHandler::~wxWin32FrameInputHandler()
{
    if ( m_menuHandler )
    {
        m_menuHandler->Detach();
        delete m_menuHandler;
    }
}

bool wxWin32FrameInputHandler::HandleMouse(wxInputConsumer *consumer,
                                           const wxMouseEvent& event)
{
    if ( event.LeftDClick() || event.LeftDown() || event.RightDown() )
    {
        wxTopLevelWindow *tlw =
            wxStaticCast(consumer->GetInputWindow(), wxTopLevelWindow);

        long hit = tlw->HitTest(event.GetPosition());

        if ( event.LeftDClick() && hit == wxHT_TOPLEVEL_TITLEBAR )
        {
            tlw->PerformAction(wxACTION_TOPLEVEL_BUTTON_CLICK,
                               tlw->IsMaximized() ? wxTOPLEVEL_BUTTON_RESTORE
                                                  : wxTOPLEVEL_BUTTON_MAXIMIZE);
            return true;
        }
        else if ( tlw->GetWindowStyle() & wxSYSTEM_MENU )
        {
            if ( (event.LeftDown() && hit == wxHT_TOPLEVEL_ICON) ||
                 (event.RightDown() &&
                      (hit == wxHT_TOPLEVEL_TITLEBAR ||
                       hit == wxHT_TOPLEVEL_ICON)) )
            {
#if wxUSE_MENUS
                PopupSystemMenu(tlw);
#endif // wxUSE_MENUS
                return true;
            }
        }
    }

    return wxStdInputHandler::HandleMouse(consumer, event);
}

#if wxUSE_MENUS

void wxWin32FrameInputHandler::PopupSystemMenu(wxTopLevelWindow *window) const
{
    wxMenu menu;

    if ( window->GetWindowStyle() & wxMAXIMIZE_BOX )
        menu.Append(wxID_RESTORE_FRAME , _("&Restore"));
    menu.Append(wxID_MOVE_FRAME , _("&Move"));
    if ( window->GetWindowStyle() & wxRESIZE_BORDER )
        menu.Append(wxID_RESIZE_FRAME , _("&Size"));
    if ( wxSystemSettings::HasFeature(wxSYS_CAN_ICONIZE_FRAME) )
        menu.Append(wxID_ICONIZE_FRAME , _("Mi&nimize"));
    if ( window->GetWindowStyle() & wxMAXIMIZE_BOX )
        menu.Append(wxID_MAXIMIZE_FRAME , _("Ma&ximize"));
    menu.AppendSeparator();
    menu.Append(wxID_CLOSE_FRAME, _("Close\tAlt-F4"));

    if ( window->GetWindowStyle() & wxMAXIMIZE_BOX )
    {
        if ( window->IsMaximized() )
        {
            menu.Enable(wxID_MAXIMIZE_FRAME, false);
            menu.Enable(wxID_MOVE_FRAME, false);
            if ( window->GetWindowStyle() & wxRESIZE_BORDER )
                menu.Enable(wxID_RESIZE_FRAME, false);
        }
        else
            menu.Enable(wxID_RESTORE_FRAME, false);
    }

    window->PopupMenu(&menu, wxPoint(0, 0));
}

#endif // wxUSE_MENUS

bool wxWin32FrameInputHandler::HandleActivation(wxInputConsumer *consumer,
                                                bool activated)
{
    if ( consumer->GetInputWindow()->GetWindowStyle() & wxSYSTEM_MENU )
    {
        // always detach if active frame changed:
        m_menuHandler->Detach();

        if ( activated )
        {
            m_menuHandler->Attach(consumer);
        }
    }

    return wxStdInputHandler::HandleActivation(consumer, activated);
}

#endif // wxUSE_THEME_WIN32
