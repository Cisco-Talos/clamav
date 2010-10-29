///////////////////////////////////////////////////////////////////////////////
// Name:        src/univ/themes/gtk.cpp
// Purpose:     wxUniversal theme implementing GTK-like LNF
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

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/univ/theme.h"

#if wxUSE_THEME_GTK

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/dcmemory.h"
    #include "wx/dcclient.h"
    #include "wx/window.h"

    #include "wx/menu.h"

    #include "wx/bmpbuttn.h"
    #include "wx/button.h"
    #include "wx/checkbox.h"
    #include "wx/listbox.h"
    #include "wx/checklst.h"
    #include "wx/combobox.h"
    #include "wx/scrolbar.h"
    #include "wx/slider.h"
    #include "wx/textctrl.h"
    #include "wx/toolbar.h"
    #include "wx/statusbr.h"

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

#include "wx/univ/stdrend.h"
#include "wx/univ/inpcons.h"
#include "wx/univ/inphand.h"
#include "wx/univ/colschem.h"

class wxGTKMenuGeometryInfo;

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// standard border size
static const int BORDER_THICKNESS = 2;

// ----------------------------------------------------------------------------
// wxGTKRenderer: draw the GUI elements in GTK style
// ----------------------------------------------------------------------------

class wxGTKRenderer : public wxStdRenderer
{
public:
    wxGTKRenderer(const wxColourScheme *scheme);

    // wxRenderer methods
    virtual void DrawFocusRect(wxWindow* win, wxDC& dc, const wxRect& rect, int flags = 0);
    virtual void DrawTextBorder(wxDC& dc,
                                wxBorder border,
                                const wxRect& rect,
                                int flags = 0,
                                wxRect *rectIn = NULL);
    virtual void DrawButtonLabel(wxDC& dc,
                                 const wxString& label,
                                 const wxBitmap& image,
                                 const wxRect& rect,
                                 int flags,
                                 int alignment,
                                 int indexAccel,
                                 wxRect *rectBounds);
    virtual void DrawButtonBorder(wxDC& dc,
                                  const wxRect& rect,
                                  int flags = 0,
                                  wxRect *rectIn = NULL);
    virtual void DrawArrow(wxDC& dc,
                           wxDirection dir,
                           const wxRect& rect,
                           int flags = 0);
    virtual void DrawScrollbarArrow(wxDC& dc,
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

#if wxUSE_TEXTCTRL
    virtual void DrawLineWrapMark(wxDC& dc, const wxRect& rect);
#endif // wxUSE_TEXTCTRL

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
    virtual void DrawSliderTicks(wxDC& WXUNUSED(dc),
                                 const wxRect& WXUNUSED(rect),
                                 int WXUNUSED(lenThumb),
                                 wxOrientation WXUNUSED(orient),
                                 int WXUNUSED(start),
                                 int WXUNUSED(end),
                                 int WXUNUSED(step) = 1,
                                 int WXUNUSED(flags) = 0,
                                 long WXUNUSED(style) = 0)
    {
        // we don't have the ticks in GTK version
    }
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

    virtual void GetComboBitmaps(wxBitmap *bmpNormal,
                                 wxBitmap *bmpFocus,
                                 wxBitmap *bmpPressed,
                                 wxBitmap *bmpDisabled);

    virtual void AdjustSize(wxSize *size, const wxWindow *window);

    // geometry and hit testing
#if wxUSE_SCROLLBAR
    virtual wxSize GetScrollbarArrowSize() const
        { return m_sizeScrollbarArrow; }
#endif // wxUSE_SCROLLBAR

    virtual wxSize GetCheckBitmapSize() const
        { return wxSize(10, 10); }
    virtual wxSize GetRadioBitmapSize() const
        { return wxSize(11, 11); }
    virtual wxCoord GetCheckItemMargin() const
        { return 2; }

#if wxUSE_TOOLBAR
    virtual wxSize GetToolBarButtonSize(wxCoord *separator) const
        { if ( separator ) *separator = 5; return wxSize(16, 15); }
    virtual wxSize GetToolBarMargin() const
        { return wxSize(6, 6); }
#endif // wxUSE_TOOLBAR

#if wxUSE_TEXTCTRL
    virtual wxRect GetTextClientArea(const wxTextCtrl *text,
                                     const wxRect& rect,
                                     wxCoord *extraSpaceBeyond) const;
#endif // wxUSE_TEXTCTRL

#if wxUSE_NOTEBOOK
    virtual wxSize GetTabIndent() const { return wxSize(2, 2); }
    virtual wxSize GetTabPadding() const { return wxSize(6, 6); }
#endif // wxUSE_NOTEBOOK

#if wxUSE_SLIDER
    virtual wxCoord GetSliderDim() const { return 15; }
    virtual wxCoord GetSliderTickLen() const { return 0; }
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

    // helpers for "wxBitmap wxColourScheme::Get()"
    void DrawCheckBitmap(wxDC& dc, const wxRect& rect);
    void DrawUncheckBitmap(wxDC& dc, const wxRect& rect, bool isPressed);
    void DrawUndeterminedBitmap(wxDC& dc, const wxRect& rect, bool isPressed);

protected:
    // overridden wxStdRenderer methods
    virtual void DrawSunkenBorder(wxDC& dc, wxRect *rect);

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

    // get the colour to use for background
    wxColour GetBackgroundColour(int flags) const
    {
        if ( flags & wxCONTROL_PRESSED )
            return wxSCHEME_COLOUR(m_scheme, CONTROL_PRESSED);
        else if ( flags & wxCONTROL_CURRENT )
            return wxSCHEME_COLOUR(m_scheme, CONTROL_CURRENT);
        else
            return wxSCHEME_COLOUR(m_scheme, CONTROL);
    }

    // as DrawShadedRect() but the pixels in the bottom left and upper right
    // border are drawn with the pen1, not pen2
    void DrawAntiShadedRect(wxDC& dc, wxRect *rect,
                            const wxPen& pen1, const wxPen& pen2);

    // used for drawing opened rectangles - draws only one side of it at once
    // (and doesn't adjust the rect)
    void DrawAntiShadedRectSide(wxDC& dc,
                                const wxRect& rect,
                                const wxPen& pen1,
                                const wxPen& pen2,
                                wxDirection dir);

    // draw an opened rect for the arrow in given direction
    void DrawArrowBorder(wxDC& dc,
                         wxRect *rect,
                         wxDirection dir);

    // draw two sides of the rectangle
    void DrawThumbBorder(wxDC& dc,
                         wxRect *rect,
                         wxOrientation orient);

    // just as DrawRaisedBorder() except that the bottom left and up right
    // pixels of the interior rect are drawn in another colour (i.e. the inner
    // rect is drawn with DrawAntiShadedRect() and not DrawShadedRect())
    void DrawAntiRaisedBorder(wxDC& dc, wxRect *rect);

    // draw inner GTK shadow
    void DrawInnerShadedRect(wxDC& dc, wxRect *rect);

    // get the line wrap indicator bitmap
    wxBitmap GetLineWrapBitmap() const;

    virtual wxBitmap GetCheckBitmap(int flags);
    virtual wxBitmap GetRadioBitmap(int flags);

    // draw a /\ or \/ line from (x1, y1) to (x2, y1) passing by the point
    // ((x1 + x2)/2, y2)
    void DrawUpZag(wxDC& dc,
                   wxCoord x1, wxCoord x2,
                   wxCoord y1, wxCoord y2);
    void DrawDownZag(wxDC& dc,
                     wxCoord x1, wxCoord x2,
                     wxCoord y1, wxCoord y2);

    // draw the radio button bitmap for the given state
    void DrawRadioButtonBitmap(wxDC& dc, const wxRect& rect, int flags);

    // common part of DrawMenuItem() and DrawMenuBarItem()
    void DoDrawMenuItem(wxDC& dc,
                        const wxRect& rect,
                        const wxString& label,
                        int flags,
                        int indexAccel,
                        const wxString& accel = wxEmptyString,
                        const wxBitmap& bitmap = wxNullBitmap,
                        const wxGTKMenuGeometryInfo *geometryInfo = NULL);

    // initialize the combo bitmaps
    void InitComboBitmaps();

    virtual wxBitmap GetFrameButtonBitmap(FrameButtonType WXUNUSED(type))
    {
        return wxNullBitmap;
    }

private:
    // data
    wxSize m_sizeScrollbarArrow;

    // GDI objects
    wxPen m_penGrey;

    // the checkbox and radio button bitmaps: first row is for the normal,
    // second for the pressed state and the columns are for checked, unchecked
    // and undeterminated respectively
    wxBitmap m_bitmapsCheckbox[IndicatorState_MaxCtrl][IndicatorStatus_Max],
             m_bitmapsRadiobtn[IndicatorState_MaxCtrl][IndicatorStatus_Max];

    // the line wrap bitmap (drawn at the end of wrapped lines)
    wxBitmap m_bmpLineWrap;

    // the combobox bitmaps
    enum
    {
        ComboState_Normal,
        ComboState_Focus,
        ComboState_Pressed,
        ComboState_Disabled,
        ComboState_Max
    };

    wxBitmap m_bitmapsCombo[ComboState_Max];
};

// ----------------------------------------------------------------------------
// wxGTKInputHandler and derived classes: process the keyboard and mouse
// messages according to GTK standards
// ----------------------------------------------------------------------------

class wxGTKInputHandler : public wxInputHandler
{
public:
    wxGTKInputHandler() { }

    virtual bool HandleKey(wxInputConsumer *control,
                           const wxKeyEvent& event,
                           bool pressed);
    virtual bool HandleMouse(wxInputConsumer *control,
                             const wxMouseEvent& event);
    virtual bool HandleMouseMove(wxInputConsumer *control,
                                 const wxMouseEvent& event);
};

#if wxUSE_SCROLLBAR

class wxGTKScrollBarInputHandler : public wxStdScrollBarInputHandler
{
public:
    wxGTKScrollBarInputHandler(wxRenderer *renderer, wxInputHandler *handler)
        : wxStdScrollBarInputHandler(renderer, handler) { }

protected:
    virtual void Highlight(wxScrollBar *scrollbar, bool doIt)
    {
        // only arrows and the thumb can be highlighted
        if ( !IsArrow() && m_htLast != wxHT_SCROLLBAR_THUMB )
            return;

        wxStdScrollBarInputHandler::Highlight(scrollbar, doIt);
    }

    virtual void Press(wxScrollBar *scrollbar, bool doIt)
    {
        // only arrows can be pressed
        if ( !IsArrow() )
            return;

        wxStdScrollBarInputHandler::Press(scrollbar, doIt);
    }

    // any button can be used to drag the scrollbar under GTK+
    virtual bool IsAllowedButton(int WXUNUSED(button)) const { return true; }

    bool IsArrow() const
    {
        return m_htLast == wxHT_SCROLLBAR_ARROW_LINE_1 ||
                m_htLast == wxHT_SCROLLBAR_ARROW_LINE_2;
    }
};

#endif // wxUSE_SCROLLBAR

#if wxUSE_CHECKBOX

class wxGTKCheckboxInputHandler : public wxStdInputHandler
{
public:
    wxGTKCheckboxInputHandler(wxInputHandler *handler)
        : wxStdInputHandler(handler) { }

    virtual bool HandleKey(wxInputConsumer *control,
                           const wxKeyEvent& event,
                           bool pressed);
};

#endif // wxUSE_CHECKBOX

#if wxUSE_TEXTCTRL

class wxGTKTextCtrlInputHandler : public wxStdInputHandler
{
public:
    wxGTKTextCtrlInputHandler(wxInputHandler *handler)
        : wxStdInputHandler(handler) { }

    virtual bool HandleKey(wxInputConsumer *control,
                           const wxKeyEvent& event,
                           bool pressed);
};

#endif // wxUSE_TEXTCTRL

// ----------------------------------------------------------------------------
// wxGTKColourScheme: uses the standard GTK colours
// ----------------------------------------------------------------------------

class wxGTKColourScheme : public wxColourScheme
{
public:
    virtual wxColour Get(StdColour col) const;
    virtual wxColour GetBackground(wxWindow *win) const;
};

// ----------------------------------------------------------------------------
// wxGTKArtProvider
// ----------------------------------------------------------------------------

class wxGTKArtProvider : public wxArtProvider
{
protected:
    virtual wxBitmap CreateBitmap(const wxArtID& id,
                                  const wxArtClient& client,
                                  const wxSize& size);
};

// ----------------------------------------------------------------------------
// wxGTKTheme
// ----------------------------------------------------------------------------

WX_DEFINE_ARRAY_PTR(wxInputHandler *, wxArrayHandlers);

class wxGTKTheme : public wxTheme
{
public:
    wxGTKTheme();
    virtual ~wxGTKTheme();

    virtual wxRenderer *GetRenderer();
    virtual wxArtProvider *GetArtProvider();
    virtual wxInputHandler *GetInputHandler(const wxString& control,
                                            wxInputConsumer *consumer);
    virtual wxColourScheme *GetColourScheme();

private:
    wxGTKRenderer *m_renderer;

    wxGTKArtProvider *m_artProvider;

    // the names of the already created handlers and the handlers themselves
    // (these arrays are synchronized)
    wxSortedArrayString m_handlerNames;
    wxArrayHandlers m_handlers;

    wxGTKColourScheme *m_scheme;

    WX_DECLARE_THEME(gtk)
};

// ============================================================================
// implementation
// ============================================================================

WX_IMPLEMENT_THEME(wxGTKTheme, gtk, wxTRANSLATE("GTK+ theme"));

// ----------------------------------------------------------------------------
// wxGTKTheme
// ----------------------------------------------------------------------------

wxGTKTheme::wxGTKTheme()
{
    m_scheme = NULL;
    m_renderer = NULL;
    m_artProvider = NULL;
}

wxGTKTheme::~wxGTKTheme()
{
    delete m_renderer;
    delete m_scheme;
    delete m_artProvider;
}

wxRenderer *wxGTKTheme::GetRenderer()
{
    if ( !m_renderer )
    {
        m_renderer = new wxGTKRenderer(GetColourScheme());
    }

    return m_renderer;
}

wxArtProvider *wxGTKTheme::GetArtProvider()
{
    if ( !m_artProvider )
    {
        m_artProvider = new wxGTKArtProvider;
    }

    return m_artProvider;
}

wxColourScheme *wxGTKTheme::GetColourScheme()
{
    if ( !m_scheme )
    {
        m_scheme = new wxGTKColourScheme;
    }
    return m_scheme;
}

wxInputHandler *wxGTKTheme::GetInputHandler(const wxString& control,
                                            wxInputConsumer *consumer)
{
    wxInputHandler *handler = NULL;
    int n = m_handlerNames.Index(control);
    if ( n == wxNOT_FOUND )
    {
        static wxGTKInputHandler s_handlerDef;

        wxInputHandler * const
          handlerStd = consumer->DoGetStdInputHandler(&s_handlerDef);

        // create a new handler
#if wxUSE_CHECKBOX
        if ( control == wxINP_HANDLER_CHECKBOX )
        {
            static wxGTKCheckboxInputHandler s_handler(handlerStd);

            handler = &s_handler;
        }
        else
#endif // wxUSE_CHECKBOX
#if wxUSE_SCROLLBAR
        if ( control == wxINP_HANDLER_SCROLLBAR )
        {
            static wxGTKScrollBarInputHandler s_handler(m_renderer, handlerStd);

            handler = &s_handler;
        }
        else
#endif // wxUSE_SCROLLBAR
#if wxUSE_TEXTCTRL
        if ( control == wxINP_HANDLER_TEXTCTRL )
        {
            static wxGTKTextCtrlInputHandler s_handler(handlerStd);

            handler = &s_handler;
        }
        else
#endif // wxUSE_TEXTCTRL
        {
            // no special handler for this control
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

// ============================================================================
// wxGTKColourScheme
// ============================================================================

wxColour wxGTKColourScheme::GetBackground(wxWindow *win) const
{
    wxColour col;
    if ( win->UseBgCol() )
    {
        // use the user specified colour
        col = win->GetBackgroundColour();
    }

    if ( !win->ShouldInheritColours() )
    {
        // doesn't depend on the state
        if ( !col.Ok() )
        {
            col = Get(WINDOW);
        }
    }
    else
    {
        int flags = win->GetStateFlags();

        // the colour set by the user should be used for the normal state
        // and for the states for which we don't have any specific colours
        if ( !col.Ok() || (flags != 0) )
        {
#if wxUSE_SCROLLBAR
            if ( wxDynamicCast(win, wxScrollBar) )
                col = Get(SCROLLBAR);
            else
#endif //wxUSE_SCROLLBAR
                 if ( (flags & wxCONTROL_CURRENT) && win->CanBeHighlighted() )
                col = Get(CONTROL_CURRENT);
            else if ( flags & wxCONTROL_PRESSED )
                col = Get(CONTROL_PRESSED);
            else
                col = Get(CONTROL);
        }
    }

    return col;
}

wxColour wxGTKColourScheme::Get(wxGTKColourScheme::StdColour col) const
{
    switch ( col )
    {
        case FRAME:
        case WINDOW:            return *wxWHITE;

        case SHADOW_DARK:       return *wxBLACK;
        case SHADOW_HIGHLIGHT:  return *wxWHITE;
        case SHADOW_IN:         return wxColour(0xd6d6d6);
        case SHADOW_OUT:        return wxColour(0x969696);

        case CONTROL:           return wxColour(0xd6d6d6);
        case CONTROL_PRESSED:   return wxColour(0xc3c3c3);
        case CONTROL_CURRENT:   return wxColour(0xeaeaea);

        case CONTROL_TEXT:      return *wxBLACK;
        case CONTROL_TEXT_DISABLED:
                                return wxColour(0x757575);
        case CONTROL_TEXT_DISABLED_SHADOW:
                                return *wxWHITE;

        case SCROLLBAR:
        case SCROLLBAR_PRESSED: return wxColour(0xc3c3c3);

        case HIGHLIGHT:         return wxColour(0x9c0000);
        case HIGHLIGHT_TEXT:    return wxColour(0xffffff);

        case GAUGE:             return Get(CONTROL_CURRENT);

        case TITLEBAR:          return wxColour(0xaeaaae);
        case TITLEBAR_ACTIVE:   return wxColour(0x820300);
        case TITLEBAR_TEXT:     return wxColour(0xc0c0c0);
        case TITLEBAR_ACTIVE_TEXT:
                                return *wxWHITE;

        case DESKTOP:           return *wxBLACK;

        case MAX:
        default:
            wxFAIL_MSG(wxT("invalid standard colour"));
            return *wxBLACK;
    }
}

// ============================================================================
// wxGTKRenderer
// ============================================================================

// ----------------------------------------------------------------------------
// construction
// ----------------------------------------------------------------------------

wxGTKRenderer::wxGTKRenderer(const wxColourScheme *scheme)
             : wxStdRenderer(scheme)
{
    m_sizeScrollbarArrow = wxSize(15, 14);

    m_penGrey = wxPen(wxSCHEME_COLOUR(scheme, SCROLLBAR));
}

// ----------------------------------------------------------------------------
// border stuff
// ----------------------------------------------------------------------------

void wxGTKRenderer::DrawAntiShadedRectSide(wxDC& dc,
                                           const wxRect& rect,
                                           const wxPen& pen1,
                                           const wxPen& pen2,
                                           wxDirection dir)
{
    dc.SetPen(dir == wxLEFT || dir == wxUP ? pen1 : pen2);

    switch ( dir )
    {
        case wxLEFT:
            dc.DrawLine(rect.GetLeft(), rect.GetTop(),
                        rect.GetLeft(), rect.GetBottom() + 1);
            break;

        case wxUP:
            dc.DrawLine(rect.GetLeft(), rect.GetTop(),
                        rect.GetRight() + 1, rect.GetTop());
            break;

        case wxRIGHT:
            dc.DrawLine(rect.GetRight(), rect.GetTop(),
                        rect.GetRight(), rect.GetBottom() + 1);
            break;

        case wxDOWN:
            dc.DrawLine(rect.GetLeft(), rect.GetBottom(),
                        rect.GetRight() + 1, rect.GetBottom());
            break;

        default:
            wxFAIL_MSG(wxT("unknown rectangle side"));
    }
}

void wxGTKRenderer::DrawAntiShadedRect(wxDC& dc, wxRect *rect,
                                       const wxPen& pen1, const wxPen& pen2)
{
    // draw the rectangle
    dc.SetPen(pen1);
    dc.DrawLine(rect->GetLeft(), rect->GetTop(),
                rect->GetLeft(), rect->GetBottom() + 1);
    dc.DrawLine(rect->GetLeft() + 1, rect->GetTop(),
                rect->GetRight() + 1, rect->GetTop());
    dc.SetPen(pen2);
    dc.DrawLine(rect->GetRight(), rect->GetTop() + 1,
                rect->GetRight(), rect->GetBottom());
    dc.DrawLine(rect->GetLeft() + 1, rect->GetBottom(),
                rect->GetRight() + 1, rect->GetBottom());

    // adjust the rect
    rect->Inflate(-1);
}

void wxGTKRenderer::DrawInnerShadedRect(wxDC& dc, wxRect *rect)
{
    DrawAntiShadedRect(dc, rect, m_penDarkGrey, m_penHighlight);
    DrawAntiShadedRect(dc, rect, m_penBlack, m_penHighlight);
}

void wxGTKRenderer::DrawAntiRaisedBorder(wxDC& dc, wxRect *rect)
{
    DrawShadedRect(dc, rect, m_penHighlight, m_penBlack);
    DrawAntiShadedRect(dc, rect, m_penLightGrey, m_penDarkGrey);
}

void wxGTKRenderer::DrawSunkenBorder(wxDC& dc, wxRect *rect)
{
    DrawAntiShadedRect(dc, rect, m_penDarkGrey, m_penHighlight);
    DrawShadedRect(dc, rect, m_penBlack, m_penLightGrey);
}

void
wxGTKRenderer::DrawFocusRect(wxWindow* WXUNUSED(win), wxDC& dc, const wxRect& rect, int WXUNUSED(flags))
{
    dc.SetBrush(*wxTRANSPARENT_BRUSH);
    wxRect rectFocus = rect;
    DrawRect(dc, &rectFocus, m_penBlack);
}

void wxGTKRenderer::DrawTextBorder(wxDC& dc,
                                   wxBorder border,
                                   const wxRect& rectOrig,
                                   int flags,
                                   wxRect *rectIn)
{
    wxRect rect = rectOrig;

    if ( border != wxBORDER_NONE )
    {
        if ( flags & wxCONTROL_FOCUSED )
        {
            DrawRect(dc, &rect, m_penBlack);
            DrawAntiShadedRect(dc, &rect, m_penDarkGrey, m_penHighlight);
        }
        else // !focused
        {
            DrawInnerShadedRect(dc, &rect);
        }
    }

    if ( rectIn )
        *rectIn = rect;
}

void wxGTKRenderer::DrawButtonLabel(wxDC& dc,
                                    const wxString& label,
                                    const wxBitmap& image,
                                    const wxRect& rect,
                                    int flags,
                                    int alignment,
                                    int indexAccel,
                                    wxRect *rectBounds)
{
    // no focus rect around buttons label in GTK+
    wxStdRenderer::DrawButtonLabel(dc, label, image, rect, flags,
                                   alignment, indexAccel, rectBounds);
}

void wxGTKRenderer::DrawButtonBorder(wxDC& dc,
                                     const wxRect& rectTotal,
                                     int flags,
                                     wxRect *rectIn)
{
    wxRect rect = rectTotal;

    if ( flags & wxCONTROL_PRESSED )
    {
        // button pressed: draw a black border around it and an inward shade
        DrawRect(dc, &rect, m_penBlack);

        DrawInnerShadedRect(dc, &rect);
    }
    else // button not pressed
    {
        if ( flags & wxCONTROL_ISDEFAULT )
        {
            // TODO
        }

        if ( flags & wxCONTROL_FOCUSED )
        {
            // button is currently default: add an extra border around it
            DrawRect(dc, &rect, m_penBlack);
        }

        // now draw a normal button
        DrawShadedRect(dc, &rect, m_penHighlight, m_penBlack);
        DrawAntiShadedRect(dc, &rect, GetBackgroundColour(flags), m_penDarkGrey);
    }

    if ( rectIn )
        *rectIn = rect;
}

// ----------------------------------------------------------------------------
// lines and frames
// ----------------------------------------------------------------------------

void wxGTKRenderer::DrawFrameWithLabel(wxDC& dc,
                                       const wxString& label,
                                       const wxRect& rectFrame,
                                       const wxRect& rectTextOrig,
                                       int flags,
                                       int alignment,
                                       int indexAccel)
{
    wxRect rectText(rectTextOrig);
    rectText.Inflate(1, 0);

    wxRect rectLabel;
    DrawLabel(dc, label, rectText, flags, alignment, indexAccel, &rectLabel);
    rectLabel.x -= 1;
    rectLabel.width += 2;

    DrawFrameWithoutLabel(dc, rectFrame, rectLabel);

    // GTK+ does it like this
    dc.SetPen(m_penHighlight);
    dc.DrawPoint(rectText.x, rectFrame.y);
    dc.DrawPoint(rectText.x + rectLabel.width - 3, rectFrame.y);
}

// ----------------------------------------------------------------------------
// check/radio buttons
// ----------------------------------------------------------------------------

void wxGTKRenderer::DrawCheckItemBitmap(wxDC& dc,
                                        const wxBitmap& bitmap,
                                        const wxRect& rect,
                                        int flags)
{
    // never draw the focus rect around the check indicators here
    DrawCheckButton(dc, wxEmptyString, bitmap, rect, flags & ~wxCONTROL_FOCUSED);
}

void wxGTKRenderer::DrawUndeterminedBitmap(wxDC& dc,
                                           const wxRect& rectTotal,
                                           bool isPressed)
{
    // FIXME: For sure it is not GTK look but it is better than nothing.
    // Show me correct look and I will immediatelly make it better (ABX)
    wxRect rect = rectTotal;

    wxColour col1, col2;

    if ( isPressed )
    {
        col1 = wxSCHEME_COLOUR(m_scheme, SHADOW_DARK);
        col2 = wxSCHEME_COLOUR(m_scheme, CONTROL_PRESSED);
    }
    else
    {
        col1 = wxSCHEME_COLOUR(m_scheme, SHADOW_DARK);
        col2 = wxSCHEME_COLOUR(m_scheme, SHADOW_IN);
    }

    dc.SetPen(*wxTRANSPARENT_PEN);
    dc.SetBrush(col1);
    dc.DrawRectangle(rect);
    rect.Deflate(1);
    dc.SetBrush(col2);
    dc.DrawRectangle(rect);
}

void wxGTKRenderer::DrawUncheckBitmap(wxDC& dc,
                                      const wxRect& rectTotal,
                                      bool isPressed)
{
    wxRect rect = rectTotal;
    DrawAntiRaisedBorder(dc, &rect);

    wxColour col = wxSCHEME_COLOUR(m_scheme, SHADOW_IN);
    dc.SetPen(wxPen(col));
    dc.DrawPoint(rect.GetRight() - 1, rect.GetBottom() - 1);

    if ( isPressed )
        col = wxSCHEME_COLOUR(m_scheme, CONTROL_PRESSED);
    //else: it is SHADOW_IN, leave as is

    dc.SetPen(*wxTRANSPARENT_PEN);
    dc.SetBrush(col);
    dc.DrawRectangle(rect);
}

void wxGTKRenderer::DrawCheckBitmap(wxDC& dc, const wxRect& rectTotal)
{
    wxRect rect = rectTotal;
    DrawAntiShadedRect(dc, &rect, m_penDarkGrey, m_penHighlight);
    DrawShadedRect(dc, &rect, m_penBlack, m_penLightGrey);

    dc.SetPen(*wxTRANSPARENT_PEN);
    dc.SetBrush(wxSCHEME_COLOUR(m_scheme, CONTROL_PRESSED));
    dc.DrawRectangle(rect);
}

void wxGTKRenderer::DrawRadioButtonBitmap(wxDC& dc,
                                          const wxRect& rect,
                                          int flags)
{
    wxCoord x = rect.x,
            y = rect.y,
            xRight = rect.GetRight(),
            yBottom = rect.GetBottom();

    wxCoord yMid = (y + yBottom) / 2;

    // then draw the upper half
    dc.SetPen(flags & wxCONTROL_CHECKED ? m_penDarkGrey : m_penHighlight);
    DrawUpZag(dc, x, xRight, yMid, y);
    DrawUpZag(dc, x + 1, xRight - 1, yMid, y + 1);

    bool drawIt = true;
    if ( flags & wxCONTROL_CHECKED )
        dc.SetPen(m_penBlack);
    else if ( flags & wxCONTROL_PRESSED )
        dc.SetPen(wxPen(wxSCHEME_COLOUR(m_scheme, CONTROL_PRESSED)));
    else // unchecked and unpressed
        drawIt = false;

    if ( drawIt )
        DrawUpZag(dc, x + 2, xRight - 2, yMid, y + 2);

    // and then the lower one
    dc.SetPen(flags & wxCONTROL_CHECKED ? m_penHighlight : m_penBlack);
    DrawDownZag(dc, x, xRight, yMid, yBottom);
    if ( !(flags & wxCONTROL_CHECKED) )
        dc.SetPen(m_penDarkGrey);
    DrawDownZag(dc, x + 1, xRight - 1, yMid, yBottom - 1);

    if ( !(flags & wxCONTROL_CHECKED) )
        drawIt = true; // with the same pen
    else if ( flags & wxCONTROL_PRESSED )
    {
        dc.SetPen(wxPen(wxSCHEME_COLOUR(m_scheme, CONTROL_PRESSED)));
        drawIt = true;
    }
    else // checked and unpressed
        drawIt = false;

    if ( drawIt )
        DrawDownZag(dc, x + 2, xRight - 2, yMid, yBottom - 2);
}

void wxGTKRenderer::DrawUpZag(wxDC& dc,
                              wxCoord x1,
                              wxCoord x2,
                              wxCoord y1,
                              wxCoord y2)
{
    wxCoord xMid = (x1 + x2) / 2;
    dc.DrawLine(x1, y1, xMid, y2);
    dc.DrawLine(xMid, y2, x2 + 1, y1 + 1);
}

void wxGTKRenderer::DrawDownZag(wxDC& dc,
                                wxCoord x1,
                                wxCoord x2,
                                wxCoord y1,
                                wxCoord y2)
{
    wxCoord xMid = (x1 + x2) / 2;
    dc.DrawLine(x1 + 1, y1 + 1, xMid, y2);
    dc.DrawLine(xMid, y2, x2, y1);
}

wxBitmap wxGTKRenderer::GetCheckBitmap(int flags)
{
    if ( !m_bitmapsCheckbox[0][0].Ok() )
    {
        // init the bitmaps once only
        wxRect rect;
        wxSize size = GetCheckBitmapSize();
        rect.width = size.x;
        rect.height = size.y;
        for ( int i = 0; i < 2; i++ )
        {
            for ( int j = 0; j < 3; j++ )
                m_bitmapsCheckbox[i][j].Create(rect.width, rect.height);
        }

        wxMemoryDC dc;

        // normal checked
        dc.SelectObject(m_bitmapsCheckbox[0][0]);
        DrawCheckBitmap(dc, rect);

        // normal unchecked
        dc.SelectObject(m_bitmapsCheckbox[0][1]);
        DrawUncheckBitmap(dc, rect, false);

        // normal undeterminated
        dc.SelectObject(m_bitmapsCheckbox[0][2]);
        DrawUndeterminedBitmap(dc, rect, false);

        // pressed checked
        m_bitmapsCheckbox[1][0] = m_bitmapsCheckbox[0][0];

        // pressed unchecked
        dc.SelectObject(m_bitmapsCheckbox[1][1]);
        DrawUncheckBitmap(dc, rect, true);

        // pressed undeterminated
        dc.SelectObject(m_bitmapsCheckbox[1][2]);
        DrawUndeterminedBitmap(dc, rect, true);
    }

    IndicatorState state;
    IndicatorStatus status;
    GetIndicatorsFromFlags(flags, state, status);

    // disabled looks the same as normal
    if ( state == IndicatorState_Disabled )
        state = IndicatorState_Normal;

    return m_bitmapsCheckbox[state][status];
}

wxBitmap wxGTKRenderer::GetRadioBitmap(int flags)
{
    IndicatorState state;
    IndicatorStatus status;
    GetIndicatorsFromFlags(flags, state, status);

    wxBitmap& bmp = m_bitmapsRadiobtn[state][status];
    if ( !bmp.Ok() )
    {
        const wxSize size = GetRadioBitmapSize();

        wxMemoryDC dc;
        bmp.Create(size.x, size.y);
        dc.SelectObject(bmp);

        DrawRadioButtonBitmap(dc, size, flags);
    }

    return bmp;
}

wxBitmap wxGTKRenderer::GetLineWrapBitmap() const
{
    if ( !m_bmpLineWrap.Ok() )
    {
        // the line wrap bitmap as used by GTK+
        #define line_wrap_width 6
        #define line_wrap_height 9
        static const char line_wrap_bits[] =
        {
          0x1e, 0x3e, 0x30, 0x30, 0x39, 0x1f, 0x0f, 0x0f, 0x1f,
        };

        wxBitmap bmpLineWrap(line_wrap_bits, line_wrap_width, line_wrap_height);
        if ( !bmpLineWrap.Ok() )
        {
            wxFAIL_MSG( wxT("Failed to create line wrap XBM") );
        }
        else
        {
            wxConstCast(this, wxGTKRenderer)->m_bmpLineWrap = bmpLineWrap;
        }
    }

    return m_bmpLineWrap;
}

#if wxUSE_TOOLBAR
void wxGTKRenderer::DrawToolBarButton(wxDC& dc,
                                      const wxString& label,
                                      const wxBitmap& bitmap,
                                      const wxRect& rectOrig,
                                      int flags,
                                      long WXUNUSED(style),
                                      int tbarStyle)
{
    // we don't draw the separators at all
    if ( !label.empty() || bitmap.Ok() )
    {
        wxRect rect = rectOrig;
        rect.Deflate(BORDER_THICKNESS);

        if ( flags & wxCONTROL_PRESSED )
        {
            DrawBorder(dc, wxBORDER_SUNKEN, rect, flags, &rect);

            DrawBackground(dc, wxSCHEME_COLOUR(m_scheme, CONTROL_PRESSED), rect);
        }
        else if ( flags & wxCONTROL_CURRENT )
        {
            DrawBorder(dc, wxBORDER_RAISED, rect, flags, &rect);

            DrawBackground(dc, wxSCHEME_COLOUR(m_scheme, CONTROL_CURRENT), rect);
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
            dc.DrawBitmap(bitmap, xpoint, ypoint);
        }
    }
}
#endif // wxUSE_TOOLBAR

// ----------------------------------------------------------------------------
// text control
// ----------------------------------------------------------------------------

#if wxUSE_TEXTCTRL

wxRect wxGTKRenderer::GetTextClientArea(const wxTextCtrl *text,
                                        const wxRect& rect,
                                        wxCoord *extraSpaceBeyond) const
{
    wxRect
      rectText = wxStdRenderer::GetTextClientArea(text, rect, extraSpaceBeyond);

    if ( text->WrapLines() )
    {
        // leave enough for the line wrap bitmap indicator
        wxCoord widthMark = GetLineWrapBitmap().GetWidth() + 2;

        rectText.width -= widthMark;

        if ( extraSpaceBeyond )
            *extraSpaceBeyond = widthMark;
    }

    return rectText;
}

void wxGTKRenderer::DrawLineWrapMark(wxDC& dc, const wxRect& rect)
{
    wxBitmap bmpLineWrap = GetLineWrapBitmap();

    // for a mono bitmap he colours it appears in depends on the current text
    // colours, so set them correctly
    wxColour colFgOld;
    if ( bmpLineWrap.GetDepth() == 1 )
    {
        colFgOld = dc.GetTextForeground();

        // FIXME: I wonder what should we do if the background is black too?
        dc.SetTextForeground(*wxBLACK);
    }

    dc.DrawBitmap(bmpLineWrap,
                  rect.x, rect.y + (rect.height - bmpLineWrap.GetHeight())/2);

    if ( colFgOld.Ok() )
    {
        // restore old colour
        dc.SetTextForeground(colFgOld);
    }
}

#endif // wxUSE_TEXTCTRL

// ----------------------------------------------------------------------------
// notebook
// ----------------------------------------------------------------------------

#if wxUSE_NOTEBOOK

void wxGTKRenderer::DrawTab(wxDC& dc,
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

    // selected tab has different colour
    wxColour col = flags & wxCONTROL_SELECTED
                        ? wxSCHEME_COLOUR(m_scheme, SHADOW_IN)
                        : wxSCHEME_COLOUR(m_scheme, SCROLLBAR);
    DrawSolidRect(dc, col, rect);

    if ( flags & wxCONTROL_FOCUSED )
    {
        // draw the focus rect
        wxRect rectBorder = rect;
        rectBorder.Deflate(4, 3);
        if ( dir == wxBOTTOM )
            rectBorder.Offset(0, -1);
        if ( dir == wxRIGHT )
            rectBorder.Offset(-1, 0);

        DrawRect(dc, &rectBorder, m_penBlack);
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
        dcMem.DrawLabel(label, bitmapRotated, rectLabel, wxALIGN_CENTRE, indexAccel);
        dcMem.SelectObject(wxNullBitmap);
        bitmapMem = bitmapMem.GetSubBitmap(rectLabel);
#if wxUSE_IMAGE
        bitmapMem = wxBitmap(wxImage(bitmapMem.ConvertToImage()).Rotate90(dir==wxRIGHT))
#endif
                    ;

        dc.DrawBitmap(bitmapMem, rectLabel.y, rectLabel.x, false);
    }
    else
    {
        dc.DrawLabel(label, bitmap, rectLabel, wxALIGN_CENTRE, indexAccel);
    }

    // now draw the tab itself
    wxCoord x = SELECT_FOR_VERTICAL(rect.x,rect.y),
            y = SELECT_FOR_VERTICAL(rect.y,rect.x),
            x2 = SELECT_FOR_VERTICAL(rect.GetRight(),rect.GetBottom()),
            y2 = SELECT_FOR_VERTICAL(rect.GetBottom(),rect.GetRight());
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
                        REVERSE_FOR_VERTICAL(x, y));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y),
                        REVERSE_FOR_VERTICAL(x2, y));

            dc.SetPen(m_penBlack);
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2, y2),
                        REVERSE_FOR_VERTICAL(x2, y));

            dc.SetPen(m_penDarkGrey);
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2 - 1, y2),
                        REVERSE_FOR_VERTICAL(x2 - 1, y + 1));

            if ( flags & wxCONTROL_SELECTED )
            {
                dc.SetPen(m_penLightGrey);

                // overwrite the part of the border below this tab
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y2 + 1),
                            REVERSE_FOR_VERTICAL(x2 - 1, y2 + 1));

                // and the shadow of the tab to the left of us
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y + 2),
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
                        REVERSE_FOR_VERTICAL(x, y2));

            // it doesn't work like this (TODO: implement it properly)
#if 0
            // erase the corner of the tab to the right
            dc.SetPen(m_penLightGrey);
            dc.DrawPoint(REVERSE_FOR_VERTICAL(x2 - 1, y - 2));
            dc.DrawPoint(REVERSE_FOR_VERTICAL(x2 - 2, y - 2));
            dc.DrawPoint(REVERSE_FOR_VERTICAL(x2 - 2, y - 1));
#endif // 0

            dc.SetPen(m_penBlack);
            dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y2),
                        REVERSE_FOR_VERTICAL(x2, y2));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2, y),
                        REVERSE_FOR_VERTICAL(x2, y2));

            dc.SetPen(m_penDarkGrey);
            dc.DrawLine(REVERSE_FOR_VERTICAL(x + 2, y2 - 1),
                        REVERSE_FOR_VERTICAL(x2 - 1, y2 - 1));
            dc.DrawLine(REVERSE_FOR_VERTICAL(x2 - 1, y),
                        REVERSE_FOR_VERTICAL(x2 - 1, y2));

            if ( flags & wxCONTROL_SELECTED )
            {
                dc.SetPen(m_penLightGrey);

                // overwrite the part of the (double!) border above this tab
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y - 1),
                            REVERSE_FOR_VERTICAL(x2 - 1, y - 1));
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y - 2),
                            REVERSE_FOR_VERTICAL(x2 - 1, y - 2));

                // and the shadow of the tab to the left of us
                dc.DrawLine(REVERSE_FOR_VERTICAL(x + 1, y2 - 1),
                            REVERSE_FOR_VERTICAL(x + 1, y - 1));
            }
            break;
    }
}

#endif // wxUSE_NOTEBOOK

// ----------------------------------------------------------------------------
// slider
// ----------------------------------------------------------------------------

#if wxUSE_SLIDER

wxSize wxGTKRenderer::GetSliderThumbSize(const wxRect& rect,
                                         int lenThumb,
                                         wxOrientation orient) const
{
    static const wxCoord SLIDER_THUMB_LENGTH = 30;

    wxSize size;

    wxRect rectShaft = GetSliderShaftRect(rect, lenThumb, orient);
    if ( orient == wxHORIZONTAL )
    {
        size.x = wxMin(SLIDER_THUMB_LENGTH, rectShaft.width);
        size.y = rectShaft.height;
    }
    else // vertical
    {
        size.y = wxMin(SLIDER_THUMB_LENGTH, rectShaft.height);
        size.x = rectShaft.width;
    }

    return size;
}

wxRect wxGTKRenderer::GetSliderShaftRect(const wxRect& rect,
                                         int WXUNUSED(lenThumb),
                                         wxOrientation WXUNUSED(orient),
                                         long WXUNUSED(style)) const
{
    return rect.Deflate(2*BORDER_THICKNESS, 2*BORDER_THICKNESS);
}

void wxGTKRenderer::DrawSliderShaft(wxDC& dc,
                                    const wxRect& rectOrig,
                                    int WXUNUSED(lenThumb),
                                    wxOrientation WXUNUSED(orient),
                                    int flags,
                                    long WXUNUSED(style),
                                    wxRect *rectShaft)
{
    wxRect rect = rectOrig;

    // draw the border first
    if ( flags & wxCONTROL_FOCUSED )
    {
        DrawRect(dc, &rect, m_penBlack);
    }
    else // not focused, normal
    {
        DrawAntiShadedRect(dc, &rect, m_penDarkGrey, m_penHighlight);
    }

    DrawAntiShadedRect(dc, &rect, m_penBlack, m_penLightGrey);

    // and the background
    DrawSolidRect(dc, wxSCHEME_COLOUR(m_scheme, SCROLLBAR), rect);

    if ( rectShaft )
        *rectShaft = rect;
}

void wxGTKRenderer::DrawSliderThumb(wxDC& dc,
                                    const wxRect& rectOrig,
                                    wxOrientation orient,
                                    int WXUNUSED(flags),
                                    long WXUNUSED(style))
{
    // draw the thumb border
    wxRect rect = rectOrig;
    DrawAntiRaisedBorder(dc, &rect);

    // draw the handle in the middle
    if ( orient == wxVERTICAL )
    {
        rect.height = 2*BORDER_THICKNESS;
        rect.y = rectOrig.y + (rectOrig.height - rect.height) / 2;
    }
    else // horz
    {
        rect.width = 2*BORDER_THICKNESS;
        rect.x = rectOrig.x + (rectOrig.width - rect.width) / 2;
    }

    DrawShadedRect(dc, &rect, m_penDarkGrey, m_penHighlight);
}

#endif // wxUSE_SLIDER

#if wxUSE_MENUS

// ----------------------------------------------------------------------------
// menu and menubar
// ----------------------------------------------------------------------------

// wxGTKMenuGeometryInfo: the wxMenuGeometryInfo used by wxGTKRenderer
class wxGTKMenuGeometryInfo : public wxMenuGeometryInfo
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
        wxGTKRenderer::GetMenuGeometry(wxWindow *, const wxMenu&) const;
};

// FIXME: all constants are hardcoded but shouldn't be
static const wxCoord MENU_LEFT_MARGIN = 9;
static const wxCoord MENU_RIGHT_MARGIN = 6;

static const wxCoord MENU_HORZ_MARGIN = 6;
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

void wxGTKRenderer::DrawMenuBarItem(wxDC& dc,
                                    const wxRect& rect,
                                    const wxString& label,
                                    int flags,
                                    int indexAccel)
{
    DoDrawMenuItem(dc, rect, label, flags, indexAccel);
}

void wxGTKRenderer::DrawMenuItem(wxDC& dc,
                                 wxCoord y,
                                 const wxMenuGeometryInfo& gi,
                                 const wxString& label,
                                 const wxString& accel,
                                 const wxBitmap& bitmap,
                                 int flags,
                                 int indexAccel)
{
    const wxGTKMenuGeometryInfo& geomInfo = (const wxGTKMenuGeometryInfo&)gi;

    wxRect rect;
    rect.x = 0;
    rect.y = y;
    rect.width = geomInfo.GetSize().x;
    rect.height = geomInfo.GetItemHeight();

    DoDrawMenuItem(dc, rect, label, flags, indexAccel, accel, bitmap, &geomInfo);
}

void wxGTKRenderer::DoDrawMenuItem(wxDC& dc,
                                   const wxRect& rectOrig,
                                   const wxString& label,
                                   int flags,
                                   int indexAccel,
                                   const wxString& accel,
                                   const wxBitmap& bitmap,
                                   const wxGTKMenuGeometryInfo *geometryInfo)
{
    wxRect rect = rectOrig;

    // draw the selected item specially
    if ( flags & wxCONTROL_SELECTED )
    {
        wxRect rectIn;
        DrawBorder(dc, wxBORDER_RAISED, rect, flags, &rectIn);

        DrawBackground(dc, wxSCHEME_COLOUR(m_scheme, CONTROL_CURRENT), rectIn);
    }

    rect.Deflate(MENU_HORZ_MARGIN, MENU_VERT_MARGIN);

    // draw the bitmap: use the bitmap provided or the standard checkmark for
    // the checkable items
    if ( geometryInfo )
    {
        wxBitmap bmp = bitmap;
        if ( !bmp.Ok() && (flags & wxCONTROL_CHECKABLE) )
        {
            bmp = GetCheckBitmap(flags);
        }

        if ( bmp.Ok() )
        {
            rect.SetRight(geometryInfo->GetLabelOffset());
            wxControlRenderer::DrawBitmap(dc, bmp, rect);
        }
    }
    //else: menubar items don't have bitmaps

    // draw the label
    if ( geometryInfo )
    {
        rect.x = geometryInfo->GetLabelOffset();
        rect.SetRight(geometryInfo->GetAccelOffset());
    }

    DrawLabel(dc, label, rect, flags, wxALIGN_CENTRE_VERTICAL, indexAccel);

    // draw the accel string
    if ( !accel.empty() )
    {
        // menubar items shouldn't have them
        wxCHECK_RET( geometryInfo, wxT("accel strings only valid for menus") );

        rect.x = geometryInfo->GetAccelOffset();
        rect.SetRight(geometryInfo->GetSize().x);

        // NB: no accel index here
        DrawLabel(dc, accel, rect, flags, wxALIGN_CENTRE_VERTICAL);
    }

    // draw the submenu indicator
    if ( flags & wxCONTROL_ISSUBMENU )
    {
        wxCHECK_RET( geometryInfo, wxT("wxCONTROL_ISSUBMENU only valid for menus") );

        rect.x = geometryInfo->GetSize().x - MENU_RIGHT_MARGIN;
        rect.width = MENU_RIGHT_MARGIN;

        DrawArrow(dc, wxRIGHT, rect, flags);
    }
}

void wxGTKRenderer::DrawMenuSeparator(wxDC& dc,
                                      wxCoord y,
                                      const wxMenuGeometryInfo& geomInfo)
{
    DrawHorizontalLine(dc, y + MENU_VERT_MARGIN, 0, geomInfo.GetSize().x);
}

wxSize wxGTKRenderer::GetMenuBarItemSize(const wxSize& sizeText) const
{
    wxSize size = sizeText;

    // TODO: make this configurable
    size.x += 2*MENU_HORZ_MARGIN;
    size.y += 2*MENU_VERT_MARGIN;

    return size;
}

wxMenuGeometryInfo *wxGTKRenderer::GetMenuGeometry(wxWindow *win,
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
    wxGTKMenuGeometryInfo *gi = new wxGTKMenuGeometryInfo;

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

// ----------------------------------------------------------------------------
// combobox
// ----------------------------------------------------------------------------

void wxGTKRenderer::InitComboBitmaps()
{
    wxSize sizeArrow = m_sizeScrollbarArrow;
    sizeArrow.x -= 2;
    sizeArrow.y -= 2;

    size_t n;

    for ( n = ComboState_Normal; n < ComboState_Max; n++ )
    {
        m_bitmapsCombo[n].Create(sizeArrow.x, sizeArrow.y);
    }

    static const int comboButtonFlags[ComboState_Max] =
    {
        0,
        wxCONTROL_CURRENT,
        wxCONTROL_PRESSED,
        wxCONTROL_DISABLED,
    };

    wxRect rect(sizeArrow);

    wxMemoryDC dc;
    for ( n = ComboState_Normal; n < ComboState_Max; n++ )
    {
        int flags = comboButtonFlags[n];

        dc.SelectObject(m_bitmapsCombo[n]);
        DrawSolidRect(dc, GetBackgroundColour(flags), rect);
        DrawArrow(dc, wxDOWN, rect, flags);
    }
}

void wxGTKRenderer::GetComboBitmaps(wxBitmap *bmpNormal,
                                    wxBitmap *bmpFocus,
                                    wxBitmap *bmpPressed,
                                    wxBitmap *bmpDisabled)
{
    if ( !m_bitmapsCombo[ComboState_Normal].Ok() )
    {
        InitComboBitmaps();
    }

    if ( bmpNormal )
        *bmpNormal = m_bitmapsCombo[ComboState_Normal];
    if ( bmpFocus )
        *bmpFocus = m_bitmapsCombo[ComboState_Focus];
    if ( bmpPressed )
        *bmpPressed = m_bitmapsCombo[ComboState_Pressed];
    if ( bmpDisabled )
        *bmpDisabled = m_bitmapsCombo[ComboState_Disabled];
}

// ----------------------------------------------------------------------------
// scrollbar
// ----------------------------------------------------------------------------

void wxGTKRenderer::DrawArrowBorder(wxDC& dc,
                                    wxRect *rect,
                                    wxDirection dir)
{
    static const wxDirection sides[] =
    {
        wxUP, wxLEFT, wxRIGHT, wxDOWN
    };

    wxRect rect1, rect2, rectInner;
    rect1 =
    rect2 =
    rectInner = *rect;

    rect2.Inflate(-1);
    rectInner.Inflate(-2);

    DrawSolidRect(dc, wxSCHEME_COLOUR(m_scheme, SCROLLBAR), *rect);

    // find the side not to draw and also adjust the rectangles to compensate
    // for it
    wxDirection sideToOmit;
    switch ( dir )
    {
        case wxUP:
            sideToOmit = wxDOWN;
            rect2.height += 1;
            rectInner.height += 1;
            break;

        case wxDOWN:
            sideToOmit = wxUP;
            rect2.y -= 1;
            rect2.height += 1;
            rectInner.y -= 2;
            rectInner.height += 1;
            break;

        case wxLEFT:
            sideToOmit = wxRIGHT;
            rect2.width += 1;
            rectInner.width += 1;
            break;

        case wxRIGHT:
            sideToOmit = wxLEFT;
            rect2.x -= 1;
            rect2.width += 1;
            rectInner.x -= 2;
            rectInner.width += 1;
            break;

        default:
            wxFAIL_MSG(wxT("unknown arrow direction"));
            return;
    }

    // the outer rect first
    size_t n;
    for ( n = 0; n < WXSIZEOF(sides); n++ )
    {
        wxDirection side = sides[n];
        if ( side == sideToOmit )
            continue;

        DrawAntiShadedRectSide(dc, rect1, m_penDarkGrey, m_penHighlight, side);
    }

    // and then the inner one
    for ( n = 0; n < WXSIZEOF(sides); n++ )
    {
        wxDirection side = sides[n];
        if ( side == sideToOmit )
            continue;

        DrawAntiShadedRectSide(dc, rect2, m_penBlack, m_penGrey, side);
    }

    *rect = rectInner;
}

void wxGTKRenderer::DrawScrollbarArrow(wxDC& dc,
                                       wxDirection dir,
                                       const wxRect& rectArrow,
                                       int flags)
{
    // first of all, draw the border around it - but we don't want the border
    // on the side opposite to the arrow point
    wxRect rect = rectArrow;
    DrawArrowBorder(dc, &rect, dir);

    // then the arrow itself
    DrawArrow(dc, dir, rect, flags);
}

// gtk_default_draw_arrow() takes ~350 lines and we can't do much better here
// these people are just crazy :-(
void wxGTKRenderer::DrawArrow(wxDC& dc,
                              wxDirection dir,
                              const wxRect& rect,
                              int flags)
{
    enum
    {
        Point_First,
        Point_Second,
        Point_Third,
        Point_Max
    };

    wxPoint ptArrow[Point_Max];

    wxColour colInside = GetBackgroundColour(flags);
    wxPen penShadow[4];
    if ( flags & wxCONTROL_DISABLED )
    {
        penShadow[0] = m_penDarkGrey;
        penShadow[1] = m_penDarkGrey;
        penShadow[2] = wxNullPen;
        penShadow[3] = wxNullPen;
    }
    else if ( flags & wxCONTROL_PRESSED )
    {
        penShadow[0] = m_penDarkGrey;
        penShadow[1] = m_penHighlight;
        penShadow[2] = wxNullPen;
        penShadow[3] = m_penBlack;
    }
    else // normal arrow
    {
        penShadow[0] = m_penHighlight;
        penShadow[1] = m_penBlack;
        penShadow[2] = m_penDarkGrey;
        penShadow[3] = wxNullPen;
    }

    wxCoord middle;
    if ( dir == wxUP || dir == wxDOWN )
    {
        // horz middle
        middle = (rect.GetRight() + rect.GetLeft() + 1) / 2;
    }
    else // horz arrow
    {
        middle = (rect.GetTop() + rect.GetBottom() + 1) / 2;
    }

    // draw the arrow interior
    dc.SetPen(*wxTRANSPARENT_PEN);
    dc.SetBrush(colInside);

    switch ( dir )
    {
        case wxUP:
            ptArrow[Point_First].x = rect.GetLeft();
            ptArrow[Point_First].y = rect.GetBottom();
            ptArrow[Point_Second].x = middle;
            ptArrow[Point_Second].y = rect.GetTop();
            ptArrow[Point_Third].x = rect.GetRight();
            ptArrow[Point_Third].y = rect.GetBottom();
            break;

        case wxDOWN:
            ptArrow[Point_First] = rect.GetPosition();
            ptArrow[Point_Second].x = middle;
            ptArrow[Point_Second].y = rect.GetBottom();
            ptArrow[Point_Third].x = rect.GetRight();
            ptArrow[Point_Third].y = rect.GetTop();
            break;

        case wxLEFT:
            ptArrow[Point_First].x = rect.GetRight();
            ptArrow[Point_First].y = rect.GetTop();
            ptArrow[Point_Second].x = rect.GetLeft();
            ptArrow[Point_Second].y = middle;
            ptArrow[Point_Third].x = rect.GetRight();
            ptArrow[Point_Third].y = rect.GetBottom();
            break;

        case wxRIGHT:
            ptArrow[Point_First] = rect.GetPosition();
            ptArrow[Point_Second].x = rect.GetRight();
            ptArrow[Point_Second].y = middle;
            ptArrow[Point_Third].x = rect.GetLeft();
            ptArrow[Point_Third].y = rect.GetBottom();
            break;

        default:
            wxFAIL_MSG(wxT("unknown arrow direction"));
    }

    dc.DrawPolygon(WXSIZEOF(ptArrow), ptArrow);

    // draw the arrow border
    dc.SetPen(penShadow[0]);
    switch ( dir )
    {
        case wxUP:
            dc.DrawLine(ptArrow[Point_Second], ptArrow[Point_First]);
            dc.DrawPoint(ptArrow[Point_First]);
            if ( penShadow[3].Ok() )
            {
                dc.SetPen(penShadow[3]);
                dc.DrawLine(ptArrow[Point_First].x + 1, ptArrow[Point_First].y,
                            ptArrow[Point_Second].x, ptArrow[Point_Second].y);
            }
            dc.SetPen(penShadow[1]);
            dc.DrawLine(ptArrow[Point_Second].x + 1, ptArrow[Point_Second].y + 1,
                        ptArrow[Point_Third].x, ptArrow[Point_Third].y);
            dc.DrawPoint(ptArrow[Point_Third]);
            dc.DrawLine(ptArrow[Point_Third].x - 2, ptArrow[Point_Third].y,
                        ptArrow[Point_First].x + 1, ptArrow[Point_First].y);
            if ( penShadow[2].Ok() )
            {
                dc.SetPen(penShadow[2]);
                dc.DrawLine(ptArrow[Point_Third].x - 1, ptArrow[Point_Third].y,
                            ptArrow[Point_Second].x, ptArrow[Point_Second].y + 1);
                dc.DrawLine(ptArrow[Point_Third].x - 1, ptArrow[Point_Third].y - 1,
                            ptArrow[Point_First].x + 2, ptArrow[Point_First].y - 1);
            }
            break;

        case wxDOWN:
            dc.DrawLine(ptArrow[Point_First], ptArrow[Point_Second]);
            dc.DrawLine(ptArrow[Point_First].x + 2, ptArrow[Point_First].y,
                        ptArrow[Point_Third].x - 1, ptArrow[Point_Third].y);
            if ( penShadow[2].Ok() )
            {
                dc.SetPen(penShadow[2]);
                dc.DrawLine(ptArrow[Point_Second].x, ptArrow[Point_Second].y - 1,
                            ptArrow[Point_Third].x - 1, ptArrow[Point_Third].y - 1);
            }
            dc.SetPen(penShadow[1]);
            dc.DrawLine(ptArrow[Point_Second], ptArrow[Point_Third]);
            dc.DrawPoint(ptArrow[Point_Third]);
            break;

        case wxLEFT:
            dc.DrawLine(ptArrow[Point_Second], ptArrow[Point_First]);
            dc.DrawPoint(ptArrow[Point_First]);
            if ( penShadow[2].Ok() )
            {
                dc.SetPen(penShadow[2]);
                dc.DrawLine(ptArrow[Point_Third].x - 1, ptArrow[Point_Third].y,
                            ptArrow[Point_First].x - 1, ptArrow[Point_First].y + 2);
                dc.DrawLine(ptArrow[Point_Third].x, ptArrow[Point_Third].y,
                            ptArrow[Point_Second].x + 2, ptArrow[Point_Second].y + 1);
            }
            dc.SetPen(penShadow[1]);
            dc.DrawLine(ptArrow[Point_Third].x, ptArrow[Point_Third].y,
                        ptArrow[Point_First].x, ptArrow[Point_First].y + 1);
            dc.DrawLine(ptArrow[Point_Second].x + 1, ptArrow[Point_Second].y + 1,
                        ptArrow[Point_Third].x - 1, ptArrow[Point_Third].y);
            break;

        case wxRIGHT:
            dc.DrawLine(ptArrow[Point_First], ptArrow[Point_Third]);
            dc.DrawLine(ptArrow[Point_First].x + 2, ptArrow[Point_First].y + 1,
                        ptArrow[Point_Second].x, ptArrow[Point_Second].y);
            dc.SetPen(penShadow[1]);
            dc.DrawLine(ptArrow[Point_Second], ptArrow[Point_Third]);
            dc.DrawPoint(ptArrow[Point_Third]);
            break;

        default:
            wxFAIL_MSG(wxT("unknown arrow direction"));
            return;
    }
}

void wxGTKRenderer::DrawThumbBorder(wxDC& dc,
                                    wxRect *rect,
                                    wxOrientation orient)
{
    if ( orient == wxVERTICAL )
    {
        DrawAntiShadedRectSide(dc, *rect, m_penDarkGrey, m_penHighlight,
                               wxLEFT);
        DrawAntiShadedRectSide(dc, *rect, m_penDarkGrey, m_penHighlight,
                               wxRIGHT);
        rect->Inflate(-1, 0);

        DrawAntiShadedRectSide(dc, *rect, m_penBlack, m_penGrey,
                               wxLEFT);
        DrawAntiShadedRectSide(dc, *rect, m_penBlack, m_penGrey,
                               wxRIGHT);
        rect->Inflate(-1, 0);
    }
    else
    {
        DrawAntiShadedRectSide(dc, *rect, m_penDarkGrey, m_penHighlight,
                               wxUP);
        DrawAntiShadedRectSide(dc, *rect, m_penDarkGrey, m_penHighlight,
                               wxDOWN);
        rect->Inflate(0, -1);

        DrawAntiShadedRectSide(dc, *rect, m_penBlack, m_penGrey,
                               wxUP);
        DrawAntiShadedRectSide(dc, *rect, m_penBlack, m_penGrey,
                               wxDOWN);
        rect->Inflate(0, -1);
    }
}

void wxGTKRenderer::DrawScrollbarThumb(wxDC& dc,
                                       wxOrientation orient,
                                       const wxRect& rect,
                                       int flags)
{
    // the thumb is never pressed never has focus border under GTK and the
    // scrollbar background never changes at all
    int flagsThumb = flags & ~(wxCONTROL_PRESSED | wxCONTROL_FOCUSED);

    // we don't want the border in the direction of the scrollbar movement
    wxRect rectThumb = rect;
    DrawThumbBorder(dc, &rectThumb, orient);

    DrawButtonBorder(dc, rectThumb, flagsThumb, &rectThumb);
    DrawBackground(dc, wxNullColour, rectThumb, flagsThumb);
}

void wxGTKRenderer::DrawScrollbarShaft(wxDC& dc,
                                       wxOrientation orient,
                                       const wxRect& rect,
                                       int WXUNUSED(flags))
{
    wxRect rectBar = rect;
    DrawThumbBorder(dc, &rectBar, orient);
    DrawSolidRect(dc, wxSCHEME_COLOUR(m_scheme, SCROLLBAR), rectBar);
}

// ----------------------------------------------------------------------------
// size adjustments
// ----------------------------------------------------------------------------

void wxGTKRenderer::AdjustSize(wxSize *size, const wxWindow *window)
{
#if wxUSE_BMPBUTTON
    if ( wxDynamicCast(window, wxBitmapButton) )
    {
        size->x += 4;
        size->y += 4;
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
            // TODO: this is ad hoc...
            size->x += 3*window->GetCharWidth();
            wxCoord minBtnHeight = 18;
            if ( size->y < minBtnHeight )
                size->y = minBtnHeight;

            // button border width
            size->y += 4;
        }
    } else
#endif // wxUSE_BUTTON || wxUSE_TOGGLEBTN
#if wxUSE_SCROLLBAR
    if ( wxDynamicCast(window, wxScrollBar) )
    {
        // we only set the width of vert scrollbars and height of the
        // horizontal ones
        if ( window->GetWindowStyle() & wxSB_HORIZONTAL )
            size->y = m_sizeScrollbarArrow.x;
        else
            size->x = m_sizeScrollbarArrow.x;
    }
    else
#endif // wxUSE_SCROLLBAR
    {
        // take into account the border width
        wxStdRenderer::AdjustSize(size, window);
    }
}

// ----------------------------------------------------------------------------
// standard icons
// ----------------------------------------------------------------------------

/* Copyright (c) Julian Smart */
static const char *error_xpm[] = {
/* columns rows colors chars-per-pixel */
"48 48 4 1",
"  c None",
"X c #242424",
"o c #DCDF00",
". c #C00000",
/* pixels */
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                    .....                       ",
"                .............                   ",
"              .................                 ",
"             ...................                ",
"           .......................              ",
"          .........................             ",
"         ...........................            ",
"         ...........................X           ",
"        .............................X          ",
"       ...............................          ",
"       ...............................X         ",
"      .................................X        ",
"      .................................X        ",
"      .................................XX       ",
"      ...ooooooooooooooooooooooooooo...XX       ",
"     ....ooooooooooooooooooooooooooo....X       ",
"     ....ooooooooooooooooooooooooooo....X       ",
"     ....ooooooooooooooooooooooooooo....XX      ",
"     ....ooooooooooooooooooooooooooo....XX      ",
"     ....ooooooooooooooooooooooooooo....XX      ",
"      ...ooooooooooooooooooooooooooo...XXX      ",
"      ...ooooooooooooooooooooooooooo...XXX      ",
"      .................................XX       ",
"      .................................XX       ",
"       ...............................XXX       ",
"       ...............................XXX       ",
"        .............................XXX        ",
"         ...........................XXXX        ",
"         ...........................XXX         ",
"          .........................XXX          ",
"           .......................XXXX          ",
"            X...................XXXXX           ",
"             X.................XXXXX            ",
"               X.............XXXXX              ",
"                XXXX.....XXXXXXXX               ",
"                  XXXXXXXXXXXXX                 ",
"                      XXXXX                     ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                "
};

/* Copyright (c) Julian Smart */
static const char *info_xpm[] = {
/* columns rows colors chars-per-pixel */
"48 48 9 1",
"$ c Black",
"O c #FFFFFF",
"@ c #808080",
"+ c #000080",
"o c #E8EB01",
"  c None",
"X c #FFFF40",
"# c #C0C0C0",
". c #ABAD01",
/* pixels */
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                     .....                      ",
"                   ..XXXXX..                    ",
"                 ..XXXXXXXXo..                  ",
"                .XXXOXXXXXXXoo.                 ",
"                .XOOXXX+XXXXXo.                 ",
"               .XOOOXX+++XXXXoo.                ",
"               .XOOXXX+++XXXXXo.                ",
"              .XOOOXXX+++XXXXXXo.               ",
"              .XOOXXXX+++XXXXXXo.               ",
"              .XXXXXXX+++XXXXXXX.               ",
"              .XXXXXXX+++XXXXXXo.               ",
"              .XXXXXXX+++XXXXXoo.               ",
"               .XXXXXX+++XXXXXo.                ",
"               .XXXXXXX+XXXXXXo.                ",
"                .XXXXXXXXXXXXo.                 ",
"                .XXXXX+++XXXoo.                 ",
"                 .XXXX+++XXoo.                  ",
"                  .XXXXXXXXo.                   ",
"                  ..XXXXXXo..                   ",
"                   .XXXXXo..                    ",
"                   @#######@                    ",
"                   @@@@@@@@@                    ",
"                   @#######@                    ",
"                   @@@@@@@@@                    ",
"                   @#######@                    ",
"                    @@@@@@@                     ",
"                      ###                       ",
"                      $$$                       ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                "
};

/* Copyright (c) Julian Smart */
static const char *warning_xpm[] = {
/* columns rows colors chars-per-pixel */
"48 48 9 1",
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
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                      .                         ",
"                     ...                        ",
"                     ...                        ",
"                    .....                       ",
"                   ...X..                       ",
"                   ..XXX..                      ",
"                  ...XXX...                     ",
"                  ..XXXXX..                     ",
"                 ..XXXXXX...                    ",
"                ...XXoO+XX..                    ",
"                ..XXXO@#XXX..                   ",
"               ..XXXXO@#XXX...                  ",
"              ...XXXXO@#XXXX..                  ",
"              ..XXXXXO@#XXXX...                 ",
"             ...XXXXXo@OXXXXX..                 ",
"            ...XXXXXXo@OXXXXXX..                ",
"            ..XXXXXXX$@OXXXXXX...               ",
"           ...XXXXXXXX@XXXXXXXX..               ",
"          ...XXXXXXXXXXXXXXXXXX...              ",
"          ..XXXXXXXXXXOXXXXXXXXX..              ",
"         ...XXXXXXXXXO@#XXXXXXXXX..             ",
"         ..XXXXXXXXXXX#XXXXXXXXXX...            ",
"        ...XXXXXXXXXXXXXXXXXXXXXXX..            ",
"       ...XXXXXXXXXXXXXXXXXXXXXXXX...           ",
"       ..............................           ",
"       ..............................           ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                "
};

/* Copyright (c) Julian Smart */
static const char *question_xpm[] = {
/* columns rows colors chars-per-pixel */
"48 48 21 1",
". c Black",
"> c #696969",
"O c #1F1F00",
"+ c #181818",
"o c #F6F900",
"; c #3F3F00",
"$ c #111111",
"  c None",
"& c #202020",
"X c #AAAA00",
"@ c #949400",
": c #303030",
"1 c #383838",
"% c #2A2A00",
", c #404040",
"= c #B4B400",
"- c #484848",
"# c #151500",
"< c #9F9F00",
"2 c #6A6A00",
"* c #353500",
/* pixels */
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                   .........                    ",
"                 ...XXXXXXX..                   ",
"               ..XXXXoooooXXXO+                 ",
"             ..XXooooooooooooX@..               ",
"            ..XoooooooooooooooXX#.              ",
"           $%XoooooooooooooooooXX#.             ",
"          &.XoooooooXXXXXXooooooXX..            ",
"          .XooooooXX.$...$XXoooooX*.            ",
"         $.XoooooX%.$     .*oooooo=..           ",
"         .XooooooX..      -.XoooooX..           ",
"         .XoooooX..+       .XoooooX;.           ",
"         ...XXXX..:        .XoooooX;.           ",
"          ........        >.XoooooX;.           ",
"                          +.XoooooX..           ",
"                         ,.Xoooooo<..           ",
"                        1#XooooooXO..           ",
"                       &#XooooooX2..            ",
"                      $%XooooooXX..             ",
"                     $%XooooooXX..              ",
"                    $%XooooooXX..               ",
"                   &.XooooooXX..                ",
"                   .XooooooXX..                 ",
"                  &.XoooooXX..                  ",
"                  ..XooooXX..                   ",
"                  ..XooooX...                   ",
"                  ..XXooXX..&                   ",
"                  ...XXXXX..                    ",
"                   ........                     ",
"                                                ",
"                                                ",
"                   .......                      ",
"                  ..XXXXX..                     ",
"                 ..XXoooXX..                    ",
"                 ..XoooooX..                    ",
"                 ..XoooooX..                    ",
"                 ..XXoooXX..                    ",
"                  ..XXXXX..                     ",
"                   .......                      ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                ",
"                                                "
};

wxBitmap wxGTKArtProvider::CreateBitmap(const wxArtID& id,
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


// ============================================================================
// wxInputHandler
// ============================================================================

// ----------------------------------------------------------------------------
// wxGTKInputHandler
// ----------------------------------------------------------------------------

bool wxGTKInputHandler::HandleKey(wxInputConsumer * WXUNUSED(control),
                                  const wxKeyEvent& WXUNUSED(event),
                                  bool WXUNUSED(pressed))
{
    return false;
}

bool wxGTKInputHandler::HandleMouse(wxInputConsumer *control,
                                    const wxMouseEvent& event)
{
    // clicking on the control gives it focus
    if ( event.ButtonDown() && wxWindow::FindFocus() != control->GetInputWindow() )
    {
        control->GetInputWindow()->SetFocus();

        return true;
    }

    return false;
}

bool wxGTKInputHandler::HandleMouseMove(wxInputConsumer *control,
                                        const wxMouseEvent& event)
{
    if ( event.Entering() )
    {
        control->GetInputWindow()->SetCurrent(true);
    }
    else if ( event.Leaving() )
    {
        control->GetInputWindow()->SetCurrent(false);
    }
    else
    {
        return false;
    }

    return true;
}

#if wxUSE_CHECKBOX

// ----------------------------------------------------------------------------
// wxGTKCheckboxInputHandler
// ----------------------------------------------------------------------------

bool wxGTKCheckboxInputHandler::HandleKey(wxInputConsumer *control,
                                          const wxKeyEvent& event,
                                          bool pressed)
{
    if ( pressed )
    {
        int keycode = event.GetKeyCode();
        if ( keycode == WXK_SPACE || keycode == WXK_RETURN )
        {
            control->PerformAction(wxACTION_CHECKBOX_TOGGLE);

            return true;
        }
    }

    return false;
}

#endif // wxUSE_CHECKBOX

#if wxUSE_TEXTCTRL

// ----------------------------------------------------------------------------
// wxGTKTextCtrlInputHandler
// ----------------------------------------------------------------------------

bool wxGTKTextCtrlInputHandler::HandleKey(wxInputConsumer *control,
                                          const wxKeyEvent& event,
                                          bool pressed)
{
    // handle only GTK-specific text bindings here, the others are handled in
    // the base class
    if ( pressed )
    {
        wxControlAction action;
        int keycode = event.GetKeyCode();
        if ( event.ControlDown() )
        {
            switch ( keycode )
            {
                case 'A':
                    action = wxACTION_TEXT_HOME;
                    break;

                case 'B':
                    action = wxACTION_TEXT_LEFT;
                    break;

                case 'D':
                    action << wxACTION_TEXT_PREFIX_DEL << wxACTION_TEXT_RIGHT;
                    break;

                case 'E':
                    action = wxACTION_TEXT_END;
                    break;

                case 'F':
                    action = wxACTION_TEXT_RIGHT;
                    break;

                case 'H':
                    action << wxACTION_TEXT_PREFIX_DEL << wxACTION_TEXT_LEFT;
                    break;

                case 'K':
                    action << wxACTION_TEXT_PREFIX_DEL << wxACTION_TEXT_END;
                    break;

                case 'N':
                    action = wxACTION_TEXT_DOWN;
                    break;

                case 'P':
                    action = wxACTION_TEXT_UP;
                    break;

                case 'U':
                    //delete the entire line
                    control->PerformAction(wxACTION_TEXT_HOME);
                    action << wxACTION_TEXT_PREFIX_DEL << wxACTION_TEXT_END;
                    break;

                case 'W':
                    action << wxACTION_TEXT_PREFIX_DEL << wxACTION_TEXT_WORD_LEFT;
                    break;
            }
        }
        else if ( event.AltDown() )
        {
            switch ( keycode )
            {
                case 'B':
                    action = wxACTION_TEXT_WORD_LEFT;
                    break;

                case 'D':
                    action << wxACTION_TEXT_PREFIX_DEL << wxACTION_TEXT_WORD_RIGHT;
                    break;

                case 'F':
                    action = wxACTION_TEXT_WORD_RIGHT;
                    break;
            }
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

#endif // wxUSE_THEME_GTK
