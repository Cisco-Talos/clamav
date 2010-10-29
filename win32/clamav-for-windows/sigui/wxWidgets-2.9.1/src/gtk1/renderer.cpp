///////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/renderer.cpp
// Purpose:     implementation of wxRendererNative for wxGTK
// Author:      Vadim Zeitlin
// Modified by:
// Created:     20.07.2003
// RCS-ID:      $Id$
// Copyright:   (c) 2003 Vadim Zeitlin <vadim@wxwindows.org>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/renderer.h"

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/dc.h"
#endif

#include <gtk/gtk.h>
#include "wx/gtk1/win_gtk.h"
#include "wx/gtk1/dcclient.h"

// RR: After a correction to the orientation of the sash
//     this doesn't seem to be required anymore and it
//     seems to confuse some themes so USE_ERASE_RECT=0
#define USE_ERASE_RECT 0

// ----------------------------------------------------------------------------
// wxRendererGTK: our wxRendererNative implementation
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxRendererGTK : public wxDelegateRendererNative
{
public:
    // draw the header control button (used by wxListCtrl)
    virtual int DrawHeaderButton(wxWindow *win,
                                 wxDC& dc,
                                 const wxRect& rect,
                                 int flags = 0,
                                 wxHeaderSortIconType sortArrow = wxHDR_SORT_ICON_NONE,
                                 wxHeaderButtonParams* params=NULL);

    virtual void DrawSplitterBorder(wxWindow *win,
                                    wxDC& dc,
                                    const wxRect& rect,
                                    int flags = 0);
    virtual void DrawSplitterSash(wxWindow *win,
                                  wxDC& dc,
                                  const wxSize& size,
                                  wxCoord position,
                                  wxOrientation orient,
                                  int flags = 0);

    virtual void DrawComboBoxDropButton(wxWindow *win,
                                        wxDC& dc,
                                        const wxRect& rect,
                                        int flags = 0);

    virtual void DrawDropArrow(wxWindow *win,
                               wxDC& dc,
                               const wxRect& rect,
                               int flags = 0);

    virtual wxSplitterRenderParams GetSplitterParams(const wxWindow *win);

private:
    // FIXME: shouldn't we destroy these windows somewhere?

    // used by DrawHeaderButton and DrawComboBoxDropButton
    static GtkWidget *GetButtonWidget();
};

// ============================================================================
// implementation
// ============================================================================

/* static */
wxRendererNative& wxRendererNative::GetDefault()
{
    static wxRendererGTK s_rendererGTK;

    return s_rendererGTK;
}

// ----------------------------------------------------------------------------
// helper functions
// ----------------------------------------------------------------------------

GtkWidget *
wxRendererGTK::GetButtonWidget()
{
    static GtkWidget *s_button = NULL;
    static GtkWidget *s_window = NULL;

    if ( !s_button )
    {
        s_window = gtk_window_new( GTK_WINDOW_POPUP );
        gtk_widget_realize( s_window );
        s_button = gtk_button_new();
        gtk_container_add( GTK_CONTAINER(s_window), s_button );
        gtk_widget_realize( s_button );
    }

    return s_button;
}

// ----------------------------------------------------------------------------
// list/tree controls drawing
// ----------------------------------------------------------------------------

int
wxRendererGTK::DrawHeaderButton(wxWindow *win,
                                wxDC& dc,
                                const wxRect& rect,
                                int flags,
                                wxHeaderSortIconType WXUNUSED(sortArrow),
                                wxHeaderButtonParams* WXUNUSED(params))
{

    GtkWidget *button = GetButtonWidget();

    gtk_paint_box
    (
        button->style,
        // FIXME: I suppose GTK_PIZZA(win->m_wxwindow)->bin_window doesn't work with wxMemoryDC.
        //   Maybe use code similar as in DrawComboBoxDropButton below?
        GTK_PIZZA(win->m_wxwindow)->bin_window,
        flags & wxCONTROL_DISABLED ? GTK_STATE_INSENSITIVE : GTK_STATE_NORMAL,
        GTK_SHADOW_OUT,
        NULL,
        button,
        "button",
        dc.LogicalToDeviceX(rect.x) -1, rect.y -1, rect.width +2, rect.height +2
    );

    return rect.width + 2;
}

// ----------------------------------------------------------------------------
// splitter sash drawing
// ----------------------------------------------------------------------------

// the full sash width (should be even)
static const wxCoord SASH_SIZE = 8;

// margin around the sash
static const wxCoord SASH_MARGIN = 2;

static int GetGtkSplitterFullSize()
{
    return SASH_SIZE + SASH_MARGIN;
}

wxSplitterRenderParams
wxRendererGTK::GetSplitterParams(const wxWindow *WXUNUSED(win))
{
    // we don't draw any border, hence 0 for the second field
    return wxSplitterRenderParams
           (
               GetGtkSplitterFullSize(),
               0,
               false    // not
           );
}

void
wxRendererGTK::DrawSplitterBorder(wxWindow * WXUNUSED(win),
                                  wxDC& WXUNUSED(dc),
                                  const wxRect& WXUNUSED(rect),
                                  int WXUNUSED(flags))
{
    // nothing to do
}

void
wxRendererGTK::DrawSplitterSash(wxWindow *win,
                                wxDC& WXUNUSED(dc),
                                const wxSize& size,
                                wxCoord position,
                                wxOrientation orient,
                                int WXUNUSED(flags))
{
    if ( !win->m_wxwindow->window )
    {
        // window not realized yet
        return;
    }

    wxCoord full_size = GetGtkSplitterFullSize();

    // are we drawing vertical or horizontal splitter?
    const bool isVert = orient == wxVERTICAL;

    GdkRectangle rect;
#if USE_ERASE_RECT
    GdkRectangle erase_rect;
#endif

    if ( isVert )
    {
        int h = win->GetClientSize().GetHeight();

        rect.x = position;
        rect.y = 0;
        rect.width = full_size;
        rect.height = h;

#if USE_ERASE_RECT
        erase_rect.x = position;
        erase_rect.y = 0;
        erase_rect.width = full_size;
        erase_rect.height = h;
#endif
    }
    else // horz
    {
        int w = win->GetClientSize().GetWidth();

        rect.x = 0;
        rect.y = position;
        rect.height = full_size;
        rect.width = w;

#if USE_ERASE_RECT
        erase_rect.y = position;
        erase_rect.x = 0;
        erase_rect.height = full_size;
        erase_rect.width = w;
#endif
    }

#if USE_ERASE_RECT
    // we must erase everything first, otherwise the garbage
    // from the old sash is left when dragging it
    gtk_paint_flat_box
    (
        win->m_wxwindow->style,
        GTK_PIZZA(win->m_wxwindow)->bin_window,
        GTK_STATE_NORMAL,
        GTK_SHADOW_NONE,
        NULL,
        win->m_wxwindow,
        (char *)"viewportbin", // const_cast
        erase_rect.x,
        erase_rect.y,
        erase_rect.width,
        erase_rect.height
    );
#endif


    // leave some margin before sash itself
    position += SASH_MARGIN / 2;

    // and finally draw it using GTK paint functions
    typedef void (*GtkPaintLineFunc)(GtkStyle *, GdkWindow *,
                                                GtkStateType,
                                                GdkRectangle *, GtkWidget *,
                                                gchar *,
                                                gint, gint, gint);

    GtkPaintLineFunc func = isVert ? gtk_paint_vline : gtk_paint_hline;

    (*func)
    (
        win->m_wxwindow->style,
        GTK_PIZZA(win->m_wxwindow)->bin_window,
        GTK_STATE_NORMAL,
        NULL,
        win->m_wxwindow,
        (char *)"paned", // const_cast
        0, isVert ? size.y : size.x, position + SASH_SIZE / 2 - 1
    );

    gtk_paint_box
    (
        win->m_wxwindow->style,
        GTK_PIZZA(win->m_wxwindow)->bin_window,
        GTK_STATE_NORMAL,
        GTK_SHADOW_OUT,
        NULL,
        win->m_wxwindow,
        (char *)"paned", // const_cast
        isVert ? position : size.x - 2*SASH_SIZE,
        isVert ? size.y - 2*SASH_SIZE : position,
        SASH_SIZE, SASH_SIZE
    );
}

void
wxRendererGTK::DrawDropArrow(wxWindow *WXUNUSED(win),
                             wxDC& dc,
                             const wxRect& rect,
                             int flags)
{
    GtkWidget *button = GetButtonWidget();

    // If we give GTK_PIZZA(win->m_wxwindow)->bin_window as
    // a window for gtk_paint_xxx function, then it won't
    // work for wxMemoryDC. So that is why we assume wxDC
    // is wxWindowDC (wxClientDC, wxMemoryDC and wxPaintDC
    // are derived from it) and use its m_window.
    wxWindowDCImpl * const impl = wxDynamicCast(dc.GetImpl(), wxWindowDCImpl);
    wxCHECK_RET( impl, "must have a window DC" );

    GdkWindow* gdk_window = impl->GetGDKWindow();

    // draw arrow so that there is even space horizontally
    // on both sides
    int arrowX = rect.width/4 + 1;
    int arrowWidth = rect.width - (arrowX*2);

    // scale arrow's height accoording to the width
    int arrowHeight = rect.width/3;
    int arrowY = (rect.height-arrowHeight)/2 +
                 ((rect.height-arrowHeight) & 1);

    GtkStateType state;

    if ( flags & wxCONTROL_PRESSED )
        state = GTK_STATE_ACTIVE;
    else if ( flags & wxCONTROL_DISABLED )
        state = GTK_STATE_INSENSITIVE;
    else if ( flags & wxCONTROL_CURRENT )
        state = GTK_STATE_PRELIGHT;
    else
        state = GTK_STATE_NORMAL;

    // draw arrow on button
    gtk_paint_arrow
    (
        button->style,
        gdk_window,
        state,
        flags & wxCONTROL_PRESSED ? GTK_SHADOW_IN : GTK_SHADOW_OUT,
        NULL,
        button,
        "arrow",
        GTK_ARROW_DOWN,
        FALSE,
        rect.x + arrowX,
        rect.y + arrowY,
        arrowWidth,
        arrowHeight
    );
}

void
wxRendererGTK::DrawComboBoxDropButton(wxWindow *win,
                                      wxDC& dc,
                                      const wxRect& rect,
                                      int flags)
{
    GtkWidget *button = GetButtonWidget();

    // for reason why we do this, see DrawDropArrow
    wxWindowDCImpl * const impl = wxDynamicCast(dc.GetImpl(), wxWindowDCImpl);
    wxCHECK_RET( impl, "must have a window DC" );

    GdkWindow* gdk_window = impl->GetGDKWindow();

    // draw button
    GtkStateType state;

    if ( flags & wxCONTROL_PRESSED )
        state = GTK_STATE_ACTIVE;
    else if ( flags & wxCONTROL_DISABLED )
        state = GTK_STATE_INSENSITIVE;
    else if ( flags & wxCONTROL_CURRENT )
        state = GTK_STATE_PRELIGHT;
    else
        state = GTK_STATE_NORMAL;

    gtk_paint_box
    (
        button->style,
        gdk_window,
        state,
        flags & wxCONTROL_PRESSED ? GTK_SHADOW_IN : GTK_SHADOW_OUT,
        NULL,
        button,
        "button",
        rect.x, rect.y, rect.width, rect.height
    );

    // draw arrow on button
    DrawDropArrow(win,dc,rect,flags);

}
