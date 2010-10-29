/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/settings.cpp
// Purpose:
// Author:      Robert Roebling
// Modified by: Mart Raudsepp (GetMetric)
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/settings.h"

#ifndef WX_PRECOMP
    #include "wx/cmndata.h"
    #include "wx/toplevel.h"
#endif

#include "wx/fontutil.h"

#include <gdk/gdk.h>
#include <gdk/gdkx.h>
#include <gdk/gdkprivate.h>
#include <gtk/gtk.h>

#include <X11/Xatom.h>

#define SHIFT (8*(sizeof(short int)-sizeof(char)))

// ----------------------------------------------------------------------------
// wxSystemObjects
// ----------------------------------------------------------------------------

struct wxSystemObjects
{
    wxColour m_colBtnFace,
             m_colBtnShadow,
             m_colBtnHighlight,
             m_colHighlight,
             m_colHighlightText,
             m_colListBox,
             m_colBtnText,
             m_colMenuItemHighlight,
             m_colTooltip,
             m_colTooltipText;

    wxFont m_fontSystem;
};

static wxSystemObjects gs_objects;

// ----------------------------------------------------------------------------
// wxSystemSettings implementation
// ----------------------------------------------------------------------------

// kind of widget to use in GetColourFromGTKWidget
enum wxGtkWidgetType
{
    wxGTK_BUTTON,
    wxGTK_LIST,
    wxGTK_MENUITEM
};

// the colour we need
enum wxGtkColourType
{
    wxGTK_FG,
    wxGTK_BG,
    wxGTK_BASE
};

// wxSystemSettings::GetColour() helper: get the colours from a GTK+
// widget style, return true if we did get them, false to use defaults
static bool GetColourFromGTKWidget(int& red, int& green, int& blue,
                                   wxGtkWidgetType type = wxGTK_BUTTON,
                                   GtkStateType state = GTK_STATE_NORMAL,
                                   wxGtkColourType colour = wxGTK_BG)
{
    GtkWidget *widget;
    switch ( type )
    {
        default:
            wxFAIL_MSG( wxT("unexpected GTK widget type") );
            // fall through

        case wxGTK_BUTTON:
            widget = gtk_button_new();
            break;

        case wxGTK_LIST:
            widget = gtk_list_new();
            break;

        case wxGTK_MENUITEM:
            widget = gtk_menu_item_new();
    }

    GtkStyle *def = gtk_rc_get_style( widget );
    if ( !def )
        def = gtk_widget_get_default_style();

    bool ok;
    if ( def )
    {
        GdkColor *col;
        switch ( colour )
        {
            default:
                wxFAIL_MSG( wxT("unexpected GTK colour type") );
                // fall through

            case wxGTK_FG:
                col = def->fg;
                break;

            case wxGTK_BG:
                col = def->bg;
                break;

            case wxGTK_BASE:
                col = def->base;
                break;
        }

        red = col[state].red;
        green = col[state].green;
        blue = col[state].blue;

        ok = true;
    }
    else
    {
        ok = false;
    }

    gtk_widget_destroy( widget );

    return ok;
}

static void GetTooltipColors()
{
    GtkTooltips* tooltips = gtk_tooltips_new();
    gtk_tooltips_force_window(tooltips);
    gtk_widget_ensure_style(tooltips->tip_window);
    GdkColor c = tooltips->tip_window->style->bg[GTK_STATE_NORMAL];
    gs_objects.m_colTooltip = wxColor(c.red >> SHIFT, c.green >> SHIFT, c.blue >> SHIFT);
    c = tooltips->tip_window->style->fg[GTK_STATE_NORMAL];
    gs_objects.m_colTooltipText = wxColor(c.red >> SHIFT, c.green >> SHIFT, c.blue >> SHIFT);
    gtk_object_sink(reinterpret_cast<GtkObject*>(tooltips));
}

wxColour wxSystemSettingsNative::GetColour( wxSystemColour index )
{
    switch (index)
    {
        case wxSYS_COLOUR_SCROLLBAR:
        case wxSYS_COLOUR_BACKGROUND:
        case wxSYS_COLOUR_INACTIVECAPTION:
        case wxSYS_COLOUR_MENU:
        case wxSYS_COLOUR_WINDOWFRAME:
        case wxSYS_COLOUR_ACTIVEBORDER:
        case wxSYS_COLOUR_INACTIVEBORDER:
        case wxSYS_COLOUR_BTNFACE:
        case wxSYS_COLOUR_MENUBAR:
        case wxSYS_COLOUR_3DLIGHT:
            if (!gs_objects.m_colBtnFace.Ok())
            {
                int red, green, blue;
                if ( !GetColourFromGTKWidget(red, green, blue) )
                {
                    red =
                    green = 0;
                    blue = 0x9c40;
                }

                gs_objects.m_colBtnFace = wxColour( red   >> SHIFT,
                                                   green >> SHIFT,
                                                   blue  >> SHIFT );
            }
            return gs_objects.m_colBtnFace;

        case wxSYS_COLOUR_WINDOW:
            return *wxWHITE;

        case wxSYS_COLOUR_3DDKSHADOW:
            return *wxBLACK;

        case wxSYS_COLOUR_GRAYTEXT:
        case wxSYS_COLOUR_BTNSHADOW:
        //case wxSYS_COLOUR_3DSHADOW:
            if (!gs_objects.m_colBtnShadow.Ok())
            {
                wxColour faceColour(GetColour(wxSYS_COLOUR_3DFACE));
                gs_objects.m_colBtnShadow =
                   wxColour((unsigned char) (faceColour.Red() * 0.666),
                            (unsigned char) (faceColour.Green() * 0.666),
                            (unsigned char) (faceColour.Blue() * 0.666));
            }

            return gs_objects.m_colBtnShadow;

        case wxSYS_COLOUR_3DHIGHLIGHT:
        //case wxSYS_COLOUR_BTNHIGHLIGHT:
            return * wxWHITE;

        case wxSYS_COLOUR_HIGHLIGHT:
            if (!gs_objects.m_colHighlight.Ok())
            {
                int red, green, blue;
                if ( !GetColourFromGTKWidget(red, green, blue,
                                             wxGTK_BUTTON,
                                             GTK_STATE_SELECTED) )
                {
                    red =
                    green = 0;
                    blue = 0x9c40;
                }

                gs_objects.m_colHighlight = wxColour( red   >> SHIFT,
                                                        green >> SHIFT,
                                                        blue  >> SHIFT );
            }
            return gs_objects.m_colHighlight;

        case wxSYS_COLOUR_LISTBOX:
            if (!gs_objects.m_colListBox.Ok())
            {
                int red, green, blue;
                if ( GetColourFromGTKWidget(red, green, blue,
                                            wxGTK_LIST,
                                            GTK_STATE_NORMAL,
                                            wxGTK_BASE) )
                {
                    gs_objects.m_colListBox = wxColour( red   >> SHIFT,
                                                          green >> SHIFT,
                                                          blue  >> SHIFT );
                }
                else
                {
                    gs_objects.m_colListBox = wxColour(*wxWHITE);
                }
            }
            return gs_objects.m_colListBox;

        case wxSYS_COLOUR_MENUTEXT:
        case wxSYS_COLOUR_WINDOWTEXT:
        case wxSYS_COLOUR_CAPTIONTEXT:
        case wxSYS_COLOUR_INACTIVECAPTIONTEXT:
        case wxSYS_COLOUR_BTNTEXT:
        case wxSYS_COLOUR_LISTBOXTEXT:
            if (!gs_objects.m_colBtnText.Ok())
            {
                int red, green, blue;
                if ( !GetColourFromGTKWidget(red, green, blue,
                                             wxGTK_BUTTON,
                                             GTK_STATE_NORMAL,
                                             wxGTK_FG) )
                {
                    red =
                    green =
                    blue = 0;
                }

                gs_objects.m_colBtnText = wxColour( red   >> SHIFT,
                                                      green >> SHIFT,
                                                      blue  >> SHIFT );
            }
            return gs_objects.m_colBtnText;

        case wxSYS_COLOUR_INFOBK:
            if (!gs_objects.m_colTooltip.Ok()) {
                GetTooltipColors();
            }
            return gs_objects.m_colTooltip;

        case wxSYS_COLOUR_INFOTEXT:
            if (!gs_objects.m_colTooltipText.Ok()) {
                GetTooltipColors();
            }
            return gs_objects.m_colTooltipText;

        case wxSYS_COLOUR_HIGHLIGHTTEXT:
            if (!gs_objects.m_colHighlightText.Ok())
            {
                wxColour hclr = GetColour(wxSYS_COLOUR_HIGHLIGHT);
                if (hclr.Red() > 200 && hclr.Green() > 200 && hclr.Blue() > 200)
                    gs_objects.m_colHighlightText = wxColour(*wxBLACK);
                else
                    gs_objects.m_colHighlightText = wxColour(*wxWHITE);
            }
            return gs_objects.m_colHighlightText;

        case wxSYS_COLOUR_APPWORKSPACE:
            return *wxWHITE;    // ?

        case wxSYS_COLOUR_ACTIVECAPTION:
        case wxSYS_COLOUR_MENUHILIGHT:
            if (!gs_objects.m_colMenuItemHighlight.Ok())
            {
                int red, green, blue;
                if ( !GetColourFromGTKWidget(red, green, blue,
                                             wxGTK_MENUITEM,
                                             GTK_STATE_SELECTED,
                                             wxGTK_BG) )
                {
                    red =
                    green =
                    blue = 0;
                }

                gs_objects.m_colMenuItemHighlight = wxColour( red  >> SHIFT,
                                                              green >> SHIFT,
                                                              blue  >> SHIFT );
            }
            return gs_objects.m_colMenuItemHighlight;

        case wxSYS_COLOUR_HOTLIGHT:
        case wxSYS_COLOUR_GRADIENTACTIVECAPTION:
        case wxSYS_COLOUR_GRADIENTINACTIVECAPTION:
            // TODO
            return *wxBLACK;

        case wxSYS_COLOUR_MAX:
        default:
            wxFAIL_MSG( wxT("unknown system colour index") );
    }

    return *wxWHITE;
}

wxFont wxSystemSettingsNative::GetFont( wxSystemFont index )
{
    switch (index)
    {
        case wxSYS_OEM_FIXED_FONT:
        case wxSYS_ANSI_FIXED_FONT:
        case wxSYS_SYSTEM_FIXED_FONT:
        {
            return *wxNORMAL_FONT;
        }
        case wxSYS_ANSI_VAR_FONT:
        case wxSYS_SYSTEM_FONT:
        case wxSYS_DEVICE_DEFAULT_FONT:
        case wxSYS_DEFAULT_GUI_FONT:
        {
            if (!gs_objects.m_fontSystem.Ok())
            {
                gs_objects.m_fontSystem = wxFont( 12, wxSWISS, wxNORMAL, wxNORMAL );
            }
            return gs_objects.m_fontSystem;
        }

        default:
            return wxNullFont;
    }
}

int
wxSystemSettingsNative::GetMetric(wxSystemMetric index, wxWindow* WXUNUSED(win))
{
    switch (index)
    {
        case wxSYS_CURSOR_X:
        case wxSYS_CURSOR_Y:
            return 16;

        // MBN: ditto for icons
        case wxSYS_ICON_X:     return 32;
        case wxSYS_ICON_Y:     return 32;

        case wxSYS_SCREEN_X:
            return gdk_screen_width();

        case wxSYS_SCREEN_Y:
            return gdk_screen_height();

        case wxSYS_HSCROLL_Y:  return 15;
        case wxSYS_VSCROLL_X:  return 15;

// a gtk1 implementation should be possible too if gtk2 efficiency/convenience functions aren't used
#if 0
        case wxSYS_CAPTION_Y:
            if (!window)
                // No realized window specified, and no implementation for that case yet.
                return -1;

            // Check if wm supports frame extents - we can't know the caption height if it does not.
#if GTK_CHECK_VERSION(2,2,0)
            if (!gtk_check_version(2,2,0))
            {
                if (!gdk_x11_screen_supports_net_wm_hint(
                        gdk_drawable_get_screen(window),
                        gdk_atom_intern("_NET_FRAME_EXTENTS", false) ) )
                    return -1;
            }
            else
#endif
            {
                if (!gdk_net_wm_supports(gdk_atom_intern("_NET_FRAME_EXTENTS", false)))
                    return -1;
            }

            wxASSERT_MSG( wxDynamicCast(win, wxTopLevelWindow),
                          wxT("Asking for caption height of a non toplevel window") );

            // Get the height of the top windowmanager border.
            // This is the titlebar in most cases. The titlebar might be elsewhere, and
            // we could check which is the thickest wm border to decide on which side the
            // titlebar is, but this might lead to interesting behaviours in used code.
            // Reconsider when we have a way to report to the user on which side it is.

            Atom type;
            gint format;
            gulong nitems;

#if GTK_CHECK_VERSION(2,2,0)
            if (!gtk_check_version(2,2,0))
            {
                gulong bytes_after;
                success = (XGetWindowProperty (GDK_DISPLAY_XDISPLAY(gdk_drawable_get_display(window)),
                                    GDK_WINDOW_XWINDOW(window),
                                    gdk_x11_get_xatom_by_name_for_display (
                                            gdk_drawable_get_display(window),
                                            "_NET_FRAME_EXTENTS" ),
                                    0, // left, right, top, bottom, CARDINAL[4]/32
                                    G_MAXLONG, // size of long
                                    false, // do not delete property
                                    XA_CARDINAL, // 32 bit
                                    &type, &format, &nitems, &bytes_after, &data
                                   ) == Success);
            }
#endif
            if (success)
            {
                int caption_height = -1;

                if ((type == XA_CARDINAL) && (format == 32) && (nitems >= 3) && (data))
                {
                    long *borders;
                    borders = (long*)data;
                    caption_height = borders[2]; // top frame extent
                }

                if (data)
                    XFree(data);

                return caption_height;
            }

            // Try a default approach without a window pointer, if possible
            // ...

            return -1;
#endif // gtk2

        case wxSYS_PENWINDOWS_PRESENT:
            // No MS Windows for Pen computing extension available in X11 based gtk+.
            return 0;

        default:
            return -1;   // metric is unknown
    }
}

bool wxSystemSettingsNative::HasFeature(wxSystemFeature index)
{
    switch (index)
    {
        case wxSYS_CAN_ICONIZE_FRAME:
            return false;

        case wxSYS_CAN_DRAW_FRAME_DECORATIONS:
            return true;

        default:
            return false;
    }
}
