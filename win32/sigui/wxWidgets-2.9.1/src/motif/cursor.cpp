/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/cursor.cpp
// Purpose:     wxCursor class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/list.h"
#endif

#include "wx/cursor.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/window.h"
    #include "wx/image.h"
    #include "wx/log.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#include <X11/cursorfont.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

// Cursor for one display, so we can choose the correct one for
// the current display.
class wxXCursor
{
public:
    WXDisplay*  m_display;
    WXCursor    m_cursor;
};

WX_DECLARE_LIST(wxXCursor, wxXCursorList);
#include "wx/listimpl.cpp"
WX_DEFINE_LIST(wxXCursorList)

class WXDLLEXPORT wxCursorRefData: public wxGDIRefData
{
public:
    wxCursorRefData();
    virtual ~wxCursorRefData();

    wxXCursorList m_cursors;  // wxXCursor objects, one per display
    wxStockCursor m_cursorId; // wxWidgets standard cursor id

    friend class wxCursor;
};

#define M_CURSORDATA ((wxCursorRefData *)m_refData)
#define M_CURSORHANDLERDATA ((wxCursorRefData *)bitmap->m_refData)

IMPLEMENT_DYNAMIC_CLASS(wxCursor, wxObject)

wxCursorRefData::wxCursorRefData()
{
    m_cursorId = wxCURSOR_NONE;
}

wxCursorRefData::~wxCursorRefData()
{
    wxXCursorList::compatibility_iterator node = m_cursors.GetFirst();
    while (node)
    {
        wxXCursor* c = node->GetData();
        XFreeCursor((Display*) c->m_display, (Cursor) c->m_cursor);
        delete c;
        node = node->GetNext();
    }
}

wxCursor::wxCursor()
{
}

#if wxUSE_IMAGE
wxCursor::wxCursor(const wxImage & image)
{
    unsigned char * rgbBits = image.GetData();
    int w = image.GetWidth() ;
    int h = image.GetHeight();
    bool bHasMask = image.HasMask();
    int imagebitcount = (w*h)/8;

    unsigned char * bits = new unsigned char [imagebitcount];
    unsigned char * maskBits = new unsigned char [imagebitcount];

    int i, j, i8;
    unsigned char c, cMask;
    for (i=0; i<imagebitcount; i++)
    {
        bits[i] = 0xff;
        i8 = i * 8;

        cMask = 0xfe; // 11111110
        for (j=0; j<8; j++)
        {
            // possible overflow if we do the summation first ?
            c = (unsigned char)(rgbBits[(i8+j)*3]/3 + rgbBits[(i8+j)*3+1]/3 + rgbBits[(i8+j)*3+2]/3);
            // if average value is > mid grey
            if (c>127)
                bits[i] = bits[i] & cMask;
            cMask = (unsigned char)((cMask << 1) | 1);
        }
    }

    if (bHasMask)
    {
        unsigned char
            r = image.GetMaskRed(),
            g = image.GetMaskGreen(),
            b = image.GetMaskBlue();

        for (i=0; i<imagebitcount; i++)
        {
            maskBits[i] = 0x0;
            i8 = i * 8;

            cMask = 0x1;
            for (j=0; j<8; j++)
            {
                if (rgbBits[(i8+j)*3] != r || rgbBits[(i8+j)*3+1] != g || rgbBits[(i8+j)*3+2] != b)
                    maskBits[i] = maskBits[i] | cMask;
                cMask = (unsigned char)(cMask << 1);
            }
        }
    }
    else // no mask
    {
        for (i=0; i<imagebitcount; i++)
            maskBits[i] = 0xFF;
    }

    int hotSpotX;
    int hotSpotY;

    if (image.HasOption(wxIMAGE_OPTION_CUR_HOTSPOT_X))
        hotSpotX = image.GetOptionInt(wxIMAGE_OPTION_CUR_HOTSPOT_X);
    else
        hotSpotX = 0;

    if (image.HasOption(wxIMAGE_OPTION_CUR_HOTSPOT_Y))
        hotSpotY = image.GetOptionInt(wxIMAGE_OPTION_CUR_HOTSPOT_Y);
    else
        hotSpotY = 0;

    if (hotSpotX < 0 || hotSpotX >= w)
        hotSpotX = 0;
    if (hotSpotY < 0 || hotSpotY >= h)
        hotSpotY = 0;

    Create( (const char*)bits, w, h, hotSpotX, hotSpotY,
            (const char*)maskBits );

    delete[] bits;
    delete[] maskBits;
}
#endif

void wxCursor::Create(const char bits[], int width, int height,
                      int hotSpotX, int hotSpotY, const char maskBits[])
{
    if( !m_refData )
        m_refData = new wxCursorRefData;

    Display *dpy = (Display*) wxGetDisplay();
    int screen_num =  DefaultScreen (dpy);

    Pixmap pixmap = XCreatePixmapFromBitmapData (dpy,
                                          RootWindow (dpy, screen_num),
                                          (char*) bits, width, height,
                                          1 , 0 , 1);

    Pixmap mask_pixmap = None;
    if (maskBits != NULL)
    {
        mask_pixmap = XCreatePixmapFromBitmapData (dpy,
                                          RootWindow (dpy, screen_num),
                                          (char*) maskBits, width, height,
                                          1 , 0 , 1);
    }

    Create( (WXPixmap)pixmap, (WXPixmap)mask_pixmap, hotSpotX, hotSpotY );

    XFreePixmap( dpy, pixmap );
    if (mask_pixmap != None)
    {
        XFreePixmap( dpy, mask_pixmap );
    }
}

void wxCursor::Create(WXPixmap pixmap, WXPixmap mask_pixmap,
                      int hotSpotX, int hotSpotY)
{
    if( !m_refData )
        m_refData = new wxCursorRefData;

    Display *dpy = (Display*) wxGetDisplay();
    int screen_num =  DefaultScreen (dpy);

    XColor foreground_color;
    XColor background_color;
    foreground_color.pixel = BlackPixel(dpy, screen_num);
    background_color.pixel = WhitePixel(dpy, screen_num);
    Colormap cmap = (Colormap) wxTheApp->GetMainColormap((WXDisplay*) dpy);
    XQueryColor(dpy, cmap, &foreground_color);
    XQueryColor(dpy, cmap, &background_color);

    Cursor cursor = XCreatePixmapCursor (dpy,
                                  (Pixmap)pixmap,
                                  (Pixmap)mask_pixmap,
                                  &foreground_color,
                                  &background_color,
                                  hotSpotX ,
                                  hotSpotY);

    if (cursor)
    {
        wxXCursor *c = new wxXCursor;

        c->m_cursor = (WXCursor) cursor;
        c->m_display = (WXDisplay*) dpy;
        M_CURSORDATA->m_cursors.Append(c);
    }
}

wxCursor::wxCursor(const char bits[], int width, int height,
                   int hotSpotX, int hotSpotY, const char maskBits[] ,
                   const wxColour* WXUNUSED(fg), const wxColour* WXUNUSED(bg) )
{
    Create(bits, width, height, hotSpotX, hotSpotY, maskBits);
}

wxCursor::wxCursor(const wxString& name, wxBitmapType type,
                   int hotSpotX, int hotSpotY)
{
    // Must be an XBM file
    if (type != wxBITMAP_TYPE_XBM) {
        wxLogError("Invalid cursor bitmap type '%d'", type);
        return;
    }

    m_refData = new wxCursorRefData;

    int hotX = -1, hotY = -1;
    unsigned int w, h;
    Pixmap pixmap = None, mask_pixmap = None;

    Display *dpy = (Display*) wxGetDisplay();
    int screen_num =  DefaultScreen (dpy);

    int value = XReadBitmapFile (dpy, RootWindow (dpy, screen_num),
                                 name.mb_str(),
                                 &w, &h, &pixmap, &hotX, &hotY);

    if (value == BitmapSuccess)
    {
        // TODO: how do we determine whether hotX, hotY were read correctly?
        if (hotX < 0 || hotY < 0)
        {
            hotX = hotSpotX;
            hotY = hotSpotY;
        }
        if (hotX < 0 || hotY < 0)
        {
            hotX = 0;
            hotY = 0;
        }

        Create( (WXPixmap)pixmap, (WXPixmap)mask_pixmap, hotX, hotY );

        XFreePixmap( dpy, pixmap );
    }
}

// Cursors by stock number
void wxCursor::InitFromStock(wxStockCursor id)
{
    m_refData = new wxCursorRefData;
    M_CURSORDATA->m_cursorId = id;
}

wxCursor::~wxCursor()
{
}

wxGDIRefData *wxCursor::CreateGDIRefData() const
{
    return new wxCursorRefData;
}

wxGDIRefData *wxCursor::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxCursorRefData(*static_cast<const wxCursorRefData *>(data));
}

// Motif-specific: create/get a cursor for the current display
WXCursor wxCursor::GetXCursor(WXDisplay* display) const
{
    if (!M_CURSORDATA)
        return (WXCursor) 0;
    wxXCursorList::compatibility_iterator node = M_CURSORDATA->m_cursors.GetFirst();
    while (node)
    {
        wxXCursor* c = node->GetData();
        if (c->m_display == display)
            return c->m_cursor;
        node = node->GetNext();
    }

    // No cursor for this display, so let's see if we're an id-type cursor.

    if (M_CURSORDATA->m_cursorId != wxCURSOR_NONE)
    {
        WXCursor cursor = MakeCursor(display, M_CURSORDATA->m_cursorId);
        if (cursor)
        {
            wxXCursor* c = new wxXCursor;
            c->m_cursor = cursor;
            c->m_display = display;
            M_CURSORDATA->m_cursors.Append(c);
            return cursor;
        }
        else
            return (WXCursor) 0;
    }

    // Not an id-type cursor, so we don't know how to create it.
    return (WXCursor) 0;
}

// Make a cursor from standard id
WXCursor wxCursor::MakeCursor(WXDisplay* display, wxStockCursor id) const
{
    Display* dpy = (Display*) display;
    Cursor cursor = (Cursor) 0;
    int x_cur = -1;

    switch (id)
    {
    case wxCURSOR_CHAR:             return (WXCursor)cursor;

    case wxCURSOR_WAIT:             x_cur = XC_watch; break;
    case wxCURSOR_CROSS:            x_cur = XC_crosshair; break;
    case wxCURSOR_HAND:             x_cur = XC_hand1; break;
    case wxCURSOR_BULLSEYE:         x_cur = XC_target; break;
    case wxCURSOR_PENCIL:           x_cur = XC_pencil; break;
    case wxCURSOR_MAGNIFIER:        x_cur = XC_sizing; break;
    case wxCURSOR_IBEAM:            x_cur = XC_xterm; break;
    case wxCURSOR_NO_ENTRY:         x_cur = XC_pirate; break;
    case wxCURSOR_LEFT_BUTTON:      x_cur = XC_leftbutton; break;
    case wxCURSOR_RIGHT_BUTTON:     x_cur = XC_rightbutton; break;
    case wxCURSOR_MIDDLE_BUTTON:    x_cur =  XC_middlebutton; break;
    case wxCURSOR_QUESTION_ARROW:   x_cur = XC_question_arrow; break;
    case wxCURSOR_SIZING:           x_cur = XC_sizing; break;
    case wxCURSOR_WATCH:            x_cur = XC_watch; break;
    case wxCURSOR_SPRAYCAN:         x_cur = XC_spraycan; break;
    case wxCURSOR_PAINT_BRUSH:      x_cur = XC_spraycan; break;
    case wxCURSOR_SIZENWSE:
    case wxCURSOR_SIZENESW:         x_cur = XC_crosshair; break;
    case wxCURSOR_SIZEWE:           x_cur = XC_sb_h_double_arrow; break;
    case wxCURSOR_SIZENS:           x_cur = XC_sb_v_double_arrow; break;
    case wxCURSOR_POINT_LEFT:       x_cur = XC_sb_left_arrow; break;
    case wxCURSOR_POINT_RIGHT:      x_cur = XC_sb_right_arrow; break;
        // (JD Huggins) added more stock cursors for X
        // X-only cursors BEGIN
    case wxCURSOR_CROSS_REVERSE:    x_cur = XC_cross_reverse; break;
    case wxCURSOR_DOUBLE_ARROW:     x_cur = XC_double_arrow; break;
    case wxCURSOR_BASED_ARROW_UP:   x_cur = XC_based_arrow_up; break;
    case wxCURSOR_BASED_ARROW_DOWN: x_cur = XC_based_arrow_down; break;
    case wxCURSOR_BLANK:
    {
        GC gc;
        XGCValues gcv;
        Pixmap empty_pixmap;
        XColor blank_color;

        empty_pixmap =
            XCreatePixmap (dpy, RootWindow (dpy, DefaultScreen (dpy)),
                           16, 16, 1);
        gcv.function = GXxor;
        gc = XCreateGC (dpy,
                        empty_pixmap,
                        GCFunction,
                        &gcv);
        XCopyArea (dpy,
                   empty_pixmap,
                   empty_pixmap,
                   gc,
                   0, 0,
                   16, 16,
                   0, 0);
        XFreeGC (dpy, gc);
        cursor = XCreatePixmapCursor (dpy,
                                      empty_pixmap,
                                      empty_pixmap,
                                      &blank_color,
                                      &blank_color,
                                      8, 8);

        break;
    }
    case wxCURSOR_ARROW:
    default:       x_cur =  XC_top_left_arrow; break;
    }

    if( x_cur == -1 )
        return (WXCursor)cursor;

    cursor = XCreateFontCursor (dpy, x_cur);
    return (WXCursor) cursor;
}

// Global cursor setting
void wxSetCursor(const wxCursor& WXUNUSED(cursor))
{
  // Nothing to do for Motif (no global cursor)
}


// ----------------------------------------------------------------------------
// busy cursor stuff
// ----------------------------------------------------------------------------

static int wxBusyCursorCount = 0;

// Helper function
static void
wxXSetBusyCursor (wxWindow * win, const wxCursor * cursor)
{
    Display *display = (Display*) win->GetXDisplay();

    Window xwin = (Window) win->GetXWindow();
    if (!xwin)
       return;

    XSetWindowAttributes attrs;

    if (cursor)
    {
        attrs.cursor = (Cursor) cursor->GetXCursor(display);
    }
    else
    {
        // Restore old cursor
        if (win->GetCursor().Ok())
            attrs.cursor = (Cursor) win->GetCursor().GetXCursor(display);
        else
            attrs.cursor = None;
    }
    if (xwin)
        XChangeWindowAttributes (display, xwin, CWCursor, &attrs);

    XFlush (display);

    for(wxWindowList::compatibility_iterator node = win->GetChildren().GetFirst (); node;
        node = node->GetNext())
    {
        wxWindow *child = node->GetData ();
        wxXSetBusyCursor (child, cursor);
    }
}

// Set the cursor to the busy cursor for all windows
void wxBeginBusyCursor(const wxCursor *cursor)
{
    wxBusyCursorCount++;
    if (wxBusyCursorCount == 1)
    {
        for(wxWindowList::compatibility_iterator node = wxTopLevelWindows.GetFirst (); node;
            node = node->GetNext())
        {
            wxWindow *win = node->GetData ();
            wxXSetBusyCursor (win, cursor);
        }
    }
}

// Restore cursor to normal
void wxEndBusyCursor()
{
    if (wxBusyCursorCount == 0)
        return;

    wxBusyCursorCount--;
    if (wxBusyCursorCount == 0)
    {
        for(wxWindowList::compatibility_iterator node = wxTopLevelWindows.GetFirst (); node;
            node = node->GetNext())
        {
            wxWindow *win = node->GetData ();
            wxXSetBusyCursor (win, NULL);
        }
    }
}

// true if we're between the above two calls
bool wxIsBusy()
{
    return (wxBusyCursorCount > 0);
}
