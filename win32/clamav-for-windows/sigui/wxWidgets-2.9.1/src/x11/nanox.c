/*
 * nanox.c
 *
 * Replacements for some comomon Xlib functions
 * Licence: The wxWindows licence
 */

#include "wx/setup.h"

#if wxUSE_NANOX

#include <ctype.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include "wx/defs.h"
#include "wx/x11/nanox/X11/Xlib.h"

/* Expands to some compatibility functions (see XtoNX.h) */

STATIC_FUNCTIONS

static GR_PALETTE* s_globalColormap = 0;

Colormap DefaultColormapOfScreen(Screen* screen)
{
    if (!s_globalColormap)
    {
        s_globalColormap = (GR_PALETTE*) malloc(sizeof(GR_PALETTE));
       
        GrGetSystemPalette(s_globalColormap);
    }

    return s_globalColormap;
}

int XSetGraphicsExposures( Display* display, GC gc, Bool graphics_exposures)
{
    return Success ;
}

int XWarpPointer( Display* display, Window srcW, Window destW,
                 int srcX, int srcY,
                 unsigned int srcWidth,
                 unsigned int srcHeight,
                 int destX, int destY)
{
    GrMoveCursor(destX, destY);
    return Success;
}

int XSetInputFocus(Display* display, Window focus, int revert_to, Time time)
{
    GrSetFocus(focus);
    return Success;
}

int XGetInputFocus(Display* display, Window* focus_return, int* revert_to_return)
{
    * focus_return = GrGetFocus();
    * revert_to_return = 0;
    return Success;
}

int XGrabPointer(Display* display, Window grab_window,
                 Bool owner_events, unsigned int event_mask,
                 int pointer_mode, int keyboard_mode,
                 Window confine_to, Cursor cursor, Time time)
{
    /* According to comments in srvevent.c in Nano-X, the pointer
     * is implicitly grabbed when a mouse button is down.
     * We may be able to simulate this further in the event loop.
     */
    return Success;
}

int XUngrabPointer(Display* display, Time time)
{
    return Success;
}

int XCopyArea(Display* display, Drawable src, Drawable dest, GC gc,
              int src_x, int src_y, unsigned int width, unsigned int height,
              int dest_x, int dest_y)
{
    GrCopyArea(dest, gc, dest_x, dest_y,
			width, height, src,
			src_x, src_y, 0);
    return Success;
}

int XCopyPlane(Display* display, Drawable src, Drawable dest, GC gc,
              int src_x, int src_y, unsigned int width, unsigned int height,
              int dest_x, int dest_y, unsigned long plane)
{
    GrCopyArea(dest, gc, dest_x, dest_y,
			width, height, src,
			src_x, src_y, 0);
    return Success;
}

#if 0
typedef struct {
  GR_WINDOW_ID wid;		/* window id (or 0 if no such window) */
  GR_WINDOW_ID parent;		/* parent window id */
  GR_WINDOW_ID child;		/* first child window id (or 0) */
  GR_WINDOW_ID sibling;		/* next sibling window id (or 0) */
  GR_BOOL inputonly;		/* TRUE if window is input only */
  GR_BOOL mapped;		/* TRUE if window is mapped */
  GR_COUNT unmapcount;		/* reasons why window is unmapped */
  GR_COORD x;			/* absolute x position of window */
  GR_COORD y;			/* absolute y position of window */
  GR_SIZE width;		/* width of window */
  GR_SIZE height;		/* height of window */
  GR_SIZE bordersize;		/* size of border */
  GR_COLOR bordercolor;		/* color of border */
  GR_COLOR background;		/* background color */
  GR_EVENT_MASK eventmask;	/* current event mask for this client */
  GR_WM_PROPS props;		/* window properties */
  GR_CURSOR_ID cursor;		/* cursor id*/
  unsigned long processid;	/* process id of owner*/
} GR_WINDOW_INFO;

typedef struct {
     int x, y;		      /* location of window */
     int width, height;       /* width and height of window */
     int border_width;	      /* border width of window */
     int depth; 	      /* depth of window */
     Visual *visual;	      /* the associated visual structure */
     Window root;	      /* root of screen containing window */
     int class; 	      /* InputOutput, InputOnly*/
     int bit_gravity;	      /* one of the bit gravity values */
     int win_gravity;	      /* one of the window gravity values */
     int backing_store;       /* NotUseful, WhenMapped, Always */
     unsigned long backing_planes;/* planes to be preserved if possible */
     unsigned long backing_pixel;/* value to be used when restoring planes */
     Bool save_under;	      /* boolean, should bits under be saved? */
     Colormap colormap;       /* color map to be associated with window */
     Bool map_installed;      /* boolean, is color map currently installed*/
     int map_state;	      /* IsUnmapped, IsUnviewable, IsViewable */
     long all_event_masks;    /* set of events all people have interest in*/
     long your_event_mask;    /* my event mask */
     long do_not_propagate_mask;/* set of events that should not propagate */
     Bool override_redirect;  /* boolean value for override-redirect */
     Screen *screen;	      /* back pointer to correct screen */
} XWindowAttributes;

#endif


Status XGetWindowAttributes(Display* display, Window w,
                            XWindowAttributes* window_attributes)
{
    GR_WINDOW_INFO info;
    Window parent = 0;
    GrFlush();
    GrGetWindowInfo(w, & info);

    window_attributes->x = info.x;
    window_attributes->y = info.y;
    window_attributes->width = info.width;
    window_attributes->height = info.height;
    window_attributes->border_width = info.bordersize;
    window_attributes->depth = 0;
    window_attributes->visual = NULL;
    window_attributes->root = 0;
    window_attributes->_class = info.inputonly ? InputOnly : InputOutput ;
    window_attributes->bit_gravity = 0;
    window_attributes->win_gravity = 0;
    window_attributes->backing_store = 0;
    window_attributes->backing_planes = 0;
    window_attributes->backing_pixel = 0;
    window_attributes->save_under = FALSE;
    window_attributes->colormap = DefaultColormapOfScreen(0);
    window_attributes->map_installed = FALSE;
    window_attributes->map_state = info.mapped ? IsViewable : IsUnmapped ;
    window_attributes->all_event_masks = 0;
    window_attributes->do_not_propagate_mask = 0;
    window_attributes->override_redirect = FALSE;
    window_attributes->screen = NULL;

    /* We need to check if any parents are unmapped,
     * or we will report a window as mapped when it is not.
     */
    parent = info.parent;
    while (parent)
    {
        GrGetWindowInfo(parent, & info);
        if (info.mapped == 0)
            window_attributes->map_state = IsUnmapped;

        parent = info.parent;
    }

    return 1;
}

static XErrorHandler* g_ErrorHandler = NULL;

void DefaultNanoXErrorHandler(GR_EVENT_ERROR* ep)
{
    if (g_ErrorHandler)
    {
        XErrorEvent errEvent;
        errEvent.type = ep->type;
        errEvent.display = NULL;
        errEvent.resourceid = ep->id;
        errEvent.serial = 0;
        errEvent.error_code = ep->code;
        errEvent.request_code = 0;
        errEvent.minor_code = 0;
        (*g_ErrorHandler)(NULL, & errEvent);
    }
}

XErrorHandler XSetErrorHandler (XErrorHandler handler)
{
    XErrorHandler oldHandler = g_ErrorHandler;
    g_ErrorHandler = handler;
    GrSetErrorHandler(DefaultNanoXErrorHandler);
    return oldHandler;
}

static Screen s_screen;
Screen *XScreenOfDisplay(Display*		display,
                         int screen_number)
{
    /* TODO: fill in the members. See Xlib.h */
    return & s_screen;
}

int DisplayWidth(Display* display, int screen)
{
    return _display.display_width;
}

int DisplayHeight(Display* display, int screen)
{
    return _display.display_height;
}

int DefaultDepth(Display* display, int screen)
{
    return _display.display_bpp;
}

int XAllocColor(Display* display, Colormap cmap,
                XColor* color)
{
    GR_PIXELVAL pixel;
    GrFindColor(GR_RGB(color->red, color->green, color->blue), & pixel);
    color->pixel = pixel;
    return 1;
}

typedef struct {
    const char* name;
    unsigned int red;
    unsigned int green;
    unsigned int blue;
} _wxColourEntry;

static _wxColourEntry _wxColourDatabase[] =
{
    { "WHITE", 255, 255, 255 },
    { "BLACK", 0, 0, 0 },
    { "RED", 255, 0, 0 },
    { "GREEN", 0, 255, 0 },
    { "BLUE", 0, 255, 255 },
    { "GREY", 128, 128, 128 },
    { "GRAY", 128, 128, 128 },
    { "LIGHT GREY", 192, 192, 192 },
    { "LIGHT GRAY", 192, 192, 192 },
    { "DARK GREY", 32, 32, 32 },
    { "DARK GRAY", 32, 32, 32 },
    { "CYAN", 0, 255, 255 },
    { "MAGENTA", 255, 255, 0 },

    /* TODO: the rest */
    { NULL, 0, 0, 0 }
};

int XParseColor(Display* display, Colormap cmap,
                const char* cname, XColor* color)
{
    int i = 0;
    for (;;)
    {
        if (!_wxColourDatabase[i].name)
            break;
        else
        {
            if (strcmp(cname, _wxColourDatabase[i].name) == 0)
            {
                color->red = _wxColourDatabase[i].red;
                color->green = _wxColourDatabase[i].green;
                color->blue = _wxColourDatabase[i].blue;

                return 1;
            }
            i ++;
        }
    }

    /* Not found: use black */
    color->red = 0;
    color->green = 0;
    color->blue = 0;
    
    return 0;
}

int XDrawLine(Display* display, Window win, GC gc,
              int x1, int y1, int x2, int y2)
{
    GR_POINT points[2];
    points[0].x = x1;
    points[0].y = y1;
    points[1].x = x2;
    points[1].y = y2;

    GrDrawLines(win, gc, points, 2);
    return 1;
}

int XTextExtents( XFontStruct* font, char* s, int len, int* direction,
                  int* ascent, int* descent2, XCharStruct* overall)
{
    GR_SIZE retwidth, retheight, retbase;
    GR_GC_ID gc = GrNewGC();

    *ascent = font->info.baseline;
    *direction = 1; /* ? */
    *descent2 = 0; /* ? */

    GrSetGCFont(gc, font->fid);

    /* TODO need to set the relevant flags for the character set.
     * A good trick might be to pass a wxString instead of char*
     * to this function.
     */
    
    GrGetGCTextSize(gc, s, len, GR_TFASCII, & retwidth,
                    & retheight, & retbase);
    if (overall)
    {
        overall->width = retwidth;
        overall->lbearing = 0;
        overall->rbearing = 0;
        overall->ascent = *ascent;
        overall->descent = 0;
        overall->attributes = 0;
    }

    GrDestroyGC(gc);
    
    return 1;
}

XFontStruct* XLoadQueryFont(Display* display, const char* fontSpec)
{
    /* TODO: map fontSpec to something sensible for Nano-X */
    char *fontName = NULL;
    XFontStruct* fontInfo = malloc(sizeof(XFontStruct));
    fontInfo->fid = GrCreateFont(fontName, 0, 0);
    GrGetFontInfo(fontInfo->fid, & fontInfo->info);
    printf("Warning: should not call XLoadQueryFont since font spec is not used in Nano-X.\n");
    return fontInfo;
}

int XFreeFont(Display* display, XFontStruct* fontStruct)
{
    GrDestroyFont(fontStruct->fid);
    free(fontStruct);
    return 1;
}

int XQueryColor(Display* display, Colormap cmap, XColor* color)
{
    /* cmap is a GR_PALETTE */
    if (color->pixel < cmap->count)
    {
        color->red = cmap->palette[color->pixel].r;
        color->green = cmap->palette[color->pixel].g;
        color->blue = cmap->palette[color->pixel].b;
        return 1;
    }
    else
        return 0;
}

int XConfigureWindow(Display* display, Window w, int mask, XWindowChanges* changes)
{
    if ((mask & CWX) && (mask & CWY))
        GrMoveWindow(w, changes->x, changes->y);
    if ((mask & CWWidth) && (mask & CWHeight))
        GrResizeWindow(w, changes->width, changes->height);
    if (mask & CWBorderWidth)
    {
        /* TODO */
    }
    if (mask & CWSibling)
    {
        /* TODO */
    }
    if (mask & CWStackMode)
    {
        /* TODO */
    }
    return 1;
}

int XTranslateCoordinates(Display* display, Window srcWindow, Window destWindow, int srcX, int srcY, int* destX, int* destY, Window* childReturn)
{
    int offx = 0;
    int offy = 0;

    Window w = srcWindow;
    while (w != GR_ROOT_WINDOW_ID)
    {
        GR_WINDOW_INFO info;
        GrGetWindowInfo(w, & info);
        w = info.parent;

        offx += info.x ;
        offy += info.y ;
    }

    w = destWindow;

    while (w != GR_ROOT_WINDOW_ID)
    {
        GR_WINDOW_INFO info;
        GrGetWindowInfo(w, & info);
        w = info.parent;

        offx -= info.x ;
        offy -= info.y ;
    }

    *destX = srcX + offx;
    *destY = srcY + offy;

    if (childReturn)
        *childReturn = 0;

    return 1;
}

/* Should not really be necessary but in no-optimize mode
 * gcc complains that wxNoop is not found if wxNoop is inline.
 */

void wxNoop()
{
}

#endif
  /* wxUSE_NANOX */
