/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk/window.cpp
// Purpose:     wxWindowGTK implementation
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling, Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __VMS
#define XWarpPointer XWARPPOINTER
#endif

#include "wx/window.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/toplevel.h"
    #include "wx/dcclient.h"
    #include "wx/menu.h"
    #include "wx/settings.h"
    #include "wx/msgdlg.h"
    #include "wx/math.h"
#endif

#include "wx/dnd.h"
#include "wx/tooltip.h"
#include "wx/caret.h"
#include "wx/fontutil.h"
#include "wx/sysopt.h"

#include <ctype.h>

#include "wx/gtk/private.h"
#include "wx/gtk/private/win_gtk.h"
#include <gdk/gdkkeysyms.h>
#include <gdk/gdkx.h>

#if !GTK_CHECK_VERSION(2,10,0)
    // GTK+ can reliably detect Meta key state only since 2.10 when
    // GDK_META_MASK was introduced -- there wasn't any way to detect it
    // in older versions. wxGTK used GDK_MOD2_MASK for this purpose, but
    // GDK_MOD2_MASK is documented as:
    //
    //     the fifth modifier key (it depends on the modifier mapping of the X
    //     server which key is interpreted as this modifier)
    //
    // In other words, it isn't guaranteed to map to Meta. This is a real
    // problem: it is common to map NumLock to it (in fact, it's an exception
    // if the X server _doesn't_ use it for NumLock).  So the old code caused
    // wxKeyEvent::MetaDown() to always return true as long as NumLock was on
    // on many systems, which broke all applications using
    // wxKeyEvent::GetModifiers() to check modifiers state (see e.g.  here:
    // http://tinyurl.com/56lsk2).
    //
    // Because of this, it's better to not detect Meta key state at all than
    // to detect it incorrectly. Hence the following #define, which causes
    // m_metaDown to be always set to false.
    #define GDK_META_MASK 0
#endif

//-----------------------------------------------------------------------------
// documentation on internals
//-----------------------------------------------------------------------------

/*
   I have been asked several times about writing some documentation about
   the GTK port of wxWidgets, especially its internal structures. Obviously,
   you cannot understand wxGTK without knowing a little about the GTK, but
   some more information about what the wxWindow, which is the base class
   for all other window classes, does seems required as well.

   I)

   What does wxWindow do? It contains the common interface for the following
   jobs of its descendants:

   1) Define the rudimentary behaviour common to all window classes, such as
   resizing, intercepting user input (so as to make it possible to use these
   events for special purposes in a derived class), window names etc.

   2) Provide the possibility to contain and manage children, if the derived
   class is allowed to contain children, which holds true for those window
   classes which do not display a native GTK widget. To name them, these
   classes are wxPanel, wxScrolledWindow, wxDialog, wxFrame. The MDI frame-
   work classes are a special case and are handled a bit differently from
   the rest. The same holds true for the wxNotebook class.

   3) Provide the possibility to draw into a client area of a window. This,
   too, only holds true for classes that do not display a native GTK widget
   as above.

   4) Provide the entire mechanism for scrolling widgets. This actual inter-
   face for this is usually in wxScrolledWindow, but the GTK implementation
   is in this class.

   5) A multitude of helper or extra methods for special purposes, such as
   Drag'n'Drop, managing validators etc.

   6) Display a border (sunken, raised, simple or none).

   Normally one might expect, that one wxWidgets window would always correspond
   to one GTK widget. Under GTK, there is no such all-round widget that has all
   the functionality. Moreover, the GTK defines a client area as a different
   widget from the actual widget you are handling. Last but not least some
   special classes (e.g. wxFrame) handle different categories of widgets and
   still have the possibility to draw something in the client area.
   It was therefore required to write a special purpose GTK widget, that would
   represent a client area in the sense of wxWidgets capable to do the jobs
   2), 3) and 4). I have written this class and it resides in win_gtk.c of
   this directory.

   All windows must have a widget, with which they interact with other under-
   lying GTK widgets. It is this widget, e.g. that has to be resized etc and
   the wxWindow class has a member variable called m_widget which holds a
   pointer to this widget. When the window class represents a GTK native widget,
   this is (in most cases) the only GTK widget the class manages. E.g. the
   wxStaticText class handles only a GtkLabel widget a pointer to which you
   can find in m_widget (defined in wxWindow)

   When the class has a client area for drawing into and for containing children
   it has to handle the client area widget (of the type wxPizza, defined in
   win_gtk.cpp), but there could be any number of widgets, handled by a class.
   The common rule for all windows is only, that the widget that interacts with
   the rest of GTK must be referenced in m_widget and all other widgets must be
   children of this widget on the GTK level. The top-most widget, which also
   represents the client area, must be in the m_wxwindow field and must be of
   the type wxPizza.

   As I said, the window classes that display a GTK native widget only have
   one widget, so in the case of e.g. the wxButton class m_widget holds a
   pointer to a GtkButton widget. But windows with client areas (for drawing
   and children) have a m_widget field that is a pointer to a GtkScrolled-
   Window and a m_wxwindow field that is pointer to a wxPizza and this
   one is (in the GTK sense) a child of the GtkScrolledWindow.

   If the m_wxwindow field is set, then all input to this widget is inter-
   cepted and sent to the wxWidgets class. If not, all input to the widget
   that gets pointed to by m_widget gets intercepted and sent to the class.

   II)

   The design of scrolling in wxWidgets is markedly different from that offered
   by the GTK itself and therefore we cannot simply take it as it is. In GTK,
   clicking on a scrollbar belonging to scrolled window will inevitably move
   the window. In wxWidgets, the scrollbar will only emit an event, send this
   to (normally) a wxScrolledWindow and that class will call ScrollWindow()
   which actually moves the window and its sub-windows. Note that wxPizza
   memorizes how much it has been scrolled but that wxWidgets forgets this
   so that the two coordinates systems have to be kept in synch. This is done
   in various places using the pizza->m_scroll_x and pizza->m_scroll_y values.

   III)

   Singularly the most broken code in GTK is the code that is supposed to
   inform subwindows (child windows) about new positions. Very often, duplicate
   events are sent without changes in size or position, equally often no
   events are sent at all (All this is due to a bug in the GtkContainer code
   which got fixed in GTK 1.2.6). For that reason, wxGTK completely ignores
   GTK's own system and it simply waits for size events for toplevel windows
   and then iterates down the respective size events to all window. This has
   the disadvantage that windows might get size events before the GTK widget
   actually has the reported size. This doesn't normally pose any problem, but
   the OpenGL drawing routines rely on correct behaviour. Therefore, I have
   added the m_nativeSizeEvents flag, which is true only for the OpenGL canvas,
   i.e. the wxGLCanvas will emit a size event, when (and not before) the X11
   window that is used for OpenGL output really has that size (as reported by
   GTK).

   IV)

   If someone at some point of time feels the immense desire to have a look at,
   change or attempt to optimise the Refresh() logic, this person will need an
   intimate understanding of what "draw" and "expose" events are and what
   they are used for, in particular when used in connection with GTK's
   own windowless widgets. Beware.

   V)

   Cursors, too, have been a constant source of pleasure. The main difficulty
   is that a GdkWindow inherits a cursor if the programmer sets a new cursor
   for the parent. To prevent this from doing too much harm, SetCursor calls
   GTKUpdateCursor, which will recursively re-set the cursors of all child windows.
   Also don't forget that cursors (like much else) are connected to GdkWindows,
   not GtkWidgets and that the "window" field of a GtkWidget might very well
   point to the GdkWindow of the parent widget (-> "window-less widget") and
   that the two obviously have very different meanings.
*/

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

// Don't allow event propagation during drag
bool g_blockEventsOnDrag;
// Don't allow mouse event propagation during scroll
bool g_blockEventsOnScroll;
extern wxCursor   g_globalCursor;

// mouse capture state: the window which has it and if the mouse is currently
// inside it
static wxWindowGTK  *g_captureWindow = NULL;
static bool g_captureWindowHasMouse = false;

// The window that currently has focus:
static wxWindowGTK *gs_currentFocus = NULL;
// The window that is scheduled to get focus in the next event loop iteration
// or NULL if there's no pending focus change:
static wxWindowGTK *gs_pendingFocus = NULL;

// the window that has deferred focus-out event pending, if any (see
// GTKAddDeferredFocusOut() for details)
static wxWindowGTK *gs_deferredFocusOut = NULL;

// global variables because GTK+ DnD want to have the
// mouse event that caused it
GdkEvent    *g_lastMouseEvent = NULL;
int          g_lastButtonNumber = 0;

//-----------------------------------------------------------------------------
// debug
//-----------------------------------------------------------------------------

// the trace mask used for the focus debugging messages
#define TRACE_FOCUS wxT("focus")

//-----------------------------------------------------------------------------
// missing gdk functions
//-----------------------------------------------------------------------------

void
gdk_window_warp_pointer (GdkWindow      *window,
                         gint            x,
                         gint            y)
{
  if (!window)
    window = gdk_get_default_root_window();

  if (!GDK_WINDOW_DESTROYED(window))
  {
      XWarpPointer (GDK_WINDOW_XDISPLAY(window),
                    None,              /* not source window -> move from anywhere */
                    GDK_WINDOW_XID(window),  /* dest window */
                    0, 0, 0, 0,        /* not source window -> move from anywhere */
                    x, y );
  }
}


//-----------------------------------------------------------------------------
// "size_request" of m_widget
//-----------------------------------------------------------------------------

extern "C" {
static void
wxgtk_window_size_request_callback(GtkWidget * WXUNUSED(widget),
                                   GtkRequisition *requisition,
                                   wxWindow * win)
{
    int w, h;
    win->GetSize( &w, &h );
    if (w < 2)
        w = 2;
    if (h < 2)
        h = 2;

    requisition->height = h;
    requisition->width = w;
}
}

//-----------------------------------------------------------------------------
// "expose_event" of m_wxwindow
//-----------------------------------------------------------------------------

extern "C" {
static gboolean
gtk_window_expose_callback( GtkWidget*,
                            GdkEventExpose *gdk_event,
                            wxWindow *win )
{
    if (gdk_event->window == win->GTKGetDrawingWindow())
    {
        win->GetUpdateRegion() = wxRegion( gdk_event->region );
        win->GtkSendPaintEvents();
    }
    // Let parent window draw window-less widgets
    return FALSE;
}
}

#ifndef __WXUNIVERSAL__
//-----------------------------------------------------------------------------
// "expose_event" from m_wxwindow->parent, for drawing border
//-----------------------------------------------------------------------------

extern "C" {
static gboolean
expose_event_border(GtkWidget* widget, GdkEventExpose* gdk_event, wxWindow* win)
{
    if (gdk_event->window != gtk_widget_get_parent_window(win->m_wxwindow))
        return false;

    if (!win->IsShown())
        return false;

    const GtkAllocation& alloc = win->m_wxwindow->allocation;
    const int x = alloc.x;
    const int y = alloc.y;
    const int w = alloc.width;
    const int h = alloc.height;

    if (w <= 0 || h <= 0)
        return false;

    if (win->HasFlag(wxBORDER_SIMPLE))
    {
        gdk_draw_rectangle(gdk_event->window,
            widget->style->black_gc, false, x, y, w - 1, h - 1);
    }
    else
    {
        GtkShadowType shadow = GTK_SHADOW_IN;
        if (win->HasFlag(wxBORDER_RAISED))
            shadow = GTK_SHADOW_OUT;

        // Style detail to use
        const char* detail;
        if (win->m_widget == win->m_wxwindow)
            // for non-scrollable wxWindows
            detail = "entry";
        else
            // for scrollable ones
            detail = "viewport";

        gtk_paint_shadow(
           win->m_wxwindow->style, gdk_event->window, GTK_STATE_NORMAL,
           shadow, NULL, wxGTKPrivate::GetEntryWidget(), detail, x, y, w, h);
    }
    return false;
}
}

//-----------------------------------------------------------------------------
// "parent_set" from m_wxwindow
//-----------------------------------------------------------------------------

extern "C" {
static void
parent_set(GtkWidget* widget, GtkObject* old_parent, wxWindow* win)
{
    if (old_parent)
    {
        g_signal_handlers_disconnect_by_func(
            old_parent, (void*)expose_event_border, win);
    }
    if (widget->parent)
    {
        g_signal_connect_after(widget->parent, "expose_event",
            G_CALLBACK(expose_event_border), win);
    }
}
}
#endif // !__WXUNIVERSAL__

//-----------------------------------------------------------------------------
// "key_press_event" from any window
//-----------------------------------------------------------------------------

// These are used when transforming Ctrl-alpha to ascii values 1-26
inline bool wxIsLowerChar(int code)
{
    return (code >= 'a' && code <= 'z' );
}

inline bool wxIsUpperChar(int code)
{
    return (code >= 'A' && code <= 'Z' );
}


// set WXTRACE to this to see the key event codes on the console
#define TRACE_KEYS  wxT("keyevent")

// translates an X key symbol to WXK_XXX value
//
// if isChar is true it means that the value returned will be used for EVT_CHAR
// event and then we choose the logical WXK_XXX, i.e. '/' for GDK_KP_Divide,
// for example, while if it is false it means that the value is going to be
// used for KEY_DOWN/UP events and then we translate GDK_KP_Divide to
// WXK_NUMPAD_DIVIDE
static long wxTranslateKeySymToWXKey(KeySym keysym, bool isChar)
{
    long key_code;

    switch ( keysym )
    {
        // Shift, Control and Alt don't generate the CHAR events at all
        case GDK_Shift_L:
        case GDK_Shift_R:
            key_code = isChar ? 0 : WXK_SHIFT;
            break;
        case GDK_Control_L:
        case GDK_Control_R:
            key_code = isChar ? 0 : WXK_CONTROL;
            break;
        case GDK_Meta_L:
        case GDK_Meta_R:
        case GDK_Alt_L:
        case GDK_Alt_R:
        case GDK_Super_L:
        case GDK_Super_R:
            key_code = isChar ? 0 : WXK_ALT;
            break;

        // neither do the toggle modifies
        case GDK_Scroll_Lock:
            key_code = isChar ? 0 : WXK_SCROLL;
            break;

        case GDK_Caps_Lock:
            key_code = isChar ? 0 : WXK_CAPITAL;
            break;

        case GDK_Num_Lock:
            key_code = isChar ? 0 : WXK_NUMLOCK;
            break;


        // various other special keys
        case GDK_Menu:
            key_code = WXK_MENU;
            break;

        case GDK_Help:
            key_code = WXK_HELP;
            break;

        case GDK_BackSpace:
            key_code = WXK_BACK;
            break;

        case GDK_ISO_Left_Tab:
        case GDK_Tab:
            key_code = WXK_TAB;
            break;

        case GDK_Linefeed:
        case GDK_Return:
            key_code = WXK_RETURN;
            break;

        case GDK_Clear:
            key_code = WXK_CLEAR;
            break;

        case GDK_Pause:
            key_code = WXK_PAUSE;
            break;

        case GDK_Select:
            key_code = WXK_SELECT;
            break;

        case GDK_Print:
            key_code = WXK_PRINT;
            break;

        case GDK_Execute:
            key_code = WXK_EXECUTE;
            break;

        case GDK_Escape:
            key_code = WXK_ESCAPE;
            break;

        // cursor and other extended keyboard keys
        case GDK_Delete:
            key_code = WXK_DELETE;
            break;

        case GDK_Home:
            key_code = WXK_HOME;
            break;

        case GDK_Left:
            key_code = WXK_LEFT;
            break;

        case GDK_Up:
            key_code = WXK_UP;
            break;

        case GDK_Right:
            key_code = WXK_RIGHT;
            break;

        case GDK_Down:
            key_code = WXK_DOWN;
            break;

        case GDK_Prior:     // == GDK_Page_Up
            key_code = WXK_PAGEUP;
            break;

        case GDK_Next:      // == GDK_Page_Down
            key_code = WXK_PAGEDOWN;
            break;

        case GDK_End:
            key_code = WXK_END;
            break;

        case GDK_Begin:
            key_code = WXK_HOME;
            break;

        case GDK_Insert:
            key_code = WXK_INSERT;
            break;


        // numpad keys
        case GDK_KP_0:
        case GDK_KP_1:
        case GDK_KP_2:
        case GDK_KP_3:
        case GDK_KP_4:
        case GDK_KP_5:
        case GDK_KP_6:
        case GDK_KP_7:
        case GDK_KP_8:
        case GDK_KP_9:
            key_code = (isChar ? '0' : int(WXK_NUMPAD0)) + keysym - GDK_KP_0;
            break;

        case GDK_KP_Space:
            key_code = isChar ? ' ' : int(WXK_NUMPAD_SPACE);
            break;

        case GDK_KP_Tab:
            key_code = isChar ? WXK_TAB : WXK_NUMPAD_TAB;
            break;

        case GDK_KP_Enter:
            key_code = isChar ? WXK_RETURN : WXK_NUMPAD_ENTER;
            break;

        case GDK_KP_F1:
            key_code = isChar ? WXK_F1 : WXK_NUMPAD_F1;
            break;

        case GDK_KP_F2:
            key_code = isChar ? WXK_F2 : WXK_NUMPAD_F2;
            break;

        case GDK_KP_F3:
            key_code = isChar ? WXK_F3 : WXK_NUMPAD_F3;
            break;

        case GDK_KP_F4:
            key_code = isChar ? WXK_F4 : WXK_NUMPAD_F4;
            break;

        case GDK_KP_Home:
            key_code = isChar ? WXK_HOME : WXK_NUMPAD_HOME;
            break;

        case GDK_KP_Left:
            key_code = isChar ? WXK_LEFT : WXK_NUMPAD_LEFT;
            break;

        case GDK_KP_Up:
            key_code = isChar ? WXK_UP : WXK_NUMPAD_UP;
            break;

        case GDK_KP_Right:
            key_code = isChar ? WXK_RIGHT : WXK_NUMPAD_RIGHT;
            break;

        case GDK_KP_Down:
            key_code = isChar ? WXK_DOWN : WXK_NUMPAD_DOWN;
            break;

        case GDK_KP_Prior: // == GDK_KP_Page_Up
            key_code = isChar ? WXK_PAGEUP : WXK_NUMPAD_PAGEUP;
            break;

        case GDK_KP_Next: // == GDK_KP_Page_Down
            key_code = isChar ? WXK_PAGEDOWN : WXK_NUMPAD_PAGEDOWN;
            break;

        case GDK_KP_End:
            key_code = isChar ? WXK_END : WXK_NUMPAD_END;
            break;

        case GDK_KP_Begin:
            key_code = isChar ? WXK_HOME : WXK_NUMPAD_BEGIN;
            break;

        case GDK_KP_Insert:
            key_code = isChar ? WXK_INSERT : WXK_NUMPAD_INSERT;
            break;

        case GDK_KP_Delete:
            key_code = isChar ? WXK_DELETE : WXK_NUMPAD_DELETE;
            break;

        case GDK_KP_Equal:
            key_code = isChar ? '=' : int(WXK_NUMPAD_EQUAL);
            break;

        case GDK_KP_Multiply:
            key_code = isChar ? '*' : int(WXK_NUMPAD_MULTIPLY);
            break;

        case GDK_KP_Add:
            key_code = isChar ? '+' : int(WXK_NUMPAD_ADD);
            break;

        case GDK_KP_Separator:
            // FIXME: what is this?
            key_code = isChar ? '.' : int(WXK_NUMPAD_SEPARATOR);
            break;

        case GDK_KP_Subtract:
            key_code = isChar ? '-' : int(WXK_NUMPAD_SUBTRACT);
            break;

        case GDK_KP_Decimal:
            key_code = isChar ? '.' : int(WXK_NUMPAD_DECIMAL);
            break;

        case GDK_KP_Divide:
            key_code = isChar ? '/' : int(WXK_NUMPAD_DIVIDE);
            break;


        // function keys
        case GDK_F1:
        case GDK_F2:
        case GDK_F3:
        case GDK_F4:
        case GDK_F5:
        case GDK_F6:
        case GDK_F7:
        case GDK_F8:
        case GDK_F9:
        case GDK_F10:
        case GDK_F11:
        case GDK_F12:
            key_code = WXK_F1 + keysym - GDK_F1;
            break;

        default:
            key_code = 0;
    }

    return key_code;
}

static inline bool wxIsAsciiKeysym(KeySym ks)
{
    return ks < 256;
}

static void wxFillOtherKeyEventFields(wxKeyEvent& event,
                                      wxWindowGTK *win,
                                      GdkEventKey *gdk_event)
{
    int x = 0;
    int y = 0;
    GdkModifierType state;
    if (gdk_event->window)
        gdk_window_get_pointer(gdk_event->window, &x, &y, &state);

    event.SetTimestamp( gdk_event->time );
    event.SetId(win->GetId());
    event.m_shiftDown = (gdk_event->state & GDK_SHIFT_MASK) != 0;
    event.m_controlDown = (gdk_event->state & GDK_CONTROL_MASK) != 0;
    event.m_altDown = (gdk_event->state & GDK_MOD1_MASK) != 0;
    event.m_metaDown = (gdk_event->state & GDK_META_MASK) != 0;
    event.m_rawCode = (wxUint32) gdk_event->keyval;
    event.m_rawFlags = 0;
#if wxUSE_UNICODE
    event.m_uniChar = gdk_keyval_to_unicode(gdk_event->keyval);
#endif
    wxGetMousePosition( &x, &y );
    win->ScreenToClient( &x, &y );
    event.m_x = x;
    event.m_y = y;
    event.SetEventObject( win );
}


static bool
wxTranslateGTKKeyEventToWx(wxKeyEvent& event,
                           wxWindowGTK *win,
                           GdkEventKey *gdk_event)
{
    // VZ: it seems that GDK_KEY_RELEASE event doesn't set event->string
    //     but only event->keyval which is quite useless to us, so remember
    //     the last character from GDK_KEY_PRESS and reuse it as last resort
    //
    // NB: should be MT-safe as we're always called from the main thread only
    static struct
    {
        KeySym keysym;
        long   keycode;
    } s_lastKeyPress = { 0, 0 };

    KeySym keysym = gdk_event->keyval;

    wxLogTrace(TRACE_KEYS, wxT("Key %s event: keysym = %ld"),
               event.GetEventType() == wxEVT_KEY_UP ? wxT("release")
                                                    : wxT("press"),
               keysym);

    long key_code = wxTranslateKeySymToWXKey(keysym, false /* !isChar */);

    if ( !key_code )
    {
        // do we have the translation or is it a plain ASCII character?
        if ( (gdk_event->length == 1) || wxIsAsciiKeysym(keysym) )
        {
            // we should use keysym if it is ASCII as X does some translations
            // like "I pressed while Control is down" => "Ctrl-I" == "TAB"
            // which we don't want here (but which we do use for OnChar())
            if ( !wxIsAsciiKeysym(keysym) )
            {
                keysym = (KeySym)gdk_event->string[0];
            }

            // we want to always get the same key code when the same key is
            // pressed regardless of the state of the modifiers, i.e. on a
            // standard US keyboard pressing '5' or '%' ('5' key with
            // Shift) should result in the same key code in OnKeyDown():
            // '5' (although OnChar() will get either '5' or '%').
            //
            // to do it we first translate keysym to keycode (== scan code)
            // and then back but always using the lower register
            Display *dpy = (Display *)wxGetDisplay();
            KeyCode keycode = XKeysymToKeycode(dpy, keysym);

            wxLogTrace(TRACE_KEYS, wxT("\t-> keycode %d"), keycode);

            KeySym keysymNormalized = XKeycodeToKeysym(dpy, keycode, 0);

            // use the normalized, i.e. lower register, keysym if we've
            // got one
            key_code = keysymNormalized ? keysymNormalized : keysym;

            // as explained above, we want to have lower register key codes
            // normally but for the letter keys we want to have the upper ones
            //
            // NB: don't use XConvertCase() here, we want to do it for letters
            // only
            key_code = toupper(key_code);
        }
        else // non ASCII key, what to do?
        {
            // by default, ignore it
            key_code = 0;

            // but if we have cached information from the last KEY_PRESS
            if ( gdk_event->type == GDK_KEY_RELEASE )
            {
                // then reuse it
                if ( keysym == s_lastKeyPress.keysym )
                {
                    key_code = s_lastKeyPress.keycode;
                }
            }
        }

        if ( gdk_event->type == GDK_KEY_PRESS )
        {
            // remember it to be reused for KEY_UP event later
            s_lastKeyPress.keysym = keysym;
            s_lastKeyPress.keycode = key_code;
        }
    }

    wxLogTrace(TRACE_KEYS, wxT("\t-> wxKeyCode %ld"), key_code);

    // sending unknown key events doesn't really make sense
    if ( !key_code )
        return false;

    // now fill all the other fields
    wxFillOtherKeyEventFields(event, win, gdk_event);

    event.m_keyCode = key_code;
#if wxUSE_UNICODE
    if ( gdk_event->type == GDK_KEY_PRESS ||  gdk_event->type == GDK_KEY_RELEASE )
    {
        event.m_uniChar = key_code;
    }
#endif

    return true;
}


struct wxGtkIMData
{
    GtkIMContext *context;
    GdkEventKey  *lastKeyEvent;

    wxGtkIMData()
    {
        context = gtk_im_multicontext_new();
        lastKeyEvent = NULL;
    }
    ~wxGtkIMData()
    {
        g_object_unref (context);
    }
};

namespace
{

// Send wxEVT_CHAR_HOOK event to the parent of the window and if it wasn't
// processed, send wxEVT_CHAR to the window itself. Return true if either of
// them was handled.
bool
SendCharHookAndCharEvents(const wxKeyEvent& event, wxWindow *win)
{
    // wxEVT_CHAR_HOOK must be sent to the top level parent window to allow it
    // to handle key events in all of its children.
    wxWindow * const parent = wxGetTopLevelParent(win);
    if ( parent )
    {
        // We need to make a copy of the event object because it is
        // modified while it's handled, notably its WasProcessed() flag
        // is set after it had been processed once.
        wxKeyEvent eventCharHook(event);
        eventCharHook.SetEventType(wxEVT_CHAR_HOOK);
        if ( parent->HandleWindowEvent(eventCharHook) )
            return true;
    }

    // As above, make a copy of the event first.
    wxKeyEvent eventChar(event);
    eventChar.SetEventType(wxEVT_CHAR);
    return win->HandleWindowEvent(eventChar);
}

} // anonymous namespace

extern "C" {
static gboolean
gtk_window_key_press_callback( GtkWidget *WXUNUSED(widget),
                               GdkEventKey *gdk_event,
                               wxWindow *win )
{
    if (!win->m_hasVMT)
        return FALSE;
    if (g_blockEventsOnDrag)
        return FALSE;

    wxKeyEvent event( wxEVT_KEY_DOWN );
    bool ret = false;
    bool return_after_IM = false;

    if( wxTranslateGTKKeyEventToWx(event, win, gdk_event) )
    {
        // Emit KEY_DOWN event
        ret = win->HandleWindowEvent( event );
    }
    else
    {
        // Return after IM processing as we cannot do
        // anything with it anyhow.
        return_after_IM = true;
    }

    if ((!ret) && (win->m_imData != NULL))
    {
        // We should let GTK+ IM filter key event first. According to GTK+ 2.0 API
        // docs, if IM filter returns true, no further processing should be done.
        // we should send the key_down event anyway.
        bool intercepted_by_IM = gtk_im_context_filter_keypress(win->m_imData->context, gdk_event);
        win->m_imData->lastKeyEvent = NULL;
        if (intercepted_by_IM)
        {
            wxLogTrace(TRACE_KEYS, wxT("Key event intercepted by IM"));
            return TRUE;
        }
    }

    if (return_after_IM)
        return FALSE;

#if wxUSE_ACCEL
    if (!ret)
    {
        wxWindowGTK *ancestor = win;
        while (ancestor)
        {
            int command = ancestor->GetAcceleratorTable()->GetCommand( event );
            if (command != -1)
            {
                wxCommandEvent menu_event( wxEVT_COMMAND_MENU_SELECTED, command );
                ret = ancestor->HandleWindowEvent( menu_event );

                if ( !ret )
                {
                    // if the accelerator wasn't handled as menu event, try
                    // it as button click (for compatibility with other
                    // platforms):
                    wxCommandEvent button_event( wxEVT_COMMAND_BUTTON_CLICKED, command );
                    ret = ancestor->HandleWindowEvent( button_event );
                }

                break;
            }
            if (ancestor->IsTopLevel())
                break;
            ancestor = ancestor->GetParent();
        }
    }
#endif // wxUSE_ACCEL

    // Only send wxEVT_CHAR event if not processed yet. Thus, ALT-x
    // will only be sent if it is not in an accelerator table.
    if (!ret)
    {
        long key_code;
        KeySym keysym = gdk_event->keyval;
        // Find key code for EVT_CHAR and EVT_CHAR_HOOK events
        key_code = wxTranslateKeySymToWXKey(keysym, true /* isChar */);
        if ( !key_code )
        {
            if ( wxIsAsciiKeysym(keysym) )
            {
                // ASCII key
                key_code = (unsigned char)keysym;
            }
            // gdk_event->string is actually deprecated
            else if ( gdk_event->length == 1 )
            {
                key_code = (unsigned char)gdk_event->string[0];
            }
        }

        if ( key_code )
        {
            wxLogTrace(TRACE_KEYS, wxT("Char event: %ld"), key_code);

            event.m_keyCode = key_code;

            // To conform to the docs we need to translate Ctrl-alpha
            // characters to values in the range 1-26.
            if ( event.ControlDown() &&
                 ( wxIsLowerChar(key_code) || wxIsUpperChar(key_code) ))
            {
                if ( wxIsLowerChar(key_code) )
                    event.m_keyCode = key_code - 'a' + 1;
                if ( wxIsUpperChar(key_code) )
                    event.m_keyCode = key_code - 'A' + 1;
#if wxUSE_UNICODE
                event.m_uniChar = event.m_keyCode;
#endif
            }

            ret = SendCharHookAndCharEvents(event, win);
        }
    }

    return ret;
}
}

extern "C" {
static void
gtk_wxwindow_commit_cb (GtkIMContext * WXUNUSED(context),
                        const gchar  *str,
                        wxWindow     *window)
{
    wxKeyEvent event( wxEVT_KEY_DOWN );

    // take modifiers, cursor position, timestamp etc. from the last
    // key_press_event that was fed into Input Method:
    if (window->m_imData->lastKeyEvent)
    {
        wxFillOtherKeyEventFields(event,
                                  window, window->m_imData->lastKeyEvent);
    }
    else
    {
        event.SetEventObject( window );
    }

    const wxString data(wxGTK_CONV_BACK_SYS(str));
    if( data.empty() )
        return;

    for( wxString::const_iterator pstr = data.begin(); pstr != data.end(); ++pstr )
    {
#if wxUSE_UNICODE
        event.m_uniChar = *pstr;
        // Backward compatible for ISO-8859-1
        event.m_keyCode = *pstr < 256 ? event.m_uniChar : 0;
        wxLogTrace(TRACE_KEYS, wxT("IM sent character '%c'"), event.m_uniChar);
#else
        event.m_keyCode = (char)*pstr;
#endif  // wxUSE_UNICODE

        // To conform to the docs we need to translate Ctrl-alpha
        // characters to values in the range 1-26.
        if ( event.ControlDown() &&
             ( wxIsLowerChar(*pstr) || wxIsUpperChar(*pstr) ))
        {
            if ( wxIsLowerChar(*pstr) )
                event.m_keyCode = *pstr - 'a' + 1;
            if ( wxIsUpperChar(*pstr) )
                event.m_keyCode = *pstr - 'A' + 1;

            event.m_keyCode = *pstr - 'a' + 1;
#if wxUSE_UNICODE
            event.m_uniChar = event.m_keyCode;
#endif
        }

        SendCharHookAndCharEvents(event, window);
    }
}
}


//-----------------------------------------------------------------------------
// "key_release_event" from any window
//-----------------------------------------------------------------------------

extern "C" {
static gboolean
gtk_window_key_release_callback( GtkWidget * WXUNUSED(widget),
                                 GdkEventKey *gdk_event,
                                 wxWindowGTK *win )
{
    if (!win->m_hasVMT)
        return FALSE;

    if (g_blockEventsOnDrag)
        return FALSE;

    wxKeyEvent event( wxEVT_KEY_UP );
    if ( !wxTranslateGTKKeyEventToWx(event, win, gdk_event) )
    {
        // unknown key pressed, ignore (the event would be useless anyhow)
        return FALSE;
    }

    return win->GTKProcessEvent(event);
}
}

// ============================================================================
// the mouse events
// ============================================================================

// ----------------------------------------------------------------------------
// mouse event processing helpers
// ----------------------------------------------------------------------------

// init wxMouseEvent with the info from GdkEventXXX struct
template<typename T> void InitMouseEvent(wxWindowGTK *win,
                                         wxMouseEvent& event,
                                         T *gdk_event)
{
    event.SetTimestamp( gdk_event->time );
    event.m_shiftDown = (gdk_event->state & GDK_SHIFT_MASK) != 0;
    event.m_controlDown = (gdk_event->state & GDK_CONTROL_MASK) != 0;
    event.m_altDown = (gdk_event->state & GDK_MOD1_MASK) != 0;
    event.m_metaDown = (gdk_event->state & GDK_META_MASK) != 0;
    event.m_leftDown = (gdk_event->state & GDK_BUTTON1_MASK) != 0;
    event.m_middleDown = (gdk_event->state & GDK_BUTTON2_MASK) != 0;
    event.m_rightDown = (gdk_event->state & GDK_BUTTON3_MASK) != 0;
    event.m_aux1Down = (gdk_event->state & GDK_BUTTON4_MASK) != 0;
    event.m_aux2Down = (gdk_event->state & GDK_BUTTON5_MASK) != 0;

    wxPoint pt = win->GetClientAreaOrigin();
    event.m_x = (wxCoord)gdk_event->x - pt.x;
    event.m_y = (wxCoord)gdk_event->y - pt.y;

    if ((win->m_wxwindow) && (win->GetLayoutDirection() == wxLayout_RightToLeft))
    {
        // origin in the upper right corner
        int window_width = win->m_wxwindow->allocation.width;
        event.m_x = window_width - event.m_x;
    }

    event.SetEventObject( win );
    event.SetId( win->GetId() );
    event.SetTimestamp( gdk_event->time );
}

static void AdjustEventButtonState(wxMouseEvent& event)
{
    // GDK reports the old state of the button for a button press event, but
    // for compatibility with MSW and common sense we want m_leftDown be TRUE
    // for a LEFT_DOWN event, not FALSE, so we will invert
    // left/right/middleDown for the corresponding click events

    if ((event.GetEventType() == wxEVT_LEFT_DOWN) ||
        (event.GetEventType() == wxEVT_LEFT_DCLICK) ||
        (event.GetEventType() == wxEVT_LEFT_UP))
    {
        event.m_leftDown = !event.m_leftDown;
        return;
    }

    if ((event.GetEventType() == wxEVT_MIDDLE_DOWN) ||
        (event.GetEventType() == wxEVT_MIDDLE_DCLICK) ||
        (event.GetEventType() == wxEVT_MIDDLE_UP))
    {
        event.m_middleDown = !event.m_middleDown;
        return;
    }

    if ((event.GetEventType() == wxEVT_RIGHT_DOWN) ||
        (event.GetEventType() == wxEVT_RIGHT_DCLICK) ||
        (event.GetEventType() == wxEVT_RIGHT_UP))
    {
        event.m_rightDown = !event.m_rightDown;
        return;
    }
}

// find the window to send the mouse event too
static
wxWindowGTK *FindWindowForMouseEvent(wxWindowGTK *win, wxCoord& x, wxCoord& y)
{
    wxCoord xx = x;
    wxCoord yy = y;

    if (win->m_wxwindow)
    {
        wxPizza* pizza = WX_PIZZA(win->m_wxwindow);
        xx += pizza->m_scroll_x;
        yy += pizza->m_scroll_y;
    }

    wxWindowList::compatibility_iterator node = win->GetChildren().GetFirst();
    while (node)
    {
        wxWindowGTK *child = node->GetData();

        node = node->GetNext();
        if (!child->IsShown())
            continue;

        if (child->GTKIsTransparentForMouse())
        {
            // wxStaticBox is transparent in the box itself
            int xx1 = child->m_x;
            int yy1 = child->m_y;
            int xx2 = child->m_x + child->m_width;
            int yy2 = child->m_y + child->m_height;

            // left
            if (((xx >= xx1) && (xx <= xx1+10) && (yy >= yy1) && (yy <= yy2)) ||
            // right
                ((xx >= xx2-10) && (xx <= xx2) && (yy >= yy1) && (yy <= yy2)) ||
            // top
                ((xx >= xx1) && (xx <= xx2) && (yy >= yy1) && (yy <= yy1+10)) ||
            // bottom
                ((xx >= xx1) && (xx <= xx2) && (yy >= yy2-1) && (yy <= yy2)))
            {
                win = child;
                x -= child->m_x;
                y -= child->m_y;
                break;
            }

        }
        else
        {
            if ((child->m_wxwindow == NULL) &&
                (child->m_x <= xx) &&
                (child->m_y <= yy) &&
                (child->m_x+child->m_width  >= xx) &&
                (child->m_y+child->m_height >= yy))
            {
                win = child;
                x -= child->m_x;
                y -= child->m_y;
                break;
            }
        }
    }

    return win;
}

// ----------------------------------------------------------------------------
// common event handlers helpers
// ----------------------------------------------------------------------------

bool wxWindowGTK::GTKProcessEvent(wxEvent& event) const
{
    // nothing special at this level
    return HandleWindowEvent(event);
}

bool wxWindowGTK::GTKShouldIgnoreEvent() const
{
    return !m_hasVMT || g_blockEventsOnDrag;
}

int wxWindowGTK::GTKCallbackCommonPrologue(GdkEventAny *event) const
{
    if (!m_hasVMT)
        return FALSE;
    if (g_blockEventsOnDrag)
        return TRUE;
    if (g_blockEventsOnScroll)
        return TRUE;

    if (!GTKIsOwnWindow(event->window))
        return FALSE;

    return -1;
}

// overloads for all GDK event types we use here: we need to have this as
// GdkEventXXX can't be implicitly cast to GdkEventAny even if it, in fact,
// derives from it in the sense that the structs have the same layout
#define wxDEFINE_COMMON_PROLOGUE_OVERLOAD(T)                                  \
    static int wxGtkCallbackCommonPrologue(T *event, wxWindowGTK *win)        \
    {                                                                         \
        return win->GTKCallbackCommonPrologue((GdkEventAny *)event);          \
    }

wxDEFINE_COMMON_PROLOGUE_OVERLOAD(GdkEventButton)
wxDEFINE_COMMON_PROLOGUE_OVERLOAD(GdkEventMotion)
wxDEFINE_COMMON_PROLOGUE_OVERLOAD(GdkEventCrossing)

#undef wxDEFINE_COMMON_PROLOGUE_OVERLOAD

#define wxCOMMON_CALLBACK_PROLOGUE(event, win)                                \
    const int rc = wxGtkCallbackCommonPrologue(event, win);                   \
    if ( rc != -1 )                                                           \
        return rc

// all event handlers must have C linkage as they're called from GTK+ C code
extern "C"
{

//-----------------------------------------------------------------------------
// "button_press_event"
//-----------------------------------------------------------------------------

static gboolean
gtk_window_button_press_callback( GtkWidget *widget,
                                  GdkEventButton *gdk_event,
                                  wxWindowGTK *win )
{
    wxCOMMON_CALLBACK_PROLOGUE(gdk_event, win);

    g_lastButtonNumber = gdk_event->button;

    // GDK sends surplus button down events
    // before a double click event. We
    // need to filter these out.
    if ((gdk_event->type == GDK_BUTTON_PRESS) && (win->m_wxwindow))
    {
        GdkEvent *peek_event = gdk_event_peek();
        if (peek_event)
        {
            if ((peek_event->type == GDK_2BUTTON_PRESS) ||
                (peek_event->type == GDK_3BUTTON_PRESS))
            {
                gdk_event_free( peek_event );
                return TRUE;
            }
            else
            {
                gdk_event_free( peek_event );
            }
        }
    }

    wxEventType event_type = wxEVT_NULL;

    if ( gdk_event->type == GDK_2BUTTON_PRESS &&
            gdk_event->button >= 1 && gdk_event->button <= 3 )
    {
        // Reset GDK internal timestamp variables in order to disable GDK
        // triple click events. GDK will then next time believe no button has
        // been clicked just before, and send a normal button click event.
        GdkDisplay* display = gtk_widget_get_display (widget);
        display->button_click_time[1] = 0;
        display->button_click_time[0] = 0;
    }

    if (gdk_event->button == 1)
    {
        // note that GDK generates triple click events which are not supported
        // by wxWidgets but still have to be passed to the app as otherwise
        // clicks would simply go missing
        switch (gdk_event->type)
        {
            // we shouldn't get triple clicks at all for GTK2 because we
            // suppress them artificially using the code above but we still
            // should map them to something for GTK1 and not just ignore them
            // as this would lose clicks
            case GDK_3BUTTON_PRESS:     // we could also map this to DCLICK...
            case GDK_BUTTON_PRESS:
                event_type = wxEVT_LEFT_DOWN;
                break;

            case GDK_2BUTTON_PRESS:
                event_type = wxEVT_LEFT_DCLICK;
                break;

            default:
                // just to silence gcc warnings
                ;
        }
    }
    else if (gdk_event->button == 2)
    {
        switch (gdk_event->type)
        {
            case GDK_3BUTTON_PRESS:
            case GDK_BUTTON_PRESS:
                event_type = wxEVT_MIDDLE_DOWN;
                break;

            case GDK_2BUTTON_PRESS:
                event_type = wxEVT_MIDDLE_DCLICK;
                break;

            default:
                ;
        }
    }
    else if (gdk_event->button == 3)
    {
        switch (gdk_event->type)
        {
            case GDK_3BUTTON_PRESS:
            case GDK_BUTTON_PRESS:
                event_type = wxEVT_RIGHT_DOWN;
                break;

            case GDK_2BUTTON_PRESS:
                event_type = wxEVT_RIGHT_DCLICK;
                break;

            default:
                ;
        }
    }

    if ( event_type == wxEVT_NULL )
    {
        // unknown mouse button or click type
        return FALSE;
    }

    g_lastMouseEvent = (GdkEvent*) gdk_event;

    wxMouseEvent event( event_type );
    InitMouseEvent( win, event, gdk_event );

    AdjustEventButtonState(event);

    // find the correct window to send the event to: it may be a different one
    // from the one which got it at GTK+ level because some controls don't have
    // their own X window and thus cannot get any events.
    if ( !g_captureWindow )
        win = FindWindowForMouseEvent(win, event.m_x, event.m_y);

    // reset the event object and id in case win changed.
    event.SetEventObject( win );
    event.SetId( win->GetId() );

    bool ret = win->GTKProcessEvent( event );
    g_lastMouseEvent = NULL;
    if ( ret )
        return TRUE;

    if ((event_type == wxEVT_LEFT_DOWN) && !win->IsOfStandardClass() &&
        (gs_currentFocus != win) /* && win->IsFocusable() */)
    {
        win->SetFocus();
    }

    if (event_type == wxEVT_RIGHT_DOWN)
    {
        // generate a "context menu" event: this is similar to right mouse
        // click under many GUIs except that it is generated differently
        // (right up under MSW, ctrl-click under Mac, right down here) and
        //
        // (a) it's a command event and so is propagated to the parent
        // (b) under some ports it can be generated from kbd too
        // (c) it uses screen coords (because of (a))
        wxContextMenuEvent evtCtx(
            wxEVT_CONTEXT_MENU,
            win->GetId(),
            win->ClientToScreen(event.GetPosition()));
        evtCtx.SetEventObject(win);
        return win->GTKProcessEvent(evtCtx);
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// "button_release_event"
//-----------------------------------------------------------------------------

static gboolean
gtk_window_button_release_callback( GtkWidget *WXUNUSED(widget),
                                    GdkEventButton *gdk_event,
                                    wxWindowGTK *win )
{
    wxCOMMON_CALLBACK_PROLOGUE(gdk_event, win);

    g_lastButtonNumber = 0;

    wxEventType event_type = wxEVT_NULL;

    switch (gdk_event->button)
    {
        case 1:
            event_type = wxEVT_LEFT_UP;
            break;

        case 2:
            event_type = wxEVT_MIDDLE_UP;
            break;

        case 3:
            event_type = wxEVT_RIGHT_UP;
            break;

        default:
            // unknown button, don't process
            return FALSE;
    }

    g_lastMouseEvent = (GdkEvent*) gdk_event;

    wxMouseEvent event( event_type );
    InitMouseEvent( win, event, gdk_event );

    AdjustEventButtonState(event);

    if ( !g_captureWindow )
        win = FindWindowForMouseEvent(win, event.m_x, event.m_y);

    // reset the event object and id in case win changed.
    event.SetEventObject( win );
    event.SetId( win->GetId() );

    bool ret = win->GTKProcessEvent(event);

    g_lastMouseEvent = NULL;

    return ret;
}

//-----------------------------------------------------------------------------
// "motion_notify_event"
//-----------------------------------------------------------------------------

static gboolean
gtk_window_motion_notify_callback( GtkWidget * WXUNUSED(widget),
                                   GdkEventMotion *gdk_event,
                                   wxWindowGTK *win )
{
    wxCOMMON_CALLBACK_PROLOGUE(gdk_event, win);

    if (gdk_event->is_hint)
    {
        int x = 0;
        int y = 0;
        GdkModifierType state;
        gdk_window_get_pointer(gdk_event->window, &x, &y, &state);
        gdk_event->x = x;
        gdk_event->y = y;
    }

    g_lastMouseEvent = (GdkEvent*) gdk_event;

    wxMouseEvent event( wxEVT_MOTION );
    InitMouseEvent(win, event, gdk_event);

    if ( g_captureWindow )
    {
        // synthesise a mouse enter or leave event if needed
        GdkWindow *winUnderMouse = gdk_window_at_pointer(NULL, NULL);
        // This seems to be necessary and actually been added to
        // GDK itself in version 2.0.X
        gdk_flush();

        bool hasMouse = winUnderMouse == gdk_event->window;
        if ( hasMouse != g_captureWindowHasMouse )
        {
            // the mouse changed window
            g_captureWindowHasMouse = hasMouse;

            wxMouseEvent eventM(g_captureWindowHasMouse ? wxEVT_ENTER_WINDOW
                                                        : wxEVT_LEAVE_WINDOW);
            InitMouseEvent(win, eventM, gdk_event);
            eventM.SetEventObject(win);
            win->GTKProcessEvent(eventM);
        }
    }
    else // no capture
    {
        win = FindWindowForMouseEvent(win, event.m_x, event.m_y);

        // reset the event object and id in case win changed.
        event.SetEventObject( win );
        event.SetId( win->GetId() );
    }

    if ( !g_captureWindow )
    {
        wxSetCursorEvent cevent( event.m_x, event.m_y );
        if (win->GTKProcessEvent( cevent ))
        {
            win->SetCursor( cevent.GetCursor() );
        }
    }

    bool ret = win->GTKProcessEvent(event);

    g_lastMouseEvent = NULL;

    return ret;
}

//-----------------------------------------------------------------------------
// "scroll_event" (mouse wheel event)
//-----------------------------------------------------------------------------

static gboolean
window_scroll_event_hscrollbar(GtkWidget*, GdkEventScroll* gdk_event, wxWindow* win)
{
    if (gdk_event->direction != GDK_SCROLL_LEFT &&
        gdk_event->direction != GDK_SCROLL_RIGHT)
    {
        return false;
    }

    wxMouseEvent event(wxEVT_MOUSEWHEEL);
    InitMouseEvent(win, event, gdk_event);

    GtkRange *range = win->m_scrollBar[wxWindow::ScrollDir_Horz];
    if (!range) return FALSE;

    if (range && GTK_WIDGET_VISIBLE (range))
    {
        GtkAdjustment *adj = range->adjustment;
        gdouble delta = adj->step_increment * 3;
        if (gdk_event->direction == GDK_SCROLL_LEFT)
            delta = -delta;

        gdouble new_value = CLAMP (adj->value + delta, adj->lower, adj->upper - adj->page_size);

        gtk_adjustment_set_value (adj, new_value);

        return TRUE;
    }

    return FALSE;
}

static gboolean
window_scroll_event(GtkWidget*, GdkEventScroll* gdk_event, wxWindow* win)
{
    if (gdk_event->direction != GDK_SCROLL_UP &&
        gdk_event->direction != GDK_SCROLL_DOWN)
    {
        return false;
    }

    wxMouseEvent event(wxEVT_MOUSEWHEEL);
    InitMouseEvent(win, event, gdk_event);

    // FIXME: Get these values from GTK or GDK
    event.m_linesPerAction = 3;
    event.m_wheelDelta = 120;
    if (gdk_event->direction == GDK_SCROLL_UP)
        event.m_wheelRotation = 120;
    else
        event.m_wheelRotation = -120;

    if (win->GTKProcessEvent(event))
      return TRUE;

    GtkRange *range = win->m_scrollBar[wxWindow::ScrollDir_Vert];
    if (!range) return FALSE;

    if (range && GTK_WIDGET_VISIBLE (range))
    {
        GtkAdjustment *adj = range->adjustment;
        gdouble delta = adj->step_increment * 3;
        if (gdk_event->direction == GDK_SCROLL_UP)
          delta = -delta;

        gdouble new_value = CLAMP (adj->value + delta, adj->lower, adj->upper - adj->page_size);

        gtk_adjustment_set_value (adj, new_value);

        return TRUE;
    }

    return FALSE;
}

//-----------------------------------------------------------------------------
// "popup-menu"
//-----------------------------------------------------------------------------

static gboolean wxgtk_window_popup_menu_callback(GtkWidget*, wxWindowGTK* win)
{
    wxContextMenuEvent event(wxEVT_CONTEXT_MENU, win->GetId(), wxPoint(-1, -1));
    event.SetEventObject(win);
    return win->GTKProcessEvent(event);
}

//-----------------------------------------------------------------------------
// "focus_in_event"
//-----------------------------------------------------------------------------

static gboolean
gtk_window_focus_in_callback( GtkWidget * WXUNUSED(widget),
                              GdkEventFocus *WXUNUSED(event),
                              wxWindowGTK *win )
{
    return win->GTKHandleFocusIn();
}

//-----------------------------------------------------------------------------
// "focus_out_event"
//-----------------------------------------------------------------------------

static gboolean
gtk_window_focus_out_callback( GtkWidget * WXUNUSED(widget),
                               GdkEventFocus * WXUNUSED(gdk_event),
                               wxWindowGTK *win )
{
    return win->GTKHandleFocusOut();
}

//-----------------------------------------------------------------------------
// "focus"
//-----------------------------------------------------------------------------

static gboolean
wx_window_focus_callback(GtkWidget *widget,
                         GtkDirectionType WXUNUSED(direction),
                         wxWindowGTK *win)
{
    // the default handler for focus signal in GtkScrolledWindow sets
    // focus to the window itself even if it doesn't accept focus, i.e. has no
    // GTK_CAN_FOCUS in its style -- work around this by forcibly preventing
    // the signal from reaching gtk_scrolled_window_focus() if we don't have
    // any children which might accept focus (we know we don't accept the focus
    // ourselves as this signal is only connected in this case)
    if ( win->GetChildren().empty() )
        g_signal_stop_emission_by_name(widget, "focus");

    // we didn't change the focus
    return FALSE;
}

//-----------------------------------------------------------------------------
// "enter_notify_event"
//-----------------------------------------------------------------------------

static gboolean
gtk_window_enter_callback( GtkWidget *widget,
                           GdkEventCrossing *gdk_event,
                           wxWindowGTK *win )
{
    wxCOMMON_CALLBACK_PROLOGUE(gdk_event, win);

    // Event was emitted after a grab
    if (gdk_event->mode != GDK_CROSSING_NORMAL) return FALSE;

    int x = 0;
    int y = 0;
    GdkModifierType state = (GdkModifierType)0;

    gdk_window_get_pointer( widget->window, &x, &y, &state );

    wxMouseEvent event( wxEVT_ENTER_WINDOW );
    InitMouseEvent(win, event, gdk_event);
    wxPoint pt = win->GetClientAreaOrigin();
    event.m_x = x + pt.x;
    event.m_y = y + pt.y;

    if ( !g_captureWindow )
    {
        wxSetCursorEvent cevent( event.m_x, event.m_y );
        if (win->GTKProcessEvent( cevent ))
        {
            win->SetCursor( cevent.GetCursor() );
        }
    }

    return win->GTKProcessEvent(event);
}

//-----------------------------------------------------------------------------
// "leave_notify_event"
//-----------------------------------------------------------------------------

static gboolean
gtk_window_leave_callback( GtkWidget *widget,
                           GdkEventCrossing *gdk_event,
                           wxWindowGTK *win )
{
    wxCOMMON_CALLBACK_PROLOGUE(gdk_event, win);

    // Event was emitted after an ungrab
    if (gdk_event->mode != GDK_CROSSING_NORMAL) return FALSE;

    wxMouseEvent event( wxEVT_LEAVE_WINDOW );

    int x = 0;
    int y = 0;
    GdkModifierType state = (GdkModifierType)0;

    gdk_window_get_pointer( widget->window, &x, &y, &state );

    InitMouseEvent(win, event, gdk_event);

    return win->GTKProcessEvent(event);
}

//-----------------------------------------------------------------------------
// "value_changed" from scrollbar
//-----------------------------------------------------------------------------

static void
gtk_scrollbar_value_changed(GtkRange* range, wxWindow* win)
{
    wxEventType eventType = win->GTKGetScrollEventType(range);
    if (eventType != wxEVT_NULL)
    {
        // Convert scroll event type to scrollwin event type
        eventType += wxEVT_SCROLLWIN_TOP - wxEVT_SCROLL_TOP;

        // find the scrollbar which generated the event
        wxWindowGTK::ScrollDir dir = win->ScrollDirFromRange(range);

        // generate the corresponding wx event
        const int orient = wxWindow::OrientFromScrollDir(dir);
        wxScrollWinEvent event(eventType, win->GetScrollPos(orient), orient);
        event.SetEventObject(win);

        win->GTKProcessEvent(event);
    }
}

//-----------------------------------------------------------------------------
// "button_press_event" from scrollbar
//-----------------------------------------------------------------------------

static gboolean
gtk_scrollbar_button_press_event(GtkRange*, GdkEventButton*, wxWindow* win)
{
    g_blockEventsOnScroll = true;
    win->m_mouseButtonDown = true;

    return false;
}

//-----------------------------------------------------------------------------
// "event_after" from scrollbar
//-----------------------------------------------------------------------------

static void
gtk_scrollbar_event_after(GtkRange* range, GdkEvent* event, wxWindow* win)
{
    if (event->type == GDK_BUTTON_RELEASE)
    {
        g_signal_handlers_block_by_func(range, (void*)gtk_scrollbar_event_after, win);

        const int orient = wxWindow::OrientFromScrollDir(
                                        win->ScrollDirFromRange(range));
        wxScrollWinEvent evt(wxEVT_SCROLLWIN_THUMBRELEASE,
                                win->GetScrollPos(orient), orient);
        evt.SetEventObject(win);
        win->GTKProcessEvent(evt);
    }
}

//-----------------------------------------------------------------------------
// "button_release_event" from scrollbar
//-----------------------------------------------------------------------------

static gboolean
gtk_scrollbar_button_release_event(GtkRange* range, GdkEventButton*, wxWindow* win)
{
    g_blockEventsOnScroll = false;
    win->m_mouseButtonDown = false;
    // If thumb tracking
    if (win->m_isScrolling)
    {
        win->m_isScrolling = false;
        // Hook up handler to send thumb release event after this emission is finished.
        // To allow setting scroll position from event handler, sending event must
        // be deferred until after the GtkRange handler for this signal has run
        g_signal_handlers_unblock_by_func(range, (void*)gtk_scrollbar_event_after, win);
    }

    return false;
}

//-----------------------------------------------------------------------------
// "realize" from m_widget
//-----------------------------------------------------------------------------

static void
gtk_window_realized_callback(GtkWidget* widget, wxWindow* win)
{
    if (win->m_imData)
    {
        gtk_im_context_set_client_window( win->m_imData->context,
            win->m_wxwindow ? win->GTKGetDrawingWindow() : widget->window);
    }

    // We cannot set colours and fonts before the widget
    // been realized, so we do this directly after realization
    // or otherwise in idle time

    if (win->m_needsStyleChange)
    {
        win->SetBackgroundStyle(win->GetBackgroundStyle());
        win->m_needsStyleChange = false;
    }

    wxWindowCreateEvent event( win );
    event.SetEventObject( win );
    win->GTKProcessEvent( event );

    win->GTKUpdateCursor(true, false);
}

//-----------------------------------------------------------------------------
// "size_allocate" from m_wxwindow or m_widget
//-----------------------------------------------------------------------------

static void
size_allocate(GtkWidget*, GtkAllocation* alloc, wxWindow* win)
{
    int w = alloc->width;
    int h = alloc->height;
    if (win->m_wxwindow)
    {
        int border_x, border_y;
        WX_PIZZA(win->m_wxwindow)->get_border_widths(border_x, border_y);
        w -= 2 * border_x;
        h -= 2 * border_y;
        if (w < 0) w = 0;
        if (h < 0) h = 0;
    }
    if (win->m_oldClientWidth != w || win->m_oldClientHeight != h)
    {
        win->m_oldClientWidth  = w;
        win->m_oldClientHeight = h;
        // this callback can be connected to m_wxwindow,
        // so always get size from m_widget->allocation
        win->m_width  = win->m_widget->allocation.width;
        win->m_height = win->m_widget->allocation.height;
        if (!win->m_nativeSizeEvent)
        {
            wxSizeEvent event(win->GetSize(), win->GetId());
            event.SetEventObject(win);
            win->GTKProcessEvent(event);
        }
    }
}

//-----------------------------------------------------------------------------
// "grab_broken"
//-----------------------------------------------------------------------------

#if GTK_CHECK_VERSION(2, 8, 0)
static gboolean
gtk_window_grab_broken( GtkWidget*,
                        GdkEventGrabBroken *event,
                        wxWindow *win )
{
    // Mouse capture has been lost involuntarily, notify the application
    if(!event->keyboard && wxWindow::GetCapture() == win)
    {
        wxMouseCaptureLostEvent evt( win->GetId() );
        evt.SetEventObject( win );
        win->HandleWindowEvent( evt );
    }
    return false;
}
#endif

//-----------------------------------------------------------------------------
// "style_set"
//-----------------------------------------------------------------------------

static
void gtk_window_style_set_callback( GtkWidget *WXUNUSED(widget),
                               GtkStyle *previous_style,
                               wxWindow* win )
{
    if (win && previous_style)
    {
        wxSysColourChangedEvent event;
        event.SetEventObject(win);

        win->GTKProcessEvent( event );
    }
}

} // extern "C"

// ----------------------------------------------------------------------------
// this wxWindowBase function is implemented here (in platform-specific file)
// because it is static and so couldn't be made virtual
// ----------------------------------------------------------------------------

wxWindow *wxWindowBase::DoFindFocus()
{
    wxWindowGTK *focus = gs_pendingFocus ? gs_pendingFocus : gs_currentFocus;
    // the cast is necessary when we compile in wxUniversal mode
    return static_cast<wxWindow*>(focus);
}

void wxWindowGTK::AddChildGTK(wxWindowGTK* child)
{
    wxASSERT_MSG(m_wxwindow, "Cannot add a child to a window without a client area");

    // the window might have been scrolled already, we
    // have to adapt the position
    wxPizza* pizza = WX_PIZZA(m_wxwindow);
    child->m_x += pizza->m_scroll_x;
    child->m_y += pizza->m_scroll_y;

    gtk_widget_set_size_request(
        child->m_widget, child->m_width, child->m_height);
    pizza->put(child->m_widget, child->m_x, child->m_y);
}

//-----------------------------------------------------------------------------
// global functions
//-----------------------------------------------------------------------------

wxWindow *wxGetActiveWindow()
{
    return wxWindow::FindFocus();
}


wxMouseState wxGetMouseState()
{
    wxMouseState ms;

    gint x;
    gint y;
    GdkModifierType mask;

    gdk_window_get_pointer(NULL, &x, &y, &mask);

    ms.SetX(x);
    ms.SetY(y);
    ms.SetLeftDown((mask & GDK_BUTTON1_MASK) != 0);
    ms.SetMiddleDown((mask & GDK_BUTTON2_MASK) != 0);
    ms.SetRightDown((mask & GDK_BUTTON3_MASK) != 0);
    ms.SetAux1Down((mask & GDK_BUTTON4_MASK) != 0);
    ms.SetAux2Down((mask & GDK_BUTTON5_MASK) != 0);

    ms.SetControlDown((mask & GDK_CONTROL_MASK) != 0);
    ms.SetShiftDown((mask & GDK_SHIFT_MASK) != 0);
    ms.SetAltDown((mask & GDK_MOD1_MASK) != 0);
    ms.SetMetaDown((mask & GDK_META_MASK) != 0);

    return ms;
}

//-----------------------------------------------------------------------------
// wxWindowGTK
//-----------------------------------------------------------------------------

// in wxUniv/MSW this class is abstract because it doesn't have DoPopupMenu()
// method
#ifdef __WXUNIVERSAL__
    IMPLEMENT_ABSTRACT_CLASS(wxWindowGTK, wxWindowBase)
#else // __WXGTK__
    IMPLEMENT_DYNAMIC_CLASS(wxWindow, wxWindowBase)
#endif // __WXUNIVERSAL__/__WXGTK__

void wxWindowGTK::Init()
{
    // GTK specific
    m_widget = NULL;
    m_wxwindow = NULL;
    m_focusWidget = NULL;

    // position/size
    m_x = 0;
    m_y = 0;
    m_width = 0;
    m_height = 0;

    m_hasVMT = false;

    m_showOnIdle = false;

    m_noExpose = false;
    m_nativeSizeEvent = false;

    m_isScrolling = false;
    m_mouseButtonDown = false;

    // initialize scrolling stuff
    for ( int dir = 0; dir < ScrollDir_Max; dir++ )
    {
        m_scrollBar[dir] = NULL;
        m_scrollPos[dir] = 0;
    }

    m_oldClientWidth =
    m_oldClientHeight = 0;

    m_clipPaintRegion = false;

    m_needsStyleChange = false;

    m_cursor = *wxSTANDARD_CURSOR;

    m_imData = NULL;
    m_dirtyTabOrder = false;
}

wxWindowGTK::wxWindowGTK()
{
    Init();
}

wxWindowGTK::wxWindowGTK( wxWindow *parent,
                          wxWindowID id,
                          const wxPoint &pos,
                          const wxSize &size,
                          long style,
                          const wxString &name  )
{
    Init();

    Create( parent, id, pos, size, style, name );
}

bool wxWindowGTK::Create( wxWindow *parent,
                          wxWindowID id,
                          const wxPoint &pos,
                          const wxSize &size,
                          long style,
                          const wxString &name  )
{
    // Get default border
    wxBorder border = GetBorder(style);

    style &= ~wxBORDER_MASK;
    style |= border;

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, wxDefaultValidator, name ))
    {
        wxFAIL_MSG( wxT("wxWindowGTK creation failed") );
        return false;
    }

        // We should accept the native look
#if 0
        GtkScrolledWindowClass *scroll_class = GTK_SCROLLED_WINDOW_CLASS( GTK_OBJECT_GET_CLASS(m_widget) );
        scroll_class->scrollbar_spacing = 0;
#endif


    m_wxwindow = wxPizza::New(m_windowStyle);
#ifndef __WXUNIVERSAL__
    if (HasFlag(wxPizza::BORDER_STYLES))
    {
        g_signal_connect(m_wxwindow, "parent_set",
            G_CALLBACK(parent_set), this);
    }
#endif
    if (!HasFlag(wxHSCROLL) && !HasFlag(wxVSCROLL))
        m_widget = m_wxwindow;
    else
    {
        m_widget = gtk_scrolled_window_new( NULL, NULL );

        GtkScrolledWindow *scrolledWindow = GTK_SCROLLED_WINDOW(m_widget);

        // There is a conflict with default bindings at GTK+
        // level between scrolled windows and notebooks both of which want to use
        // Ctrl-PageUp/Down: scrolled windows for scrolling in the horizontal
        // direction and notebooks for changing pages -- we decide that if we don't
        // have wxHSCROLL style we can safely sacrifice horizontal scrolling if it
        // means we can get working keyboard navigation in notebooks
        if ( !HasFlag(wxHSCROLL) )
        {
            GtkBindingSet *
                bindings = gtk_binding_set_by_class(G_OBJECT_GET_CLASS(m_widget));
            if ( bindings )
            {
                gtk_binding_entry_remove(bindings, GDK_Page_Up, GDK_CONTROL_MASK);
                gtk_binding_entry_remove(bindings, GDK_Page_Down, GDK_CONTROL_MASK);
            }
        }

        if (HasFlag(wxALWAYS_SHOW_SB))
        {
            gtk_scrolled_window_set_policy( scrolledWindow, GTK_POLICY_ALWAYS, GTK_POLICY_ALWAYS );

            scrolledWindow->hscrollbar_visible = TRUE;
            scrolledWindow->vscrollbar_visible = TRUE;
        }
        else
        {
            gtk_scrolled_window_set_policy( scrolledWindow, GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC );
        }

        m_scrollBar[ScrollDir_Horz] = GTK_RANGE(scrolledWindow->hscrollbar);
        m_scrollBar[ScrollDir_Vert] = GTK_RANGE(scrolledWindow->vscrollbar);
        if (GetLayoutDirection() == wxLayout_RightToLeft)
            gtk_range_set_inverted( m_scrollBar[ScrollDir_Horz], TRUE );

        gtk_container_add( GTK_CONTAINER(m_widget), m_wxwindow );

        // connect various scroll-related events
        for ( int dir = 0; dir < ScrollDir_Max; dir++ )
        {
            // these handlers block mouse events to any window during scrolling
            // such as motion events and prevent GTK and wxWidgets from fighting
            // over where the slider should be
            g_signal_connect(m_scrollBar[dir], "button_press_event",
                         G_CALLBACK(gtk_scrollbar_button_press_event), this);
            g_signal_connect(m_scrollBar[dir], "button_release_event",
                         G_CALLBACK(gtk_scrollbar_button_release_event), this);

            gulong handler_id = g_signal_connect(m_scrollBar[dir], "event_after",
                                G_CALLBACK(gtk_scrollbar_event_after), this);
            g_signal_handler_block(m_scrollBar[dir], handler_id);

            // these handlers get notified when scrollbar slider moves
            g_signal_connect_after(m_scrollBar[dir], "value_changed",
                         G_CALLBACK(gtk_scrollbar_value_changed), this);
        }

        gtk_widget_show( m_wxwindow );
    }
    g_object_ref(m_widget);

    if (m_parent)
        m_parent->DoAddChild( this );

    m_focusWidget = m_wxwindow;

    SetCanFocus(AcceptsFocus());

    PostCreation();

    return true;
}

wxWindowGTK::~wxWindowGTK()
{
    SendDestroyEvent();

    if (gs_currentFocus == this)
        gs_currentFocus = NULL;
    if (gs_pendingFocus == this)
        gs_pendingFocus = NULL;

    if ( gs_deferredFocusOut == this )
        gs_deferredFocusOut = NULL;

    m_hasVMT = false;

    // destroy children before destroying this window itself
    DestroyChildren();

    // unhook focus handlers to prevent stray events being
    // propagated to this (soon to be) dead object
    if (m_focusWidget != NULL)
    {
        g_signal_handlers_disconnect_by_func (m_focusWidget,
                                              (gpointer) gtk_window_focus_in_callback,
                                              this);
        g_signal_handlers_disconnect_by_func (m_focusWidget,
                                              (gpointer) gtk_window_focus_out_callback,
                                              this);
    }

    if (m_widget)
        Show( false );

    // delete before the widgets to avoid a crash on solaris
    delete m_imData;

    // avoid problem with GTK+ 2.18 where a frozen window causes the whole
    // TLW to be frozen, and if the window is then destroyed, nothing ever
    // gets painted again
    if (IsFrozen())
        DoThaw();

    if (m_widget)
    {
        // Note that gtk_widget_destroy() does not destroy the widget, it just
        // emits the "destroy" signal. The widget is not actually destroyed
        // until its reference count drops to zero.
        gtk_widget_destroy(m_widget);
        // Release our reference, should be the last one
        g_object_unref(m_widget);
        m_widget = NULL;
    }
    m_wxwindow = NULL;
}

bool wxWindowGTK::PreCreation( wxWindowGTK *parent, const wxPoint &pos,  const wxSize &size )
{
    if ( GTKNeedsParent() )
    {
        wxCHECK_MSG( parent, false, wxT("Must have non-NULL parent") );
    }

    // Use either the given size, or the default if -1 is given.
    // See wxWindowBase for these functions.
    m_width = WidthDefault(size.x) ;
    m_height = HeightDefault(size.y);

    m_x = (int)pos.x;
    m_y = (int)pos.y;

    return true;
}

void wxWindowGTK::PostCreation()
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid window") );

    if (m_wxwindow)
    {
        if (!m_noExpose)
        {
            // these get reported to wxWidgets -> wxPaintEvent

            g_signal_connect (m_wxwindow, "expose_event",
                              G_CALLBACK (gtk_window_expose_callback), this);

            if (GetLayoutDirection() == wxLayout_LeftToRight)
                gtk_widget_set_redraw_on_allocate(m_wxwindow, HasFlag(wxFULL_REPAINT_ON_RESIZE));
        }

        // Create input method handler
        m_imData = new wxGtkIMData;

        // Cannot handle drawing preedited text yet
        gtk_im_context_set_use_preedit( m_imData->context, FALSE );

        g_signal_connect (m_imData->context, "commit",
                          G_CALLBACK (gtk_wxwindow_commit_cb), this);
    }

    // focus handling

    if (!GTK_IS_WINDOW(m_widget))
    {
        if (m_focusWidget == NULL)
            m_focusWidget = m_widget;

        if (m_wxwindow)
        {
            g_signal_connect (m_focusWidget, "focus_in_event",
                          G_CALLBACK (gtk_window_focus_in_callback), this);
            g_signal_connect (m_focusWidget, "focus_out_event",
                                G_CALLBACK (gtk_window_focus_out_callback), this);
        }
        else
        {
            g_signal_connect_after (m_focusWidget, "focus_in_event",
                          G_CALLBACK (gtk_window_focus_in_callback), this);
            g_signal_connect_after (m_focusWidget, "focus_out_event",
                                G_CALLBACK (gtk_window_focus_out_callback), this);
        }
    }

    if ( !AcceptsFocusFromKeyboard() )
    {
        SetCanFocus(false);

        g_signal_connect(m_widget, "focus",
                            G_CALLBACK(wx_window_focus_callback), this);
    }

    // connect to the various key and mouse handlers

    GtkWidget *connect_widget = GetConnectWidget();

    ConnectWidget( connect_widget );

    /* We cannot set colours, fonts and cursors before the widget has
       been realized, so we do this directly after realization */
    g_signal_connect (connect_widget, "realize",
                      G_CALLBACK (gtk_window_realized_callback), this);

    if (!IsTopLevel())
    {
        g_signal_connect(m_wxwindow ? m_wxwindow : m_widget, "size_allocate",
            G_CALLBACK(size_allocate), this);
    }

#if GTK_CHECK_VERSION(2, 8, 0)
    if ( gtk_check_version(2,8,0) == NULL )
    {
        // Make sure we can notify the app when mouse capture is lost
        if ( m_wxwindow )
        {
            g_signal_connect (m_wxwindow, "grab_broken_event",
                          G_CALLBACK (gtk_window_grab_broken), this);
        }

        if ( connect_widget != m_wxwindow )
        {
            g_signal_connect (connect_widget, "grab_broken_event",
                        G_CALLBACK (gtk_window_grab_broken), this);
        }
    }
#endif // GTK+ >= 2.8

    if ( GTKShouldConnectSizeRequest() )
    {
        // This is needed if we want to add our windows into native
        // GTK controls, such as the toolbar. With this callback, the
        // toolbar gets to know the correct size (the one set by the
        // programmer). Sadly, it misbehaves for wxComboBox.
        g_signal_connect (m_widget, "size_request",
                          G_CALLBACK (wxgtk_window_size_request_callback),
                          this);
    }

    InheritAttributes();

    m_hasVMT = true;

    SetLayoutDirection(wxLayout_Default);

    // unless the window was created initially hidden (i.e. Hide() had been
    // called before Create()), we should show it at GTK+ level as well
    if ( IsShown() )
        gtk_widget_show( m_widget );
}

gulong wxWindowGTK::GTKConnectWidget(const char *signal, void (*callback)())
{
    return g_signal_connect(m_widget, signal, callback, this);
}

void wxWindowGTK::ConnectWidget( GtkWidget *widget )
{
    g_signal_connect (widget, "key_press_event",
                      G_CALLBACK (gtk_window_key_press_callback), this);
    g_signal_connect (widget, "key_release_event",
                      G_CALLBACK (gtk_window_key_release_callback), this);
    g_signal_connect (widget, "button_press_event",
                      G_CALLBACK (gtk_window_button_press_callback), this);
    g_signal_connect (widget, "button_release_event",
                      G_CALLBACK (gtk_window_button_release_callback), this);
    g_signal_connect (widget, "motion_notify_event",
                      G_CALLBACK (gtk_window_motion_notify_callback), this);

    g_signal_connect (widget, "scroll_event",
                      G_CALLBACK (window_scroll_event), this);
    if (m_scrollBar[ScrollDir_Horz])
        g_signal_connect (m_scrollBar[ScrollDir_Horz], "scroll_event",
                      G_CALLBACK (window_scroll_event_hscrollbar), this);
    if (m_scrollBar[ScrollDir_Vert])
        g_signal_connect (m_scrollBar[ScrollDir_Vert], "scroll_event",
                      G_CALLBACK (window_scroll_event), this);

    g_signal_connect (widget, "popup_menu",
                     G_CALLBACK (wxgtk_window_popup_menu_callback), this);
    g_signal_connect (widget, "enter_notify_event",
                      G_CALLBACK (gtk_window_enter_callback), this);
    g_signal_connect (widget, "leave_notify_event",
                      G_CALLBACK (gtk_window_leave_callback), this);

    if (IsTopLevel() && m_wxwindow)
        g_signal_connect (m_wxwindow, "style_set",
                              G_CALLBACK (gtk_window_style_set_callback), this);
}

bool wxWindowGTK::Destroy()
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid window") );

    m_hasVMT = false;

    return wxWindowBase::Destroy();
}

void wxWindowGTK::DoMoveWindow(int x, int y, int width, int height)
{
    gtk_widget_set_size_request(m_widget, width, height);

    // inform the parent to perform the move
    wxASSERT_MSG(m_parent && m_parent->m_wxwindow,
                 "the parent window has no client area?");
    WX_PIZZA(m_parent->m_wxwindow)->move(m_widget, x, y);
}

void wxWindowGTK::ConstrainSize()
{
#ifdef __WXGPE__
    // GPE's window manager doesn't like size hints at all, esp. when the user
    // has to use the virtual keyboard, so don't constrain size there
    if (!IsTopLevel())
#endif
    {
        const wxSize minSize = GetMinSize();
        const wxSize maxSize = GetMaxSize();
        if (minSize.x > 0 && m_width  < minSize.x) m_width  = minSize.x;
        if (minSize.y > 0 && m_height < minSize.y) m_height = minSize.y;
        if (maxSize.x > 0 && m_width  > maxSize.x) m_width  = maxSize.x;
        if (maxSize.y > 0 && m_height > maxSize.y) m_height = maxSize.y;
    }
}

void wxWindowGTK::DoSetSize( int x, int y, int width, int height, int sizeFlags )
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid window") );
    wxASSERT_MSG( (m_parent != NULL), wxT("wxWindowGTK::SetSize requires parent.\n") );

    int currentX, currentY;
    GetPosition(&currentX, &currentY);
    if (x == -1 && !(sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        x = currentX;
    if (y == -1 && !(sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        y = currentY;
    AdjustForParentClientOrigin(x, y, sizeFlags);

    // calculate the best size if we should auto size the window
    if ( ((sizeFlags & wxSIZE_AUTO_WIDTH) && width == -1) ||
         ((sizeFlags & wxSIZE_AUTO_HEIGHT) && height == -1) )
    {
        const wxSize sizeBest = GetBestSize();
        if ( (sizeFlags & wxSIZE_AUTO_WIDTH) && width == -1 )
            width = sizeBest.x;
        if ( (sizeFlags & wxSIZE_AUTO_HEIGHT) && height == -1 )
            height = sizeBest.y;
    }

    const wxSize oldSize(m_width, m_height);
    if (width != -1)
        m_width = width;
    if (height != -1)
        m_height = height;

    if (m_parent->m_wxwindow)
    {
        wxPizza* pizza = WX_PIZZA(m_parent->m_wxwindow);
        m_x = x + pizza->m_scroll_x;
        m_y = y + pizza->m_scroll_y;

        int left_border = 0;
        int right_border = 0;
        int top_border = 0;
        int bottom_border = 0;

        /* the default button has a border around it */
        if (GTK_WIDGET_CAN_DEFAULT(m_widget))
        {
            GtkBorder *default_border = NULL;
            gtk_widget_style_get( m_widget, "default_border", &default_border, NULL );
            if (default_border)
            {
                left_border += default_border->left;
                right_border += default_border->right;
                top_border += default_border->top;
                bottom_border += default_border->bottom;
                gtk_border_free( default_border );
            }
        }

        DoMoveWindow( m_x - left_border,
                      m_y - top_border,
                      m_width+left_border+right_border,
                      m_height+top_border+bottom_border );
    }

    if (m_width != oldSize.x || m_height != oldSize.y)
    {
        // update these variables to keep size_allocate handler
        // from sending another size event for this change
        GetClientSize( &m_oldClientWidth, &m_oldClientHeight );

        gtk_widget_queue_resize(m_widget);
        if (!m_nativeSizeEvent)
        {
            wxSizeEvent event( wxSize(m_width,m_height), GetId() );
            event.SetEventObject( this );
            HandleWindowEvent( event );
        }
    } else
    if (sizeFlags & wxSIZE_FORCE_EVENT)
    {
        wxSizeEvent event( wxSize(m_width,m_height), GetId() );
        event.SetEventObject( this );
        HandleWindowEvent( event );
    }
}

bool wxWindowGTK::GTKShowFromOnIdle()
{
    if (IsShown() && m_showOnIdle && !GTK_WIDGET_VISIBLE (m_widget))
    {
        GtkAllocation alloc;
        alloc.x = m_x;
        alloc.y = m_y;
        alloc.width = m_width;
        alloc.height = m_height;
        gtk_widget_size_allocate( m_widget, &alloc );
        gtk_widget_show( m_widget );
        wxShowEvent eventShow(GetId(), true);
        eventShow.SetEventObject(this);
        HandleWindowEvent(eventShow);
        m_showOnIdle = false;
        return true;
    }

    return false;
}

void wxWindowGTK::OnInternalIdle()
{
    if ( gs_deferredFocusOut )
        GTKHandleDeferredFocusOut();

    // Check if we have to show window now
    if (GTKShowFromOnIdle()) return;

    if ( m_dirtyTabOrder )
    {
        m_dirtyTabOrder = false;
        RealizeTabOrder();
    }

    // Update style if the window was not yet realized when
    // SetBackgroundStyle() was called
    if (m_needsStyleChange)
    {
        SetBackgroundStyle(GetBackgroundStyle());
        m_needsStyleChange = false;
    }

    if (wxUpdateUIEvent::CanUpdate(this) && IsShownOnScreen())
        UpdateWindowUI(wxUPDATE_UI_FROMIDLE);
}

void wxWindowGTK::DoGetSize( int *width, int *height ) const
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    if (width) (*width) = m_width;
    if (height) (*height) = m_height;
}

void wxWindowGTK::DoSetClientSize( int width, int height )
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    const wxSize size = GetSize();
    const wxSize clientSize = GetClientSize();
    SetSize(width + (size.x - clientSize.x), height + (size.y - clientSize.y));
}

void wxWindowGTK::DoGetClientSize( int *width, int *height ) const
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    int w = m_width;
    int h = m_height;

    if ( m_wxwindow )
    {
        // if window is scrollable, account for scrollbars
        if ( GTK_IS_SCROLLED_WINDOW(m_widget) )
        {
            GtkPolicyType policy[ScrollDir_Max];
            gtk_scrolled_window_get_policy(GTK_SCROLLED_WINDOW(m_widget),
                                           &policy[ScrollDir_Horz],
                                           &policy[ScrollDir_Vert]);

            for ( int i = 0; i < ScrollDir_Max; i++ )
            {
                // don't account for the scrollbars we don't have
                GtkRange * const range = m_scrollBar[i];
                if ( !range )
                    continue;

                // nor for the ones we have but don't current show
                switch ( policy[i] )
                {
                    case GTK_POLICY_NEVER:
                        // never shown so doesn't take any place
                        continue;

                    case GTK_POLICY_ALWAYS:
                        // no checks necessary
                        break;

                    case GTK_POLICY_AUTOMATIC:
                        // may be shown or not, check
                        GtkAdjustment *adj = gtk_range_get_adjustment(range);
                        if ( adj->upper <= adj->page_size )
                            continue;
                }

                GtkScrolledWindowClass *scroll_class =
                    GTK_SCROLLED_WINDOW_CLASS( GTK_OBJECT_GET_CLASS(m_widget) );

                GtkRequisition req;
                gtk_widget_size_request(GTK_WIDGET(range), &req);
                if (i == ScrollDir_Horz)
                    h -= req.height + scroll_class->scrollbar_spacing;
                else
                    w -= req.width + scroll_class->scrollbar_spacing;
            }
        }

        const wxSize sizeBorders = DoGetBorderSize();
        w -= sizeBorders.x;
        h -= sizeBorders.y;

        if (w < 0)
            w = 0;
        if (h < 0)
            h = 0;
    }

    if (width) *width = w;
    if (height) *height = h;
}

wxSize wxWindowGTK::DoGetBorderSize() const
{
    if ( !m_wxwindow )
        return wxWindowBase::DoGetBorderSize();

    int x, y;
    WX_PIZZA(m_wxwindow)->get_border_widths(x, y);

    return 2*wxSize(x, y);
}

void wxWindowGTK::DoGetPosition( int *x, int *y ) const
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    int dx = 0;
    int dy = 0;
    if (!IsTopLevel() && m_parent && m_parent->m_wxwindow)
    {
        wxPizza* pizza = WX_PIZZA(m_parent->m_wxwindow);
        dx = pizza->m_scroll_x;
        dy = pizza->m_scroll_y;
    }

    if (m_x == -1 && m_y == -1)
    {
        GdkWindow *source = NULL;
        if (m_wxwindow)
            source = m_wxwindow->window;
        else
            source = m_widget->window;

        if (source)
        {
            int org_x = 0;
            int org_y = 0;
            gdk_window_get_origin( source, &org_x, &org_y );

            if (m_parent)
                m_parent->ScreenToClient(&org_x, &org_y);

            const_cast<wxWindowGTK*>(this)->m_x = org_x;
            const_cast<wxWindowGTK*>(this)->m_y = org_y;
        }
    }

    if (x) (*x) = m_x - dx;
    if (y) (*y) = m_y - dy;
}

void wxWindowGTK::DoClientToScreen( int *x, int *y ) const
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    if (!m_widget->window) return;

    GdkWindow *source = NULL;
    if (m_wxwindow)
        source = m_wxwindow->window;
    else
        source = m_widget->window;

    int org_x = 0;
    int org_y = 0;
    gdk_window_get_origin( source, &org_x, &org_y );

    if (!m_wxwindow)
    {
        if (GTK_WIDGET_NO_WINDOW (m_widget))
        {
            org_x += m_widget->allocation.x;
            org_y += m_widget->allocation.y;
        }
    }


    if (x)
    {
        if (GetLayoutDirection() == wxLayout_RightToLeft)
            *x = (GetClientSize().x - *x) + org_x;
        else
            *x += org_x;
    }

    if (y) *y += org_y;
}

void wxWindowGTK::DoScreenToClient( int *x, int *y ) const
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    if (!m_widget->window) return;

    GdkWindow *source = NULL;
    if (m_wxwindow)
        source = m_wxwindow->window;
    else
        source = m_widget->window;

    int org_x = 0;
    int org_y = 0;
    gdk_window_get_origin( source, &org_x, &org_y );

    if (!m_wxwindow)
    {
        if (GTK_WIDGET_NO_WINDOW (m_widget))
        {
            org_x += m_widget->allocation.x;
            org_y += m_widget->allocation.y;
        }
    }

    if (x)
    {
        if (GetLayoutDirection() == wxLayout_RightToLeft)
            *x = (GetClientSize().x - *x) - org_x;
        else
            *x -= org_x;
    }
    if (y) *y -= org_y;
}

bool wxWindowGTK::Show( bool show )
{
    if ( !wxWindowBase::Show(show) )
    {
        // nothing to do
        return false;
    }

    // notice that we may call Hide() before the window is created and this is
    // actually useful to create it hidden initially -- but we can't call
    // Show() before it is created
    if ( !m_widget )
    {
        wxASSERT_MSG( !show, "can't show invalid window" );
        return true;
    }

    if ( show )
    {
        if ( m_showOnIdle )
        {
            // defer until later
            return true;
        }

        gtk_widget_show(m_widget);
    }
    else // hide
    {
        gtk_widget_hide(m_widget);
    }

    wxShowEvent eventShow(GetId(), show);
    eventShow.SetEventObject(this);
    HandleWindowEvent(eventShow);

    return true;
}

void wxWindowGTK::DoEnable( bool enable )
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    gtk_widget_set_sensitive( m_widget, enable );
    if (m_wxwindow && (m_wxwindow != m_widget))
        gtk_widget_set_sensitive( m_wxwindow, enable );
}

int wxWindowGTK::GetCharHeight() const
{
    wxCHECK_MSG( (m_widget != NULL), 12, wxT("invalid window") );

    wxFont font = GetFont();
    wxCHECK_MSG( font.Ok(), 12, wxT("invalid font") );

    PangoContext* context = gtk_widget_get_pango_context(m_widget);

    if (!context)
        return 0;

    PangoFontDescription *desc = font.GetNativeFontInfo()->description;
    PangoLayout *layout = pango_layout_new(context);
    pango_layout_set_font_description(layout, desc);
    pango_layout_set_text(layout, "H", 1);
    PangoLayoutLine *line = (PangoLayoutLine *)pango_layout_get_lines(layout)->data;

    PangoRectangle rect;
    pango_layout_line_get_extents(line, NULL, &rect);

    g_object_unref (layout);

    return (int) PANGO_PIXELS(rect.height);
}

int wxWindowGTK::GetCharWidth() const
{
    wxCHECK_MSG( (m_widget != NULL), 8, wxT("invalid window") );

    wxFont font = GetFont();
    wxCHECK_MSG( font.Ok(), 8, wxT("invalid font") );

    PangoContext* context = gtk_widget_get_pango_context(m_widget);

    if (!context)
        return 0;

    PangoFontDescription *desc = font.GetNativeFontInfo()->description;
    PangoLayout *layout = pango_layout_new(context);
    pango_layout_set_font_description(layout, desc);
    pango_layout_set_text(layout, "g", 1);
    PangoLayoutLine *line = (PangoLayoutLine *)pango_layout_get_lines(layout)->data;

    PangoRectangle rect;
    pango_layout_line_get_extents(line, NULL, &rect);

    g_object_unref (layout);

    return (int) PANGO_PIXELS(rect.width);
}

void wxWindowGTK::DoGetTextExtent( const wxString& string,
                                   int *x,
                                   int *y,
                                   int *descent,
                                   int *externalLeading,
                                   const wxFont *theFont ) const
{
    wxFont fontToUse = theFont ? *theFont : GetFont();

    wxCHECK_RET( fontToUse.Ok(), wxT("invalid font") );

    if (string.empty())
    {
        if (x) (*x) = 0;
        if (y) (*y) = 0;
        return;
    }

    PangoContext *context = NULL;
    if (m_widget)
        context = gtk_widget_get_pango_context( m_widget );

    if (!context)
    {
        if (x) (*x) = 0;
        if (y) (*y) = 0;
        return;
    }

    PangoFontDescription *desc = fontToUse.GetNativeFontInfo()->description;
    PangoLayout *layout = pango_layout_new(context);
    pango_layout_set_font_description(layout, desc);
    {
        const wxCharBuffer data = wxGTK_CONV( string );
        if ( data )
            pango_layout_set_text(layout, data, strlen(data));
    }

    PangoRectangle rect;
    pango_layout_get_extents(layout, NULL, &rect);

    if (x) (*x) = (wxCoord) PANGO_PIXELS(rect.width);
    if (y) (*y) = (wxCoord) PANGO_PIXELS(rect.height);
    if (descent)
    {
        PangoLayoutIter *iter = pango_layout_get_iter(layout);
        int baseline = pango_layout_iter_get_baseline(iter);
        pango_layout_iter_free(iter);
        *descent = *y - PANGO_PIXELS(baseline);
    }
    if (externalLeading) (*externalLeading) = 0;  // ??

    g_object_unref (layout);
}

void wxWindowGTK::GTKDisableFocusOutEvent()
{
    g_signal_handlers_block_by_func( m_focusWidget,
                                (gpointer) gtk_window_focus_out_callback, this);
}

void wxWindowGTK::GTKEnableFocusOutEvent()
{
    g_signal_handlers_unblock_by_func( m_focusWidget,
                                (gpointer) gtk_window_focus_out_callback, this);
}

bool wxWindowGTK::GTKHandleFocusIn()
{
    // Disable default focus handling for custom windows since the default GTK+
    // handler issues a repaint
    const bool retval = m_wxwindow ? true : false;


    // NB: if there's still unprocessed deferred focus-out event (see
    //     GTKHandleFocusOut() for explanation), we need to process it first so
    //     that the order of focus events -- focus-out first, then focus-in
    //     elsewhere -- is preserved
    if ( gs_deferredFocusOut )
    {
        if ( GTKNeedsToFilterSameWindowFocus() &&
             gs_deferredFocusOut == this )
        {
            // GTK+ focus changed from this wxWindow back to itself, so don't
            // emit any events at all
            wxLogTrace(TRACE_FOCUS,
                       "filtered out spurious focus change within %s(%p, %s)",
                       GetClassInfo()->GetClassName(), this, GetLabel());
            gs_deferredFocusOut = NULL;
            return retval;
        }

        // otherwise we need to send focus-out first
        wxASSERT_MSG ( gs_deferredFocusOut != this,
                       "GTKHandleFocusIn(GTKFocus_Normal) called even though focus changed back to itself - derived class should handle this" );
        GTKHandleDeferredFocusOut();
    }


    wxLogTrace(TRACE_FOCUS,
               "handling focus_in event for %s(%p, %s)",
               GetClassInfo()->GetClassName(), this, GetLabel());

    if (m_imData)
        gtk_im_context_focus_in(m_imData->context);

    gs_currentFocus = this;
    gs_pendingFocus = NULL;

#if wxUSE_CARET
    // caret needs to be informed about focus change
    wxCaret *caret = GetCaret();
    if ( caret )
    {
        caret->OnSetFocus();
    }
#endif // wxUSE_CARET

    // Notify the parent keeping track of focus for the kbd navigation
    // purposes that we got it.
    wxChildFocusEvent eventChildFocus(static_cast<wxWindow*>(this));
    GTKProcessEvent(eventChildFocus);

    wxFocusEvent eventFocus(wxEVT_SET_FOCUS, GetId());
    eventFocus.SetEventObject(this);
    GTKProcessEvent(eventFocus);

    return retval;
}

bool wxWindowGTK::GTKHandleFocusOut()
{
    // Disable default focus handling for custom windows since the default GTK+
    // handler issues a repaint
    const bool retval = m_wxwindow ? true : false;


    // NB: If a control is composed of several GtkWidgets and when focus
    //     changes from one of them to another within the same wxWindow, we get
    //     a focus-out event followed by focus-in for another GtkWidget owned
    //     by the same wx control. We don't want to generate two spurious
    //     wxEVT_SET_FOCUS events in this case, so we defer sending wx events
    //     from GTKHandleFocusOut() until we know for sure it's not coming back
    //     (i.e. in GTKHandleFocusIn() or at idle time).
    if ( GTKNeedsToFilterSameWindowFocus() )
    {
        wxASSERT_MSG( gs_deferredFocusOut == NULL,
                      "deferred focus out event already pending" );
        wxLogTrace(TRACE_FOCUS,
                   "deferring focus_out event for %s(%p, %s)",
                   GetClassInfo()->GetClassName(), this, GetLabel());
        gs_deferredFocusOut = this;
        return retval;
    }

    GTKHandleFocusOutNoDeferring();

    return retval;
}

void wxWindowGTK::GTKHandleFocusOutNoDeferring()
{
    wxLogTrace(TRACE_FOCUS,
               "handling focus_out event for %s(%p, %s)",
               GetClassInfo()->GetClassName(), this, GetLabel());

    if (m_imData)
        gtk_im_context_focus_out(m_imData->context);

    if ( gs_currentFocus != this )
    {
        // Something is terribly wrong, gs_currentFocus is out of sync with the
        // real focus. We will reset it to NULL anyway, because after this
        // focus-out event is handled, one of the following with happen:
        //
        // * either focus will go out of the app altogether, in which case
        //   gs_currentFocus _should_ be NULL
        //
        // * or it goes to another control, in which case focus-in event will
        //   follow immediately and it will set gs_currentFocus to the right
        //   value
        wxLogDebug("window %s(%p, %s) lost focus even though it didn't have it",
                   GetClassInfo()->GetClassName(), this, GetLabel());
    }
    gs_currentFocus = NULL;

#if wxUSE_CARET
    // caret needs to be informed about focus change
    wxCaret *caret = GetCaret();
    if ( caret )
    {
        caret->OnKillFocus();
    }
#endif // wxUSE_CARET

    wxFocusEvent event( wxEVT_KILL_FOCUS, GetId() );
    event.SetEventObject( this );
    GTKProcessEvent( event );
}

/*static*/
void wxWindowGTK::GTKHandleDeferredFocusOut()
{
    // NB: See GTKHandleFocusOut() for explanation. This function is called
    //     from either GTKHandleFocusIn() or OnInternalIdle() to process
    //     deferred event.
    if ( gs_deferredFocusOut )
    {
        wxWindowGTK *win = gs_deferredFocusOut;
        gs_deferredFocusOut = NULL;

        wxLogTrace(TRACE_FOCUS,
                   "processing deferred focus_out event for %s(%p, %s)",
                   win->GetClassInfo()->GetClassName(), win, win->GetLabel());

        win->GTKHandleFocusOutNoDeferring();
    }
}

void wxWindowGTK::SetFocus()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid window") );

    // Setting "physical" focus is not immediate in GTK+ and while
    // gtk_widget_is_focus ("determines if the widget is the focus widget
    // within its toplevel", i.e. returns true for one widget per TLW, not
    // globally) returns true immediately after grabbing focus,
    // GTK_WIDGET_HAS_FOCUS (which returns true only for the one widget that
    // has focus at the moment) takes affect only after the window is shown
    // (if it was hidden at the moment of the call) or at the next event loop
    // iteration.
    //
    // Because we want to FindFocus() call immediately following
    // foo->SetFocus() to return foo, we have to keep track of "pending" focus
    // ourselves.
    gs_pendingFocus = this;

    GtkWidget *widget = m_wxwindow ? m_wxwindow : m_focusWidget;

    if ( GTK_IS_CONTAINER(widget) &&
         !GTK_WIDGET_CAN_FOCUS(widget) )
    {
        wxLogTrace(TRACE_FOCUS,
                   wxT("Setting focus to a child of %s(%p, %s)"),
                   GetClassInfo()->GetClassName(), this, GetLabel().c_str());
        gtk_widget_child_focus(widget, GTK_DIR_TAB_FORWARD);
    }
    else
    {
        wxLogTrace(TRACE_FOCUS,
                   wxT("Setting focus to %s(%p, %s)"),
                   GetClassInfo()->GetClassName(), this, GetLabel().c_str());
        gtk_widget_grab_focus(widget);
    }
}

void wxWindowGTK::SetCanFocus(bool canFocus)
{
    if ( canFocus )
        GTK_WIDGET_SET_FLAGS(m_widget, GTK_CAN_FOCUS);
    else
        GTK_WIDGET_UNSET_FLAGS(m_widget, GTK_CAN_FOCUS);

    if ( m_wxwindow && (m_widget != m_wxwindow) )
    {
        if ( canFocus )
            GTK_WIDGET_SET_FLAGS(m_wxwindow, GTK_CAN_FOCUS);
        else
            GTK_WIDGET_UNSET_FLAGS(m_wxwindow, GTK_CAN_FOCUS);
    }
}

bool wxWindowGTK::Reparent( wxWindowBase *newParentBase )
{
    wxCHECK_MSG( (m_widget != NULL), false, wxT("invalid window") );

    wxWindowGTK *oldParent = m_parent,
             *newParent = (wxWindowGTK *)newParentBase;

    wxASSERT( GTK_IS_WIDGET(m_widget) );

    if ( !wxWindowBase::Reparent(newParent) )
        return false;

    wxASSERT( GTK_IS_WIDGET(m_widget) );

    if (oldParent)
        gtk_container_remove( GTK_CONTAINER(m_widget->parent), m_widget );

    wxASSERT( GTK_IS_WIDGET(m_widget) );

    if (newParent)
    {
        if (GTK_WIDGET_VISIBLE (newParent->m_widget))
        {
            m_showOnIdle = true;
            gtk_widget_hide( m_widget );
        }
        /* insert GTK representation */
        newParent->AddChildGTK(this);
    }

    SetLayoutDirection(wxLayout_Default);

    return true;
}

void wxWindowGTK::DoAddChild(wxWindowGTK *child)
{
    wxASSERT_MSG( (m_widget != NULL), wxT("invalid window") );
    wxASSERT_MSG( (child != NULL), wxT("invalid child window") );

    /* add to list */
    AddChild( child );

    /* insert GTK representation */
    AddChildGTK(child);
}

void wxWindowGTK::AddChild(wxWindowBase *child)
{
    wxWindowBase::AddChild(child);
    m_dirtyTabOrder = true;
    wxTheApp->WakeUpIdle();
}

void wxWindowGTK::RemoveChild(wxWindowBase *child)
{
    wxWindowBase::RemoveChild(child);
    m_dirtyTabOrder = true;
    wxTheApp->WakeUpIdle();
}

/* static */
wxLayoutDirection wxWindowGTK::GTKGetLayout(GtkWidget *widget)
{
    return gtk_widget_get_direction(widget) == GTK_TEXT_DIR_RTL
                ? wxLayout_RightToLeft
                : wxLayout_LeftToRight;
}

/* static */
void wxWindowGTK::GTKSetLayout(GtkWidget *widget, wxLayoutDirection dir)
{
    wxASSERT_MSG( dir != wxLayout_Default, wxT("invalid layout direction") );

    gtk_widget_set_direction(widget,
                             dir == wxLayout_RightToLeft ? GTK_TEXT_DIR_RTL
                                                         : GTK_TEXT_DIR_LTR);
}

wxLayoutDirection wxWindowGTK::GetLayoutDirection() const
{
    return GTKGetLayout(m_widget);
}

void wxWindowGTK::SetLayoutDirection(wxLayoutDirection dir)
{
    if ( dir == wxLayout_Default )
    {
        const wxWindow *const parent = GetParent();
        if ( parent )
        {
            // inherit layout from parent.
            dir = parent->GetLayoutDirection();
        }
        else // no parent, use global default layout
        {
            dir = wxTheApp->GetLayoutDirection();
        }
    }

    if ( dir == wxLayout_Default )
        return;

    GTKSetLayout(m_widget, dir);

    if (m_wxwindow && (m_wxwindow != m_widget))
        GTKSetLayout(m_wxwindow, dir);
}

wxCoord
wxWindowGTK::AdjustForLayoutDirection(wxCoord x,
                                      wxCoord WXUNUSED(width),
                                      wxCoord WXUNUSED(widthTotal)) const
{
    // We now mirror the coordinates of RTL windows in wxPizza
    return x;
}

void wxWindowGTK::DoMoveInTabOrder(wxWindow *win, WindowOrder move)
{
    wxWindowBase::DoMoveInTabOrder(win, move);
    m_dirtyTabOrder = true;
    wxTheApp->WakeUpIdle();
}

bool wxWindowGTK::DoNavigateIn(int flags)
{
    if ( flags & wxNavigationKeyEvent::WinChange )
    {
        wxFAIL_MSG( wxT("not implemented") );

        return false;
    }
    else // navigate inside the container
    {
        wxWindow *parent = wxGetTopLevelParent((wxWindow *)this);
        wxCHECK_MSG( parent, false, wxT("every window must have a TLW parent") );

        GtkDirectionType dir;
        dir = flags & wxNavigationKeyEvent::IsForward ? GTK_DIR_TAB_FORWARD
                                                      : GTK_DIR_TAB_BACKWARD;

        gboolean rc;
        g_signal_emit_by_name(parent->m_widget, "focus", dir, &rc);

        return rc == TRUE;
    }
}

bool wxWindowGTK::GTKWidgetNeedsMnemonic() const
{
    // none needed by default
    return false;
}

void wxWindowGTK::GTKWidgetDoSetMnemonic(GtkWidget* WXUNUSED(w))
{
    // nothing to do by default since none is needed
}

void wxWindowGTK::RealizeTabOrder()
{
    if (m_wxwindow)
    {
        if ( !m_children.empty() )
        {
            // we don't only construct the correct focus chain but also use
            // this opportunity to update the mnemonic widgets for the widgets
            // that need them

            GList *chain = NULL;
            wxWindowGTK* mnemonicWindow = NULL;

            for ( wxWindowList::const_iterator i = m_children.begin();
                  i != m_children.end();
                  ++i )
            {
                wxWindowGTK *win = *i;

                if ( mnemonicWindow )
                {
                    if ( win->AcceptsFocusFromKeyboard() )
                    {
                        // wxComboBox et al. needs to focus on on a different
                        // widget than m_widget, so if the main widget isn't
                        // focusable try the connect widget
                        GtkWidget* w = win->m_widget;
                        if ( !GTK_WIDGET_CAN_FOCUS(w) )
                        {
                            w = win->GetConnectWidget();
                            if ( !GTK_WIDGET_CAN_FOCUS(w) )
                                w = NULL;
                        }

                        if ( w )
                        {
                            mnemonicWindow->GTKWidgetDoSetMnemonic(w);
                            mnemonicWindow = NULL;
                        }
                    }
                }
                else if ( win->GTKWidgetNeedsMnemonic() )
                {
                    mnemonicWindow = win;
                }

                chain = g_list_prepend(chain, win->m_widget);
            }

            chain = g_list_reverse(chain);

            gtk_container_set_focus_chain(GTK_CONTAINER(m_wxwindow), chain);
            g_list_free(chain);
        }
        else // no children
        {
            gtk_container_unset_focus_chain(GTK_CONTAINER(m_wxwindow));
        }
    }
}

void wxWindowGTK::Raise()
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    if (m_wxwindow && m_wxwindow->window)
    {
        gdk_window_raise( m_wxwindow->window );
    }
    else if (m_widget->window)
    {
        gdk_window_raise( m_widget->window );
    }
}

void wxWindowGTK::Lower()
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    if (m_wxwindow && m_wxwindow->window)
    {
        gdk_window_lower( m_wxwindow->window );
    }
    else if (m_widget->window)
    {
        gdk_window_lower( m_widget->window );
    }
}

bool wxWindowGTK::SetCursor( const wxCursor &cursor )
{
    if ( !wxWindowBase::SetCursor(cursor.Ok() ? cursor : *wxSTANDARD_CURSOR) )
        return false;

    GTKUpdateCursor();

    return true;
}

void wxWindowGTK::GTKUpdateCursor(bool update_self /*=true*/, bool recurse /*=true*/)
{
    if (update_self)
    {
        wxCursor cursor(g_globalCursor.Ok() ? g_globalCursor : GetCursor());
        if ( cursor.Ok() )
        {
            wxArrayGdkWindows windowsThis;
            GdkWindow* window = GTKGetWindow(windowsThis);
            if (window)
                gdk_window_set_cursor( window, cursor.GetCursor() );
            else
            {
                const size_t count = windowsThis.size();
                for ( size_t n = 0; n < count; n++ )
                {
                    GdkWindow *win = windowsThis[n];
                    // It can be zero if the window has not been realized yet.
                    if ( win )
                    {
                        gdk_window_set_cursor(win, cursor.GetCursor());
                    }
                }
            }
        }
    }

    if (recurse)
    {
        for (wxWindowList::iterator it = GetChildren().begin(); it != GetChildren().end(); ++it)
        {
            (*it)->GTKUpdateCursor( true );
        }
    }
}

void wxWindowGTK::WarpPointer( int x, int y )
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    // We provide this function ourselves as it is
    // missing in GDK (top of this file).

    GdkWindow *window = NULL;
    if (m_wxwindow)
        window = m_wxwindow->window;
    else
        window = GetConnectWidget()->window;

    if (window)
        gdk_window_warp_pointer( window, x, y );
}

wxWindowGTK::ScrollDir wxWindowGTK::ScrollDirFromRange(GtkRange *range) const
{
    // find the scrollbar which generated the event
    for ( int dir = 0; dir < ScrollDir_Max; dir++ )
    {
        if ( range == m_scrollBar[dir] )
            return (ScrollDir)dir;
    }

    wxFAIL_MSG( wxT("event from unknown scrollbar received") );

    return ScrollDir_Max;
}

bool wxWindowGTK::DoScrollByUnits(ScrollDir dir, ScrollUnit unit, int units)
{
    bool changed = false;
    GtkRange* range = m_scrollBar[dir];
    if ( range && units )
    {
        GtkAdjustment* adj = range->adjustment;
        gdouble inc = unit == ScrollUnit_Line ? adj->step_increment
                                              : adj->page_increment;

        const int posOld = int(adj->value + 0.5);
        gtk_range_set_value(range, posOld + units*inc);

        changed = int(adj->value + 0.5) != posOld;
    }

    return changed;
}

bool wxWindowGTK::ScrollLines(int lines)
{
    return DoScrollByUnits(ScrollDir_Vert, ScrollUnit_Line, lines);
}

bool wxWindowGTK::ScrollPages(int pages)
{
    return DoScrollByUnits(ScrollDir_Vert, ScrollUnit_Page, pages);
}

void wxWindowGTK::Refresh(bool WXUNUSED(eraseBackground),
                          const wxRect *rect)
{
    if ( !m_widget )
    {
        // it is valid to call Refresh() for a window which hasn't been created
        // yet, it simply doesn't do anything in this case
        return;
    }

    if (!m_wxwindow)
    {
        if (rect)
            gtk_widget_queue_draw_area( m_widget, rect->x, rect->y, rect->width, rect->height );
        else
            gtk_widget_queue_draw( m_widget );
    }
    else
    {
        // Just return if the widget or one of its ancestors isn't mapped
        GtkWidget *w;
        for (w = m_wxwindow; w != NULL; w = w->parent)
            if (!GTK_WIDGET_MAPPED (w))
                return;

        GdkWindow* window = GTKGetDrawingWindow();
        if (rect)
        {
            int x = rect->x;
            if (GetLayoutDirection() == wxLayout_RightToLeft)
                x = GetClientSize().x - x - rect->width;
            GdkRectangle r;
            r.x = rect->x;
            r.y = rect->y;
            r.width = rect->width;
            r.height = rect->height;
            gdk_window_invalidate_rect(window, &r, true);
        }
        else
            gdk_window_invalidate_rect(window, NULL, true);
    }
}

void wxWindowGTK::Update()
{
    if (m_widget && GTK_WIDGET_MAPPED(m_widget))
    {
        GdkDisplay* display = gtk_widget_get_display(m_widget);
        // Flush everything out to the server, and wait for it to finish.
        // This ensures nothing will overwrite the drawing we are about to do.
        gdk_display_sync(display);

        GdkWindow* window = GTKGetDrawingWindow();
        if (window == NULL)
            window = m_widget->window;
        gdk_window_process_updates(window, true);

        // Flush again, but no need to wait for it to finish
        gdk_display_flush(display);
    }
}

bool wxWindowGTK::DoIsExposed( int x, int y ) const
{
    return m_updateRegion.Contains(x, y) != wxOutRegion;
}

bool wxWindowGTK::DoIsExposed( int x, int y, int w, int h ) const
{
    if (GetLayoutDirection() == wxLayout_RightToLeft)
        return m_updateRegion.Contains(x-w, y, w, h) != wxOutRegion;
    else
        return m_updateRegion.Contains(x, y, w, h) != wxOutRegion;
}

void wxWindowGTK::GtkSendPaintEvents()
{
    if (!m_wxwindow)
    {
        m_updateRegion.Clear();
        return;
    }

    // Clip to paint region in wxClientDC
    m_clipPaintRegion = true;

    m_nativeUpdateRegion = m_updateRegion;

    if (GetLayoutDirection() == wxLayout_RightToLeft)
    {
        // Transform m_updateRegion under RTL
        m_updateRegion.Clear();

        gint width;
        gdk_drawable_get_size(m_wxwindow->window, &width, NULL);

        wxRegionIterator upd( m_nativeUpdateRegion );
        while (upd)
        {
            wxRect rect;
            rect.x = upd.GetX();
            rect.y = upd.GetY();
            rect.width = upd.GetWidth();
            rect.height = upd.GetHeight();

            rect.x = width - rect.x - rect.width;
            m_updateRegion.Union( rect );

            ++upd;
        }
    }

    switch ( GetBackgroundStyle() )
    {
        case wxBG_STYLE_ERASE:
            {
                wxWindowDC dc( (wxWindow*)this );
                dc.SetDeviceClippingRegion( m_updateRegion );

                // Work around gtk-qt <= 0.60 bug whereby the window colour
                // remains grey
                if ( UseBgCol() &&
                        wxSystemOptions::
                            GetOptionInt("gtk.window.force-background-colour") )
                {
                    dc.SetBackground(GetBackgroundColour());
                    dc.Clear();
                }

                wxEraseEvent erase_event( GetId(), &dc );
                erase_event.SetEventObject( this );

                if ( HandleWindowEvent(erase_event) )
                {
                    // background erased, don't do it again
                    break;
                }
            }
            // fall through

        case wxBG_STYLE_SYSTEM:
            if ( GetThemeEnabled() )
            {
                // find ancestor from which to steal background
                wxWindow *parent = wxGetTopLevelParent((wxWindow *)this);
                if (!parent)
                    parent = (wxWindow*)this;

                if (GTK_WIDGET_MAPPED(parent->m_widget))
                {
                    wxRegionIterator upd( m_nativeUpdateRegion );
                    while (upd)
                    {
                        GdkRectangle rect;
                        rect.x = upd.GetX();
                        rect.y = upd.GetY();
                        rect.width = upd.GetWidth();
                        rect.height = upd.GetHeight();

                        gtk_paint_flat_box( parent->m_widget->style,
                                    GTKGetDrawingWindow(),
                                    (GtkStateType)GTK_WIDGET_STATE(m_wxwindow),
                                    GTK_SHADOW_NONE,
                                    &rect,
                                    parent->m_widget,
                                    (char *)"base",
                                    0, 0, -1, -1 );

                        ++upd;
                    }
                }
            }
            break;

        case wxBG_STYLE_PAINT:
            // nothing to do: window will be painted over in EVT_PAINT
            break;

        default:
            wxFAIL_MSG( "unsupported background style" );
    }

    wxNcPaintEvent nc_paint_event( GetId() );
    nc_paint_event.SetEventObject( this );
    HandleWindowEvent( nc_paint_event );

    wxPaintEvent paint_event( GetId() );
    paint_event.SetEventObject( this );
    HandleWindowEvent( paint_event );

    m_clipPaintRegion = false;

    m_updateRegion.Clear();
    m_nativeUpdateRegion.Clear();
}

void wxWindowGTK::SetDoubleBuffered( bool on )
{
    wxCHECK_RET( (m_widget != NULL), wxT("invalid window") );

    if ( m_wxwindow )
        gtk_widget_set_double_buffered( m_wxwindow, on );
}

bool wxWindowGTK::IsDoubleBuffered() const
{
    return GTK_WIDGET_DOUBLE_BUFFERED( m_wxwindow );
}

void wxWindowGTK::ClearBackground()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid window") );
}

#if wxUSE_TOOLTIPS
void wxWindowGTK::DoSetToolTip( wxToolTip *tip )
{
    wxWindowBase::DoSetToolTip(tip);

    if (m_tooltip)
    {
        m_tooltip->GTKApply( (wxWindow *)this );
    }
    else
    {
        GtkWidget *w = GetConnectWidget();
        wxToolTip::GTKApply(w, NULL);
#if GTK_CHECK_VERSION(2, 12, 0)
        // Just applying NULL doesn't work on 2.12.0, so also use
        // gtk_widget_set_has_tooltip. It is part of the new GtkTooltip API
        // but seems also to work with the old GtkTooltips.
        if (gtk_check_version(2, 12, 0) == NULL)
            gtk_widget_set_has_tooltip(w, FALSE);
#endif
    }
}

void wxWindowGTK::GTKApplyToolTip( GtkTooltips *tips, const gchar *tip )
{
    gtk_tooltips_set_tip(tips, GetConnectWidget(), tip, NULL);
}
#endif // wxUSE_TOOLTIPS

bool wxWindowGTK::SetBackgroundColour( const wxColour &colour )
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid window") );

    if (!wxWindowBase::SetBackgroundColour(colour))
        return false;

    if (colour.Ok())
    {
        // We need the pixel value e.g. for background clearing.
        m_backgroundColour.CalcPixel(gtk_widget_get_colormap(m_widget));
    }

    // apply style change (forceStyle=true so that new style is applied
    // even if the bg colour changed from valid to wxNullColour)
    GTKApplyWidgetStyle(true);

    return true;
}

bool wxWindowGTK::SetForegroundColour( const wxColour &colour )
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid window") );

    if (!wxWindowBase::SetForegroundColour(colour))
    {
        return false;
    }

    if (colour.Ok())
    {
        // We need the pixel value e.g. for background clearing.
        m_foregroundColour.CalcPixel(gtk_widget_get_colormap(m_widget));
    }

    // apply style change (forceStyle=true so that new style is applied
    // even if the bg colour changed from valid to wxNullColour):
    GTKApplyWidgetStyle(true);

    return true;
}

PangoContext *wxWindowGTK::GTKGetPangoDefaultContext()
{
    return gtk_widget_get_pango_context( m_widget );
}

GtkRcStyle *wxWindowGTK::GTKCreateWidgetStyle(bool forceStyle)
{
    // do we need to apply any changes at all?
    if ( !forceStyle &&
         !m_font.Ok() &&
         !m_foregroundColour.Ok() && !m_backgroundColour.Ok() )
    {
        return NULL;
    }

    GtkRcStyle *style = gtk_rc_style_new();

    if ( m_font.Ok() )
    {
        style->font_desc =
            pango_font_description_copy( m_font.GetNativeFontInfo()->description );
    }

    int flagsNormal = 0,
        flagsPrelight = 0,
        flagsActive = 0,
        flagsInsensitive = 0;

    if ( m_foregroundColour.Ok() )
    {
        const GdkColor *fg = m_foregroundColour.GetColor();

        style->fg[GTK_STATE_NORMAL] =
        style->text[GTK_STATE_NORMAL] = *fg;
        flagsNormal |= GTK_RC_FG | GTK_RC_TEXT;

        style->fg[GTK_STATE_PRELIGHT] =
        style->text[GTK_STATE_PRELIGHT] = *fg;
        flagsPrelight |= GTK_RC_FG | GTK_RC_TEXT;

        style->fg[GTK_STATE_ACTIVE] =
        style->text[GTK_STATE_ACTIVE] = *fg;
        flagsActive |= GTK_RC_FG | GTK_RC_TEXT;
    }

    if ( m_backgroundColour.Ok() )
    {
        const GdkColor *bg = m_backgroundColour.GetColor();

        style->bg[GTK_STATE_NORMAL] =
        style->base[GTK_STATE_NORMAL] = *bg;
        flagsNormal |= GTK_RC_BG | GTK_RC_BASE;

        style->bg[GTK_STATE_PRELIGHT] =
        style->base[GTK_STATE_PRELIGHT] = *bg;
        flagsPrelight |= GTK_RC_BG | GTK_RC_BASE;

        style->bg[GTK_STATE_ACTIVE] =
        style->base[GTK_STATE_ACTIVE] = *bg;
        flagsActive |= GTK_RC_BG | GTK_RC_BASE;

        style->bg[GTK_STATE_INSENSITIVE] =
        style->base[GTK_STATE_INSENSITIVE] = *bg;
        flagsInsensitive |= GTK_RC_BG | GTK_RC_BASE;
    }

    style->color_flags[GTK_STATE_NORMAL] = (GtkRcFlags)flagsNormal;
    style->color_flags[GTK_STATE_PRELIGHT] = (GtkRcFlags)flagsPrelight;
    style->color_flags[GTK_STATE_ACTIVE] = (GtkRcFlags)flagsActive;
    style->color_flags[GTK_STATE_INSENSITIVE] = (GtkRcFlags)flagsInsensitive;

    return style;
}

void wxWindowGTK::GTKApplyWidgetStyle(bool forceStyle)
{
    GtkRcStyle *style = GTKCreateWidgetStyle(forceStyle);
    if ( style )
    {
        DoApplyWidgetStyle(style);
        gtk_rc_style_unref(style);
    }

    // Style change may affect GTK+'s size calculation:
    InvalidateBestSize();
}

void wxWindowGTK::DoApplyWidgetStyle(GtkRcStyle *style)
{
    if ( m_wxwindow )
    {
        // block the signal temporarily to avoid sending
        // wxSysColourChangedEvents when we change the colours ourselves
        bool unblock = false;
        if ( IsTopLevel() )
        {
            unblock = true;
            g_signal_handlers_block_by_func(
                m_wxwindow, (void *)gtk_window_style_set_callback, this);
        }

        gtk_widget_modify_style(m_wxwindow, style);

        if ( unblock )
        {
            g_signal_handlers_unblock_by_func(
                m_wxwindow, (void *)gtk_window_style_set_callback, this);
        }
    }
    else
    {
        gtk_widget_modify_style(m_widget, style);
    }
}

bool wxWindowGTK::SetBackgroundStyle(wxBackgroundStyle style)
{
    wxWindowBase::SetBackgroundStyle(style);

    if ( style == wxBG_STYLE_PAINT )
    {
        GdkWindow *window;
        if ( m_wxwindow )
        {
            window = GTKGetDrawingWindow();
        }
        else
        {
            GtkWidget * const w = GetConnectWidget();
            window = w ? w->window : NULL;
        }

        if (window)
        {
            // Make sure GDK/X11 doesn't refresh the window
            // automatically.
            gdk_window_set_back_pixmap( window, None, False );
#ifdef __X__
            Display* display = GDK_WINDOW_DISPLAY(window);
            XFlush(display);
#endif
            m_needsStyleChange = false;
        }
        else // window not realized yet
        {
            // Do in OnIdle, because the window is not yet available
            m_needsStyleChange = true;
        }

        // Don't apply widget style, or we get a grey background
    }
    else
    {
        // apply style change (forceStyle=true so that new style is applied
        // even if the bg colour changed from valid to wxNullColour):
        GTKApplyWidgetStyle(true);
    }

    return true;
}

// ----------------------------------------------------------------------------
// Pop-up menu stuff
// ----------------------------------------------------------------------------

#if wxUSE_MENUS_NATIVE

extern "C" {
static
void wxPopupMenuPositionCallback( GtkMenu *menu,
                                  gint *x, gint *y,
                                  gboolean * WXUNUSED(whatever),
                                  gpointer user_data )
{
    // ensure that the menu appears entirely on screen
    GtkRequisition req;
    gtk_widget_get_child_requisition(GTK_WIDGET(menu), &req);

    wxSize sizeScreen = wxGetDisplaySize();
    wxPoint *pos = (wxPoint*)user_data;

    gint xmax = sizeScreen.x - req.width,
         ymax = sizeScreen.y - req.height;

    *x = pos->x < xmax ? pos->x : xmax;
    *y = pos->y < ymax ? pos->y : ymax;
}
}

bool wxWindowGTK::DoPopupMenu( wxMenu *menu, int x, int y )
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid window") );

    menu->UpdateUI();

    wxPoint pos;
    gpointer userdata;
    GtkMenuPositionFunc posfunc;
    if ( x == -1 && y == -1 )
    {
        // use GTK's default positioning algorithm
        userdata = NULL;
        posfunc = NULL;
    }
    else
    {
        pos = ClientToScreen(wxPoint(x, y));
        userdata = &pos;
        posfunc = wxPopupMenuPositionCallback;
    }

    menu->m_popupShown = true;
    gtk_menu_popup(
                  GTK_MENU(menu->m_menu),
                  NULL,           // parent menu shell
                  NULL,           // parent menu item
                  posfunc,                      // function to position it
                  userdata,                     // client data
                  0,                            // button used to activate it
                  gtk_get_current_event_time()
                );

    while (menu->m_popupShown)
    {
        gtk_main_iteration();
    }

    return true;
}

#endif // wxUSE_MENUS_NATIVE

#if wxUSE_DRAG_AND_DROP

void wxWindowGTK::SetDropTarget( wxDropTarget *dropTarget )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid window") );

    GtkWidget *dnd_widget = GetConnectWidget();

    if (m_dropTarget) m_dropTarget->GtkUnregisterWidget( dnd_widget );

    if (m_dropTarget) delete m_dropTarget;
    m_dropTarget = dropTarget;

    if (m_dropTarget) m_dropTarget->GtkRegisterWidget( dnd_widget );
}

#endif // wxUSE_DRAG_AND_DROP

GtkWidget* wxWindowGTK::GetConnectWidget()
{
    GtkWidget *connect_widget = m_widget;
    if (m_wxwindow) connect_widget = m_wxwindow;

    return connect_widget;
}

bool wxWindowGTK::GTKIsOwnWindow(GdkWindow *window) const
{
    wxArrayGdkWindows windowsThis;
    GdkWindow * const winThis = GTKGetWindow(windowsThis);

    return winThis ? window == winThis
                   : windowsThis.Index(window) != wxNOT_FOUND;
}

GdkWindow *wxWindowGTK::GTKGetWindow(wxArrayGdkWindows& WXUNUSED(windows)) const
{
    return m_wxwindow ? GTKGetDrawingWindow() : m_widget->window;
}

bool wxWindowGTK::SetFont( const wxFont &font )
{
    wxCHECK_MSG( m_widget != NULL, false, wxT("invalid window") );

    if (!wxWindowBase::SetFont(font))
        return false;

    // apply style change (forceStyle=true so that new style is applied
    // even if the font changed from valid to wxNullFont):
    GTKApplyWidgetStyle(true);

    return true;
}

void wxWindowGTK::DoCaptureMouse()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid window") );

    GdkWindow *window = NULL;
    if (m_wxwindow)
        window = GTKGetDrawingWindow();
    else
        window = GetConnectWidget()->window;

    wxCHECK_RET( window, wxT("CaptureMouse() failed") );

    const wxCursor* cursor = &m_cursor;
    if (!cursor->Ok())
        cursor = wxSTANDARD_CURSOR;

    gdk_pointer_grab( window, FALSE,
                      (GdkEventMask)
                         (GDK_BUTTON_PRESS_MASK |
                          GDK_BUTTON_RELEASE_MASK |
                          GDK_POINTER_MOTION_HINT_MASK |
                          GDK_POINTER_MOTION_MASK),
                      NULL,
                      cursor->GetCursor(),
                      (guint32)GDK_CURRENT_TIME );
    g_captureWindow = this;
    g_captureWindowHasMouse = true;
}

void wxWindowGTK::DoReleaseMouse()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid window") );

    wxCHECK_RET( g_captureWindow, wxT("can't release mouse - not captured") );

    g_captureWindow = NULL;

    GdkWindow *window = NULL;
    if (m_wxwindow)
        window = GTKGetDrawingWindow();
    else
        window = GetConnectWidget()->window;

    if (!window)
        return;

    gdk_pointer_ungrab ( (guint32)GDK_CURRENT_TIME );
}

void wxWindowGTK::GTKReleaseMouseAndNotify()
{
    DoReleaseMouse();
    wxMouseCaptureLostEvent evt(GetId());
    evt.SetEventObject( this );
    HandleWindowEvent( evt );
}

/* static */
wxWindow *wxWindowBase::GetCapture()
{
    return (wxWindow *)g_captureWindow;
}

bool wxWindowGTK::IsRetained() const
{
    return false;
}

void wxWindowGTK::SetScrollbar(int orient,
                               int pos,
                               int thumbVisible,
                               int range,
                               bool WXUNUSED(update))
{
    const int dir = ScrollDirFromOrient(orient);
    GtkRange* const sb = m_scrollBar[dir];
    wxCHECK_RET( sb, wxT("this window is not scrollable") );

    if (range <= 0)
    {
        // GtkRange requires upper > lower
        range =
        thumbVisible = 1;
    }

    GtkAdjustment * const adj = sb->adjustment;
    adj->step_increment = 1;
    adj->page_increment =
    adj->page_size = thumbVisible;
    adj->value = pos;

    g_signal_handlers_block_by_func(
        sb, (void*)gtk_scrollbar_value_changed, this);

    gtk_range_set_range(sb, 0, range);
    m_scrollPos[dir] = sb->adjustment->value;

    g_signal_handlers_unblock_by_func(
        sb, (void*)gtk_scrollbar_value_changed, this);
}

void wxWindowGTK::SetScrollPos(int orient, int pos, bool WXUNUSED(refresh))
{
    const int dir = ScrollDirFromOrient(orient);
    GtkRange * const sb = m_scrollBar[dir];
    wxCHECK_RET( sb, wxT("this window is not scrollable") );

    // This check is more than an optimization. Without it, the slider
    //   will not move smoothly while tracking when using wxScrollHelper.
    if (GetScrollPos(orient) != pos)
    {
        g_signal_handlers_block_by_func(
            sb, (void*)gtk_scrollbar_value_changed, this);

        gtk_range_set_value(sb, pos);
        m_scrollPos[dir] = sb->adjustment->value;

        g_signal_handlers_unblock_by_func(
            sb, (void*)gtk_scrollbar_value_changed, this);
    }
}

int wxWindowGTK::GetScrollThumb(int orient) const
{
    GtkRange * const sb = m_scrollBar[ScrollDirFromOrient(orient)];
    wxCHECK_MSG( sb, 0, wxT("this window is not scrollable") );

    return wxRound(sb->adjustment->page_size);
}

int wxWindowGTK::GetScrollPos( int orient ) const
{
    GtkRange * const sb = m_scrollBar[ScrollDirFromOrient(orient)];
    wxCHECK_MSG( sb, 0, wxT("this window is not scrollable") );

    return wxRound(sb->adjustment->value);
}

int wxWindowGTK::GetScrollRange( int orient ) const
{
    GtkRange * const sb = m_scrollBar[ScrollDirFromOrient(orient)];
    wxCHECK_MSG( sb, 0, wxT("this window is not scrollable") );

    return wxRound(sb->adjustment->upper);
}

// Determine if increment is the same as +/-x, allowing for some small
//   difference due to possible inexactness in floating point arithmetic
static inline bool IsScrollIncrement(double increment, double x)
{
    wxASSERT(increment > 0);
    const double tolerance = 1.0 / 1024;
    return fabs(increment - fabs(x)) < tolerance;
}

wxEventType wxWindowGTK::GTKGetScrollEventType(GtkRange* range)
{
    wxASSERT(range == m_scrollBar[0] || range == m_scrollBar[1]);

    const int barIndex = range == m_scrollBar[1];
    GtkAdjustment* adj = range->adjustment;

    const int value = wxRound(adj->value);

    // save previous position
    const double oldPos = m_scrollPos[barIndex];
    // update current position
    m_scrollPos[barIndex] = adj->value;
    // If event should be ignored, or integral position has not changed
    if (!m_hasVMT || g_blockEventsOnDrag || value == wxRound(oldPos))
    {
        return wxEVT_NULL;
    }

    wxEventType eventType = wxEVT_SCROLL_THUMBTRACK;
    if (!m_isScrolling)
    {
        // Difference from last change event
        const double diff = adj->value - oldPos;
        const bool isDown = diff > 0;

        if (IsScrollIncrement(adj->step_increment, diff))
        {
            eventType = isDown ? wxEVT_SCROLL_LINEDOWN : wxEVT_SCROLL_LINEUP;
        }
        else if (IsScrollIncrement(adj->page_increment, diff))
        {
            eventType = isDown ? wxEVT_SCROLL_PAGEDOWN : wxEVT_SCROLL_PAGEUP;
        }
        else if (m_mouseButtonDown)
        {
            // Assume track event
            m_isScrolling = true;
        }
    }
    return eventType;
}

void wxWindowGTK::ScrollWindow( int dx, int dy, const wxRect* WXUNUSED(rect) )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid window") );

    wxCHECK_RET( m_wxwindow != NULL, wxT("window needs client area for scrolling") );

    // No scrolling requested.
    if ((dx == 0) && (dy == 0)) return;

    m_clipPaintRegion = true;

    WX_PIZZA(m_wxwindow)->scroll(dx, dy);

    m_clipPaintRegion = false;

#if wxUSE_CARET
    bool restoreCaret = (GetCaret() != NULL && GetCaret()->IsVisible());
    if (restoreCaret)
    {
        wxRect caretRect(GetCaret()->GetPosition(), GetCaret()->GetSize());
        if (dx > 0)
            caretRect.width += dx;
        else
        {
            caretRect.x += dx; caretRect.width -= dx;
        }
        if (dy > 0)
            caretRect.height += dy;
        else
        {
            caretRect.y += dy; caretRect.height -= dy;
        }

        RefreshRect(caretRect);
    }
#endif // wxUSE_CARET
}

void wxWindowGTK::GTKScrolledWindowSetBorder(GtkWidget* w, int wxstyle)
{
    //RN: Note that static controls usually have no border on gtk, so maybe
    //it makes sense to treat that as simply no border at the wx level
    //as well...
    if (!(wxstyle & wxNO_BORDER) && !(wxstyle & wxBORDER_STATIC))
    {
        GtkShadowType gtkstyle;

        if(wxstyle & wxBORDER_RAISED)
            gtkstyle = GTK_SHADOW_OUT;
        else if ((wxstyle & wxBORDER_SUNKEN) || (wxstyle & wxBORDER_THEME))
            gtkstyle = GTK_SHADOW_IN;
#if 0
        // Now obsolete
        else if (wxstyle & wxBORDER_DOUBLE)
            gtkstyle = GTK_SHADOW_ETCHED_IN;
#endif
        else //default
            gtkstyle = GTK_SHADOW_IN;

        gtk_scrolled_window_set_shadow_type( GTK_SCROLLED_WINDOW(w),
                                             gtkstyle );
    }
}

void wxWindowGTK::SetWindowStyleFlag( long style )
{
    // Updates the internal variable. NB: Now m_windowStyle bits carry the _new_ style values already
    wxWindowBase::SetWindowStyleFlag(style);
}

// Find the wxWindow at the current mouse position, also returning the mouse
// position.
wxWindow* wxFindWindowAtPointer(wxPoint& pt)
{
    pt = wxGetMousePosition();
    wxWindow* found = wxFindWindowAtPoint(pt);
    return found;
}

// Get the current mouse position.
wxPoint wxGetMousePosition()
{
  /* This crashes when used within wxHelpContext,
     so we have to use the X-specific implementation below.
    gint x, y;
    GdkModifierType *mask;
    (void) gdk_window_get_pointer(NULL, &x, &y, mask);

    return wxPoint(x, y);
  */

    int x, y;
    GdkWindow* windowAtPtr = gdk_window_at_pointer(& x, & y);

    Display *display = windowAtPtr ? GDK_WINDOW_XDISPLAY(windowAtPtr) : GDK_DISPLAY();
    Window rootWindow = RootWindowOfScreen (DefaultScreenOfDisplay(display));
    Window rootReturn, childReturn;
    int rootX, rootY, winX, winY;
    unsigned int maskReturn;

    XQueryPointer (display,
           rootWindow,
           &rootReturn,
                   &childReturn,
                   &rootX, &rootY, &winX, &winY, &maskReturn);
    return wxPoint(rootX, rootY);

}

GdkWindow* wxWindowGTK::GTKGetDrawingWindow() const
{
    GdkWindow* window = NULL;
    if (m_wxwindow)
        window = m_wxwindow->window;
    return window;
}

// ----------------------------------------------------------------------------
// freeze/thaw
// ----------------------------------------------------------------------------

extern "C"
{

// this is called if we attempted to freeze unrealized widget when it finally
// is realized (and so can be frozen):
static void wx_frozen_widget_realize(GtkWidget* w, wxWindowGTK* win)
{
    wxASSERT( w && !GTK_WIDGET_NO_WINDOW(w) );
    wxASSERT( GTK_WIDGET_REALIZED(w) );

    g_signal_handlers_disconnect_by_func
    (
        w,
        (void*)wx_frozen_widget_realize,
        win
    );

    GdkWindow* window = w->window;
    if (w == win->m_wxwindow)
        window = win->GTKGetDrawingWindow();
    gdk_window_freeze_updates(window);
}

} // extern "C"

void wxWindowGTK::GTKFreezeWidget(GtkWidget *w)
{
    if ( !w || GTK_WIDGET_NO_WINDOW(w) )
        return; // window-less widget, cannot be frozen

    if ( !GTK_WIDGET_REALIZED(w) )
    {
        // we can't thaw unrealized widgets because they don't have GdkWindow,
        // so set it up to be done immediately after realization:
        g_signal_connect_after
        (
            w,
            "realize",
            G_CALLBACK(wx_frozen_widget_realize),
            this
        );
        return;
    }

    GdkWindow* window = w->window;
    if (w == m_wxwindow)
        window = GTKGetDrawingWindow();
    gdk_window_freeze_updates(window);
}

void wxWindowGTK::GTKThawWidget(GtkWidget *w)
{
    if ( !w || GTK_WIDGET_NO_WINDOW(w) )
        return; // window-less widget, cannot be frozen

    if ( !GTK_WIDGET_REALIZED(w) )
    {
        // the widget wasn't realized yet, no need to thaw
        g_signal_handlers_disconnect_by_func
        (
            w,
            (void*)wx_frozen_widget_realize,
            this
        );
        return;
    }

    GdkWindow* window = w->window;
    if (w == m_wxwindow)
        window = GTKGetDrawingWindow();
    gdk_window_thaw_updates(window);
}

void wxWindowGTK::DoFreeze()
{
    GTKFreezeWidget(m_widget);
    if ( m_wxwindow && m_widget != m_wxwindow )
        GTKFreezeWidget(m_wxwindow);
}

void wxWindowGTK::DoThaw()
{
    GTKThawWidget(m_widget);
    if ( m_wxwindow && m_widget != m_wxwindow )
        GTKThawWidget(m_wxwindow);
}
