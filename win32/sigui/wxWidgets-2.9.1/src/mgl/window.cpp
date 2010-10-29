/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/window.cpp
// Purpose:     wxWindow
// Author:      Vaclav Slavik
//              (based on GTK & MSW implementations)
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

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

#include "wx/window.h"

#ifndef WX_PRECOMP
    #include "wx/msgdlg.h"
    #include "wx/accel.h"
    #include "wx/dc.h"
    #include "wx/dcclient.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/panel.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/dcscreen.h"
    #include "wx/menu.h"
#endif

#if wxUSE_DRAG_AND_DROP
    #include "wx/dnd.h"
#endif

#include "wx/sysopt.h"
#include "wx/mgl/private.h"
#include "wx/caret.h"

#include <mgraph.hpp>

#if wxUSE_TOOLTIPS
    #include "wx/tooltip.h"
#endif

// ---------------------------------------------------------------------------
// global variables
// ---------------------------------------------------------------------------

// MGL window manager and associated DC.
winmng_t *g_winMng = NULL;
MGLDevCtx *g_displayDC = NULL;

// the window that has keyboard focus:
static wxWindowMGL *gs_focusedWindow = NULL;
// the window that is about to be focused after currently focused
// one looses focus:
static wxWindow *gs_toBeFocusedWindow = NULL;
// the window that is currently under mouse cursor:
static wxWindowMGL *gs_windowUnderMouse = NULL;
// the window that has mouse capture
static wxWindowMGL *gs_mouseCapture = NULL;
// the frame that is currently active (i.e. its child has focus). It is
// used to generate wxActivateEvents
static wxWindowMGL *gs_activeFrame = NULL;
// track the mouse button state for wxGetMouseState()
unsigned long g_buttonState = 0;

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

// Custom identifiers used to distinguish between various event handlers
// and capture handlers passed to MGL_wm
enum
{
    wxMGL_CAPTURE_MOUSE = 1,
    wxMGL_CAPTURE_KEYB  = 2
};


// ---------------------------------------------------------------------------
// private functions
// ---------------------------------------------------------------------------

// Returns toplevel grandparent of given window:
static wxWindowMGL* wxGetTopLevelParent(wxWindowMGL *win)
{
    wxWindowMGL *p = win;
    while (p && !p->IsTopLevel())
         p = p->GetParent();
    return p;
}

// An easy way to capture screenshots:
static void wxCaptureScreenshot(bool activeWindowOnly)
{
#ifdef __DOS__
    #define SCREENSHOT_FILENAME wxT("sshot%03i.png")
#else
    #define SCREENSHOT_FILENAME wxT("screenshot-%03i.png")
#endif
    static int screenshot_num = 0;
    wxString screenshot;

    do
    {
        screenshot.Printf(SCREENSHOT_FILENAME, screenshot_num++);
    } while ( wxFileExists(screenshot) && screenshot_num < 1000 );

    wxRect r(0, 0, g_displayDC->sizex(), g_displayDC->sizey());

    if ( activeWindowOnly && gs_activeFrame )
    {
        r.Intersect(gs_activeFrame->GetRect());
    }

    g_displayDC->savePNGFromDC(screenshot.mb_str(),
                               r.x, r. y, r.x+r.width, r.y+r.height);

    wxMessageBox(wxString::Format(wxT("Screenshot captured: %s"),
                                  screenshot.c_str()));
}

// ---------------------------------------------------------------------------
// MGL_WM hooks:
// ---------------------------------------------------------------------------

static void MGLAPI wxWindowPainter(window_t *wnd, MGLDC *dc)
{
    wxWindowMGL *w = (wxWindow*) wnd->userData;

    if ( w && !(w->GetWindowStyle() & wxTRANSPARENT_WINDOW) )
    {
        MGLDevCtx ctx(dc);
        w->HandlePaint(&ctx);
    }
}

static ibool MGLAPI wxWindowMouseHandler(window_t *wnd, event_t *e)
{
    wxWindowMGL *win = (wxWindowMGL*)MGL_wmGetWindowUserData(wnd);
    wxPoint orig(win->GetClientAreaOrigin());
    wxPoint where;

    g_buttonState = e->modifiers;

    MGL_wmCoordGlobalToLocal(win->GetHandle(),
                             e->where_x, e->where_y, &where.x, &where.y);

    for (wxWindowMGL *w = win; w; w = w->GetParent())
    {
        if ( !w->IsEnabled() )
            return FALSE;
        if ( w->IsTopLevel() )
            break;
    }

    wxEventType type = wxEVT_NULL;
    wxMouseEvent event;
    event.SetEventObject(win);
    event.SetTimestamp(e->when);
    event.m_x = where.x - orig.x;
    event.m_y = where.y - orig.y;
    event.m_shiftDown = ( e->modifiers & EVT_SHIFTKEY ) != 0;
    event.m_controlDown = ( e->modifiers & EVT_CTRLSTATE ) != 0;
    event.m_altDown = ( e->modifiers & EVT_LEFTALT ) != 0;
    event.m_metaDown = ( e->modifiers & EVT_RIGHTALT ) != 0;
    event.m_leftDown = ( e->modifiers & EVT_LEFTBUT ) != 0;
    event.m_middleDown = ( e->modifiers & EVT_MIDDLEBUT ) != 0;
    event.m_rightDown = ( e->modifiers & EVT_RIGHTBUT ) != 0;

    switch (e->what)
    {
        case EVT_MOUSEDOWN:
            // Change focus if the user clicks outside focused window:
            if ( win->CanAcceptFocus() && wxWindow::FindFocus() != win )
                win->SetFocus();

            if ( e->message & EVT_DBLCLICK )
            {
                if ( e->message & EVT_LEFTBMASK )
                    type = wxEVT_LEFT_DCLICK;
                else if ( e->message & EVT_MIDDLEBMASK )
                    type = wxEVT_MIDDLE_DCLICK;
                else if ( e->message & EVT_RIGHTBMASK )
                    type = wxEVT_RIGHT_DCLICK;
            }
            else
            {
                if ( e->message & EVT_LEFTBMASK )
                    type = wxEVT_LEFT_DOWN;
                else if ( e->message & EVT_MIDDLEBMASK )
                    type = wxEVT_MIDDLE_DOWN;
                else if ( e->message & EVT_RIGHTBMASK )
                    type = wxEVT_RIGHT_DOWN;
            }

            break;

        case EVT_MOUSEUP:
            if ( e->message & EVT_LEFTBMASK )
                type = wxEVT_LEFT_UP;
            else if ( e->message & EVT_MIDDLEBMASK )
                type = wxEVT_MIDDLE_UP;
            else if ( e->message & EVT_RIGHTBMASK )
                type = wxEVT_RIGHT_UP;
            break;

        case EVT_MOUSEMOVE:
            if ( !gs_mouseCapture )
            {
                if ( win != gs_windowUnderMouse )
                {
                    if ( gs_windowUnderMouse )
                    {
                        wxMouseEvent event2(event);
                        MGL_wmCoordGlobalToLocal(gs_windowUnderMouse->GetHandle(),
                                                 e->where_x, e->where_y,
                                                 &event2.m_x, &event2.m_y);

                        wxPoint orig(gs_windowUnderMouse->GetClientAreaOrigin());
                        event2.m_x -= orig.x;
                        event2.m_y -= orig.y;

                        event2.SetEventObject(gs_windowUnderMouse);
                        event2.SetEventType(wxEVT_LEAVE_WINDOW);
                        gs_windowUnderMouse->HandleWindowEvent(event2);
                    }

                    wxMouseEvent event3(event);
                    event3.SetEventType(wxEVT_ENTER_WINDOW);
                    win->HandleWindowEvent(event3);

                    gs_windowUnderMouse = win;
                }
            }
            else // gs_mouseCapture
            {
                bool inside = (where.x >= 0 &&
                               where.y >= 0 &&
                               where.x < win->GetSize().x &&
                               where.y < win->GetSize().y);
                if ( (inside && gs_windowUnderMouse != win) ||
                     (!inside && gs_windowUnderMouse == win) )
                {
                    wxMouseEvent evt(inside ?
                                     wxEVT_ENTER_WINDOW : wxEVT_LEAVE_WINDOW);
                    evt.SetEventObject(win);
                    win->HandleWindowEvent(evt);
                    gs_windowUnderMouse = inside ? win : NULL;
                }
            }

            type = wxEVT_MOTION;
            break;

        default:
            break;
    }

    if ( type == wxEVT_NULL )
    {
        return FALSE;
    }
    else
    {
        event.SetEventType(type);
        return win->HandleWindowEvent(event);
    }
}

static long wxScanToKeyCode(event_t *event, bool translate)
{
    // VS: make it __WXDEBUG__-only, since we have lots of wxLogTrace calls
    //     here and the arguments would be stored in non-debug executable even
    //     though wxLogTrace would be no-op...
    #ifdef __WXDEBUG__
      #define KEY(mgl_key,wx_key) \
        case mgl_key: \
          wxLogTrace(wxT("keyevents"), \
                     wxT("key " #mgl_key ", mapped to " #wx_key)); \
          key = wx_key; \
          break;
    #else
      #define KEY(mgl_key,wx_key) \
        case mgl_key: key = wx_key; break;
    #endif

    long key = 0;

    if ( translate )
    {
        bool numlock = (event->modifiers & EVT_NUMLOCK) != 0;

        switch ( EVT_scanCode(event->message) )
        {
            KEY (KB_padMinus,       WXK_NUMPAD_SUBTRACT)
            KEY (KB_padPlus,        WXK_NUMPAD_ADD)
            KEY (KB_padTimes,       WXK_NUMPAD_MULTIPLY)
            KEY (KB_padDivide,      WXK_NUMPAD_DIVIDE)
            KEY (KB_padCenter,      numlock ? WXK_NUMPAD5 : WXK_NUMPAD_SEPARATOR) // ?
            KEY (KB_padLeft,        numlock ? WXK_NUMPAD4 : WXK_NUMPAD_LEFT)
            KEY (KB_padRight,       numlock ? WXK_NUMPAD6 : WXK_NUMPAD_RIGHT)
            KEY (KB_padUp,          numlock ? WXK_NUMPAD8 : WXK_NUMPAD_UP)
            KEY (KB_padDown,        numlock ? WXK_NUMPAD2 : WXK_NUMPAD_DOWN)
            KEY (KB_padInsert,      numlock ? WXK_NUMPAD0 : WXK_NUMPAD_INSERT)
            KEY (KB_padDelete,      numlock ? WXK_DECIMAL : WXK_NUMPAD_DELETE)
            KEY (KB_padHome,        numlock ? WXK_NUMPAD7 : WXK_NUMPAD_HOME)
            KEY (KB_padEnd,         numlock ? WXK_NUMPAD1 : WXK_NUMPAD_END)
            KEY (KB_padPageUp,      numlock ? WXK_NUMPAD9 : WXK_NUMPAD_PAGEUP)
            KEY (KB_padPageDown,    numlock ? WXK_NUMPAD3 : WXK_NUMPAD_PAGEDOWN)
            KEY (KB_1,              '1')
            KEY (KB_2,              '2')
            KEY (KB_3,              '3')
            KEY (KB_4,              '4')
            KEY (KB_5,              '5')
            KEY (KB_6,              '6')
            KEY (KB_7,              '7')
            KEY (KB_8,              '8')
            KEY (KB_9,              '9')
            KEY (KB_0,              '0')
            KEY (KB_minus,          WXK_SUBTRACT)
            KEY (KB_equals,         WXK_ADD)
            KEY (KB_backSlash,      '\\')
            KEY (KB_Q,              'Q')
            KEY (KB_W,              'W')
            KEY (KB_E,              'E')
            KEY (KB_R,              'R')
            KEY (KB_T,              'T')
            KEY (KB_Y,              'Y')
            KEY (KB_U,              'U')
            KEY (KB_I,              'I')
            KEY (KB_O,              'O')
            KEY (KB_P,              'P')
            KEY (KB_leftSquareBrace,'[')
            KEY (KB_rightSquareBrace,']')
            KEY (KB_A,              'A')
            KEY (KB_S,              'S')
            KEY (KB_D,              'D')
            KEY (KB_F,              'F')
            KEY (KB_G,              'G')
            KEY (KB_H,              'H')
            KEY (KB_J,              'J')
            KEY (KB_K,              'K')
            KEY (KB_L,              'L')
            KEY (KB_semicolon,      ';')
            KEY (KB_apostrophe,     '\'')
            KEY (KB_Z,              'Z')
            KEY (KB_X,              'X')
            KEY (KB_C,              'C')
            KEY (KB_V,              'V')
            KEY (KB_B,              'B')
            KEY (KB_N,              'N')
            KEY (KB_M,              'M')
            KEY (KB_comma,          ',')
            KEY (KB_period,         '.')
            KEY (KB_divide,         WXK_DIVIDE)
            KEY (KB_space,          WXK_SPACE)
            KEY (KB_tilde,          '~')

            default: break;
        }
    }

    if ( key == 0 )
    {
        switch ( EVT_scanCode(event->message) )
        {
            KEY (KB_padEnter,       WXK_NUMPAD_ENTER)
            KEY (KB_F1,             WXK_F1)
            KEY (KB_F2,             WXK_F2)
            KEY (KB_F3,             WXK_F3)
            KEY (KB_F4,             WXK_F4)
            KEY (KB_F5,             WXK_F5)
            KEY (KB_F6,             WXK_F6)
            KEY (KB_F7,             WXK_F7)
            KEY (KB_F8,             WXK_F8)
            KEY (KB_F9,             WXK_F9)
            KEY (KB_F10,            WXK_F10)
            KEY (KB_F11,            WXK_F11)
            KEY (KB_F12,            WXK_F12)
            KEY (KB_left,           WXK_LEFT)
            KEY (KB_right,          WXK_RIGHT)
            KEY (KB_up,             WXK_UP)
            KEY (KB_down,           WXK_DOWN)
            KEY (KB_insert,         WXK_INSERT)
            KEY (KB_delete,         WXK_DELETE)
            KEY (KB_home,           WXK_HOME)
            KEY (KB_end,            WXK_END)
            KEY (KB_pageUp,         WXK_PAGEUP)
            KEY (KB_pageDown,       WXK_PAGEDOWN)
            KEY (KB_capsLock,       WXK_CAPITAL)
            KEY (KB_numLock,        WXK_NUMLOCK)
            KEY (KB_scrollLock,     WXK_SCROLL)
            KEY (KB_leftShift,      WXK_SHIFT)
            KEY (KB_rightShift,     WXK_SHIFT)
            KEY (KB_leftCtrl,       WXK_CONTROL)
            KEY (KB_rightCtrl,      WXK_CONTROL)
            KEY (KB_leftAlt,        WXK_ALT)
            KEY (KB_rightAlt,       WXK_ALT)
            KEY (KB_leftWindows,    WXK_START)
            KEY (KB_rightWindows,   WXK_START)
            KEY (KB_menu,           WXK_MENU)
            KEY (KB_sysReq,         WXK_SNAPSHOT)
            KEY (KB_esc,            WXK_ESCAPE)
            KEY (KB_backspace,      WXK_BACK)
            KEY (KB_tab,            WXK_TAB)
            KEY (KB_enter,          WXK_RETURN)

            default:
                key = EVT_asciiCode(event->message);
                break;
        }
    }

    #undef KEY

    return key;
}

static bool wxHandleSpecialKeys(wxKeyEvent& event)
{
    // Add an easy way to capture screenshots:
    if ( event.m_keyCode == WXK_SNAPSHOT
    #ifdef __WXDEBUG__ // FIXME_MGL - remove when KB_sysReq works in MGL!
         || (event.m_keyCode == WXK_F1 &&
            event.m_shiftDown && event.m_controlDown)
    #endif
       )
    {
        wxCaptureScreenshot(event.m_altDown/*only active wnd?*/);
        return true;
    }

    return false;
}

static ibool MGLAPI wxWindowKeybHandler(window_t *wnd, event_t *e)
{
    wxWindowMGL *win = (wxWindowMGL*)MGL_wmGetWindowUserData(wnd);

    if ( !win->IsEnabled() ) return FALSE;

    wxPoint where;
    MGL_wmCoordGlobalToLocal(win->GetHandle(),
                             e->where_x, e->where_y, &where.x, &where.y);

    wxKeyEvent event;
    event.SetEventObject(win);
    event.SetTimestamp(e->when);
    event.m_keyCode = wxScanToKeyCode(e, true);
    event.m_x = where.x;
    event.m_y = where.y;
    event.m_shiftDown = ( e->modifiers & EVT_SHIFTKEY ) != 0;
    event.m_controlDown = ( e->modifiers & EVT_CTRLSTATE ) != 0;
    event.m_altDown = ( e->modifiers & EVT_LEFTALT ) != 0;
    event.m_metaDown = ( e->modifiers & EVT_RIGHTALT ) != 0;

    if ( e->what == EVT_KEYUP )
    {
        event.SetEventType(wxEVT_KEY_UP);
        return win->HandleWindowEvent(event);
    }
    else
    {
        bool ret;
        wxKeyEvent event2;

        event.SetEventType(wxEVT_KEY_DOWN);
        event2 = event;

        ret = win->HandleWindowEvent(event);

        // wxMSW doesn't send char events with Alt pressed
        // Only send wxEVT_CHAR event if not processed yet. Thus, ALT-x
        // will only be sent if it is not in an accelerator table:
        event2.m_keyCode = wxScanToKeyCode(e, false);
        if ( !ret && event2.m_keyCode != 0 )
        {
            event2.SetEventType(wxEVT_CHAR);
            ret = win->HandleWindowEvent(event2);
        }

        // Synthetize navigation key event, but do it only if the TAB key
        // wasn't handled yet:
        if ( !ret && event.m_keyCode == WXK_TAB &&
             win->GetParent() && win->GetParent()->HasFlag(wxTAB_TRAVERSAL) )
        {
            wxNavigationKeyEvent navEvent;
            navEvent.SetEventObject(win->GetParent());
            // Shift-TAB goes in reverse direction:
            navEvent.SetDirection(!event.m_shiftDown);
            // Ctrl-TAB changes the (parent) window, i.e. switch notebook page:
            navEvent.SetWindowChange(event.m_controlDown);
            navEvent.SetCurrentFocus(wxStaticCast(win, wxWindow));
            ret = win->HandleWindowEvent(navEvent);
        }

        // Finally, process special meaning keys that are usually
        // a responsibility of OS or window manager:
        if ( !ret )
            ret = wxHandleSpecialKeys(event);

        return ret;
    }
}

// ---------------------------------------------------------------------------
// event tables
// ---------------------------------------------------------------------------

// in wxUniv this class is abstract because it doesn't have DoPopupMenu()
IMPLEMENT_ABSTRACT_CLASS(wxWindowMGL, wxWindowBase)

BEGIN_EVENT_TABLE(wxWindowMGL, wxWindowBase)
END_EVENT_TABLE()

// ===========================================================================
// implementation
// ===========================================================================

// ----------------------------------------------------------------------------
// constructors and such
// ----------------------------------------------------------------------------

extern wxVideoMode wxGetDefaultDisplayMode();

void wxWindowMGL::Init()
{
    // First of all, make sure window manager is up and running. If it is
    // not the case, initialize it in default display mode
    if ( !g_winMng )
    {
        if ( !wxTheApp->SetDisplayMode(wxGetDefaultDisplayMode()) )
        {
            wxLogFatalError(_("Cannot initialize display."));
        }
    }

    // mgl specific:
    m_wnd = NULL;
    m_isShown = true;
    m_paintMGLDC = NULL;
    m_eraseBackground = -1;
}

// Destructor
wxWindowMGL::~wxWindowMGL()
{
    SendDestroyEvent();

    if ( gs_mouseCapture == this )
        ReleaseMouse();

    if (gs_activeFrame == this)
    {
        gs_activeFrame = NULL;
        // activate next frame in Z-order:
        if ( m_wnd->prev )
        {
            wxWindowMGL *win = (wxWindowMGL*)m_wnd->prev->userData;
            win->SetFocus();
        }
        else if ( m_wnd->next )
        {
            wxWindowMGL *win = (wxWindowMGL*)m_wnd->next->userData;
            win->SetFocus();
        }
    }

    if ( gs_focusedWindow == this )
        KillFocus();

    if ( gs_windowUnderMouse == this )
        gs_windowUnderMouse = NULL;

    DestroyChildren();

    if ( m_wnd )
        MGL_wmDestroyWindow(m_wnd);
}

// real construction (Init() must have been called before!)
bool wxWindowMGL::Create(wxWindow *parent,
                         wxWindowID id,
                         const wxPoint& pos,
                         const wxSize& size,
                         long style,
                         const wxString& name)
{
    if ( !CreateBase(parent, id, pos, size, style, wxDefaultValidator, name) )
        return false;

    if ( parent )
        parent->AddChild(this);

    int x, y, w, h;
    x = pos.x, y = pos.y;
    if ( x == -1 )
        x = 0; // FIXME_MGL, something better, see GTK+
    if ( y == -1 )
        y = 0; // FIXME_MGL, something better, see GTK+
    AdjustForParentClientOrigin(x, y, 0);
    w = WidthDefault(size.x);
    h = HeightDefault(size.y);

    long mgl_style = 0;
    window_t *wnd_parent = parent ? parent->GetHandle() : NULL;

    if ( style & wxFULL_REPAINT_ON_RESIZE )
    {
        mgl_style |= MGL_WM_FULL_REPAINT_ON_RESIZE;
    }
    if ( style & wxSTAY_ON_TOP )
    {
        mgl_style |= MGL_WM_ALWAYS_ON_TOP;
    }
    if ( style & wxPOPUP_WINDOW )
    {
        mgl_style |= MGL_WM_ALWAYS_ON_TOP;
        // it is created hidden as other top level windows
        m_isShown = false;
        wnd_parent = NULL;
    }

    window_t *wnd = MGL_wmCreateWindow(g_winMng, wnd_parent, x, y, w, h);

    MGL_wmSetWindowFlags(wnd, mgl_style);
    MGL_wmShowWindow(wnd, m_isShown);

    SetMGLwindow_t(wnd);

    return true;
}

void wxWindowMGL::SetMGLwindow_t(struct window_t *wnd)
{
    if ( m_wnd )
        MGL_wmDestroyWindow(m_wnd);

    m_wnd = wnd;
    if ( !m_wnd ) return;

    m_isShown = (bool)m_wnd->visible;

    MGL_wmSetWindowUserData(m_wnd, (void*) this);
    MGL_wmSetWindowPainter(m_wnd, wxWindowPainter);
    MGL_wmPushWindowEventHandler(m_wnd, wxWindowMouseHandler, EVT_MOUSEEVT, 0);
    MGL_wmPushWindowEventHandler(m_wnd, wxWindowKeybHandler, EVT_KEYEVT, 0);

    if ( m_cursor.Ok() )
        MGL_wmSetWindowCursor(m_wnd, *m_cursor.GetMGLCursor());
    else
        MGL_wmSetWindowCursor(m_wnd, *wxSTANDARD_CURSOR->GetMGLCursor());
}

// ---------------------------------------------------------------------------
// basic operations
// ---------------------------------------------------------------------------

void wxWindowMGL::SetFocus()
{
    if ( gs_focusedWindow == this ) return;

    wxWindowMGL *oldFocusedWindow = gs_focusedWindow;

    if ( gs_focusedWindow )
    {
        gs_toBeFocusedWindow = (wxWindow*)this;
        gs_focusedWindow->KillFocus();
        gs_toBeFocusedWindow = NULL;
    }

    gs_focusedWindow = this;

    MGL_wmCaptureEvents(GetHandle(), EVT_KEYEVT, wxMGL_CAPTURE_KEYB);

    wxWindowMGL *active = wxGetTopLevelParent(this);
    if ( !(m_windowStyle & wxPOPUP_WINDOW) && active != gs_activeFrame )
    {
        if ( gs_activeFrame )
        {
            wxActivateEvent event(wxEVT_ACTIVATE, false, gs_activeFrame->GetId());
            event.SetEventObject(gs_activeFrame);
            gs_activeFrame->HandleWindowEvent(event);
        }

        gs_activeFrame = active;
        wxActivateEvent event(wxEVT_ACTIVATE, true, gs_activeFrame->GetId());
        event.SetEventObject(gs_activeFrame);
        gs_activeFrame->HandleWindowEvent(event);
    }

    // notify the parent keeping track of focus for the kbd navigation
    // purposes that we got it
    wxChildFocusEvent eventFocus((wxWindow*)this);
    HandleWindowEvent(eventFocus);

    wxFocusEvent event(wxEVT_SET_FOCUS, GetId());
    event.SetEventObject(this);
    event.SetWindow((wxWindow*)oldFocusedWindow);
    HandleWindowEvent(event);

#if wxUSE_CARET
    // caret needs to be informed about focus change
    wxCaret *caret = GetCaret();
    if ( caret )
        caret->OnSetFocus();
#endif // wxUSE_CARET
}

void wxWindowMGL::KillFocus()
{
    if ( gs_focusedWindow != this ) return;
    gs_focusedWindow = NULL;

    if ( m_isBeingDeleted ) return;

    MGL_wmUncaptureEvents(GetHandle(), wxMGL_CAPTURE_KEYB);

#if wxUSE_CARET
    // caret needs to be informed about focus change
    wxCaret *caret = GetCaret();
    if ( caret )
        caret->OnKillFocus();
#endif // wxUSE_CARET

    wxFocusEvent event(wxEVT_KILL_FOCUS, GetId());
    event.SetEventObject(this);
    event.SetWindow(gs_toBeFocusedWindow);
    HandleWindowEvent(event);
}

// ----------------------------------------------------------------------------
// this wxWindowBase function is implemented here (in platform-specific file)
// because it is static and so couldn't be made virtual
// ----------------------------------------------------------------------------
wxWindow *wxWindowBase::DoFindFocus()
{
    return (wxWindow*)gs_focusedWindow;
}

bool wxWindowMGL::Show(bool show)
{
    if ( !wxWindowBase::Show(show) )
        return false;

    MGL_wmShowWindow(m_wnd, show);

    if (!show && gs_activeFrame == this)
    {
        // activate next frame in Z-order:
        if ( m_wnd->prev )
        {
            wxWindowMGL *win = (wxWindowMGL*)m_wnd->prev->userData;
            win->SetFocus();
        }
        else if ( m_wnd->next )
        {
            wxWindowMGL *win = (wxWindowMGL*)m_wnd->next->userData;
            win->SetFocus();
        }
        else
        {
            gs_activeFrame = NULL;
        }
    }

    return true;
}

// Raise the window to the top of the Z order
void wxWindowMGL::Raise()
{
    MGL_wmRaiseWindow(m_wnd);
}

// Lower the window to the bottom of the Z order
void wxWindowMGL::Lower()
{
    MGL_wmLowerWindow(m_wnd);
}

void wxWindowMGL::DoCaptureMouse()
{
    if ( gs_mouseCapture )
        MGL_wmUncaptureEvents(gs_mouseCapture->m_wnd, wxMGL_CAPTURE_MOUSE);

    gs_mouseCapture = this;
    MGL_wmCaptureEvents(m_wnd, EVT_MOUSEEVT, wxMGL_CAPTURE_MOUSE);
}

void wxWindowMGL::DoReleaseMouse()
{
    wxASSERT_MSG( gs_mouseCapture == this, wxT("attempt to release mouse, but this window hasn't captured it") );

    MGL_wmUncaptureEvents(m_wnd, wxMGL_CAPTURE_MOUSE);
    gs_mouseCapture = NULL;
}

/* static */ wxWindow *wxWindowBase::GetCapture()
{
    return (wxWindow*)gs_mouseCapture;
}

bool wxWindowMGL::SetCursor(const wxCursor& cursor)
{
    if ( !wxWindowBase::SetCursor(cursor) )
    {
        // no change
        return false;
    }

    if ( m_cursor.Ok() )
        MGL_wmSetWindowCursor(m_wnd, *m_cursor.GetMGLCursor());
    else
        MGL_wmSetWindowCursor(m_wnd, *wxSTANDARD_CURSOR->GetMGLCursor());

    return true;
}

void wxWindowMGL::WarpPointer(int x, int y)
{
    int w, h;
    wxDisplaySize(&w, &h);

    ClientToScreen(&x, &y);
    if ( x < 0 )
        x = 0;
    if ( y < 0 )
        y = 0;
    if ( x >= w )
        x = w-1;
    if ( y >= h )
        y = h-1;

    EVT_setMousePos(x, y);
}

// Set this window to be the child of 'parent'.
bool wxWindowMGL::Reparent(wxWindowBase *parent)
{
    if ( !wxWindowBase::Reparent(parent) )
        return false;

    MGL_wmReparentWindow(m_wnd, parent->GetHandle());

    return true;
}


// ---------------------------------------------------------------------------
// drag and drop
// ---------------------------------------------------------------------------

#if wxUSE_DRAG_AND_DROP

void wxWindowMGL::SetDropTarget(wxDropTarget *pDropTarget)
{
    if ( m_dropTarget != 0 ) {
        m_dropTarget->Revoke(m_hWnd);
        delete m_dropTarget;
    }

    m_dropTarget = pDropTarget;
    if ( m_dropTarget != 0 )
        m_dropTarget->Register(m_hWnd);
}
// FIXME_MGL
#endif // wxUSE_DRAG_AND_DROP

// old style file-manager drag&drop support: we retain the old-style
// DragAcceptFiles in parallel with SetDropTarget.
void wxWindowMGL::DragAcceptFiles(bool WXUNUSED(accept))
{
#if 0 // FIXME_MGL
    HWND hWnd = GetHwnd();
    if ( hWnd )
        ::DragAcceptFiles(hWnd, (BOOL)accept);
#endif
}

// ---------------------------------------------------------------------------
// moving and resizing
// ---------------------------------------------------------------------------

// Get total size
void wxWindowMGL::DoGetSize(int *x, int *y) const
{
    wxASSERT_MSG( m_wnd, wxT("invalid window") );

    if (x) *x = m_wnd->width;
    if (y) *y = m_wnd->height;
}

void wxWindowMGL::DoGetPosition(int *x, int *y) const
{
    wxASSERT_MSG( m_wnd, wxT("invalid window") );

    int pX = 0, pY = 0;
    AdjustForParentClientOrigin(pX, pY, 0);

    if (x) *x = m_wnd->x - pX;
    if (y) *y = m_wnd->y - pY;
}

void wxWindowMGL::DoScreenToClient(int *x, int *y) const
{
    int ax, ay;
    MGL_wmCoordGlobalToLocal(m_wnd, 0, 0, &ax, &ay);
    if (x)
        (*x) += ax;
    if (y)
        (*y) += ay;
}

void wxWindowMGL::DoClientToScreen(int *x, int *y) const
{
    int ax, ay;
    MGL_wmCoordLocalToGlobal(m_wnd, 0, 0, &ax, &ay);
    if (x)
        (*x) += ax;
    if (y)
        (*y) += ay;
}

// Get size *available for subwindows* i.e. excluding menu bar etc.
void wxWindowMGL::DoGetClientSize(int *x, int *y) const
{
    DoGetSize(x, y);
}

void wxWindowMGL::DoMoveWindow(int x, int y, int width, int height)
{
    wxRect rcClient(GetClientRect());

    MGL_wmSetWindowPosition(m_wnd, x, y, width, height);

    // When the origin or a window stays fixed but the height or width
    // changes, invalidate the old and new non-client areas
    if ( !HasFlag(wxFULL_REPAINT_ON_RESIZE) &&
         m_wnd->x == x && m_wnd->y == y &&
         rcClient.Intersect(GetClientRect()) != wxRect(0, 0, width, height) )
    {
        wxRegion rgn(0, 0, width, height);
        rgn.Subtract(rcClient);

        // This should work I think, but doesn't seem to:
        //MGL_wmInvalidateWindowRegion(m_wnd, rgn.GetMGLRegion().rgnPointer());

        // Use MGL_wmInvalidateWindowRect instead:
        for (wxRegionIterator it(rgn); it; it++)
        {
            rect_t rc;
            rc.left = it.GetX();
            rc.top = it.GetY();
            rc.right = rc.left + it.GetW();
            rc.bottom = rc.top + it.GetH();
            MGL_wmInvalidateWindowRect(m_wnd, &rc);
        }
    }
}

// set the size of the window: if the dimensions are positive, just use them,
// but if any of them is equal to -1, it means that we must find the value for
// it ourselves (unless sizeFlags contains wxSIZE_ALLOW_MINUS_ONE flag, in
// which case -1 is a valid value for x and y)
//
// If sizeFlags contains wxSIZE_AUTO_WIDTH/HEIGHT flags (default), we calculate
// the width/height to best suit our contents, otherwise we reuse the current
// width/height
void wxWindowMGL::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
    // get the current size and position...
    int currentX, currentY;
    GetPosition(&currentX, &currentY);
    int currentW,currentH;
    GetSize(&currentW, &currentH);

    // ... and don't do anything (avoiding flicker) if it's already ok
    if ( x == currentX && y == currentY &&
         width == currentW && height == currentH )
    {
        return;
    }

    if ( x == -1 && !(sizeFlags & wxSIZE_ALLOW_MINUS_ONE) )
        x = currentX;
    if ( y == -1 && !(sizeFlags & wxSIZE_ALLOW_MINUS_ONE) )
        y = currentY;

    AdjustForParentClientOrigin(x, y, sizeFlags);

    wxSize size(-1, -1);
    if ( width == -1 )
    {
        if ( sizeFlags & wxSIZE_AUTO_WIDTH )
        {
            size = DoGetBestSize();
            width = size.x;
        }
        else
        {
            // just take the current one
            width = currentW;
        }
    }

    if ( height == -1 )
    {
        if ( sizeFlags & wxSIZE_AUTO_HEIGHT )
        {
            if ( size.x == -1 )
            {
                size = DoGetBestSize();
            }
            //else: already called DoGetBestSize() above

            height = size.y;
        }
        else
        {
            // just take the current one
            height = currentH;
        }
    }

    int maxWidth = GetMaxWidth(),
        minWidth = GetMinWidth(),
        maxHeight = GetMaxHeight(),
        minHeight = GetMinHeight();

    if ( minWidth != -1 && width < minWidth ) width = minWidth;
    if ( maxWidth != -1 && width > maxWidth ) width = maxWidth;
    if ( minHeight != -1 && height < minHeight ) height = minHeight;
    if ( maxHeight != -1 && height > maxHeight ) height = maxHeight;

    if ( m_wnd->x != x || m_wnd->y != y ||
         (int)m_wnd->width != width || (int)m_wnd->height != height )
    {
        DoMoveWindow(x, y, width, height);

        wxSize newSize(width, height);
        wxSizeEvent event(newSize, GetId());
        event.SetEventObject(this);
        HandleWindowEvent(event);
    }
}

void wxWindowMGL::DoSetClientSize(int width, int height)
{
    SetSize(width, height);
}

// ---------------------------------------------------------------------------
// text metrics
// ---------------------------------------------------------------------------

int wxWindowMGL::GetCharHeight() const
{
    wxScreenDC dc;
    dc.SetFont(m_font);
    return dc.GetCharHeight();
}

int wxWindowMGL::GetCharWidth() const
{
    wxScreenDC dc;
    dc.SetFont(m_font);
    return dc.GetCharWidth();
}

void wxWindowMGL::DoGetTextExtent(const wxString& string,
                                  int *x, int *y,
                                  int *descent,
                                  int *externalLeading,
                                  const wxFont *theFont) const
{
    wxScreenDC dc;
    if (!theFont)
        theFont = &m_font;
    dc.GetTextExtent(string, x, y, descent, externalLeading, (wxFont*)theFont);
}


// ---------------------------------------------------------------------------
// painting
// ---------------------------------------------------------------------------

void wxWindowMGL::Refresh(bool eraseBack, const wxRect *rect)
{
    if ( m_eraseBackground == -1 )
        m_eraseBackground = eraseBack;
    else
        m_eraseBackground |= eraseBack;

    if ( rect )
    {
        rect_t r;
        r.left = rect->GetLeft(), r.right = rect->GetRight();
        r.top = rect->GetTop(), r.bottom = rect->GetBottom();
        MGL_wmInvalidateWindowRect(GetHandle(), &r);
    }
    else
        MGL_wmInvalidateWindow(GetHandle());
}

void wxWindowMGL::Update()
{
    if ( !IsFrozen() )
        MGL_wmUpdateDC(g_winMng);
}

void wxWindowMGL::DoFreeze()
{
    m_refreshAfterThaw = false;
}

void wxWindowMGL::DoThaw()
{
    if ( m_refreshAfterThaw )
        Refresh();
}

void wxWindowMGL::HandlePaint(MGLDevCtx *dc)
{
    if ( IsFrozen() )
    {
        // Don't paint anything if the window is frozen.
        m_refreshAfterThaw = true;
        return;
    }

#if wxDEBUG_LEVEL >= 2
    // FIXME_MGL -- debugging stuff, to be removed!
    static int debugPaintEvents = -1;
    if ( debugPaintEvents == -1 )
        debugPaintEvents = wxGetEnv(wxT("WXMGL_DEBUG_PAINT_EVENTS"), NULL);
    if ( debugPaintEvents )
    {
        dc->setColorRGB(255,0,255);
        dc->fillRect(-1000,-1000,2000,2000);
        wxMilliSleep(50);
    }
#endif // wxDEBUG_LEVEL >= 2

    MGLRegion clip;
    dc->getClipRegion(clip);
    m_updateRegion = wxRegion(clip);
    m_paintMGLDC = dc;

#if wxUSE_CARET
    // must hide caret temporarily, otherwise we'd get rendering artifacts
    wxCaret *caret = GetCaret();
    if ( caret )
        caret->Hide();
#endif // wxUSE_CARET

    if ( m_eraseBackground != 0 )
    {
        wxWindowDC dc((wxWindow*)this);
        wxEraseEvent eventEr(m_windowId, &dc);
        eventEr.SetEventObject(this);
        HandleWindowEvent(eventEr);
    }
    m_eraseBackground = -1;

    wxNcPaintEvent eventNc(GetId());
    eventNc.SetEventObject(this);
    HandleWindowEvent(eventNc);

    wxPaintEvent eventPt(GetId());
    eventPt.SetEventObject(this);
    HandleWindowEvent(eventPt);

#if wxUSE_CARET
    if ( caret )
        caret->Show();
#endif // wxUSE_CARET

    m_paintMGLDC = NULL;
    m_updateRegion.Clear();
}


// Find the wxWindow at the current mouse position, returning the mouse
// position.
wxWindow* wxFindWindowAtPointer(wxPoint& pt)
{
    return wxFindWindowAtPoint(pt = wxGetMousePosition());
}

wxWindow* wxFindWindowAtPoint(const wxPoint& pt)
{
    window_t *wnd = MGL_wmGetWindowAtPosition(g_winMng, pt.x, pt.y);
    return (wxWindow*)wnd->userData;
}


// ---------------------------------------------------------------------------
// idle events processing
// ---------------------------------------------------------------------------

void wxWindowMGL::OnInternalIdle()
{
    if (wxUpdateUIEvent::CanUpdate(this) && IsShown())
        UpdateWindowUI(wxUPDATE_UI_FROMIDLE);
}
