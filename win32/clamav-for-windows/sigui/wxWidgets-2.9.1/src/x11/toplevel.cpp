///////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/toplevel.cpp
// Purpose:     implements wxTopLevelWindow for X11
// Author:      Julian Smart
// Modified by:
// Created:     24.09.01
// RCS-ID:      $Id$
// Copyright:   (c) 2002 Julian Smart
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/toplevel.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/string.h"
    #include "wx/log.h"
    #include "wx/intl.h"
    #include "wx/frame.h"
    #include "wx/menu.h"
    #include "wx/statusbr.h"
    #include "wx/settings.h"
#endif //WX_PRECOMP

#include "wx/x11/private.h"
#include "X11/Xutil.h"

#include "wx/unix/utilsx11.h"

bool wxMWMIsRunning(Window w);

// ----------------------------------------------------------------------------
// wxTopLevelWindowX11 creation
// ----------------------------------------------------------------------------

void wxTopLevelWindowX11::Init()
{
    m_iconized =
    m_maximizeOnShow = false;

    // unlike (almost?) all other windows, frames are created hidden
    m_isShown = false;

    // Data to save/restore when calling ShowFullScreen
    m_fsStyle = 0;
    m_fsIsMaximized = false;
    m_fsIsShowing = false;

    m_needResizeInIdle = false;

    m_x = wxDefaultCoord;
    m_y = wxDefaultCoord;
    m_width = 20;
    m_height = 20;
}

bool wxTopLevelWindowX11::Create(wxWindow *parent,
                                 wxWindowID id,
                                 const wxString& title,
                                 const wxPoint& pos,
                                 const wxSize& size,
                                 long style,
                                 const wxString& name)
{
    // init our fields
    Init();

    m_windowStyle = style;
    m_parent = parent;

    SetName(name);

    m_windowId = id == wxID_ANY ? NewControlId() : id;

    if (parent)
        parent->AddChild(this);

    wxTopLevelWindows.Append(this);

    Display *xdisplay = wxGlobalDisplay();
    int xscreen = DefaultScreen( xdisplay );
    Visual *xvisual = DefaultVisual( xdisplay, xscreen );
    Window xparent = RootWindow( xdisplay, xscreen );
    Colormap cm = DefaultColormap( xdisplay, xscreen );

    if (GetExtraStyle() & wxTOPLEVEL_EX_DIALOG)
        m_backgroundColour = wxSystemSettings::GetColour(wxSYS_COLOUR_BTNFACE);
    else
        m_backgroundColour = wxSystemSettings::GetColour(wxSYS_COLOUR_APPWORKSPACE);
    m_backgroundColour.CalcPixel( (WXColormap) cm );
    m_hasBgCol = true;

    m_x = pos.x;
    if (m_x < -1)
        m_x = 10;

    m_y = pos.y;
    if (m_y < 0)
        m_y = 10;

    m_width = size.x;
    if (m_width < 0)
        m_width = 500;

    m_height = size.y;
    if (m_height < 0)
        m_height = 380;

#if !wxUSE_NANOX
    XSetWindowAttributes xattributes;

    long xattributes_mask =
        CWBorderPixel | CWBackPixel;

    xattributes.background_pixel = m_backgroundColour.GetPixel();
    xattributes.border_pixel = BlackPixel( xdisplay, xscreen );

    if (HasFlag( wxNO_BORDER ))
    {
        xattributes_mask |= CWOverrideRedirect;
        xattributes.override_redirect = True;
    }

    if (!HasFlag( wxFULL_REPAINT_ON_RESIZE ))
    {
        xattributes_mask |= CWBitGravity;
        xattributes.bit_gravity = NorthWestGravity;
    }

    xattributes_mask |= CWEventMask;
    xattributes.event_mask =
        ExposureMask | KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask |
        ButtonMotionMask | EnterWindowMask | LeaveWindowMask | PointerMotionMask |
        KeymapStateMask | FocusChangeMask | ColormapChangeMask | StructureNotifyMask |
        PropertyChangeMask;

    Window xwindow = XCreateWindow( xdisplay, xparent, m_x, m_y, m_width, m_height,
                                    0, DefaultDepth(xdisplay,xscreen), InputOutput, xvisual, xattributes_mask, &xattributes );
#else
    long backColor, foreColor;
    backColor = GR_RGB(m_backgroundColour.Red(), m_backgroundColour.Green(), m_backgroundColour.Blue());
    foreColor = GR_RGB(m_foregroundColour.Red(), m_foregroundColour.Green(), m_foregroundColour.Blue());

    Window xwindow = XCreateWindowWithColor( xdisplay, xparent, m_x, m_y, m_width, m_height,
                                    0, 0, InputOutput, xvisual, backColor, foreColor);
#endif

    m_mainWindow = (WXWindow) xwindow;
    m_clientWindow = (WXWindow) xwindow;
    wxAddWindowToTable( xwindow, (wxWindow*) this );

#if wxUSE_NANOX
    XSelectInput( xdisplay, xwindow,
                  GR_EVENT_MASK_CLOSE_REQ |
                  ExposureMask |
                  KeyPressMask |
                  KeyReleaseMask |
                  ButtonPressMask |
                  ButtonReleaseMask |
                  ButtonMotionMask |
                  EnterWindowMask |
                  LeaveWindowMask |
                  PointerMotionMask |
                  KeymapStateMask |
                  FocusChangeMask |
                  ColormapChangeMask |
                  StructureNotifyMask |
                  PropertyChangeMask
                  );
#endif

    // Set background to None which will prevent X11 from clearing the
    // background completely.
    XSetWindowBackgroundPixmap( xdisplay, xwindow, None );

#if !wxUSE_NANOX
    if (HasFlag( wxSTAY_ON_TOP ))
    {
        Window xroot = RootWindow( xdisplay, xscreen );
        XSetTransientForHint( xdisplay, xwindow, xroot );
    }
    else
    {
       if (GetExtraStyle() & wxTOPLEVEL_EX_DIALOG)
       {
            if (GetParent() && GetParent()->X11GetMainWindow())
            {
                Window xparentwindow = (Window) GetParent()->X11GetMainWindow();
                XSetTransientForHint( xdisplay, xwindow, xparentwindow );
            }
        }
    }

    XSizeHints size_hints;
    size_hints.flags = PSize | PPosition | PWinGravity;
    size_hints.x = m_x;
    size_hints.y = m_y;
    size_hints.width = m_width;
    size_hints.height = m_height;
    size_hints.win_gravity = NorthWestGravity;
    XSetWMNormalHints( xdisplay, xwindow, &size_hints);

    XWMHints wm_hints;
    wm_hints.flags = InputHint | StateHint;
    if (GetParent())
    {
        wm_hints.flags |= WindowGroupHint;
        wm_hints.window_group = (Window) GetParent()->X11GetMainWindow();
    }
    wm_hints.input = True;
    wm_hints.initial_state = NormalState;
    XSetWMHints( xdisplay, xwindow, &wm_hints);

    Atom wm_protocols[2];
    wm_protocols[0] = XInternAtom( xdisplay, "WM_DELETE_WINDOW", False );
    wm_protocols[1] = XInternAtom( xdisplay, "WM_TAKE_FOCUS", False );
    XSetWMProtocols( xdisplay, xwindow, wm_protocols, 2);

#endif

    wxSetWMDecorations( xwindow, style);

    SetTitle(title);

    return true;
}

wxTopLevelWindowX11::~wxTopLevelWindowX11()
{
    wxTopLevelWindows.DeleteObject(this);

    // If this is the last top-level window, exit.
    if ( wxTheApp && (wxTopLevelWindows.GetCount() == 0) )
    {
        wxTheApp->SetTopWindow(NULL);

        if (wxTheApp->GetExitOnFrameDelete())
        {
            // Signal to the app that we're going to close
            wxTheApp->ExitMainLoop();
        }
    }
}

void wxTopLevelWindowX11::OnInternalIdle()
{
    wxWindow::OnInternalIdle();

    // Do this only after the last idle event so that
    // all windows have been updated before a new
    // round of size events is sent
    if (m_needResizeInIdle && !wxTheApp->Pending())
    {
        wxSizeEvent event( GetClientSize(), GetId() );
        event.SetEventObject( this );
        HandleWindowEvent( event );

        m_needResizeInIdle = false;
    }
}

// ----------------------------------------------------------------------------
// wxTopLevelWindowX11 showing
// ----------------------------------------------------------------------------

bool wxTopLevelWindowX11::Show(bool show)
{
    if (show)
    {
        wxSizeEvent event(GetSize(), GetId());

        event.SetEventObject(this);
        HandleWindowEvent(event);

        m_needResizeInIdle = false;
    }

    bool ret = wxWindowX11::Show(show);

    return ret;
}

// ----------------------------------------------------------------------------
// wxTopLevelWindowX11 maximize/minimize
// ----------------------------------------------------------------------------

void wxTopLevelWindowX11::Maximize(bool WXUNUSED(maximize))
{
    // TODO
}

bool wxTopLevelWindowX11::IsMaximized() const
{
    // TODO
    return true;
}

void wxTopLevelWindowX11::Iconize(bool iconize)
{
    if ( !iconize )
    {
        Restore();
        return;
    }

    if (!m_iconized && X11GetMainWindow())
    {
        if (XIconifyWindow(wxGlobalDisplay(),
            (Window) X11GetMainWindow(), DefaultScreen(wxGlobalDisplay())) != 0)
            m_iconized = true;
    }
}

bool wxTopLevelWindowX11::IsIconized() const
{
    return m_iconized;
}

void wxTopLevelWindowX11::Restore()
{
    // This is the way to deiconify the window, according to the X FAQ
    if (m_iconized && X11GetMainWindow())
    {
        XMapWindow(wxGlobalDisplay(), (Window) X11GetMainWindow());
        m_iconized = false;
    }
}

// ----------------------------------------------------------------------------
// wxTopLevelWindowX11 fullscreen
// ----------------------------------------------------------------------------

bool wxTopLevelWindowX11::ShowFullScreen(bool show, long style)
{
    if (show)
    {
        if (IsFullScreen())
            return false;

        m_fsIsShowing = true;
        m_fsStyle = style;

        // TODO

        return true;
    }
    else
    {
        if (!IsFullScreen())
            return false;

        m_fsIsShowing = false;

        // TODO
        return true;
    }
}

// ----------------------------------------------------------------------------
// wxTopLevelWindowX11 misc
// ----------------------------------------------------------------------------

void wxTopLevelWindowX11::DoSetIcon(const wxIcon& icon)
{
    if (icon.Ok() && X11GetMainWindow())
    {
#if !wxUSE_NANOX
        XWMHints *wmHints = XAllocWMHints();
        wmHints->icon_pixmap = (Pixmap) icon.GetPixmap();

        wmHints->flags = IconPixmapHint;

        if (icon.GetMask())
        {
            wmHints->flags |= IconMaskHint;
            wmHints->icon_mask = (Pixmap) icon.GetMask()->GetBitmap();
        }

        XSetWMHints(wxGlobalDisplay(), (Window) X11GetMainWindow(), wmHints);
        XFree(wmHints);
#endif
    }
}

void wxTopLevelWindowX11::SetIcons(const wxIconBundle& icons )
{
    // this sets m_icon
    wxTopLevelWindowBase::SetIcons( icons );

    DoSetIcon( icons.GetIcon( -1 ) );
    wxSetIconsX11( wxGlobalDisplay(), X11GetMainWindow(), icons );
}

bool wxTopLevelWindowX11::SetShape(const wxRegion& region)
{
    return wxDoSetShape( wxGlobalDisplay(),
                         (Window)X11GetMainWindow(),
                         region );
}

void wxTopLevelWindowX11::SetTitle(const wxString& title)
{
    m_title = title;

    if (X11GetMainWindow())
    {
#if wxUSE_UNICODE
        //  I wonder of e.g. Metacity takes UTF-8 here
        XStoreName(wxGlobalDisplay(), (Window) X11GetMainWindow(),
            (const char*) title.ToAscii() );
        XSetIconName(wxGlobalDisplay(), (Window) X11GetMainWindow(),
            (const char*) title.ToAscii() );
#else
        XStoreName(wxGlobalDisplay(), (Window) X11GetMainWindow(),
            (const char*) title);
        XSetIconName(wxGlobalDisplay(), (Window) X11GetMainWindow(),
            (const char*) title);
#endif
    }
}

wxString wxTopLevelWindowX11::GetTitle() const
{
    return m_title;
}

// For implementation purposes - sometimes decorations make the client area
// smaller
wxPoint wxTopLevelWindowX11::GetClientAreaOrigin() const
{
    // wxFrame::GetClientAreaOrigin
    // does the required calculation already.
    return wxPoint(0, 0);
}

void wxTopLevelWindowX11::DoGetClientSize( int *width, int *height ) const
{
    if (width)
       *width = m_width;
    if (height)
       *height = m_height;
}

void wxTopLevelWindowX11::DoGetSize( int *width, int *height ) const
{
    // TODO add non-client size

    if (width)
       *width = m_width;
    if (height)
       *height = m_height;
}

void wxTopLevelWindowX11::DoSetClientSize(int width, int height)
{
    int old_width = m_width;
    int old_height = m_height;

    m_width = width;
    m_height = height;

    if (m_width == old_width && m_height == old_height)
        return;

    // wxLogDebug("DoSetClientSize: %s (%ld) %dx%d", GetClassInfo()->GetClassName(), GetId(), width, height);

#if !wxUSE_NANOX
    XSizeHints size_hints;
    size_hints.flags = PSize;
    size_hints.width = width;
    size_hints.height = height;
    XSetWMNormalHints( wxGlobalDisplay(), (Window) X11GetMainWindow(), &size_hints );
#endif

    wxWindowX11::DoSetClientSize(width, height);
}

void wxTopLevelWindowX11::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
    int old_x = m_x;
    int old_y = m_y;
    int old_width = m_width;
    int old_height = m_height;

    if (x != wxDefaultCoord || (sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        m_x = x;

    if (y != wxDefaultCoord || (sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        m_y = y;

    if (width != wxDefaultCoord || (sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        m_width = width;

    if (height != wxDefaultCoord || (sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        m_height = height;

    if (m_x == old_x && m_y == old_y && m_width == old_width && m_height == old_height)
        return;

    // wxLogDebug("DoSetSize: %s (%ld) %d, %d %dx%d", GetClassInfo()->GetClassName(), GetId(), x, y, width, height);

#if !wxUSE_NANOX
    XSizeHints size_hints;
    size_hints.flags = 0;
    size_hints.flags |= PPosition;
    size_hints.flags |= PSize;
    size_hints.x = m_x;
    size_hints.y = m_y;
    size_hints.width = m_width;
    size_hints.height = m_height;
    XSetWMNormalHints( wxGlobalDisplay(), (Window) X11GetMainWindow(), &size_hints);
#endif

    wxWindowX11::DoSetSize(x, y, width, height, sizeFlags);

#if 0
    Display *display = wxGlobalDisplay();
    Window root = RootWindowOfScreen(DefaultScreenOfDisplay(display));
    Window parent_window = window,
        next_parent   = window;

    // search for the parent that is child of ROOT, because the WM may
    // reparent twice and notify only the next parent (like FVWM)
    while (next_parent != root) {
        Window *theChildren;
#if wxUSE_NANOX
        GR_COUNT n;
#else
        unsigned int n;
#endif
        parent_window = next_parent;
        XQueryTree(display, parent_window, &root,
            &next_parent, &theChildren, &n);
        XFree(theChildren); // not needed
    }

    XWindowChanges windowChanges;
    windowChanges.x = x;
    windowChanges.y = y;
    windowChanges.width = width;
    windowChanges.height = height;
    windowChanges.stack_mode = 0;
    int valueMask = CWX | CWY | CWWidth | CWHeight;

    if (x != wxDefaultCoord || (sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
    {
        valueMask |= CWX;
    }
    if (y != wxDefaultCoord || (sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
    {
        valueMask |= CWY;
    }
    if (width != wxDefaultCoord)
    {
        windowChanges.width = wxMax(1, width);
        valueMask |= CWWidth;
    }
    if (height != wxDefaultCoord)
    {
        windowChanges.height = wxMax(1, height);
        valueMask |= CWHeight;
    }

    XConfigureWindow( display, parent_window, valueMask, &windowChanges );
#endif
}

void wxTopLevelWindowX11::DoGetPosition(int *x, int *y) const
{
    XSync(wxGlobalDisplay(), False);
    Window window = (Window) m_mainWindow;
    if (!window)
        return ;

    Display *display = wxGlobalDisplay();
    Window root = RootWindowOfScreen(DefaultScreenOfDisplay(display));
    Window parent_window = window,
        next_parent   = window;

    // search for the parent that is child of ROOT, because the WM may
    // reparent twice and notify only the next parent (like FVWM)
    while (next_parent != root) {
        Window *theChildren;
#if wxUSE_NANOX
        GR_COUNT n;
#else
        unsigned int n;
#endif
        parent_window = next_parent;
        XQueryTree(display, parent_window, &root,
            &next_parent, &theChildren, &n);
        XFree(theChildren); // not needed
    }
#if 0
    int xx, yy; unsigned int dummy;
    XGetGeometry(display, parent_window, &root,
                 &xx, &yy, &dummy, &dummy, &dummy, &dummy);
    if (x) *x = xx;
    if (y) *y = yy;
#else
    XWindowAttributes attr;
    Status status = XGetWindowAttributes( wxGlobalDisplay(), parent_window, & attr);
    if (status)
    {
        if (x) *x = attr.x;
        if (y) *y = attr.y;
    }
    else
    {
        if (x) *x = 0;
        if (y) *y = 0;
    }
#endif
}


#ifndef MWM_DECOR_BORDER

#define MWM_HINTS_FUNCTIONS     (1L << 0)
#define MWM_HINTS_DECORATIONS   (1L << 1)
#define MWM_HINTS_INPUT_MODE    (1L << 2)
#define MWM_HINTS_STATUS        (1L << 3)

#define MWM_DECOR_ALL           (1L << 0)
#define MWM_DECOR_BORDER        (1L << 1)
#define MWM_DECOR_RESIZEH       (1L << 2)
#define MWM_DECOR_TITLE         (1L << 3)
#define MWM_DECOR_MENU          (1L << 4)
#define MWM_DECOR_MINIMIZE      (1L << 5)
#define MWM_DECOR_MAXIMIZE      (1L << 6)

#define MWM_FUNC_ALL            (1L << 0)
#define MWM_FUNC_RESIZE         (1L << 1)
#define MWM_FUNC_MOVE           (1L << 2)
#define MWM_FUNC_MINIMIZE       (1L << 3)
#define MWM_FUNC_MAXIMIZE       (1L << 4)
#define MWM_FUNC_CLOSE          (1L << 5)

#define MWM_INPUT_MODELESS 0
#define MWM_INPUT_PRIMARY_APPLICATION_MODAL 1
#define MWM_INPUT_SYSTEM_MODAL 2
#define MWM_INPUT_FULL_APPLICATION_MODAL 3
#define MWM_INPUT_APPLICATION_MODAL MWM_INPUT_PRIMARY_APPLICATION_MODAL

#define MWM_TEAROFF_WINDOW (1L<<0)

#endif

struct MwmHints {
    long flags;
    long functions;
    long decorations;
    long input_mode;
};

#define PROP_MOTIF_WM_HINTS_ELEMENTS 5

// Set the window manager decorations according to the
// given wxWidgets style
bool wxSetWMDecorations(Window w, long style)
{
#if wxUSE_NANOX
    GR_WM_PROPERTIES wmProp;

    wmProp.flags = 0;
    wmProp.props = 0;

    if (style & wxRESIZE_BORDER)
    {
        wmProp.props |= GR_WM_PROPS_APPFRAME ;
        wmProp.flags |= GR_WM_FLAGS_PROPS ;
    }

    if (style & wxCLOSE_BOX)
    {
        wmProp.props |= GR_WM_PROPS_CLOSEBOX ;
        wmProp.flags |= GR_WM_FLAGS_PROPS ;
    }

    if ((style & wxCAPTION) ||
        (style & wxTINY_CAPTION))
    {
        wmProp.props |= GR_WM_PROPS_CAPTION ;
        wmProp.flags |= GR_WM_FLAGS_PROPS ;

        // The default dialog style doesn't include any kind
        // of border, which is a bit odd. Anyway, inclusion
        // of a caption surely implies a border.
        style |= wxRESIZE_BORDER;
    }

    if (style & wxRESIZE_BORDER)
    {
        wmProp.props |= GR_WM_PROPS_APPFRAME ;
        wmProp.flags |= GR_WM_FLAGS_PROPS ;
    }

    if (style & wxSIMPLE_BORDER)
    {
        wmProp.props |= GR_WM_PROPS_BORDER ;
        wmProp.flags |= GR_WM_FLAGS_PROPS ;
    }

    if (style & wxMINIMIZE_BOX)
    {
    }

    if (style & wxMAXIMIZE_BOX)
    {
        wmProp.props |= GR_WM_PROPS_MAXIMIZE ;
        wmProp.flags |= GR_WM_FLAGS_PROPS ;
    }

    if (((style & wxBORDER) != wxBORDER) && ((style & wxRESIZE_BORDER) != wxRESIZE_BORDER)
        && ((style & wxRESIZE_BORDER) != wxRESIZE_BORDER))
    {
        wmProp.props |= GR_WM_PROPS_NODECORATE ;
        wmProp.flags |= GR_WM_FLAGS_PROPS ;
    }

    GrSetWMProperties(w, & wmProp);

#else

    Atom mwm_wm_hints = XInternAtom(wxGlobalDisplay(),"_MOTIF_WM_HINTS", False);
    if (mwm_wm_hints == 0)
       return false;

    MwmHints hints;
    hints.flags = MWM_HINTS_DECORATIONS | MWM_HINTS_FUNCTIONS;
    hints.decorations = 0;
    hints.functions = 0;

    if ((style & wxSIMPLE_BORDER) || (style & wxNO_BORDER))
    {
        // leave zeros
    }
    else
    {
        hints.decorations = MWM_DECOR_BORDER;
        hints.functions = MWM_FUNC_MOVE;

        if ((style & wxCAPTION) != 0)
            hints.decorations |= MWM_DECOR_TITLE;

        if ((style & wxSYSTEM_MENU) != 0)
            hints.decorations |= MWM_DECOR_MENU;

        if ((style & wxCLOSE_BOX) != 0)
            hints.functions |= MWM_FUNC_CLOSE;

        if ((style & wxMINIMIZE_BOX) != 0)
        {
            hints.functions |= MWM_FUNC_MINIMIZE;
            hints.decorations |= MWM_DECOR_MINIMIZE;
        }

        if ((style & wxMAXIMIZE_BOX) != 0)
        {
            hints.functions |= MWM_FUNC_MAXIMIZE;
            hints.decorations |= MWM_DECOR_MAXIMIZE;
        }

        if ((style & wxRESIZE_BORDER) != 0)
        {
            hints.functions |= MWM_FUNC_RESIZE;
            hints.decorations |= MWM_DECOR_RESIZEH;
        }
    }

    XChangeProperty(wxGlobalDisplay(),
                    w,
                    mwm_wm_hints, mwm_wm_hints,
                    32, PropModeReplace,
                    (unsigned char *) &hints, PROP_MOTIF_WM_HINTS_ELEMENTS);

#endif
    return true;
}
