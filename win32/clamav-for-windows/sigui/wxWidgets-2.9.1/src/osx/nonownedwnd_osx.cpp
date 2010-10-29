/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/nonownedwnd_osx.cpp
// Purpose:     implementation of wxNonOwnedWindow
// Author:      Stefan Csomor
// Created:     2008-03-24
// RCS-ID:      $Id: nonownedwnd.cpp 50329 2007-11-29 17:00:58Z VS $
// Copyright:   (c) Stefan Csomor 2008
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/log.h"
#endif // WX_PRECOMP

#include "wx/hashmap.h"
#include "wx/evtloop.h"
#include "wx/tooltip.h"
#include "wx/nonownedwnd.h"

#include "wx/osx/private.h"
#include "wx/settings.h"
#include "wx/frame.h"

#if wxUSE_SYSTEM_OPTIONS
    #include "wx/sysopt.h"
#endif

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// trace mask for activation tracing messages
#define TRACE_ACTIVATE "activation"

wxWindow* g_MacLastWindow = NULL ;

// unified title and toolbar constant - not in Tiger headers, so we duplicate it here
#define kWindowUnifiedTitleAndToolbarAttribute (1 << 7)

// ---------------------------------------------------------------------------
// wxWindowMac utility functions
// ---------------------------------------------------------------------------

WX_DECLARE_HASH_MAP(WXWindow, wxNonOwnedWindowImpl*, wxPointerHash, wxPointerEqual, MacWindowMap);

static MacWindowMap wxWinMacWindowList;

wxNonOwnedWindow* wxNonOwnedWindow::GetFromWXWindow( WXWindow win )
{
    wxNonOwnedWindowImpl* impl = wxNonOwnedWindowImpl::FindFromWXWindow(win);
    
    return ( impl != NULL ? impl->GetWXPeer() : NULL ) ;
}

wxNonOwnedWindowImpl* wxNonOwnedWindowImpl::FindFromWXWindow (WXWindow window)
{
    MacWindowMap::iterator node = wxWinMacWindowList.find(window);
    
    return (node == wxWinMacWindowList.end()) ? NULL : node->second;
}

void wxNonOwnedWindowImpl::RemoveAssociations( wxNonOwnedWindowImpl* impl)
{
    MacWindowMap::iterator it;
    for ( it = wxWinMacWindowList.begin(); it != wxWinMacWindowList.end(); ++it )
    {
        if ( it->second == impl )
        {
            wxWinMacWindowList.erase(it);
            break;
        }
    }
}

void wxNonOwnedWindowImpl::Associate( WXWindow window, wxNonOwnedWindowImpl *impl )
{
    // adding NULL WindowRef is (first) surely a result of an error and
    // nothing else :-)
    wxCHECK_RET( window != (WXWindow) NULL, wxT("attempt to add a NULL WindowRef to window list") );
    
    wxWinMacWindowList[window] = impl;
}

// ----------------------------------------------------------------------------
// wxNonOwnedWindow creation
// ----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS( wxNonOwnedWindowImpl , wxObject )

wxNonOwnedWindow *wxNonOwnedWindow::s_macDeactivateWindow = NULL;

void wxNonOwnedWindow::Init()
{
    m_nowpeer = NULL;
    m_isNativeWindowWrapper = false;
}

bool wxNonOwnedWindow::Create(wxWindow *parent,
                                 wxWindowID id,
                                 const wxPoint& pos,
                                 const wxSize& size,
                                 long style,
                                 const wxString& name)
{
    m_windowStyle = style;

    SetName( name );

    m_windowId = id == -1 ? NewControlId() : id;
    m_windowStyle = style;
    m_isShown = false;

    // create frame.
    int x = (int)pos.x;
    int y = (int)pos.y;

    wxRect display = wxGetClientDisplayRect() ;

    if ( x == wxDefaultPosition.x )
        x = display.x ;

    if ( y == wxDefaultPosition.y )
        y = display.y ;

    int w = WidthDefault(size.x);
    int h = HeightDefault(size.y);

    m_nowpeer = wxNonOwnedWindowImpl::CreateNonOwnedWindow(this, parent, wxPoint(x,y) , wxSize(w,h) , style , GetExtraStyle(), name );
    wxNonOwnedWindowImpl::Associate( m_nowpeer->GetWXWindow() , m_nowpeer ) ;
    m_peer = wxWidgetImpl::CreateContentView(this);

    DoSetWindowVariant( m_windowVariant ) ;

    wxWindowCreateEvent event(this);
    HandleWindowEvent(event);

    SetBackgroundColour(wxSystemSettings::GetColour( wxSYS_COLOUR_3DFACE ));

    if ( parent )
        parent->AddChild(this);

    return true;
}

bool wxNonOwnedWindow::Create(wxWindow *parent, WXWindow nativeWindow)
{
    m_nowpeer = wxNonOwnedWindowImpl::CreateNonOwnedWindow(this, parent, nativeWindow );
    m_isNativeWindowWrapper = true;
    wxNonOwnedWindowImpl::Associate( m_nowpeer->GetWXWindow() , m_nowpeer ) ;
    m_peer = wxWidgetImpl::CreateContentView(this);

    if ( parent )
        parent->AddChild(this);
    
    return true;
}

wxNonOwnedWindow::~wxNonOwnedWindow()
{
    SendDestroyEvent();

    wxNonOwnedWindowImpl::RemoveAssociations(m_nowpeer) ;

    DestroyChildren();

    wxDELETE(m_nowpeer);

    // avoid dangling refs
    if ( s_macDeactivateWindow == this )
        s_macDeactivateWindow = NULL;
}

bool wxNonOwnedWindow::Destroy()
{
    WillBeDestroyed();
    
    return wxWindow::Destroy();
}

void wxNonOwnedWindow::WillBeDestroyed()
{
    if ( m_nowpeer )
        m_nowpeer->WillBeDestroyed();
}

// ----------------------------------------------------------------------------
// wxNonOwnedWindow misc
// ----------------------------------------------------------------------------

bool wxNonOwnedWindow::OSXShowWithEffect(bool show,
                                         wxShowEffect effect,
                                         unsigned timeout)
{
    // Cocoa code needs to manage window visibility on its own and so calls
    // wxWindow::Show() as needed but if we already changed the internal
    // visibility flag here, Show() would do nothing, so avoid doing it
#if wxOSX_USE_CARBON
    if ( !wxWindow::Show(show) )
        return false;
#endif // Carbon

    if ( effect == wxSHOW_EFFECT_NONE ||
            !m_nowpeer || !m_nowpeer->ShowWithEffect(show, effect, timeout) )
        return Show(show);

    if ( show )
    {
        // as apps expect a size event to occur when the window is shown,
        // generate one when it is shown with effect too
        wxSizeEvent event(GetSize(), m_windowId);
        event.SetEventObject(this);
        HandleWindowEvent(event);
    }

    return true;
}

wxPoint wxNonOwnedWindow::GetClientAreaOrigin() const
{
    int left, top, width, height;
    m_nowpeer->GetContentArea(left, top, width, height);
    return wxPoint(left, top);
}

bool wxNonOwnedWindow::SetBackgroundColour(const wxColour& c )
{
    if ( !wxWindow::SetBackgroundColour(c) && m_hasBgCol )
        return false ;

    if ( GetBackgroundStyle() != wxBG_STYLE_CUSTOM )
    {
        if ( m_nowpeer )
            return m_nowpeer->SetBackgroundColour(c);
    }
    return true;
}

void wxNonOwnedWindow::SetWindowStyleFlag(long flags)
{
    if (flags == GetWindowStyleFlag())
        return;
        
    wxWindow::SetWindowStyleFlag(flags);
    
    if (m_nowpeer)
        m_nowpeer->SetWindowStyleFlag(flags);
}

// Raise the window to the top of the Z order
void wxNonOwnedWindow::Raise()
{
    m_nowpeer->Raise();
}

// Lower the window to the bottom of the Z order
void wxNonOwnedWindow::Lower()
{
    m_nowpeer->Lower();
}

void wxNonOwnedWindow::HandleActivated( double timestampsec, bool didActivate )
{
    MacActivate( (int) (timestampsec * 1000) , didActivate);
    wxActivateEvent wxevent(wxEVT_ACTIVATE, didActivate , GetId());
    wxevent.SetTimestamp( (int) (timestampsec * 1000) );
    wxevent.SetEventObject(this);
    HandleWindowEvent(wxevent);
}

void wxNonOwnedWindow::HandleResized( double timestampsec )
{
    wxSizeEvent wxevent( GetSize() , GetId());
    wxevent.SetTimestamp( (int) (timestampsec * 1000) );
    wxevent.SetEventObject( this );
    HandleWindowEvent(wxevent);
    // we have to inform some controls that have to reset things
    // relative to the toplevel window (e.g. OpenGL buffers)
    wxWindowMac::MacSuperChangedPosition() ; // like this only children will be notified
}

void wxNonOwnedWindow::HandleResizing( double WXUNUSED(timestampsec), wxRect* rect )
{
    wxRect r = *rect ;

    // this is a EVT_SIZING not a EVT_SIZE type !
    wxSizeEvent wxevent( r , GetId() ) ;
    wxevent.SetEventObject( this ) ;
    if ( HandleWindowEvent(wxevent) )
        r = wxevent.GetRect() ;

    if ( GetMaxWidth() != -1 && r.GetWidth() > GetMaxWidth() )
        r.SetWidth( GetMaxWidth() ) ;
    if ( GetMaxHeight() != -1 && r.GetHeight() > GetMaxHeight() )
        r.SetHeight( GetMaxHeight() ) ;
    if ( GetMinWidth() != -1 && r.GetWidth() < GetMinWidth() )
        r.SetWidth( GetMinWidth() ) ;
    if ( GetMinHeight() != -1 && r.GetHeight() < GetMinHeight() )
        r.SetHeight( GetMinHeight() ) ;

    *rect = r;
    // TODO actuall this is too early, in case the window extents are adjusted
    wxWindowMac::MacSuperChangedPosition() ; // like this only children will be notified
}

void wxNonOwnedWindow::HandleMoved( double timestampsec )
{
    wxMoveEvent wxevent( GetPosition() , GetId());
    wxevent.SetTimestamp( (int) (timestampsec * 1000) );
    wxevent.SetEventObject( this );
    HandleWindowEvent(wxevent);
}

void wxNonOwnedWindow::MacDelayedDeactivation(long timestamp)
{
    if (s_macDeactivateWindow)
    {
        wxLogTrace(TRACE_ACTIVATE,
                   wxT("Doing delayed deactivation of %p"),
                   s_macDeactivateWindow);

        s_macDeactivateWindow->MacActivate(timestamp, false);
    }
}

void wxNonOwnedWindow::MacActivate( long timestamp , bool WXUNUSED(inIsActivating) )
{
    wxLogTrace(TRACE_ACTIVATE, wxT("TopLevel=%p::MacActivate"), this);

    if (s_macDeactivateWindow == this)
        s_macDeactivateWindow = NULL;

    MacDelayedDeactivation(timestamp);
}

bool wxNonOwnedWindow::Show(bool show)
{
    if ( !wxWindow::Show(show) )
        return false;

    if ( m_nowpeer )
        m_nowpeer->Show(show);

    if ( show )
    {
        // because apps expect a size event to occur at this moment
        wxSizeEvent event(GetSize() , m_windowId);
        event.SetEventObject(this);
        HandleWindowEvent(event);
    }

    return true ;
}

bool wxNonOwnedWindow::SetTransparent(wxByte alpha)
{
    return m_nowpeer->SetTransparent(alpha);
}


bool wxNonOwnedWindow::CanSetTransparent()
{
    return m_nowpeer->CanSetTransparent();
}


void wxNonOwnedWindow::SetExtraStyle(long exStyle)
{
    if ( GetExtraStyle() == exStyle )
        return ;

    wxWindow::SetExtraStyle( exStyle ) ;

    if ( m_nowpeer )
        m_nowpeer->SetExtraStyle(exStyle);
}

bool wxNonOwnedWindow::SetBackgroundStyle(wxBackgroundStyle style)
{
    if ( !wxWindow::SetBackgroundStyle(style) )
        return false ;

    return m_nowpeer ? m_nowpeer->SetBackgroundStyle(style) : true;
}

void wxNonOwnedWindow::DoMoveWindow(int x, int y, int width, int height)
{
    if ( m_nowpeer == NULL )
        return;

    m_cachedClippedRectValid = false ;

    m_nowpeer->MoveWindow(x, y, width, height);
    wxWindowMac::MacSuperChangedPosition() ; // like this only children will be notified
}

void wxNonOwnedWindow::DoGetPosition( int *x, int *y ) const
{
    if ( m_nowpeer == NULL )
        return;

    int x1,y1 ;
    m_nowpeer->GetPosition(x1, y1);

    if (x)
       *x = x1 ;
    if (y)
       *y = y1 ;
}

void wxNonOwnedWindow::DoGetSize( int *width, int *height ) const
{
    if ( m_nowpeer == NULL )
        return;

    int w,h;

    m_nowpeer->GetSize(w, h);

    if (width)
       *width = w ;
    if (height)
       *height = h ;
}

void wxNonOwnedWindow::DoGetClientSize( int *width, int *height ) const
{
    if ( m_nowpeer == NULL )
        return;

    int left, top, w, h;
    m_nowpeer->GetContentArea(left, top, w, h);
    
    if (width)
       *width = w ;
    if (height)
       *height = h ;
}


void wxNonOwnedWindow::Update()
{
    m_nowpeer->Update();
}

WXWindow wxNonOwnedWindow::GetWXWindow() const
{
    return m_nowpeer ? m_nowpeer->GetWXWindow() : NULL;
}

// ---------------------------------------------------------------------------
// Shape implementation
// ---------------------------------------------------------------------------


bool wxNonOwnedWindow::DoSetShape(const wxRegion& region)
{
    wxCHECK_MSG( HasFlag(wxFRAME_SHAPED), false,
                 wxT("Shaped windows must be created with the wxFRAME_SHAPED style."));

    m_shape = region;
    
    // The empty region signifies that the shape
    // should be removed from the window.
    if ( region.IsEmpty() )
    {
        wxSize sz = GetClientSize();
        wxRegion rgn(0, 0, sz.x, sz.y);
        if ( rgn.IsEmpty() )
            return false ;
        else
            return DoSetShape(rgn);
    }

    return m_nowpeer->SetShape(region);
}
