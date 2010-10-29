/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/window.h
// Purpose:     wxWindow class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - more than minimal functionality
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_WINDOW_H_
#define _WX_WINDOW_H_

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// [at least] some version of Windows send extra mouse move messages after
// a mouse click or a key press - to temporarily fix this problem, set the
// define below to 1
//
// a better solution should be found later...
#define wxUSE_MOUSEEVENT_HACK 0

// ---------------------------------------------------------------------------
// wxWindow declaration for Palm
// ---------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxWindowPalm : public wxWindowBase
{
public:
    wxWindowPalm() { Init(); }

    wxWindowPalm(wxWindow *parent,
                wxWindowID id,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxString& name = wxPanelNameStr)
    {
        Init();
        Create(parent, id, pos, size, style, name);
    }

    virtual ~wxWindowPalm();

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxString& name = wxPanelNameStr);

    // implement base class pure virtuals

    virtual void SetLabel( const wxString& label);
    virtual wxString GetLabel() const;

    virtual void Raise();
    virtual void Lower();

    virtual bool Show( bool show = true );
    virtual bool Enable( bool enable = true );

    virtual void SetFocus();
    virtual void SetFocusFromKbd();

    virtual bool Reparent(wxWindowBase *newParent);

    virtual void WarpPointer(int x, int y);

    virtual void Refresh( bool eraseBackground = true,
                          const wxRect *rect = NULL );
    virtual void Update();

    virtual bool SetCursor( const wxCursor &cursor );
    virtual bool SetFont( const wxFont &font );

    virtual int GetCharHeight() const;
    virtual int GetCharWidth() const;

#if wxUSE_MENUS_NATIVE
    virtual bool DoPopupMenu( wxMenu *menu, int x, int y );
#endif // wxUSE_MENUS_NATIVE

    virtual void SetScrollbar( int orient, int pos, int thumbVisible,
                               int range, bool refresh = true );
    virtual void SetScrollPos( int orient, int pos, bool refresh = true );
    virtual int GetScrollPos( int orient ) const;
    virtual int GetScrollThumb( int orient ) const;
    virtual int GetScrollRange( int orient ) const;
    virtual void ScrollWindow( int dx, int dy,
                               const wxRect* rect = NULL );

    virtual bool ScrollLines(int lines);
    virtual bool ScrollPages(int pages);

#if wxUSE_DRAG_AND_DROP
    virtual void SetDropTarget( wxDropTarget *dropTarget );
#endif // wxUSE_DRAG_AND_DROP

    // Accept files for dragging
    virtual void DragAcceptFiles(bool accept);

#ifndef __WXUNIVERSAL__
    // Native resource loading (implemented in src/Palm/nativdlg.cpp)
    // FIXME: should they really be all virtual?
    virtual bool LoadNativeDialog(wxWindow* parent, wxWindowID& id);
    virtual bool LoadNativeDialog(wxWindow* parent, const wxString& name);
    wxWindow* GetWindowChild1(wxWindowID id);
    wxWindow* GetWindowChild(wxWindowID id);
#endif // __WXUNIVERSAL__

#if wxUSE_HOTKEY
    // install and deinstall a system wide hotkey
    virtual bool RegisterHotKey(int hotkeyId, int modifiers, int keycode);
    virtual bool UnregisterHotKey(int hotkeyId);
#endif // wxUSE_HOTKEY

    // implementation from now on
    // --------------------------

    // simple accessors
    // ----------------

    WXHWND GetHWND() const { return m_hWnd; }
    void SetHWND(WXHWND hWnd) { m_hWnd = hWnd; }
    virtual WXWidget GetHandle() const { return GetHWND(); }

    // event handlers
    // --------------

    void OnEraseBackground(wxEraseEvent& event);
    void OnPaint(wxPaintEvent& event);

public:
    wxWindow *FindItem(long id) const;
    wxWindow *FindItemByWinHandle(WXWINHANDLE handle, bool controlOnly = false) const;

    // Palm only: true if this control is part of the main control
    virtual bool ContainsWinHandle(WXWINHANDLE WXUNUSED(handle)) const { return false; };

    // translate wxWidgets style flags for this control into the Windows style
    // and optional extended style for the corresponding native control
    //
    // this is the function that should be overridden in the derived classes,
    // but you will mostly use PalmGetCreateWindowFlags() below
    virtual WXDWORD PalmGetStyle(long flags, WXDWORD *exstyle = NULL) const ;

    // get the Palm window flags corresponding to wxWidgets ones
    //
    // the functions returns the flags (WS_XXX) directly and puts the ext
    // (WS_EX_XXX) flags into the provided pointer if not NULL
    WXDWORD PalmGetCreateWindowFlags(WXDWORD *exflags = NULL) const
        { return PalmGetStyle(GetWindowStyle(), exflags); }

    // translate wxWidgets coords into Windows ones suitable to be passed to
    // ::CreateWindow()
    //
    // returns true if non default coords are returned, false otherwise
    bool PalmGetCreateWindowCoords(const wxPoint& pos,
                                  const wxSize& size,
                                  int& x, int& y,
                                  int& w, int& h) const;

    // creates the window of specified Windows class with given style, extended
    // style, title and geometry (default values
    //
    // returns true if the window has been created, false if creation failed
    bool PalmCreate(const wxChar *wclass,
                   const wxChar *title = NULL,
                   const wxPoint& pos = wxDefaultPosition,
                   const wxSize& size = wxDefaultSize,
                   WXDWORD style = 0,
                   WXDWORD exendedStyle = 0);

#ifndef __WXUNIVERSAL__
    // Create an appropriate wxWindow from a WinHandle
    virtual wxWindow* CreateWindowFromWinHandle(wxWindow* parent, WXWINHANDLE handle);

    // Make sure the window style reflects the WinHandle style (roughly)
    virtual void AdoptAttributesFromWinHandle();
#endif // __WXUNIVERSAL__

    // Setup background and foreground colours correctly
    virtual void SetupColours();

    // ------------------------------------------------------------------------
    // internal handlers for Palm messages: all handlers return a boolean value:
    // true means that the handler processed the event and false that it didn't
    // ------------------------------------------------------------------------

    // scroll event (both horizontal and vertical)
    virtual bool PalmOnScroll(int orientation, WXWORD nSBCode,
                              WXWORD pos, WXWINHANDLE control);

    // virtual function for implementing internal idle
    // behaviour
    virtual void OnInternalIdle() ;

protected:
    // the window handle
    WXHWND                m_hWnd;
    WXFORMPTR FrameForm;

    WXFORMPTR GetFormPtr();
    void SetFormPtr(WXFORMPTR FormPtr);

    // additional (Palm specific) flags
    bool                  m_mouseInWindow:1;
    bool                  m_lastKeydownProcessed:1;

    // the size of one page for scrolling
    int                   m_xThumbSize;
    int                   m_yThumbSize;

#if wxUSE_MOUSEEVENT_HACK
    // the coordinates of the last mouse event and the type of it
    long                  m_lastMouseX,
                          m_lastMouseY;
    int                   m_lastMouseEvent;
#endif // wxUSE_MOUSEEVENT_HACK

    WXHMENU               m_hMenu; // Menu, if any

    // implement the base class pure virtuals
    virtual void DoGetTextExtent(const wxString& string,
                                 int *x, int *y,
                                 int *descent = NULL,
                                 int *externalLeading = NULL,
                                 const wxFont *font = NULL) const;
    virtual void DoClientToScreen( int *x, int *y ) const;
    virtual void DoScreenToClient( int *x, int *y ) const;
    virtual void DoGetPosition( int *x, int *y ) const;
    virtual void DoGetSize( int *width, int *height ) const;
    virtual void DoGetClientSize( int *width, int *height ) const;
    virtual void DoSetSize(int x, int y,
                           int width, int height,
                           int sizeFlags = wxSIZE_AUTO);
    virtual void DoSetClientSize(int width, int height);

    virtual void DoCaptureMouse();
    virtual void DoReleaseMouse();

    // move the window to the specified location and resize it: this is called
    // from both DoSetSize() and DoSetClientSize() and would usually just call
    // ::MoveWindow() except for composite controls which will want to arrange
    // themselves inside the given rectangle
    virtual void DoMoveWindow(int x, int y, int width, int height);

#if wxUSE_TOOLTIPS
    virtual void DoSetToolTip( wxToolTip *tip );

    // process TTN_NEEDTEXT message properly (i.e. fixing the bugs in
    // comctl32.dll in our code -- see the function body for more info)
    bool HandleTooltipNotify(WXUINT code,
                             WXLPARAM lParam,
                             const wxString& ttip);
#endif // wxUSE_TOOLTIPS

private:
    // common part of all ctors
    void Init();

    // the (non-virtual) handlers for the events
    bool HandleMove(int x, int y);
    bool HandleMoving(wxRect& rect);
    bool HandleJoystickEvent(WXUINT msg, int x, int y, WXUINT flags);

    DECLARE_DYNAMIC_CLASS(wxWindowPalm)
    wxDECLARE_NO_COPY_CLASS(wxWindowPalm);
    DECLARE_EVENT_TABLE()
};

// ----------------------------------------------------------------------------
// global objects
// ----------------------------------------------------------------------------

// notice that this hash must be defined after wxWindow declaration as it
// needs to "see" its dtor and not just forward declaration
#include "wx/hash.h"

// pseudo-template WinHandle <-> wxWindow hash table
WX_DECLARE_HASH(wxWindowPalm, wxWindowList, wxWinHashTable);

extern wxWinHashTable *wxWinHandleHash;

#endif
    // _WX_WINDOW_H_
