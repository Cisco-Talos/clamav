/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/mdi.h
// Purpose:     MDI (Multiple Document Interface) classes
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_MDI_H_
#define _WX_MDI_H_

#include "wx/frame.h"

WXDLLIMPEXP_DATA_CORE(extern const wxChar) wxStatusLineNameStr[];

class WXDLLIMPEXP_FWD_CORE wxMDIClientWindow;
class WXDLLIMPEXP_FWD_CORE wxMDIChildFrame;

// ---------------------------------------------------------------------------
// wxMDIParentFrame
// ---------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxMDIParentFrame : public wxFrame
{
public:
    wxMDIParentFrame();
    wxMDIParentFrame(wxWindow *parent,
                     wxWindowID id,
                     const wxString& title,
                     const wxPoint& pos = wxDefaultPosition,
                     const wxSize& size = wxDefaultSize,
                     long style = wxDEFAULT_FRAME_STYLE | wxVSCROLL | wxHSCROLL,
                     const wxString& name = wxFrameNameStr)
    {
        Create(parent, id, title, pos, size, style, name);
    }

    virtual ~wxMDIParentFrame();

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& title,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxDEFAULT_FRAME_STYLE | wxVSCROLL | wxHSCROLL,
                const wxString& name = wxFrameNameStr);

    // accessors
    // ---------

    // Get the active MDI child window (Windows only)
    wxMDIChildFrame *GetActiveChild() const;

    // Get the client window
    wxMDIClientWindow *GetClientWindow() const { return m_clientWindow; }

    // Create the client window class (don't Create the window,
    // just return a new class)
    virtual wxMDIClientWindow *OnCreateClient(void);

    // MDI windows menu
    wxMenu* GetWindowMenu() const { return m_windowMenu; };
    void SetWindowMenu(wxMenu* menu) ;

    // MDI operations
    // --------------
    virtual void Cascade();
    virtual void Tile();
    virtual void ArrangeIcons();
    virtual void ActivateNext();
    virtual void ActivatePrevious();

    // handlers
    // --------

    void OnSize(wxSizeEvent& event);

    // override window proc for MDI-specific message processing
    virtual WXLRESULT MSWWindowProc(WXUINT nMsg, WXWPARAM wParam, WXLPARAM lParam);

    virtual WXLRESULT MSWDefWindowProc(WXUINT, WXWPARAM, WXLPARAM);
    virtual bool MSWTranslateMessage(WXMSG* msg);

protected:
#if wxUSE_MENUS_NATIVE
    virtual void InternalSetMenuBar();
#endif // wxUSE_MENUS_NATIVE

    virtual WXHICON GetDefaultIcon() const;

    wxMDIClientWindow *             m_clientWindow;
    wxMDIChildFrame *               m_currentChild;
    wxMenu*                         m_windowMenu;

    // true if MDI Frame is intercepting commands, not child
    bool m_parentFrameActive;

private:
    friend class WXDLLIMPEXP_FWD_CORE wxMDIChildFrame;

    DECLARE_EVENT_TABLE()
    DECLARE_DYNAMIC_CLASS(wxMDIParentFrame)
    wxDECLARE_NO_COPY_CLASS(wxMDIParentFrame);
};

// ---------------------------------------------------------------------------
// wxMDIChildFrame
// ---------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxMDIChildFrame : public wxFrame
{
public:
    wxMDIChildFrame() { Init(); }
    wxMDIChildFrame(wxMDIParentFrame *parent,
                    wxWindowID id,
                    const wxString& title,
                    const wxPoint& pos = wxDefaultPosition,
                    const wxSize& size = wxDefaultSize,
                    long style = wxDEFAULT_FRAME_STYLE,
                    const wxString& name = wxFrameNameStr)
    {
        Init();

        Create(parent, id, title, pos, size, style, name);
    }

    virtual ~wxMDIChildFrame();

    bool Create(wxMDIParentFrame *parent,
                wxWindowID id,
                const wxString& title,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxDEFAULT_FRAME_STYLE,
                const wxString& name = wxFrameNameStr);

    virtual bool IsTopLevel() const { return false; }

    // MDI operations
    virtual void Maximize(bool maximize = true);
    virtual void Restore();
    virtual void Activate();

    // Implementation only from now on
    // -------------------------------

    // Handlers
    bool HandleMDIActivate(long bActivate, WXHWND, WXHWND);
    bool HandleWindowPosChanging(void *lpPos);

    virtual WXLRESULT MSWWindowProc(WXUINT message, WXWPARAM wParam, WXLPARAM lParam);
    virtual WXLRESULT MSWDefWindowProc(WXUINT message, WXWPARAM wParam, WXLPARAM lParam);
    virtual bool MSWTranslateMessage(WXMSG *msg);

    virtual void MSWDestroyWindow();

    bool ResetWindowStyle(void *vrect);

    void OnIdle(wxIdleEvent& event);

protected:
    virtual void DoGetPosition(int *x, int *y) const;
    virtual void DoSetClientSize(int width, int height);
    virtual void InternalSetMenuBar();
    virtual bool IsMDIChild() const { return true; }

    virtual WXHICON GetDefaultIcon() const;

    // common part of all ctors
    void Init();

private:
    bool m_needsResize; // flag which tells us to artificially resize the frame

    DECLARE_EVENT_TABLE()
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxMDIChildFrame)
};

// ---------------------------------------------------------------------------
// wxMDIClientWindow
// ---------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxMDIClientWindow : public wxWindow
{
public:
    wxMDIClientWindow() { Init(); }
    wxMDIClientWindow(wxMDIParentFrame *parent, long style = 0)
    {
        Init();

        CreateClient(parent, style);
    }

    // Note: this is virtual, to allow overridden behaviour.
    virtual bool CreateClient(wxMDIParentFrame *parent,
                              long style = wxVSCROLL | wxHSCROLL);

    // Explicitly call default scroll behaviour
    void OnScroll(wxScrollEvent& event);

    virtual void DoSetSize(int x, int y,
                           int width, int height,
                           int sizeFlags = wxSIZE_AUTO);
protected:
    void Init() { m_scrollX = m_scrollY = 0; }

    int m_scrollX, m_scrollY;

private:
    DECLARE_EVENT_TABLE()
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxMDIClientWindow)
};

#endif
    // _WX_MDI_H_
