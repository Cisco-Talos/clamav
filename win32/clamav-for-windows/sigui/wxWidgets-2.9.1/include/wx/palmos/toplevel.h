///////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/toplevel.h
// Purpose:     wxTopLevelWindow
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - more than minimal functionality
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PALMOS_TOPLEVEL_H_
#define _WX_PALMOS_TOPLEVEL_H_

// ----------------------------------------------------------------------------
// wxTopLevelWindowPalm
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxTopLevelWindowPalm : public wxTopLevelWindowBase
{
public:
    // constructors and such
    wxTopLevelWindowPalm() { Init(); }

    wxTopLevelWindowPalm(wxWindow *parent,
                        wxWindowID id,
                        const wxString& title,
                        const wxPoint& pos = wxDefaultPosition,
                        const wxSize& size = wxDefaultSize,
                        long style = wxDEFAULT_FRAME_STYLE,
                        const wxString& name = wxFrameNameStr)
    {
        Init();

        (void)Create(parent, id, title, pos, size, style, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& title,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxDEFAULT_FRAME_STYLE,
                const wxString& name = wxFrameNameStr);

    virtual ~wxTopLevelWindowPalm();

    // implement base class pure virtuals

    virtual void SetTitle( const wxString& title);
    virtual wxString GetTitle() const;

    virtual void Maximize(bool maximize = true);
    virtual bool IsMaximized() const;
    virtual void Iconize(bool iconize = true);
    virtual bool IsIconized() const;
    virtual void SetIcons(const wxIconBundle& icons);
    virtual void Restore();

#ifndef __WXWINCE__
    virtual bool SetShape(const wxRegion& region);
#endif // __WXWINCE__

    virtual bool Show(bool show = true);

    virtual bool ShowFullScreen(bool show, long style = wxFULLSCREEN_ALL);
    virtual bool IsFullScreen() const { return m_fsIsShowing; }

    // wxPalm only: EnableCloseButton(false) may be used to remove the "Close"
    // button from the title bar
    bool EnableCloseButton(bool enable = true);

    // implementation from now on
    // --------------------------

    // event handlers
    void OnActivate(wxActivateEvent& event);

    // called by wxWindow whenever it gets focus
    void SetLastFocus(wxWindow *win) { m_winLastFocused = win; }
    wxWindow *GetLastFocus() const { return m_winLastFocused; }

    // interface to native frame structure
    WXFORMPTR GetForm() const;

    // handle native events
    bool HandleControlSelect(WXEVENTPTR event);
    bool HandleControlRepeat(WXEVENTPTR event);
    bool HandleSize(WXEVENTPTR event);

    virtual WXWINHANDLE GetWinHandle() const;

protected:
    // common part of all ctors
    void Init();

    // getting and setting sizes
    virtual void DoGetSize( int *width, int *height ) const;

    // common part of Iconize(), Maximize() and Restore()
    void DoShowWindow(int nShowCmd);

    // translate wxWidgets flags to Windows ones
    virtual WXDWORD PalmGetStyle(long flags, WXDWORD *exstyle) const;

    // is the window currently iconized?
    bool m_iconized;

    // should the frame be maximized when it will be shown? set by Maximize()
    // when it is called while the frame is hidden
    bool m_maximizeOnShow;

    // Data to save/restore when calling ShowFullScreen
    long                  m_fsStyle; // Passed to ShowFullScreen
    wxRect                m_fsOldSize;
    long                  m_fsOldWindowStyle;
    bool                  m_fsIsMaximized;
    bool                  m_fsIsShowing;

    // the last focused child: we restore focus to it on activation
    wxWindow             *m_winLastFocused;

    DECLARE_EVENT_TABLE()
    wxDECLARE_NO_COPY_CLASS(wxTopLevelWindowPalm);
};

#endif // _WX_PALMOS_TOPLEVEL_H_
