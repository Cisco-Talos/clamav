///////////////////////////////////////////////////////////////////////////////
// Name:        wx/msw/tooltip.h
// Purpose:     wxToolTip class - tooltip control
// Author:      Vadim Zeitlin
// Modified by:
// Created:     31.01.99
// RCS-ID:      $Id$
// Copyright:   (c) 1999 Robert Roebling, Vadim Zeitlin
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_MSW_TOOLTIP_H_
#define _WX_MSW_TOOLTIP_H_

#include "wx/object.h"
#include "wx/gdicmn.h"

class WXDLLIMPEXP_FWD_CORE wxWindow;

class WXDLLIMPEXP_CORE wxToolTip : public wxObject
{
public:
    // ctor & dtor
    wxToolTip(const wxString &tip);
    virtual ~wxToolTip();

    // ctor used by wxStatusBar to associate a tooltip to a portion of
    // the status bar window:
    wxToolTip(wxWindow* win, unsigned int id,
              const wxString &tip, const wxRect& rc);

    // accessors
        // tip text
    void SetTip(const wxString& tip);
    const wxString& GetTip() const { return m_text; }

        // the window we're associated with
    void SetWindow(wxWindow *win);
    wxWindow *GetWindow() const { return m_window; }

    // controlling tooltip behaviour: globally change tooltip parameters
        // enable or disable the tooltips globally
    static void Enable(bool flag);
        // set the delay after which the tooltip appears
    static void SetDelay(long milliseconds);
        // set the delay after which the tooltip disappears or how long the
        // tooltip remains visible
    static void SetAutoPop(long milliseconds);
        // set the delay between subsequent tooltips to appear
    static void SetReshow(long milliseconds);
        // set maximum width for the new tooltips: -1 disables wrapping
        // entirely, 0 restores the default behaviour
    static void SetMaxWidth(int width);

    // implementation only from now on
    // -------------------------------

    // should be called in response to WM_MOUSEMOVE
    static void RelayEvent(WXMSG *msg);

    // add a window to the tooltip control
    void Add(WXHWND hwnd);

    // remove any tooltip from the window
    static void Remove(WXHWND hwnd, unsigned int id, const wxRect& rc);

    // the rect we're associated with
    void SetRect(const wxRect& rc);
    const wxRect& GetRect() const { return m_rect; }

private:
    // the one and only one tooltip control we use - never access it directly
    // but use GetToolTipCtrl() which will create it when needed
    static WXHWND ms_hwndTT;

    // create the tooltip ctrl if it doesn't exist yet and return its HWND
    static WXHWND GetToolTipCtrl();

    // new tooltip maximum width, defaults to min(display width, 400)
    static int ms_maxWidth;

    // remove this tooltip from the tooltip control
    void Remove();

    wxString  m_text;           // tooltip text
    wxWindow* m_window;         // window we're associated with
    wxRect    m_rect;           // the rect of the window for which this tooltip is shown
                                // (or a rect with width/height == 0 to show it for the entire window)
    unsigned int m_id;          // the id of this tooltip (ignored when m_rect width/height is 0)

    DECLARE_ABSTRACT_CLASS(wxToolTip)
    wxDECLARE_NO_COPY_CLASS(wxToolTip);
};

#endif // _WX_MSW_TOOLTIP_H_
