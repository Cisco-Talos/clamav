///////////////////////////////////////////////////////////////////////////////
// Name:        wx/ribbon/toolbar.h
// Purpose:     Ribbon-style tool bar
// Author:      Peter Cawley
// Modified by:
// Created:     2009-07-06
// RCS-ID:      $Id$
// Copyright:   (C) Peter Cawley
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////
#ifndef _WX_RIBBON_TOOLBAR_H_
#define _WX_RIBBON_TOOLBAR_H_

#include "wx/defs.h"

#if wxUSE_RIBBON

#include "wx/ribbon/control.h"
#include "wx/ribbon/art.h"

class wxRibbonToolBarToolBase;
class wxRibbonToolBarToolGroup;
WX_DEFINE_USER_EXPORTED_ARRAY(wxRibbonToolBarToolGroup*, wxArrayRibbonToolBarToolGroup, class WXDLLIMPEXP_RIBBON);

enum wxRibbonToolBarToolState
{
    wxRIBBON_TOOLBAR_TOOL_FIRST             = 1 << 0,
    wxRIBBON_TOOLBAR_TOOL_LAST              = 1 << 1,
    wxRIBBON_TOOLBAR_TOOL_POSITION_MASK     = wxRIBBON_TOOLBAR_TOOL_FIRST | wxRIBBON_TOOLBAR_TOOL_LAST,

    wxRIBBON_TOOLBAR_TOOL_NORMAL_HOVERED    = 1 << 3,
    wxRIBBON_TOOLBAR_TOOL_DROPDOWN_HOVERED  = 1 << 4,
    wxRIBBON_TOOLBAR_TOOL_HOVER_MASK        = wxRIBBON_TOOLBAR_TOOL_NORMAL_HOVERED | wxRIBBON_TOOLBAR_TOOL_DROPDOWN_HOVERED,
    wxRIBBON_TOOLBAR_TOOL_NORMAL_ACTIVE     = 1 << 5,
    wxRIBBON_TOOLBAR_TOOL_DROPDOWN_ACTIVE   = 1 << 6,
    wxRIBBON_TOOLBAR_TOOL_ACTIVE_MASK       = wxRIBBON_TOOLBAR_TOOL_NORMAL_ACTIVE | wxRIBBON_TOOLBAR_TOOL_DROPDOWN_ACTIVE,
    wxRIBBON_TOOLBAR_TOOL_DISABLED          = 1 << 7,
    wxRIBBON_TOOLBAR_TOOL_STATE_MASK        = 0xF8,
};


class WXDLLIMPEXP_RIBBON wxRibbonToolBar : public wxRibbonControl
{
public:
    wxRibbonToolBar();

    wxRibbonToolBar(wxWindow* parent,
                  wxWindowID id = wxID_ANY,
                  const wxPoint& pos = wxDefaultPosition,
                  const wxSize& size = wxDefaultSize,
                  long style = 0);

    virtual ~wxRibbonToolBar();

    bool Create(wxWindow* parent,
                wxWindowID id = wxID_ANY,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0);

    virtual wxRibbonToolBarToolBase* AddTool(
                int tool_id,
                const wxBitmap& bitmap,
                const wxString& help_string,
                wxRibbonButtonKind kind = wxRIBBON_BUTTON_NORMAL);

    virtual wxRibbonToolBarToolBase* AddDropdownTool(
                int tool_id,
                const wxBitmap& bitmap,
                const wxString& help_string = wxEmptyString);

    virtual wxRibbonToolBarToolBase* AddHybridTool(
                int tool_id,
                const wxBitmap& bitmap,
                const wxString& help_string = wxEmptyString);

    virtual wxRibbonToolBarToolBase* AddTool(
                int tool_id,
                const wxBitmap& bitmap,
                const wxBitmap& bitmap_disabled = wxNullBitmap,
                const wxString& help_string = wxEmptyString,
                wxRibbonButtonKind kind = wxRIBBON_BUTTON_NORMAL,
                wxObject* client_data = NULL);

    virtual wxRibbonToolBarToolBase* AddSeparator();

    virtual bool Realize();
    virtual void SetRows(int nMin, int nMax = -1);

    virtual bool IsSizingContinuous() const;

protected:
    friend class wxRibbonToolBarEvent;
    virtual wxSize DoGetBestSize() const;
    wxBorder GetDefaultBorder() const { return wxBORDER_NONE; }

    void OnEraseBackground(wxEraseEvent& evt);
    void OnMouseDown(wxMouseEvent& evt);
    void OnMouseEnter(wxMouseEvent& evt);
    void OnMouseLeave(wxMouseEvent& evt);
    void OnMouseMove(wxMouseEvent& evt);
    void OnMouseUp(wxMouseEvent& evt);
    void OnPaint(wxPaintEvent& evt);
    void OnSize(wxSizeEvent& evt);

    virtual wxSize DoGetNextSmallerSize(wxOrientation direction,
                                      wxSize relative_to) const;
    virtual wxSize DoGetNextLargerSize(wxOrientation direction,
                                     wxSize relative_to) const;

    void CommonInit(long style);
    void AppendGroup();

    static wxBitmap MakeDisabledBitmap(const wxBitmap& original);

    wxArrayRibbonToolBarToolGroup m_groups;
    wxRibbonToolBarToolBase* m_hover_tool;
    wxRibbonToolBarToolBase* m_active_tool;
    wxSize* m_sizes;
    int m_nrows_min;
    int m_nrows_max;

#ifndef SWIG
    DECLARE_CLASS(wxRibbonToolBar)
    DECLARE_EVENT_TABLE()
#endif
};


class WXDLLIMPEXP_RIBBON wxRibbonToolBarEvent : public wxCommandEvent
{
public:
    wxRibbonToolBarEvent(wxEventType command_type = wxEVT_NULL,
                       int win_id = 0,
                       wxRibbonToolBar* bar = NULL)
        : wxCommandEvent(command_type, win_id)
        , m_bar(bar)
    {
    }
#ifndef SWIG
    wxRibbonToolBarEvent(const wxRibbonToolBarEvent& e) : wxCommandEvent(e)
    {
        m_bar = e.m_bar;
    }
#endif
    wxEvent *Clone() const { return new wxRibbonToolBarEvent(*this); }

    wxRibbonToolBar* GetBar() {return m_bar;}
    void SetBar(wxRibbonToolBar* bar) {m_bar = bar;}
    bool PopupMenu(wxMenu* menu);

protected:
    wxRibbonToolBar* m_bar;

#ifndef SWIG
private:
    DECLARE_DYNAMIC_CLASS_NO_ASSIGN(wxRibbonToolBarEvent)
#endif
};

#ifndef SWIG

wxDECLARE_EXPORTED_EVENT(WXDLLIMPEXP_RIBBON, wxEVT_COMMAND_RIBBONTOOL_CLICKED, wxRibbonToolBarEvent);
wxDECLARE_EXPORTED_EVENT(WXDLLIMPEXP_RIBBON, wxEVT_COMMAND_RIBBONTOOL_DROPDOWN_CLICKED, wxRibbonToolBarEvent);

typedef void (wxEvtHandler::*wxRibbonToolBarEventFunction)(wxRibbonToolBarEvent&);

#define wxRibbonToolBarEventHandler(func) \
    wxEVENT_HANDLER_CAST(wxRibbonToolBarEventFunction, func)

#define EVT_RIBBONTOOLBAR_CLICKED(winid, fn) \
    wx__DECLARE_EVT1(wxEVT_COMMAND_RIBBONTOOL_CLICKED, winid, wxRibbonToolBarEventHandler(fn))
#define EVT_RIBBONTOOLBAR_DROPDOWN_CLICKED(winid, fn) \
    wx__DECLARE_EVT1(wxEVT_COMMAND_RIBBONTOOL_DROPDOWN_CLICKED, winid, wxRibbonToolBarEventHandler(fn))
#else

// wxpython/swig event work
%constant wxEventType wxEVT_COMMAND_RIBBONTOOL_CLICKED;
%constant wxEventType wxEVT_COMMAND_RIBBONTOOL_DROPDOWN_CLICKED;

%pythoncode {
    EVT_RIBBONTOOLBAR_CLICKED = wx.PyEventBinder( wxEVT_COMMAND_RIBBONTOOL_CLICKED, 1 )
    EVT_RIBBONTOOLBAR_DROPDOWN_CLICKED = wx.PyEventBinder( wxEVT_COMMAND_RIBBONTOOL_DROPDOWN_CLICKED, 1 )
}
#endif

#endif // wxUSE_RIBBON

#endif // _WX_RIBBON_TOOLBAR_H_
