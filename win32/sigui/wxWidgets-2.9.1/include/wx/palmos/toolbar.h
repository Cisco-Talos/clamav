/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/toolbar.h
// Purpose:     wxToolBar class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_TBAR95_H_
#define _WX_TBAR95_H_

#if wxUSE_TOOLBAR

#include "wx/dynarray.h"

class WXDLLIMPEXP_CORE wxToolBar : public wxToolBarBase
{
public:
    // ctors and dtor
    wxToolBar() { Init(); }

    wxToolBar(wxWindow *parent,
                wxWindowID id,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxNO_BORDER | wxTB_HORIZONTAL,
                const wxString& name = wxToolBarNameStr)
    {
        Init();

        Create(parent, id, pos, size, style, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxNO_BORDER | wxTB_HORIZONTAL,
                const wxString& name = wxToolBarNameStr);

    virtual ~wxToolBar();

    // override/implement base class virtuals
    virtual wxToolBarToolBase *FindToolForPosition(wxCoord x, wxCoord y) const;

    virtual bool Realize();

    virtual void SetToolBitmapSize(const wxSize& size);
    virtual wxSize GetToolSize() const;

    virtual void SetRows(int nRows);

    // implementation only from now on
    // -------------------------------

    void OnMouseEvent(wxMouseEvent& event);

    void SetFocus() {}

protected:
    // common part of all ctors
    void Init();

    // recreate the control completely
    void Recreate();

    // implement base class pure virtuals
    virtual bool DoInsertTool(size_t pos, wxToolBarToolBase *tool);
    virtual bool DoDeleteTool(size_t pos, wxToolBarToolBase *tool);

    virtual void DoEnableTool(wxToolBarToolBase *tool, bool enable);
    virtual void DoToggleTool(wxToolBarToolBase *tool, bool toggle);
    virtual void DoSetToggle(wxToolBarToolBase *tool, bool toggle);

    virtual wxToolBarToolBase *CreateTool(int id,
                                          const wxString& label,
                                          const wxBitmap& bmpNormal,
                                          const wxBitmap& bmpDisabled,
                                          wxItemKind kind,
                                          wxObject *clientData,
                                          const wxString& shortHelp,
                                          const wxString& longHelp);
    virtual wxToolBarToolBase *CreateTool(wxControl *control,
                                          const wxString& label);

    // return the appropriate size and flags for the toolbar control
    virtual wxSize DoGetBestSize() const;

    // should be called whenever the toolbar size changes
    void UpdateSize();

    // the big bitmap containing all bitmaps of the toolbar buttons
    WXHBITMAP m_hBitmap;

    // the total number of toolbar elements
    size_t m_nButtons;

    // the tool the cursor is in
    wxToolBarToolBase *m_pInTool;

private:
    DECLARE_EVENT_TABLE()
    DECLARE_DYNAMIC_CLASS(wxToolBar)
    wxDECLARE_NO_COPY_CLASS(wxToolBar);
};

#endif // wxUSE_TOOLBAR

#endif
    // _WX_TBAR95_H_
