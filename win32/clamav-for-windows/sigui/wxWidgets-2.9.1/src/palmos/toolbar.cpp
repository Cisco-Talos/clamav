/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/toolbar.cpp
// Purpose:     wxToolBar
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

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

#if wxUSE_TOOLBAR && wxUSE_TOOLBAR_NATIVE

#include "wx/toolbar.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/frame.h"
    #include "wx/log.h"
    #include "wx/intl.h"
    #include "wx/settings.h"
    #include "wx/bitmap.h"
    #include "wx/dcmemory.h"
    #include "wx/control.h"
    #include "wx/app.h"         // for GetComCtl32Version
#endif

#include "wx/sysopt.h"

#include "wx/palmos/private.h"

#include "wx/palmos/wrapcctl.h"

// ----------------------------------------------------------------------------
// conditional compilation
// ----------------------------------------------------------------------------

// wxWidgets previously always considered that toolbar buttons have light grey
// (0xc0c0c0) background and so ignored any bitmap masks - however, this
// doesn't work with XPMs which then appear to have black background. To make
// this work, we must respect the bitmap masks - which we do now. This should
// be ok in any case, but to restore 100% compatible with the old version
// behaviour, you can set this to 0.
#define USE_BITMAP_MASKS 1

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxToolBar, wxControl)

/*
    TOOLBAR PROPERTIES
        tool
            bitmap
            bitmap2
            tooltip
            longhelp
            radio (bool)
            toggle (bool)
        separator
        style ( wxNO_BORDER | wxTB_HORIZONTAL)
        bitmapsize
        margins
        packing
        separation

        dontattachtoframe
*/

BEGIN_EVENT_TABLE(wxToolBar, wxToolBarBase)
    EVT_MOUSE_EVENTS(wxToolBar::OnMouseEvent)
END_EVENT_TABLE()

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

class wxToolBarTool : public wxToolBarToolBase
{
public:
    wxToolBarTool(wxToolBar *tbar,
                  int id,
                  const wxString& label,
                  const wxBitmap& bmpNormal,
                  const wxBitmap& bmpDisabled,
                  wxItemKind kind,
                  wxObject *clientData,
                  const wxString& shortHelp,
                  const wxString& longHelp)
        : wxToolBarToolBase(tbar, id, label, bmpNormal, bmpDisabled, kind,
                            clientData, shortHelp, longHelp)
    {
    }

    wxToolBarTool(wxToolBar *tbar, wxControl *control, const wxString& label)
        : wxToolBarToolBase(tbar, control, label)
    {
    }

    virtual void SetLabel(const wxString& label)
    {
    }

    // set/get the number of separators which we use to cover the space used by
    // a control in the toolbar
    void SetSeparatorsCount(size_t count) { m_nSepCount = count; }
    size_t GetSeparatorsCount() const { return m_nSepCount; }

private:
    size_t m_nSepCount;

    wxDECLARE_NO_COPY_CLASS(wxToolBarTool);
};


// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxToolBarTool
// ----------------------------------------------------------------------------

wxToolBarToolBase *wxToolBar::CreateTool(int id,
                                         const wxString& label,
                                         const wxBitmap& bmpNormal,
                                         const wxBitmap& bmpDisabled,
                                         wxItemKind kind,
                                         wxObject *clientData,
                                         const wxString& shortHelp,
                                         const wxString& longHelp)
{
    return new wxToolBarTool(this, id, label, bmpNormal, bmpDisabled, kind,
                             clientData, shortHelp, longHelp);
}

wxToolBarToolBase *
wxToolBar::CreateTool(wxControl *control, const wxString& label)
{
    return new wxToolBarTool(this, control, label);
}

// ----------------------------------------------------------------------------
// wxToolBar construction
// ----------------------------------------------------------------------------

void wxToolBar::Init()
{
}

bool wxToolBar::Create(wxWindow *parent,
                       wxWindowID id,
                       const wxPoint& pos,
                       const wxSize& size,
                       long style,
                       const wxString& name)
{
    return false;
}

void wxToolBar::Recreate()
{
}

wxToolBar::~wxToolBar()
{
}

wxSize wxToolBar::DoGetBestSize() const
{
    return wxSize(0,0);
}

// ----------------------------------------------------------------------------
// adding/removing tools
// ----------------------------------------------------------------------------

bool wxToolBar::DoInsertTool(size_t WXUNUSED(pos), wxToolBarToolBase *tool)
{
    return false;
}

bool wxToolBar::DoDeleteTool(size_t pos, wxToolBarToolBase *tool)
{
    return false;
}

bool wxToolBar::Realize()
{
    return false;
}

// ----------------------------------------------------------------------------
// toolbar geometry
// ----------------------------------------------------------------------------

void wxToolBar::SetToolBitmapSize(const wxSize& size)
{
}

void wxToolBar::SetRows(int nRows)
{
}

// The button size is bigger than the bitmap size
wxSize wxToolBar::GetToolSize() const
{
    return wxSize(0,0);
}

static
wxToolBarToolBase *GetItemSkippingDummySpacers(const wxToolBarToolsList& tools,
                                               size_t index )
{
    return 0;
}

wxToolBarToolBase *wxToolBar::FindToolForPosition(wxCoord x, wxCoord y) const
{
    return NULL;
}

void wxToolBar::UpdateSize()
{
}

// ----------------------------------------------------------------------------
// tool state
// ----------------------------------------------------------------------------

void wxToolBar::DoEnableTool(wxToolBarToolBase *tool, bool enable)
{
}

void wxToolBar::DoToggleTool(wxToolBarToolBase *tool, bool toggle)
{
}

void wxToolBar::DoSetToggle(wxToolBarToolBase *WXUNUSED(tool), bool WXUNUSED(toggle))
{
}

// ----------------------------------------------------------------------------
// event handlers
// ----------------------------------------------------------------------------

void wxToolBar::OnMouseEvent(wxMouseEvent& event)
{
}

#endif // wxUSE_TOOLBAR
