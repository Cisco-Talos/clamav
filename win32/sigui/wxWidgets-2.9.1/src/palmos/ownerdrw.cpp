///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/ownerdrw.cpp
// Purpose:     implementation of wxOwnerDrawn class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/font.h"
    #include "wx/bitmap.h"
    #include "wx/dcmemory.h"
    #include "wx/menu.h"
    #include "wx/utils.h"
    #include "wx/settings.h"
    #include "wx/menuitem.h"
    #include "wx/module.h"
#endif

#include "wx/ownerdrw.h"
#include "wx/fontutil.h"

#if wxUSE_OWNER_DRAWN

class wxMSWSystemMenuFontModule : public wxModule
{
public:

    virtual bool OnInit()
    {
        ms_systemMenuFont = new wxFont;
        return true;
    }

    virtual void OnExit()
    {
        wxDELETE(ms_systemMenuFont);
    }

    static wxFont* ms_systemMenuFont;
    static int ms_systemMenuButtonWidth;   // windows clean install default
    static int ms_systemMenuHeight;        // windows clean install default
private:
    DECLARE_DYNAMIC_CLASS(wxMSWSystemMenuFontModule)
};

// these static variables are by the wxMSWSystemMenuFontModule object
// and reflect the system settings returned by the Win32 API's
// SystemParametersInfo() call.

wxFont* wxMSWSystemMenuFontModule::ms_systemMenuFont = NULL;
int wxMSWSystemMenuFontModule::ms_systemMenuButtonWidth = 18;   // windows clean install default
int wxMSWSystemMenuFontModule::ms_systemMenuHeight = 18;        // windows clean install default

IMPLEMENT_DYNAMIC_CLASS(wxMSWSystemMenuFontModule, wxModule)

// ============================================================================
// implementation of wxOwnerDrawn class
// ============================================================================

// ctor
// ----
wxOwnerDrawn::wxOwnerDrawn(const wxString& str,
                           bool bCheckable, bool bMenuItem)
            : m_strName(str)
{
}


// these items will be set during the first invocation of the c'tor,
// because the values will be determined by checking the system settings,
// which is a chunk of code
size_t wxOwnerDrawn::ms_nDefaultMarginWidth = 0;
size_t wxOwnerDrawn::ms_nLastMarginWidth = 0;


// drawing
// -------

// get size of the item
// The item size includes the menu string, the accel string,
// the bitmap and size for a submenu expansion arrow...
bool wxOwnerDrawn::OnMeasureItem(size_t *pwidth, size_t *pheight)
{
    return false;
}

// draw the item
bool wxOwnerDrawn::OnDrawItem(wxDC& dc,
                              const wxRect& rc,
                              wxODAction act,
                              wxODStatus st)
{
    return false;
}


#endif // wxUSE_OWNER_DRAWN
