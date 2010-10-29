/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/cursor.cpp
// Purpose:     wxCursor class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/cursor.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/icon.h"
    #include "wx/gdicmn.h"
    #include "wx/image.h"
#endif

#include "wx/x11/private.h"

#if !wxUSE_NANOX
#include <X11/cursorfont.h>
#endif

//-----------------------------------------------------------------------------
// wxCursor
//-----------------------------------------------------------------------------

class wxCursorRefData: public wxGDIRefData
{
public:

    wxCursorRefData();
    virtual ~wxCursorRefData();

    WXCursor     m_cursor;
    WXDisplay   *m_display;
};

wxCursorRefData::wxCursorRefData()
{
    m_cursor = NULL;
    m_display = NULL;
}

wxCursorRefData::~wxCursorRefData()
{
    if (m_cursor)
        XFreeCursor( (Display*) m_display, (Cursor) m_cursor );
}

//-----------------------------------------------------------------------------

#define M_CURSORDATA ((wxCursorRefData *)m_refData)

IMPLEMENT_DYNAMIC_CLASS(wxCursor,wxObject)

wxCursor::wxCursor()
{

}

void wxCursor::InitFromStock( wxStockCursor cursorId )
{
    m_refData = new wxCursorRefData();

#if wxUSE_NANOX
    // TODO Create some standard cursors from bitmaps.


#else
    // !wxUSE_NANOX

    M_CURSORDATA->m_display = wxGlobalDisplay();
    wxASSERT_MSG( M_CURSORDATA->m_display, wxT("No display") );

    int x_cur = XC_left_ptr;
    switch (cursorId)
    {
        case wxCURSOR_DEFAULT:          x_cur = XC_left_ptr; break;
        case wxCURSOR_HAND:             x_cur = XC_hand1; break;
        case wxCURSOR_CROSS:            x_cur = XC_crosshair; break;
        case wxCURSOR_SIZEWE:           x_cur = XC_sb_h_double_arrow; break;
        case wxCURSOR_SIZENS:           x_cur = XC_sb_v_double_arrow; break;
        case wxCURSOR_ARROWWAIT:
        case wxCURSOR_WAIT:
        case wxCURSOR_WATCH:            x_cur = XC_watch; break;
        case wxCURSOR_SIZING:           x_cur = XC_sizing; break;
        case wxCURSOR_SPRAYCAN:         x_cur = XC_spraycan; break;
        case wxCURSOR_IBEAM:            x_cur = XC_xterm; break;
        case wxCURSOR_PENCIL:           x_cur = XC_pencil; break;
        case wxCURSOR_NO_ENTRY:         x_cur = XC_pirate; break;
        case wxCURSOR_SIZENWSE:
        case wxCURSOR_SIZENESW:         x_cur = XC_fleur; break;
        case wxCURSOR_QUESTION_ARROW:   x_cur = XC_question_arrow; break;
        case wxCURSOR_PAINT_BRUSH:      x_cur = XC_spraycan; break;
        case wxCURSOR_MAGNIFIER:        x_cur = XC_plus; break;
        case wxCURSOR_CHAR:             x_cur = XC_xterm; break;
        case wxCURSOR_LEFT_BUTTON:      x_cur = XC_leftbutton; break;
        case wxCURSOR_MIDDLE_BUTTON:    x_cur = XC_middlebutton; break;
        case wxCURSOR_RIGHT_BUTTON:     x_cur = XC_rightbutton; break;
        case wxCURSOR_BULLSEYE:         x_cur = XC_target; break;

        case wxCURSOR_POINT_LEFT:       x_cur = XC_sb_left_arrow; break;
        case wxCURSOR_POINT_RIGHT:      x_cur = XC_sb_right_arrow; break;
/*
        case wxCURSOR_DOUBLE_ARROW:     x_cur = XC_double_arrow; break;
        case wxCURSOR_CROSS_REVERSE:    x_cur = XC_cross_reverse; break;
        case wxCURSOR_BASED_ARROW_UP:   x_cur = XC_based_arrow_up; break;
        case wxCURSOR_BASED_ARROW_DOWN: x_cur = XC_based_arrow_down; break;
*/
        default:
            wxFAIL_MSG(wxT("unsupported cursor type"));
            // will use the standard one
    }

    M_CURSORDATA->m_cursor = (WXCursor) XCreateFontCursor( (Display*) M_CURSORDATA->m_display, x_cur );
#endif
}

wxCursor::wxCursor(const wxString& WXUNUSED(name),
                    wxBitmapType WXUNUSED(type),
                    int WXUNUSED(hotSpotX), int WXUNUSED(hotSpotY))
{
   wxFAIL_MSG( wxT("wxCursor creation from file not yet implemented") );
}

#if wxUSE_IMAGE
wxCursor::wxCursor( const wxImage & WXUNUSED(image) )
{
   wxFAIL_MSG( wxT("wxCursor creation from wxImage not yet implemented") );
}
#endif

wxCursor::~wxCursor()
{
}

wxGDIRefData *wxCursor::CreateGDIRefData() const
{
    return new wxCursorRefData;
}

wxGDIRefData *wxCursor::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxCursorRefData(*static_cast<const wxCursorRefData *>(data));
}

WXCursor wxCursor::GetCursor() const
{
    return M_CURSORDATA->m_cursor;
}

//-----------------------------------------------------------------------------
// busy cursor routines
//-----------------------------------------------------------------------------

/* extern */ wxCursor g_globalCursor;

static wxCursor  gs_savedCursor;
static int       gs_busyCount = 0;

const wxCursor &wxBusyCursor::GetStoredCursor()
{
    return gs_savedCursor;
}

const wxCursor wxBusyCursor::GetBusyCursor()
{
    return wxCursor(wxCURSOR_WATCH);
}

void wxEndBusyCursor()
{
    if (--gs_busyCount > 0)
        return;

    wxSetCursor( gs_savedCursor );
    gs_savedCursor = wxNullCursor;

    if (wxTheApp)
        wxTheApp->ProcessIdle();
}

void wxBeginBusyCursor( const wxCursor *WXUNUSED(cursor) )
{
    if (gs_busyCount++ > 0)
        return;

    wxASSERT_MSG( !gs_savedCursor.Ok(),
                  wxT("forgot to call wxEndBusyCursor, will leak memory") );

    gs_savedCursor = g_globalCursor;

    wxSetCursor( wxCursor(wxCURSOR_WATCH) );

    if (wxTheApp)
        wxTheApp->ProcessIdle();
}

bool wxIsBusy()
{
    return gs_busyCount > 0;
}

void wxSetCursor( const wxCursor& cursor )
{
    g_globalCursor = cursor;
}
