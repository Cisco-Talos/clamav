/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/cursor.cpp
// Purpose:
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/cursor.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/utils.h"
    #include "wx/hashmap.h"
    #include "wx/module.h"
#endif

#include "wx/mgl/private.h"


//-----------------------------------------------------------------------------
// wxCursor
//-----------------------------------------------------------------------------

class wxCursorRefData: public wxObjectRefData
{
  public:

    wxCursorRefData();
    virtual ~wxCursorRefData();

    MGLCursor *m_cursor;
};

wxCursorRefData::wxCursorRefData()
{
    m_cursor = NULL;
}

wxCursorRefData::~wxCursorRefData()
{
    delete m_cursor;
}

#define M_CURSORDATA ((wxCursorRefData *)m_refData)

//-----------------------------------------------------------------------------

WX_DECLARE_HASH_MAP(int, wxCursor, wxIntegerHash, wxIntegerEqual, wxCursorsHash);

static wxCursorsHash *gs_cursorsHash = NULL;

IMPLEMENT_DYNAMIC_CLASS(wxCursor,wxObject)

wxCursor::wxCursor()
{
}

void wxCursor::InitFromStock(wxStockCursor cursorId)
{
    if ( !gs_cursorsHash )
        gs_cursorsHash = new wxCursorsHash;

    if ( gs_cursorsHash->find(cursorId) != gs_cursorsHash->end() )
    {
        wxLogTrace(wxT("mglcursor"), wxT("cursor id %i fetched from cache"), cursorId);
        *this = (*gs_cursorsHash)[cursorId];
        return;
    }

    const char *cursorname = NULL;
    m_refData = new wxCursorRefData();

    switch (cursorId)
    {
        case wxCURSOR_ARROW:           cursorname = "arrow.cur"; break;
        case wxCURSOR_RIGHT_ARROW:     cursorname = "rightarr.cur"; break;
        case wxCURSOR_BULLSEYE:        cursorname = "bullseye.cur"; break;
        case wxCURSOR_CHAR:            cursorname = "char.cur"; break;
        case wxCURSOR_CROSS:           cursorname = "cross.cur"; break;
        case wxCURSOR_HAND:            cursorname = "hand.cur"; break;
        case wxCURSOR_IBEAM:           cursorname = "ibeam.cur"; break;
        case wxCURSOR_LEFT_BUTTON:     cursorname = "leftbtn.cur"; break;
        case wxCURSOR_MAGNIFIER:       cursorname = "magnif1.cur"; break;
        case wxCURSOR_MIDDLE_BUTTON:   cursorname = "midbtn.cur"; break;
        case wxCURSOR_NO_ENTRY:        cursorname = "noentry.cur"; break;
        case wxCURSOR_PAINT_BRUSH:     cursorname = "pbrush.cur"; break;
        case wxCURSOR_PENCIL:          cursorname = "pencil.cur"; break;
        case wxCURSOR_POINT_LEFT:      cursorname = "pntleft.cur"; break;
        case wxCURSOR_POINT_RIGHT:     cursorname = "pntright.cur"; break;
        case wxCURSOR_QUESTION_ARROW:  cursorname = "query.cur"; break;
        case wxCURSOR_RIGHT_BUTTON:    cursorname = "rightbtn.cur"; break;
        case wxCURSOR_SIZENESW:        cursorname = "sizenesw.cur"; break;
        case wxCURSOR_SIZENS:          cursorname = "sizens.cur"; break;
        case wxCURSOR_SIZENWSE:        cursorname = "sizenwse.cur"; break;
        case wxCURSOR_SIZEWE:          cursorname = "sizewe.cur"; break;
        case wxCURSOR_SIZING:          cursorname = "size.cur"; break;
        case wxCURSOR_SPRAYCAN:        cursorname = "spraycan.cur"; break;
        case wxCURSOR_WAIT:            cursorname = "wait.cur"; break;
        case wxCURSOR_WATCH:           cursorname = "clock.cur"; break;
        case wxCURSOR_BLANK:           cursorname = "blank.cur"; break;

        case wxCURSOR_NONE:
            *this = wxNullCursor;
            return;

        default:
            wxFAIL_MSG(wxT("unsupported cursor type"));
            break;
    }

    M_CURSORDATA->m_cursor = new MGLCursor(cursorname);

    // if we cannot load arrow cursor, use MGL's default arrow cursor:
    if ( !M_CURSORDATA->m_cursor->valid() && cursorId == wxCURSOR_ARROW )
    {
        delete M_CURSORDATA->m_cursor;
        M_CURSORDATA->m_cursor = new MGLCursor(MGL_DEF_CURSOR);
    }

    if ( !M_CURSORDATA->m_cursor->valid() )
    {
        wxLogError(_("Couldn't create cursor."));
        UnRef();
    }
    else
    {
        (*gs_cursorsHash)[cursorId] = *this;
        wxLogTrace(wxT("mglcursor"), wxT("cursor id %i added to cache (%s)"),
                   cursorId, cursorname);
    }
}

wxCursor::wxCursor(const wxString& cursor_file,
                   wxBitmapType type,
                   int WXUNUSED(hotSpotX), int WXUNUSED(hotSpotY))
{
    if ( type == wxBITMAP_TYPE_CUR || type == wxBITMAP_TYPE_CUR_RESOURCE )
    {
        m_refData = new wxCursorRefData();
        M_CURSORDATA->m_cursor = new MGLCursor(cursor_file.mb_str());
        if ( !M_CURSORDATA->m_cursor->valid() )
        {
            wxLogError(_("Couldn't create cursor."));
            UnRef();
        }
    }
    else
    {
        wxLogError(wxT("Cannot load cursor resource of this type."));
    }
}

wxCursor::~wxCursor()
{
    // wxObject unrefs data
}

MGLCursor *wxCursor::GetMGLCursor() const
{
    return M_CURSORDATA->m_cursor;
}



// ----------------------------------------------------------------------------
// Global cursor setting
// ----------------------------------------------------------------------------

static wxCursor  gs_globalCursor = wxNullCursor;

void wxSetCursor(const wxCursor& cursor)
{
    if ( cursor.Ok() )
    {
        if ( g_winMng )
            MGL_wmSetGlobalCursor(g_winMng, *cursor.GetMGLCursor());
        gs_globalCursor = cursor;
    }
    else
    {
        if ( g_winMng )
            MGL_wmSetGlobalCursor(g_winMng, NULL);
        gs_globalCursor = wxNullCursor;
    }
}



//-----------------------------------------------------------------------------
// busy cursor routines
//-----------------------------------------------------------------------------

static wxCursor  gs_savedCursor = wxNullCursor;
static int       gs_busyCount = 0;

const wxCursor &wxBusyCursor::GetStoredCursor()
{
    return gs_savedCursor;
}

const wxCursor wxBusyCursor::GetBusyCursor()
{
    return gs_globalCursor;
}

void wxEndBusyCursor()
{
    if ( --gs_busyCount > 0 ) return;

    wxSetCursor(gs_savedCursor);
    gs_savedCursor = wxNullCursor;
}

void wxBeginBusyCursor(const wxCursor *cursor)
{
    if ( gs_busyCount++ > 0 ) return;

    wxASSERT_MSG( !gs_savedCursor.Ok(),
                  wxT("forgot to call wxEndBusyCursor, will leak memory") );

    gs_savedCursor = gs_globalCursor;
    if ( cursor->Ok() )
        wxSetCursor(*cursor);
    else
        wxSetCursor(wxCursor(wxCURSOR_WAIT));
}

bool wxIsBusy()
{
    return (gs_busyCount > 0);
}



//-----------------------------------------------------------------------------
// module - clean up code
//-----------------------------------------------------------------------------

class wxCursorModule : public wxModule
{
public:
    virtual bool OnInit() { return true; }

    virtual void OnExit()
    {
        wxDELETE(gs_cursorsHash);
    }

private:
    DECLARE_DYNAMIC_CLASS(wxCursorModule)
};

IMPLEMENT_DYNAMIC_CLASS(wxCursorModule, wxModule)
