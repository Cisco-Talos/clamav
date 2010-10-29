/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/utilsres.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/utils.h"

#ifndef WX_PRECOMP
    #include "wx/list.h"
    #include "wx/string.h"
    #include "wx/log.h"
    #include "wx/app.h"
#endif

#include "wx/config.h"

//-----------------------------------------------------------------------------
// resource functions
//-----------------------------------------------------------------------------

bool wxWriteResource(const wxString& section, const wxString& entry, const wxString& value, const wxString& file )
{
    wxString filename( file );
    if (filename.empty()) filename = wxT(".wxWindows");

    wxFileConfig conf( wxTheApp->GetAppName(), wxTheApp->GetVendorName(), filename );

    conf.SetPath( section );

    return conf.Write( entry, value );
}

bool wxWriteResource(const wxString& section, const wxString& entry, float value, const wxString& file )
{
    wxString buf;
    buf.Printf(wxT("%.4f"), value);

    return wxWriteResource(section, entry, buf, file);
}

bool wxWriteResource(const wxString& section, const wxString& entry, long value, const wxString& file )
{
    wxString buf;
    buf.Printf(wxT("%ld"), value);

    return wxWriteResource(section, entry, buf, file);
}

bool wxWriteResource(const wxString& section, const wxString& entry, int value, const wxString& file )
{
    wxString buf;
    buf.Printf(wxT("%d"), value);

    return wxWriteResource(section, entry, buf, file);
}

bool wxGetResource(const wxString& section, const wxString& entry, wxChar **value, const wxString& file )
{
    wxString filename( file );
    if (filename.empty()) filename = wxT(".wxWindows");

    wxFileConfig conf( wxTheApp->GetAppName(), wxTheApp->GetVendorName(), filename );

    conf.SetPath( section );

    wxString result;
    if (conf.Read( entry, &result ))
    {
        if (!result.empty())
        {
            wxChar *s = new wxChar[result.Len()+1];
            wxStrcpy( s, result.c_str() );
            *value = s;
            return true;
        }
    }

    return false;
}

bool wxGetResource(const wxString& section, const wxString& entry, float *value, const wxString& file )
{
    wxChar *s = NULL;
    bool succ = wxGetResource(section, entry, (wxChar **)&s, file);
    if (succ)
    {
        *value = (float)wxStrtod(s, (wchar_t **) NULL);
        delete[] s;
        return true;
    }
    else return false;
}

bool wxGetResource(const wxString& section, const wxString& entry, long *value, const wxString& file )
{
    wxChar *s = NULL;
    bool succ = wxGetResource(section, entry, (wxChar **)&s, file);
    if (succ)
    {
        *value = wxStrtol(s, (wchar_t **) NULL, 10);
        delete[] s;
        return true;
    }
    else return false;
}

bool wxGetResource(const wxString& section, const wxString& entry, int *value, const wxString& file )
{
    wxChar *s = NULL;
    bool succ = wxGetResource(section, entry, (wxChar **)&s, file);
    if (succ)
    {
        *value = (int)wxStrtol(s, (wchar_t **) NULL, 10);
        delete[] s;
        return true;
    }
    else return false;
}
