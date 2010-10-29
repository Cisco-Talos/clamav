/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/dirdlg.cpp
// Purpose:     wxDirDialog
// Author:      David Webster
// Modified by:
// Created:     10/14/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/dirdlg.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/cmndata.h"
#endif

#include "wx/os2/private.h"

#include <stdlib.h>
#include <string.h>

#define wxDIALOG_DEFAULT_X 300
#define wxDIALOG_DEFAULT_Y 300

IMPLEMENT_CLASS(wxDirDialog, wxDialog)

wxDirDialog::wxDirDialog(wxWindow *parent, const wxString& message,
        const wxString& defaultPath,
        long style, const wxPoint& pos)
{
    m_message = message;
    m_windowStyle = style;
    m_parent = parent;
    m_path = defaultPath;
}

int wxDirDialog::ShowModal()
{
    // TODO
    return wxID_CANCEL;
}
