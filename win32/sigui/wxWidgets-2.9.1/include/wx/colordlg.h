/////////////////////////////////////////////////////////////////////////////
// Name:        wx/colrdlgg.h
// Purpose:     wxColourDialog
// Author:      Vadim Zeitiln
// Modified by:
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) wxWidgets team
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_COLORDLG_H_BASE_
#define _WX_COLORDLG_H_BASE_

#include "wx/defs.h"

#if wxUSE_COLOURDLG

#if defined(__WXMSW__) && !defined(__WXUNIVERSAL__)
    #include "wx/msw/colordlg.h"
#elif defined(__WXMAC__) && !defined(__WXUNIVERSAL__)
    #include "wx/osx/colordlg.h"
#elif defined(__WXGTK20__) && !defined(__WXUNIVERSAL__)
    #include "wx/gtk/colordlg.h"
#elif defined(__WXPALMOS__)
    #include "wx/palmos/colordlg.h"
#else
    #include "wx/generic/colrdlgg.h"

    #define wxColourDialog wxGenericColourDialog
#endif

class WXDLLIMPEXP_FWD_CORE wxColourData;

// get the colour from user and return it
WXDLLIMPEXP_CORE wxColour wxGetColourFromUser(wxWindow *parent = NULL,
                                              const wxColour& colInit = wxNullColour,
                                              const wxString& caption = wxEmptyString,
                                              wxColourData *data = NULL);

#endif // wxUSE_COLOURDLG

#endif
    // _WX_COLORDLG_H_BASE_
