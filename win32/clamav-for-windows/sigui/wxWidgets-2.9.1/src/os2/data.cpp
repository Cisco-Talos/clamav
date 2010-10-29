/////////////////////////////////////////////////////////////////////////////
// Name:        data.cpp
// Purpose:     Various OS/2-specific global data
// Author:      David Webster
// Modified by:
// Created:     09/20/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#include "wx/fontutil.h"

// Current cursor, in order to hang on to
// cursor handle when setting the cursor globally
wxCursor *g_globalCursor = NULL;

wxNativeFontInfo wxNullNativeFontInfo;

//
// Class names
//
const wxChar*                       wxFrameClassName                 = wxT("wxFrameClass");
const wxChar*                       wxFrameClassNameNoRedraw         = wxT("wxFrameClassNR");
const wxChar*                       wxMDIFrameClassName              = wxT("wxMDIFrameClass");
const wxChar*                       wxMDIFrameClassNameNoRedraw      = wxT("wxMDIFrameClassNR");
const wxChar*                       wxMDIChildFrameClassName         = wxT("wxMDIChildFrameClass");
const wxChar*                       wxMDIChildFrameClassNameNoRedraw = wxT("wxMDIChildFrameClassNR");
const wxChar*                       wxPanelClassName                 = wxT("wxPanelClass");
const wxChar*                       wxPanelClassNameNR               = wxT("wxPanelClassNR");
const wxChar*                       wxCanvasClassName                = wxT("wxCanvasClass");
const wxChar*                       wxCanvasClassNameNR              = wxT("wxCanvasClassNR");

