/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/utilsexec.cpp
// Purpose:     wxExecute implementation for PalmOS
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

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #if wxUSE_STREAMS
        #include "wx/stream.h"
    #endif
    #include "wx/module.h"
#endif

#include "wx/process.h"

#include "wx/apptrait.h"

#include <ctype.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if wxUSE_IPC
    #include "wx/dde.h"         // for WX_DDE hack in wxExecute
#endif // wxUSE_IPC

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// this module globals
// ----------------------------------------------------------------------------

// we need to create a hidden window to receive the process termination
// notifications and for this we need a (Win) class name for it which we will
// register the first time it's needed
static const wxChar *wxMSWEXEC_WNDCLASSNAME = wxT("_wxExecute_Internal_Class");
static const wxChar *gs_classForHiddenWindow = NULL;

// ----------------------------------------------------------------------------
// private types
// ----------------------------------------------------------------------------

// ============================================================================
// implementation
// ============================================================================

// ============================================================================
// wxExecute functions family
// ============================================================================

#if wxUSE_IPC

// connect to the given server via DDE and ask it to execute the command
static bool wxExecuteDDE(const wxString& ddeServer,
                         const wxString& ddeTopic,
                         const wxString& ddeCommand)
{
    return false;
}

#endif // wxUSE_IPC

long wxExecute(const wxString& cmd, int flags, wxProcess *handler)
{
    return 0;
}

long wxExecute(wxChar **argv, int flags, wxProcess *handler)
{
    return 0;
}
