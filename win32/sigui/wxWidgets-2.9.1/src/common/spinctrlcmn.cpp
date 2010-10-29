/////////////////////////////////////////////////////////////////////////////
// Name:        src/common/spinctrlcmn.cpp
// Purpose:     define wxSpinCtrl event types
// Author:      Peter Most
// Created:     01.11.08
// RCS-ID:      $Id$
// Copyright:   (c) 2008-2009 wxWidgets team
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

#include "wx/spinbutt.h"
#include "wx/spinctrl.h"

#if wxUSE_SPINCTRL

wxDEFINE_EVENT(wxEVT_COMMAND_SPINCTRL_UPDATED, wxSpinEvent);
wxDEFINE_EVENT(wxEVT_COMMAND_SPINCTRLDOUBLE_UPDATED, wxSpinDoubleEvent);

#endif // wxUSE_SPINCTRL
