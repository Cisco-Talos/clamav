////////////////////////////////////////////////////////////////////////////////
// Name:        src/common/listctrlcmn.cpp
// Purpose:     Common defines for wxListCtrl and wxListCtrl-based classes.
// Author:      Kevin Ollivier
// Created:     09/15/06
// RCS-ID:      $Id$
// Copyright:   (c) Kevin Ollivier
// Licence:     wxWindows licence
////////////////////////////////////////////////////////////////////////////////

// =============================================================================
// declarations
// =============================================================================

// -----------------------------------------------------------------------------
// headers
// -----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_LISTCTRL

#include "wx/listctrl.h"

const char wxListCtrlNameStr[] = "listCtrl";

// ListCtrl events
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_BEGIN_DRAG, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_BEGIN_RDRAG, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_BEGIN_LABEL_EDIT, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_END_LABEL_EDIT, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_DELETE_ITEM, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_DELETE_ALL_ITEMS, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_ITEM_SELECTED, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_ITEM_DESELECTED, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_KEY_DOWN, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_INSERT_ITEM, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_COL_CLICK, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_COL_RIGHT_CLICK, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_COL_BEGIN_DRAG, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_COL_DRAGGING, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_COL_END_DRAG, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_ITEM_RIGHT_CLICK, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_ITEM_MIDDLE_CLICK, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_ITEM_ACTIVATED, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_ITEM_FOCUSED, wxListEvent );
wxDEFINE_EVENT( wxEVT_COMMAND_LIST_CACHE_HINT, wxListEvent );

#endif // wxUSE_LISTCTRL
