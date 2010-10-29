///////////////////////////////////////////////////////////////////////////////
// Name:        common/datacmn.cpp
// Purpose:     contains definitions of various global wxWidgets variables
// Author:      Vadim Zeitlin
// Modified by:
// Created:     10.04.03 (from src/*/data.cpp files)
// RCS-ID:      $Id$
// Copyright:   (c) 1997-2002 wxWidgets development team
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

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
#endif // WX_PRECOMP

#include "wx/accel.h"

// ============================================================================
// implementation
// ============================================================================

// 'Null' objects
#if wxUSE_ACCEL
wxAcceleratorTable wxNullAcceleratorTable;
#endif // wxUSE_ACCEL

// Default window names
extern WXDLLEXPORT_DATA(const char) wxButtonNameStr[] = "button";
extern WXDLLEXPORT_DATA(const char) wxCheckBoxNameStr[] = "check";
extern WXDLLEXPORT_DATA(const char) wxComboBoxNameStr[] = "comboBox";
extern WXDLLEXPORT_DATA(const char) wxDialogNameStr[] = "dialog";
extern WXDLLEXPORT_DATA(const char) wxFrameNameStr[] = "frame";
extern WXDLLEXPORT_DATA(const char) wxStaticBoxNameStr[] = "groupBox";
extern WXDLLEXPORT_DATA(const char) wxListBoxNameStr[] = "listBox";
extern WXDLLEXPORT_DATA(const char) wxStaticLineNameStr[] = "staticLine";
extern WXDLLEXPORT_DATA(const char) wxStaticTextNameStr[] = "staticText";
extern WXDLLEXPORT_DATA(const char) wxStaticBitmapNameStr[] = "staticBitmap";
extern WXDLLEXPORT_DATA(const char) wxNotebookNameStr[] = "notebook";
extern WXDLLEXPORT_DATA(const char) wxPanelNameStr[] = "panel";
extern WXDLLEXPORT_DATA(const char) wxRadioBoxNameStr[] = "radioBox";
extern WXDLLEXPORT_DATA(const char) wxRadioButtonNameStr[] = "radioButton";
extern WXDLLEXPORT_DATA(const char) wxBitmapRadioButtonNameStr[] = "radioButton";
extern WXDLLEXPORT_DATA(const char) wxScrollBarNameStr[] = "scrollBar";
extern WXDLLEXPORT_DATA(const char) wxSliderNameStr[] = "slider";
extern WXDLLEXPORT_DATA(const char) wxStatusLineNameStr[] = "status_line";
extern WXDLLEXPORT_DATA(const char) wxTextCtrlNameStr[] = "text";
extern WXDLLEXPORT_DATA(const char) wxTreeCtrlNameStr[] = "treeCtrl";
extern WXDLLEXPORT_DATA(const char) wxToolBarNameStr[] = "toolbar";

// Default messages
extern WXDLLEXPORT_DATA(const char) wxMessageBoxCaptionStr[] = "Message";
extern WXDLLEXPORT_DATA(const char) wxFileSelectorPromptStr[] = "Select a file";
extern WXDLLEXPORT_DATA(const char) wxDirSelectorPromptStr[] = "Select a directory";

// Other default strings
extern WXDLLEXPORT_DATA(const char) wxFileSelectorDefaultWildcardStr[] =
#if defined(__WXMSW__) || defined(__OS2__)
    "*.*"
#else // Unix/Mac
    "*"
#endif
    ;
extern WXDLLEXPORT_DATA(const char) wxDirDialogNameStr[] = "wxDirCtrl";
extern WXDLLEXPORT_DATA(const char) wxDirDialogDefaultFolderStr[] = "/";

extern WXDLLEXPORT_DATA(const char) wxFileDialogNameStr[] = "filedlg";
