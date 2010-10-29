/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/carbon/toolbar.cpp
// Purpose:     wxToolBar
// Author:      Stefan Csomor
// Modified by:
// Created:     04/01/98
// RCS-ID:      $Id: toolbar.cpp 54954 2008-08-03 11:27:03Z VZ $
// Copyright:   (c) Stefan Csomor
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_TOOLBAR

#include "wx/toolbar.h"

#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#include "wx/app.h"
#include "wx/osx/private.h"
#include "wx/geometry.h"
#include "wx/sysopt.h"

IMPLEMENT_DYNAMIC_CLASS(wxToolBar, wxControl)

bool wxToolBar::Destroy()
{
#if wxOSX_USE_NATIVE_TOOLBAR
    MacUninstallNativeToolbar();
#endif
    return wxToolBarBase::Destroy();
}

#endif // wxUSE_TOOLBAR
