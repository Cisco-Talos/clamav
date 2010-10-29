///////////////////////////////////////////////////////////////////////////////
// Name:        wx/mgl/popupwin.h
// Purpose:     wxPopupWindow class for wxMGL
// Author:      Vadim Zeitlin
// Created:     06.01.01
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_POPUPWIN_H_
#define _WX_POPUPWIN_H_

// ----------------------------------------------------------------------------
// wxPopupWindow
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxPopupWindow : public wxPopupWindowBase
{
public:
    wxPopupWindow() { }

    wxPopupWindow(wxWindow *parent, int flags = wxBORDER_NONE)
        { (void)Create(parent, flags); }

    bool Create(wxWindow *parent, int flags = wxBORDER_NONE)
    {
        return wxPopupWindowBase::Create(parent) &&
               wxWindow::Create(parent, -1,
                                wxDefaultPosition, wxDefaultSize,
                                (flags & wxBORDER_MASK) | wxPOPUP_WINDOW);
    }

protected:
    DECLARE_DYNAMIC_CLASS(wxPopupWindow)
};

#endif // _WX_POPUPWIN_H_

