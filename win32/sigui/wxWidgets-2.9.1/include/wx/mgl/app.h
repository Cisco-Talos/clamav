/////////////////////////////////////////////////////////////////////////////
// Name:        wx/mgl/app.h
// Purpose:
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __WX_APP_H__
#define __WX_APP_H__

#include "wx/frame.h"
#include "wx/icon.h"
#include "wx/vidmode.h"

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxApp;
class WXDLLIMPEXP_FWD_BASE wxLog;
class WXDLLIMPEXP_FWD_CORE wxEventLoop;

//-----------------------------------------------------------------------------
// wxApp
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxApp: public wxAppBase
{
public:
    wxApp();
    virtual ~wxApp();

    /* override for altering the way wxGTK intializes the GUI
     * (palette/visual/colorcube). under wxMSW, OnInitGui() does nothing by
     * default. when overriding this method, the code in it is likely to be
     * platform dependent, otherwise use OnInit(). */
    virtual bool OnInitGui();

    // override base class (pure) virtuals
    virtual bool Initialize(int& argc, wxChar **argv);
    virtual void CleanUp();

    virtual void Exit();
    virtual void WakeUpIdle();

    virtual wxVideoMode GetDisplayMode() const { return m_displayMode; }
    virtual bool SetDisplayMode(const wxVideoMode& mode);

private:
    DECLARE_DYNAMIC_CLASS(wxApp)

    wxVideoMode m_displayMode;
};

#endif // __WX_APP_H__
