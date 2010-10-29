/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/glcanvas.h
// Purpose:     wxGLCanvas, for using OpenGL with wxWidgets under Palm OS
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_GLCANVAS_H_
#define _WX_GLCANVAS_H_

#include "wx/palette.h"
#include "wx/scrolwin.h"

#include "wx/msw/wrapwin.h"

#include <GL/gl.h>

class WXDLLIMPEXP_FWD_GL wxGLCanvas;     /* forward reference */

class WXDLLIMPEXP_GL wxGLContext: public wxObject
{
public:
    wxGLContext(bool isRGB, wxGLCanvas *win, const wxPalette& palette = wxNullPalette);

    wxGLContext( bool isRGB, wxGLCanvas *win,
        const wxPalette& WXUNUSED(palette),
        const wxGLContext *other /* for sharing display lists */ );

    virtual ~wxGLContext();


    void SetCurrent();

    void SetColour(const wxString& colour);

    void SwapBuffers();


    inline wxWindow* GetWindow() const { return m_window; }

    inline WXHDC GetHDC() const { return m_hDC; }

    inline HGLRC GetGLRC() const { return m_glContext; }

public:
    HGLRC            m_glContext;
    WXHDC            m_hDC;
    wxWindow*        m_window;
};

class WXDLLIMPEXP_GL wxGLCanvas: public wxWindow
{
    DECLARE_CLASS(wxGLCanvas)
public:
    wxGLCanvas(wxWindow *parent, wxWindowID id = wxID_ANY,
        const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize, long style = 0,
        const wxString& name = wxGLCanvasName, int *attribList = 0,
        const wxPalette& palette = wxNullPalette);

    wxGLCanvas(wxWindow *parent,
        const wxGLContext *shared = NULL,
        wxWindowID id = wxID_ANY,
        const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize,
        long style = 0,
        const wxString& name = wxGLCanvasName,
        int *attribList = NULL,
        const wxPalette& palette = wxNullPalette);

    wxGLCanvas(wxWindow *parent,
        const wxGLCanvas *shared = NULL,
        wxWindowID id = wxID_ANY,
        const wxPoint& pos = wxDefaultPosition,
        const wxSize& size = wxDefaultSize,
        long style = 0,
        const wxString& name = wxGLCanvasName,
        int *attribList = 0,
        const wxPalette& palette = wxNullPalette);

    virtual ~wxGLCanvas();

    // Replaces wxWindow::Create functionality, since
    // we need to use a different window class
    bool Create(wxWindow *parent, wxWindowID id,
        const wxPoint& pos, const wxSize& size,
        long style, const wxString& name);

    void SetCurrent();

#ifdef __WXUNIVERSAL__
    virtual bool SetCurrent(bool doit) { return wxWindow::SetCurrent(doit); };
#endif

    void SetColour(const wxChar *colour);

    void SwapBuffers();

    void OnSize(wxSizeEvent& event);

    void OnQueryNewPalette(wxQueryNewPaletteEvent& event);

    void OnPaletteChanged(wxPaletteChangedEvent& event);

    inline wxGLContext* GetContext() const { return m_glContext; }

    inline WXHDC GetHDC() const { return m_hDC; }

    void SetupPixelFormat(int *attribList = NULL);

    void SetupPalette(const wxPalette& palette);

protected:
    WXHDC          m_hDC;

    DECLARE_EVENT_TABLE()
};

#endif
    // _WX_GLCANVAS_H_

