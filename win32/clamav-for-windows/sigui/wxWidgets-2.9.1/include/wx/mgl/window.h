/////////////////////////////////////////////////////////////////////////////
// Name:        wx/mgl/window.h
// Purpose:     wxWindow class
// Author:      Vaclav Slavik
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_WINDOW_H_
#define _WX_WINDOW_H_

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

#include "wx/font.h"

struct window_t;
class MGLDevCtx;

// ---------------------------------------------------------------------------
// wxWindow declaration for MGL
// ---------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxWindowMGL : public wxWindowBase
{
public:
    wxWindowMGL() { Init(); }

    wxWindowMGL(wxWindow *parent,
                wxWindowID id,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxString& name = wxPanelNameStr)
    {
        Init();
        Create(parent, id, pos, size, style, name);
    }

    virtual ~wxWindowMGL();

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxString& name = wxPanelNameStr);

    // implement base class (pure) virtual methods
    // -------------------------------------------

    virtual void SetLabel( const wxString &WXUNUSED(label) ) {}
    virtual wxString GetLabel() const { return wxEmptyString; }

    virtual void Raise();
    virtual void Lower();

    virtual bool Show(bool show = true);

    virtual void SetFocus();

    virtual bool Reparent(wxWindowBase *newParent);

    virtual void WarpPointer(int x, int y);

    virtual void Refresh(bool eraseBackground = true,
                         const wxRect *rect = (const wxRect *) NULL);
    virtual void Update();

    virtual bool SetCursor(const wxCursor &cursor);
    virtual bool SetFont(const wxFont &font) { m_font = font; return true; }

    virtual int GetCharHeight() const;
    virtual int GetCharWidth() const;

#if wxUSE_DRAG_AND_DROP
    virtual void SetDropTarget(wxDropTarget *dropTarget);
#endif // wxUSE_DRAG_AND_DROP

    // Accept files for dragging
    virtual void DragAcceptFiles(bool accept);

    virtual WXWidget GetHandle() const { return m_wnd; }

    void SetMGLwindow_t(struct window_t *wnd);

    // implementation from now on
    // --------------------------

    void OnInternalIdle();

protected:
    virtual void DoFreeze();
    virtual void DoThaw();


    // the window handle
    struct window_t      *m_wnd;
    // whether there should be wxEraseEvent before wxPaintEvent or not
    // (see wxWindow::Refresh)
    bool                  m_refreshAfterThaw:1;
    int                   m_eraseBackground;

    // implement the base class pure virtuals
    virtual void DoGetTextExtent(const wxString& string,
                                 int *x, int *y,
                                 int *descent = NULL,
                                 int *externalLeading = NULL,
                                 const wxFont *font = NULL) const;
    virtual void DoClientToScreen( int *x, int *y ) const;
    virtual void DoScreenToClient( int *x, int *y ) const;
    virtual void DoGetPosition( int *x, int *y ) const;
    virtual void DoGetSize( int *width, int *height ) const;
    virtual void DoGetClientSize( int *width, int *height ) const;
    virtual void DoSetSize(int x, int y,
                           int width, int height,
                           int sizeFlags = wxSIZE_AUTO);
    virtual void DoSetClientSize(int width, int height);

    virtual void DoCaptureMouse();
    virtual void DoReleaseMouse();

    // move the window to the specified location and resize it: this is called
    // from both DoSetSize() and DoSetClientSize() and would usually just call
    // ::MoveWindow() except for composite controls which will want to arrange
    // themselves inside the given rectangle
    virtual void DoMoveWindow(int x, int y, int width, int height);

private:
    // common part of all ctors
    void Init();
    // counterpart to SetFocus
    void KillFocus();

    MGLDevCtx *m_paintMGLDC;
    friend class wxPaintDC;

    DECLARE_DYNAMIC_CLASS(wxWindowMGL)
    wxDECLARE_NO_COPY_CLASS(wxWindowMGL);
    DECLARE_EVENT_TABLE()

public:
    void HandlePaint(MGLDevCtx *dc);
    // needed by wxWindowPainter
    MGLDevCtx *GetPaintMGLDC() const { return m_paintMGLDC; }
};


#endif // _WX_WINDOW_H_
