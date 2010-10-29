/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/glcanvas.cpp
// Purpose:     wxGLCanvas, for using OpenGL with wxWidgets
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if defined(__BORLANDC__)
#pragma hdrstop
#endif

#if wxUSE_GLCANVAS

#ifndef WX_PRECOMP
    #include "wx/frame.h"
    #include "wx/settings.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/app.h"
#endif

#include "wx/palmos/private.h"

// DLL options compatibility check:
#include "wx/build.h"
WX_CHECK_BUILD_OPTIONS("wxGL")

#include "wx/glcanvas.h"

static const wxChar *wxGLCanvasClassName = wxT("wxGLCanvasClass");
static const wxChar *wxGLCanvasClassNameNoRedraw = wxT("wxGLCanvasClassNR");

LRESULT WXDLLEXPORT APIENTRY _EXPORT wxWndProc(HWND hWnd, UINT message,
                                   WPARAM wParam, LPARAM lParam);

/*
 * GLContext implementation
 */

wxGLContext::wxGLContext(bool WXUNUSED(isRGB), wxGLCanvas *win, const wxPalette& WXUNUSED(palette))
{
}

wxGLContext::wxGLContext(
               bool WXUNUSED(isRGB), wxGLCanvas *win,
               const wxPalette& WXUNUSED(palette),
               const wxGLContext *other  /* for sharing display lists */
             )
{
}

wxGLContext::~wxGLContext()
{
}

void wxGLContext::SwapBuffers()
{
}

void wxGLContext::SetCurrent()
{
}

void wxGLContext::SetColour(const wxString& colour)
{
}


/*
 * wxGLCanvas implementation
 */

IMPLEMENT_CLASS(wxGLCanvas, wxWindow)

BEGIN_EVENT_TABLE(wxGLCanvas, wxWindow)
    EVT_SIZE(wxGLCanvas::OnSize)
    EVT_PALETTE_CHANGED(wxGLCanvas::OnPaletteChanged)
    EVT_QUERY_NEW_PALETTE(wxGLCanvas::OnQueryNewPalette)
END_EVENT_TABLE()

wxGLCanvas::wxGLCanvas(wxWindow *parent, wxWindowID id,
    const wxPoint& pos, const wxSize& size, long style, const wxString& name,
    int *attribList, const wxPalette& palette) : wxWindow()
{
}

wxGLCanvas::wxGLCanvas( wxWindow *parent,
              const wxGLContext *shared, wxWindowID id,
              const wxPoint& pos, const wxSize& size, long style, const wxString& name,
              int *attribList, const wxPalette& palette )
  : wxWindow()
{
}

// Not very useful for wxMSW, but this is to be wxGTK compliant

wxGLCanvas::wxGLCanvas( wxWindow *parent, const wxGLCanvas *shared, wxWindowID id,
                        const wxPoint& pos, const wxSize& size, long style, const wxString& name,
                        int *attribList, const wxPalette& palette ):
  wxWindow()
{
}

wxGLCanvas::~wxGLCanvas()
{
}

// Replaces wxWindow::Create functionality, since we need to use a different
// window class
bool wxGLCanvas::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxPoint& pos,
                        const wxSize& size,
                        long style,
                        const wxString& name)
{
    return false;
}

static void AdjustPFDForAttributes(PIXELFORMATDESCRIPTOR& pfd, int *attribList)
{
}

void wxGLCanvas::SetupPixelFormat(int *attribList) // (HDC hDC)
{
}

void wxGLCanvas::SetupPalette(const wxPalette& palette)
{
}

void wxGLCanvas::SwapBuffers()
{
}

void wxGLCanvas::OnSize(wxSizeEvent& WXUNUSED(event))
{
}

void wxGLCanvas::SetCurrent()
{
}

void wxGLCanvas::SetColour(const wxChar *colour)
{
}

void wxGLCanvas::OnQueryNewPalette(wxQueryNewPaletteEvent& event)
{
}

void wxGLCanvas::OnPaletteChanged(wxPaletteChangedEvent& event)
{
}

void glArrayElementEXT(GLint WXUNUSED(i))
{
}

void glColorPointerEXT(GLint WXUNUSED(size), GLenum WXUNUSED(type), GLsizei WXUNUSED(stride), GLsizei WXUNUSED(count), const GLvoid *WXUNUSED(pointer))
{
}

void glDrawArraysEXT(GLenum mode, GLint first, GLsizei count)
{
}

void glEdgeFlagPointerEXT(GLsizei WXUNUSED(stride), GLsizei WXUNUSED(count), const GLboolean *WXUNUSED(pointer))
{
}

void glGetPointervEXT(GLenum WXUNUSED(pname), GLvoid* *WXUNUSED(params))
{
}

void glIndexPointerEXT(GLenum WXUNUSED(type), GLsizei WXUNUSED(stride), GLsizei WXUNUSED(count), const GLvoid *WXUNUSED(pointer))
{
}

void glNormalPointerEXT(GLenum type, GLsizei stride, GLsizei count, const GLvoid *pointer)
{
}

void glTexCoordPointerEXT(GLint WXUNUSED(size), GLenum WXUNUSED(type), GLsizei WXUNUSED(stride), GLsizei WXUNUSED(count), const GLvoid *WXUNUSED(pointer))
{
}

void glVertexPointerEXT(GLint size, GLenum type, GLsizei stride, GLsizei count, const GLvoid *pointer)
{
}

void glColorSubtableEXT(GLenum WXUNUSED(target), GLsizei WXUNUSED(start), GLsizei WXUNUSED(count), GLenum WXUNUSED(format), GLenum WXUNUSED(type), const GLvoid *WXUNUSED(table))
{
}

void glColorTableEXT(GLenum WXUNUSED(target), GLenum WXUNUSED(internalformat), GLsizei WXUNUSED(width), GLenum WXUNUSED(format), GLenum WXUNUSED(type), const GLvoid *WXUNUSED(table))
{
}

void glCopyColorTableEXT(GLenum WXUNUSED(target), GLenum WXUNUSED(internalformat), GLint WXUNUSED(x), GLint WXUNUSED(y), GLsizei WXUNUSED(width))
{
}

void glGetColorTableEXT(GLenum WXUNUSED(target), GLenum WXUNUSED(format), GLenum WXUNUSED(type), GLvoid *WXUNUSED(table))
{
}

void glGetColorTableParamaterfvEXT(GLenum WXUNUSED(target), GLenum WXUNUSED(pname), GLfloat *WXUNUSED(params))
{
}

void glGetColorTavleParameterivEXT(GLenum WXUNUSED(target), GLenum WXUNUSED(pname), GLint *WXUNUSED(params))
{
}

void glLockArraysSGI(GLint WXUNUSED(first), GLsizei WXUNUSED(count))
{
}

void glUnlockArraysSGI()
{
}


void glCullParameterdvSGI(GLenum WXUNUSED(pname), GLdouble* WXUNUSED(params))
{
}

void glCullParameterfvSGI(GLenum WXUNUSED(pname), GLfloat* WXUNUSED(params))
{
}

void glIndexFuncSGI(GLenum WXUNUSED(func), GLclampf WXUNUSED(ref))
{
}

void glIndexMaterialSGI(GLenum WXUNUSED(face), GLenum WXUNUSED(mode))
{
}

void glAddSwapHintRectWin(GLint WXUNUSED(x), GLint WXUNUSED(y), GLsizei WXUNUSED(width), GLsizei WXUNUSED(height))
{
}


//---------------------------------------------------------------------------
// wxGLApp
//---------------------------------------------------------------------------

IMPLEMENT_CLASS(wxGLApp, wxApp)

bool wxGLApp::InitGLVisual(int *attribList)
{
    return false;
}

wxGLApp::~wxGLApp()
{
}

#endif
    // wxUSE_GLCANVAS
