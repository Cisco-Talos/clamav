/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/utils.cpp
// Purpose:
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/utils.h"

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#include "wx/apptrait.h"
#include "wx/process.h"
#include "wx/evtloop.h"

#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <mgraph.hpp>

#ifdef __UNIX__
#include "wx/unix/execute.h"
#endif

#include "wx/mgl/private.h"

//----------------------------------------------------------------------------
// misc.
//----------------------------------------------------------------------------

// Get free memory in bytes, or -1 if cannot determine amount (e.g. on UNIX)
wxMemorySize wxGetFreeMemory()
{
    // TODO - probably should be extracted to
    //        src/msdos/utilsdos.cpp and src/unix/utilsunx.cpp
    //        to avoid code duplication
    return -1;
}

void wxBell()
{
    // FIXME_MGL
}

bool wxGetKeyState(wxKeyCode key)
{
    wxASSERT_MSG(key != WXK_LBUTTON && key != WXK_RBUTTON && key !=
        WXK_MBUTTON, wxT("can't use wxGetKeyState() for mouse buttons"));

    // TODO

    return false;
}

// ----------------------------------------------------------------------------
// display characterstics
// ----------------------------------------------------------------------------

void wxDisplaySize(int *width, int *height)
{
   wxASSERT_MSG( g_displayDC, wxT("You must call wxApp::SetDisplayMode before using this function") );
    if (width) *width = g_displayDC->sizex()+1;
    if (height) *height = g_displayDC->sizey()+1;
}

void wxDisplaySizeMM(int *width, int *height)
{
    wxASSERT_MSG( g_displayDC, wxT("You must call wxApp::SetDisplayMode before using this function") );

    int xDPI, yDPI;
    MGL_getDotsPerInch(&xDPI, &yDPI);

    if ( width )
        *width = (int)((g_displayDC->sizex()+1) * 25.4 / xDPI);
    if ( height )
        *height = (int)((g_displayDC->sizey()+1) * 25.4 / yDPI);
}

void wxClientDisplayRect(int *x, int *y, int *width, int *height)
{
    if ( x ) *x = 0;
    if ( y ) *y = 0;
    wxDisplaySize(width, height);
    // FIXME_MGL - windowed version needs different handling
}

bool wxColourDisplay()
{
    wxASSERT_MSG( g_displayDC, wxT("You must call wxApp::SetDisplayMode before using this function") );

    return (wxDisplayDepth() > 1);
}

int wxDisplayDepth()
{
    wxASSERT_MSG( g_displayDC, wxT("You must call wxApp::SetDisplayMode before using this function") );

    return g_displayDC->getBitsPerPixel();
}

wxPortId wxGUIAppTraits::GetToolkitVersion(int *verMaj, int *verMin) const
{
    if ( verMaj )
        *verMaj = MGL_RELEASE_MAJOR;
    if ( verMin )
        *verMin = MGL_RELEASE_MINOR;

    return wxPORT_MGL;
}

wxEventLoopBase* wxGUIAppTraits::CreateEventLoop()
{
    return new wxEventLoop;
}


void wxGetMousePosition(int* x, int* y)
{
    MS_getPos(x, y);
}

wxPoint wxGetMousePosition()
{
    wxPoint pt;
    wxGetMousePosition(&pt.x, &pt.y);
    return pt;
}

wxMouseState wxGetMouseState()
{
    wxMouseState ms;
    int x, y;

    wxGetMousePosition(&x, &y);

    ms.SetX(x);
    ms.SetY(y);

    extern unsigned long g_buttonState;
    ms.SetLeftDown(g_buttonState & EVT_LEFTBUT);
    ms.SetMiddleDown(g_buttonState & EVT_MIDDLEBUT);
    ms.SetRightDown(g_buttonState & EVT_RIGHTBUT);

    ms.SetControlDown(EVT_isKeyDown(KB_leftCtrl) || EVT_isKeyDown(KB_rightCtrl));
    ms.SetShiftDown(EVT_isKeyDown(KB_leftShift) || EVT_isKeyDown(KB_rightShift));
    ms.SetAltDown(EVT_isKeyDown(KB_leftAlt));
    ms.SetMetaDown(EVT_isKeyDown(KB_rightAlt));

    return ms;
}

