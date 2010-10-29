/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/statbmp.cpp
// Purpose:     wxStaticBitmap
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/statbmp.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#include <Xm/Label.h>
#include <Xm/LabelG.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxStaticBitmap, wxControl)

/*
 * wxStaticBitmap
 */

bool wxStaticBitmap::Create(wxWindow *parent, wxWindowID id,
           const wxBitmap& bitmap,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxString& name)
{
    if( !CreateControl( parent, id, pos, size, style, wxDefaultValidator,
                        name ) )
        return false;
    PreCreation();

    m_messageBitmap = bitmap;
    m_messageBitmapOriginal = bitmap;

    Widget parentWidget = (Widget) parent->GetClientWidget();

    m_mainWidget = (WXWidget) XtVaCreateManagedWidget ("staticBitmap",
#if wxUSE_GADGETS
                    xmLabelGadgetClass, parentWidget,
#else
                    xmLabelWidgetClass, parentWidget,
#endif
                    XmNalignment, XmALIGNMENT_BEGINNING,
                    NULL);

    wxSize actualSize(size);
    // work around the cases where the bitmap is a wxNull(Icon/Bitmap)
    if (actualSize.x == -1)
        actualSize.x = bitmap.Ok() ? bitmap.GetWidth() : 1;
    if (actualSize.y == -1)
        actualSize.y = bitmap.Ok() ? bitmap.GetHeight() : 1;

    PostCreation();
    DoSetBitmap();
    AttachWidget (parent, m_mainWidget, (WXWidget) NULL,
                  pos.x, pos.y, actualSize.x, actualSize.y);

    return true;
}

wxStaticBitmap::~wxStaticBitmap()
{
    SetBitmap(wxNullBitmap);
}

void wxStaticBitmap::DoSetBitmap()
{
    Widget widget = (Widget) m_mainWidget;
    int w2, h2;

    if (m_messageBitmapOriginal.Ok())
    {
        w2 = m_messageBitmapOriginal.GetWidth();
        h2 = m_messageBitmapOriginal.GetHeight();

        Pixmap pixmap;

        // Must re-make the bitmap to have its transparent areas drawn
        // in the current widget background colour.
        if (m_messageBitmapOriginal.GetMask())
        {
            WXPixel backgroundPixel;
            XtVaGetValues( widget, XmNbackground, &backgroundPixel,
                NULL);

            wxColour col;
            col.SetPixel(backgroundPixel);

            wxBitmap newBitmap = wxCreateMaskedBitmap(m_messageBitmapOriginal, col);
            m_messageBitmap = newBitmap;

            pixmap = (Pixmap) m_messageBitmap.GetDrawable();
        }
        else
        {
            m_bitmapCache.SetBitmap( m_messageBitmap );
            pixmap = (Pixmap)m_bitmapCache.GetLabelPixmap(widget);
        }

        XtVaSetValues (widget,
            XmNlabelPixmap, pixmap,
            XmNlabelType, XmPIXMAP,
            NULL);

        SetSize(w2, h2);
    }
    else
    {
        // Null bitmap: must not use current pixmap
        // since it is no longer valid.
        XtVaSetValues (widget,
            XmNlabelType, XmSTRING,
            XmNlabelPixmap, XmUNSPECIFIED_PIXMAP,
            NULL);
    }
}

void wxStaticBitmap::SetBitmap(const wxBitmap& bitmap)
{
    m_messageBitmap = bitmap;
    m_messageBitmapOriginal = bitmap;

    DoSetBitmap();
}

void wxStaticBitmap::ChangeBackgroundColour()
{
    wxWindow::ChangeBackgroundColour();

    // must recalculate the background colour
    m_bitmapCache.SetColoursChanged();
    DoSetBitmap();
}

void wxStaticBitmap::ChangeForegroundColour()
{
    m_bitmapCache.SetColoursChanged();
    wxWindow::ChangeForegroundColour();
}
