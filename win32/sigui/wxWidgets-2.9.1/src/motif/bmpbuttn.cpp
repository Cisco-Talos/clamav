/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/bmpbuttn.cpp
// Purpose:     wxBitmapButton
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/bmpbuttn.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/PushBG.h>
#include <Xm/PushB.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

// Implemented in button.cpp
void wxButtonCallback (Widget w, XtPointer clientData, XtPointer ptr);

// Pixmap XCreateInsensitivePixmap( Display *display, Pixmap pixmap );

IMPLEMENT_DYNAMIC_CLASS(wxBitmapButton, wxButton)

wxBitmapButton::wxBitmapButton()
{
    m_marginX = m_marginY = wxDEFAULT_BUTTON_MARGIN;
    m_insensPixmap = (WXPixmap) 0;
}

bool wxBitmapButton::Create(wxWindow *parent, wxWindowID id,
                            const wxBitmap& bitmap,
                            const wxPoint& pos,
                            const wxSize& size, long style,
                            const wxValidator& validator,
                            const wxString& name)
{
    if( !CreateControl( parent, id, pos, size, style, validator, name ) )
        return false;
    PreCreation();

    m_bitmaps[State_Normal] =
    m_bitmapsOriginal[State_Normal] = bitmap;
    m_bitmaps[State_Pressed] =
    m_bitmapsOriginal[State_Pressed] = bitmap;

    Widget parentWidget = (Widget) parent->GetClientWidget();

    /*
    * Patch Note (important)
    * There is no major reason to put a defaultButtonThickness here.
    * Not requesting it give the ability to put wxButton with a spacing
    * as small as requested. However, if some button become a DefaultButton,
    * other buttons are no more aligned -- This is why we set
    * defaultButtonThickness of ALL buttons belonging to the same wxPanel,
    * in the ::SetDefaultButton method.
    */
    Widget buttonWidget = XtVaCreateManagedWidget ("button",

        // Gadget causes problems for default button operation.
#if wxUSE_GADGETS
        xmPushButtonGadgetClass, parentWidget,
#else
        xmPushButtonWidgetClass, parentWidget,
#endif
        // See comment for wxButton::SetDefault
        // XmNdefaultButtonShadowThickness, 1,
        XmNrecomputeSize, False,
        NULL);

    m_mainWidget = (WXWidget) buttonWidget;

    XtAddCallback (buttonWidget,
                   XmNactivateCallback, (XtCallbackProc) wxButtonCallback,
                   (XtPointer) this);

    wxSize best = GetBitmapLabel().IsOk() ? GetBestSize() : wxSize(30, 30);
    if( size.x != -1 ) best.x = size.x;
    if( size.y != -1 ) best.y = size.y;

    PostCreation();
    OnSetBitmap();

    AttachWidget (parent, m_mainWidget, (WXWidget) NULL,
                  pos.x, pos.y, best.x, best.y);

    return true;
}

wxBitmapButton::~wxBitmapButton()
{
    SetBitmapLabel(wxNullBitmap);

    if (m_insensPixmap)
        XmDestroyPixmap (DefaultScreenOfDisplay ((Display*) GetXDisplay()),
                         (Pixmap) m_insensPixmap);
}

void wxBitmapButton::DoSetBitmap(const wxBitmap& bitmap, State which)
{
    m_bitmapsOriginal[which] = bitmap;

    wxBitmapButtonBase::DoSetBitmap(bitmap, which);
}

void wxBitmapButton::OnSetBitmap()
{
    wxBitmapButtonBase::OnSetBitmap();

    if ( m_bitmapsOriginal[State_Normal].IsOk() )
    {
        Pixmap pixmap = 0;
        Pixmap insensPixmap = 0;
        Pixmap armPixmap = 0;

        // Must re-make the bitmap to have its transparent areas drawn
        // in the current widget background colour.
        if ( m_bitmapsOriginal[State_Normal].GetMask() )
        {
            WXPixel backgroundPixel;
            XtVaGetValues((Widget) m_mainWidget,
                          XmNbackground, &backgroundPixel,
                          NULL);

            wxColour col;
            col.SetPixel(backgroundPixel);

            wxBitmap newBitmap =
                wxCreateMaskedBitmap(m_bitmapsOriginal[State_Normal], col);
            m_bitmaps[State_Normal] = newBitmap;
            m_bitmapCache.SetBitmap( m_bitmaps[State_Normal] );

            pixmap = (Pixmap) m_bitmaps[State_Normal].GetDrawable();
        }
        else
        {
            m_bitmapCache.SetBitmap( m_bitmaps[State_Normal] );
            pixmap = (Pixmap) m_bitmapCache.GetLabelPixmap(m_mainWidget);
        }

        if (m_bitmapsOriginal[State_Disabled].IsOk())
        {
            if (m_bitmapsOriginal[State_Disabled].GetMask())
            {
                WXPixel backgroundPixel;
                XtVaGetValues((Widget) m_mainWidget,
                              XmNbackground, &backgroundPixel,
                              NULL);

                wxColour col;
                col.SetPixel(backgroundPixel);

                wxBitmap newBitmap =
                    wxCreateMaskedBitmap(m_bitmapsOriginal[State_Disabled], col);
                m_bitmaps[State_Disabled] = newBitmap;

                insensPixmap = (Pixmap) m_bitmaps[State_Disabled].GetDrawable();
            }
            else
                insensPixmap = (Pixmap) m_bitmapCache.GetInsensPixmap(m_mainWidget);
        }
        else
            insensPixmap = (Pixmap) m_bitmapCache.GetInsensPixmap(m_mainWidget);

        // Now make the bitmap representing the armed state
        if (m_bitmapsOriginal[State_Pressed].IsOk())
        {
            if (m_bitmapsOriginal[State_Pressed].GetMask())
            {
                WXPixel backgroundPixel;
                XtVaGetValues((Widget) m_mainWidget,
                              XmNarmColor, &backgroundPixel,
                              NULL);

                wxColour col;
                col.SetPixel(backgroundPixel);

                wxBitmap newBitmap =
                    wxCreateMaskedBitmap(m_bitmapsOriginal[State_Pressed], col);
                m_bitmaps[State_Pressed] = newBitmap;

                armPixmap = (Pixmap) m_bitmaps[State_Pressed].GetDrawable();
            }
            else
                armPixmap = (Pixmap) m_bitmapCache.GetArmPixmap(m_mainWidget);
        }
        else
            armPixmap = (Pixmap) m_bitmapCache.GetArmPixmap(m_mainWidget);

        XtVaSetValues ((Widget) m_mainWidget,
            XmNlabelPixmap, pixmap,
            XmNlabelInsensitivePixmap, insensPixmap,
            XmNarmPixmap, armPixmap,
            XmNlabelType, XmPIXMAP,
            NULL);
    }
    else
    {
        // Null bitmap: must not use current pixmap
        // since it is no longer valid.
        XtVaSetValues ((Widget) m_mainWidget,
            XmNlabelType, XmSTRING,
            XmNlabelPixmap, XmUNSPECIFIED_PIXMAP,
            XmNlabelInsensitivePixmap, XmUNSPECIFIED_PIXMAP,
            XmNarmPixmap, XmUNSPECIFIED_PIXMAP,
            NULL);
    }
}

void wxBitmapButton::ChangeBackgroundColour()
{
    wxDoChangeBackgroundColour(m_mainWidget, m_backgroundColour, true);

    // Must reset the bitmaps since the colours have changed.
    OnSetBitmap();
}

wxSize wxBitmapButton::DoGetBestSize() const
{
    wxSize ret( 30,30 );

    if (GetBitmapLabel().IsOk())
    {
        int border = HasFlag(wxNO_BORDER) ? 4 : 10;
        ret.x += border;
        ret.y += border;

        ret += GetBitmapLabel().GetSize();
    }

    return ret;
}
