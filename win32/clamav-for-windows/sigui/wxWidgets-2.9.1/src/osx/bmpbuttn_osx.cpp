/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/bmpbuttn_osx.cpp
// Purpose:     wxBitmapButton
// Author:      Stefan Csomor
// Modified by:
// Created:     1998-01-01
// RCS-ID:      $Id: bmpbuttn.cpp 54820 2008-07-29 20:04:11Z SC $
// Copyright:   (c) Stefan Csomor
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_BMPBUTTON

#include "wx/bmpbuttn.h"
#include "wx/image.h"

#ifndef WX_PRECOMP
    #include "wx/dcmemory.h"
#endif

IMPLEMENT_DYNAMIC_CLASS(wxBitmapButton, wxButton)


#include "wx/osx/private.h"

//---------------------------------------------------------------------------

bool wxBitmapButton::Create( wxWindow *parent,
                             wxWindowID id,
                             const wxBitmap& bitmap,
                             const wxPoint& pos,
                             const wxSize& size,
                             long style,
                             const wxValidator& validator,
                             const wxString& name )
{
    m_macIsUserPane = false;

    if ( !wxBitmapButtonBase::Create(parent, id, pos, size, style,
                                     validator, name) )
        return false;

    if ( style & wxBU_AUTODRAW )
    {
        m_marginX =
        m_marginY = wxDEFAULT_BUTTON_MARGIN;
    }
    else
    {
        m_marginX =
        m_marginY = 0;
    }

    m_bitmaps[State_Normal] = bitmap;

    m_peer = wxWidgetImpl::CreateBitmapButton( this, parent, id, bitmap, pos, size, style, GetExtraStyle() );

    MacPostControlCreate( pos, size );

    return true;
}

wxSize wxBitmapButton::DoGetBestSize() const
{
    wxSize best(m_marginX, m_marginY);

    best *= 2;

    if ( GetBitmapLabel().IsOk() )
    {
        best += GetBitmapLabel().GetSize();
    }

    return best;
}

#endif // wxUSE_BMPBUTTON
