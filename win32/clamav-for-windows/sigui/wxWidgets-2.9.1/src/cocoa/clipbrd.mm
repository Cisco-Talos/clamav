/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/clipbrd.mm
// Purpose:     wxClipboard
// Author:      David Elliott <dfe@cox.net>
// Modified by:
// Created:     2003/07/23
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:   	wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_CLIPBOARD

#ifndef WX_PRECOMP
#endif //WX_PRECOMP
#include "wx/clipbrd.h"

IMPLEMENT_DYNAMIC_CLASS(wxClipboard, wxObject)

wxClipboard::wxClipboard()
{
}

wxClipboard::~wxClipboard()
{
}

bool wxClipboard::Open()
{
    return false;
}

void wxClipboard::Close()
{
}

bool wxClipboard::IsOpened() const
{
    return false;
}

bool wxClipboard::SetData(wxDataObject *data)
{
    return false;
}

bool wxClipboard::AddData(wxDataObject *data)
{
    return false;
}

bool wxClipboard::IsSupported(const wxDataFormat& format)
{
    return false;
}

bool wxClipboard::GetData(wxDataObject& data)
{
    return false;
}

void wxClipboard::Clear()
{
}

#endif //wxUSE_CLIPBOARD
