/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/dataobj.mm
// Purpose:     wxDataObject
// Author:      David Elliott <dfe@cox.net>
// Modified by:
// Created:     2003/07/23
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_DATAOBJ

#include "wx/dataobj.h"

#ifndef WX_PRECOMP
#endif //WX_PRECOMP

wxDataObject::wxDataObject()
{
}

wxDataObject::~wxDataObject()
{
}

bool wxDataObject::IsSupportedFormat(const wxDataFormat& format,
        Direction dir) const
{
    return false;
}

wxBitmapDataObject::wxBitmapDataObject()
{
}

wxBitmapDataObject::wxBitmapDataObject(const wxBitmap& bitmap)
{
}

wxBitmapDataObject::~wxBitmapDataObject()
{
}

void wxBitmapDataObject::SetBitmap(const wxBitmap& bitmap)
{
}

bool wxBitmapDataObject::SetData(size_t len, const void *buf)
{
    return false;
}

bool wxBitmapDataObject::GetDataHere(void *buf) const
{
    return false;
}

#endif //wxUSE_DATAOBJ
