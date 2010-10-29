/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/palette.cpp
// Purpose:     wxPalette
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_PALETTE

#include "wx/palette.h"

#ifndef WX_PRECOMP
#endif

#include "wx/palmos/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxPalette, wxGDIObject)

/*
 * Palette
 *
 */

wxPaletteRefData::wxPaletteRefData(void)
{
}

wxPaletteRefData::~wxPaletteRefData(void)
{
}

wxPalette::wxPalette(void)
{
}

wxPalette::wxPalette(int n, const unsigned char *red, const unsigned char *green, const unsigned char *blue)
{
}

wxPalette::~wxPalette(void)
{
}

bool wxPalette::FreeResource(bool WXUNUSED(force))
{
    return false;
}

bool wxPalette::Create(int n, const unsigned char *red, const unsigned char *green, const unsigned char *blue)
{
    return false;
}

int wxPalette::GetPixel(unsigned char red, unsigned char green, unsigned char blue) const
{
    return wxNOT_FOUND;
}

bool wxPalette::GetRGB(int index, unsigned char *red, unsigned char *green, unsigned char *blue) const
{
    return false;
}

void wxPalette::SetHPALETTE(WXHPALETTE pal)
{
}

#endif // wxUSE_PALETTE
