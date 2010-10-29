/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/colordlg.cpp
// Purpose:     wxColourDialog class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_COLOURDLG

#include "wx/colordlg.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/cmndata.h"
#endif

#include <UIColor.h>
#include <UIControls.h>

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxColourDialog, wxDialog)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxColourDialog
// ----------------------------------------------------------------------------

wxColourDialog::wxColourDialog()
{
}

wxColourDialog::wxColourDialog(wxWindow *parent, wxColourData *data)
{
    Create(parent, data);
}

bool wxColourDialog::Create(wxWindow *parent, wxColourData *data)
{
    m_parent = parent;

    if (data)
        m_colourData = *data;

    return true;
}

int wxColourDialog::ShowModal()
{
    wxString title = _("Choose colour");

    wxColour colour = m_colourData.GetColour();
    RGBColorType rgb;
    rgb.r = colour.Red();
    rgb.g = colour.Green();
    rgb.b = colour.Blue();
    IndexedColorType i = WinRGBToIndex ( &rgb );

    if (UIPickColor (&i,
                     &rgb,
                     (m_colourData.GetChooseFull()?UIPickColorStartRGB:UIPickColorStartPalette),
                     title.ToAscii(),
                     NULL) == false)
        return wxID_CANCEL;

    colour.Set(rgb.r, rgb.g, rgb.b);
    m_colourData.SetColour(colour);
    return wxID_OK;
}

#endif
