/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/joystick.cpp
// Purpose:     wxJoystick class
// Author:      David Webster
// Modified by:
// Created:     10/09/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_JOYSTICK

#include "wx/joystick.h"

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/window.h"
#endif

#define INCL_PM
#define INCL_DOS
#include "wx/os2/private.h"

#define NO_JOYGETPOSEX

IMPLEMENT_DYNAMIC_CLASS(wxJoystick, wxObject)

// Attributes
////////////////////////////////////////////////////////////////////////////

wxPoint wxJoystick::GetPosition() const
{
    // TODO
    return wxPoint(0, 0);
}

int wxJoystick::GetZPosition() const
{
    // TODO
    return 0;
}

int wxJoystick::GetButtonState() const
{
    // TODO
    return 0;
}

int wxJoystick::GetPOVPosition() const
{
    // TODO
    return 0;
}

int wxJoystick::GetPOVCTSPosition() const
{
    // TODO
    return 0;
}

int wxJoystick::GetRudderPosition() const
{
    // TODO
    return 0;
}

int wxJoystick::GetUPosition() const
{
    // TODO
    return 0;
}

int wxJoystick::GetVPosition() const
{
    // TODO
    return 0;
}

int wxJoystick::GetMovementThreshold() const
{
    // TODO
    return 0;
}

void wxJoystick::SetMovementThreshold(int WXUNUSED(threshold))
{
    // TODO
}

// Capabilities
////////////////////////////////////////////////////////////////////////////

bool wxJoystick::IsOk() const
{
    // TODO
    return false;
}

int wxJoystick::GetNumberJoysticks()
{
    // TODO
    return 0;
}

int wxJoystick::GetManufacturerId() const
{
    // TODO
    return 0;
}

int wxJoystick::GetProductId() const
{
    // TODO
    return 0;
}

wxString wxJoystick::GetProductName() const
{
    // TODO
    return wxEmptyString;
}

int wxJoystick::GetXMin() const
{
    // TODO
    return 0;
}

int wxJoystick::GetYMin() const
{
    // TODO
    return 0;
}

int wxJoystick::GetZMin() const
{
    // TODO
    return 0;
}

int wxJoystick::GetXMax() const
{
    // TODO
    return 0;
}

int wxJoystick::GetYMax() const
{
    // TODO
    return 0;
}

int wxJoystick::GetZMax() const
{
    // TODO
    return 0;
}

int wxJoystick::GetNumberButtons() const
{
    // TODO
    return 0;
}

int wxJoystick::GetNumberAxes() const
{
    // TODO
    return 0;
}

int wxJoystick::GetMaxButtons() const
{
    // TODO
    return 0;
}

int wxJoystick::GetMaxAxes() const
{
    // TODO
    return 0;
}

int wxJoystick::GetPollingMin() const
{
    // TODO
    return 0;
}

int wxJoystick::GetPollingMax() const
{
    // TODO
    return 0;
}

int wxJoystick::GetRudderMin() const
{
    // TODO
    return 0;
}

int wxJoystick::GetRudderMax() const
{
    // TODO
    return 0;
}

int wxJoystick::GetUMin() const
{
    // TODO
    return 0;
}

int wxJoystick::GetUMax() const
{
    // TODO
    return 0;
}

int wxJoystick::GetVMin() const
{
    // TODO
    return 0;
}

int wxJoystick::GetVMax() const
{
    // TODO
    return 0;
}

bool wxJoystick::HasRudder() const
{
    // TODO
    return false;
}

bool wxJoystick::HasZ() const
{
    // TODO
    return false;
}

bool wxJoystick::HasU() const
{
    // TODO
    return false;
}

bool wxJoystick::HasV() const
{
    // TODO
    return false;
}

bool wxJoystick::HasPOV() const
{
    // TODO
    return false;
}

bool wxJoystick::HasPOV4Dir() const
{
    // TODO
    return false;
}

bool wxJoystick::HasPOVCTS() const
{
    // TODO
    return false;
}

// Operations
////////////////////////////////////////////////////////////////////////////

bool wxJoystick::SetCapture(wxWindow* WXUNUSED(win), int WXUNUSED(pollingFreq))
{
    // TODO
    return false;
}

bool wxJoystick::ReleaseCapture()
{
    // TODO
    return false;
}

#endif  // wxUSE_JOYSTICK
