/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/pen.cpp
// Purpose:     wxPen
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

#include "wx/pen.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
#endif

static int wx2msPenStyle(int wx_style);

IMPLEMENT_DYNAMIC_CLASS(wxPen, wxGDIObject)

wxPenRefData::wxPenRefData()
{
}

wxPenRefData::wxPenRefData(const wxPenRefData& data)
{
}

wxPenRefData::~wxPenRefData()
{
}

// Pens

wxPen::wxPen()
{
}

wxPen::~wxPen()
{
}

// Should implement Create
wxPen::wxPen(const wxColour& col, int Width, wxPenStyle Style)
{
}

wxPen::wxPen(const wxBitmap& stipple, int Width)
{
}

bool wxPen::RealizeResource()
{
    return false;
}

WXHANDLE wxPen::GetResourceHandle() const
{
    return 0;
}

bool wxPen::FreeResource(bool WXUNUSED(force))
{
    return false;
}

bool wxPen::IsFree() const
{
    return false;
}

void wxPen::SetColour(const wxColour& col)
{
}

void wxPen::SetColour(unsigned char r, unsigned char g, unsigned char b)
{
}

void wxPen::SetWidth(int Width)
{
}

void wxPen::SetStyle(wxPenStyle Style)
{
}

void wxPen::SetStipple(const wxBitmap& Stipple)
{
}

void wxPen::SetDashes(int nb_dashes, const wxDash *Dash)
{
}

void wxPen::SetJoin(wxPenJoin Join)
{
}

void wxPen::SetCap(wxPenCap Cap)
{
}

wxGDIRefData *wxPen::CreateGDIRefData() const
{
    return new wxPenRefData();
}

wxGDIRefData *wxPen::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxPenRefData(*static_cast<const wxPenRefData *>(data));
}

