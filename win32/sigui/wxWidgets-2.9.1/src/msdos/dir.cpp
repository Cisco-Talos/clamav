/////////////////////////////////////////////////////////////////////////////
// Name:        src/msdos/dir.cpp
// Purpose:     wxDir implementation for DOS
// Author:      derived from wxPalmOS code
// Modified by:
// Created:     10.13.04
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

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
#endif // PCH

#include "wx/dir.h"

// ----------------------------------------------------------------------------
// define the types and functions used for file searching
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

#ifndef MAX_PATH
    #define MAX_PATH 260        // from VC++ headers
#endif

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

#define M_DIR       ((wxDirData *)m_data)

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxDir construction/destruction
// ----------------------------------------------------------------------------

wxDir::wxDir(const wxString& WXUNUSED(dirname))
{
}

bool wxDir::Open(const wxString& WXUNUSED(dirname))
{
    return false;
}

bool wxDir::IsOpened() const
{
    return false;
}

wxString wxDir::GetName() const
{
    return wxEmptyString;
}

wxDir::~wxDir()
{
}

// ----------------------------------------------------------------------------
// wxDir enumerating
// ----------------------------------------------------------------------------

bool wxDir::GetFirst(wxString *WXUNUSED(filename),
                     const wxString& WXUNUSED(filespec),
                     int WXUNUSED(flags)) const
{
    return false;
}

bool wxDir::GetNext(wxString *WXUNUSED(filename)) const
{
    return false;
}
