///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/snglinst.cpp
// Purpose:     implements wxSingleInstanceChecker class for Win32 using
//              named mutexes
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

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

#if wxUSE_SNGLINST_CHECKER

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/log.h"
#endif //WX_PRECOMP

#include "wx/snglinst.h"

#include "wx/palmos/private.h"

// ----------------------------------------------------------------------------
// wxSingleInstanceCheckerImpl: the real implementation class
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxSingleInstanceCheckerImpl
{
public:
    wxSingleInstanceCheckerImpl()
    {
    }

    bool Create(const wxString& name)
    {
        return false;
    }

    bool WasOpened() const
    {
        return false;
    }

    ~wxSingleInstanceCheckerImpl()
    {
    }

private:
    // the result of the CreateMutex() call
    bool m_wasOpened;

    // the mutex handle, may be NULL
    HANDLE m_hMutex;

    wxDECLARE_NO_COPY_CLASS(wxSingleInstanceCheckerImpl);
};

// ============================================================================
// wxSingleInstanceChecker implementation
// ============================================================================

bool wxSingleInstanceChecker::Create(const wxString& name,
                                     const wxString& WXUNUSED(path))
{
    return false;
}

bool wxSingleInstanceChecker::IsAnotherRunning() const
{
    return false;
}

wxSingleInstanceChecker::~wxSingleInstanceChecker()
{
}

#endif // wxUSE_SNGLINST_CHECKER
