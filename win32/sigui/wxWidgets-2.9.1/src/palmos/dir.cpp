/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/dir.cpp
// Purpose:     wxDir implementation for PalmOS
// Author:      William Osborne - minimal working wxPalmOS port
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

#include "pfall.h"

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

// this class stores everything we need to enumerate the files
class wxDirData
{
public:
    wxDirData(const wxString& dirname);
    ~wxDirData();

    bool IsOk() const { return m_dir != NULL; }

    void SetFileSpec(const wxString& filespec) { m_filespec = filespec; }
    void SetFlags(int flags) { m_flags = flags; }

    void Close();
    bool Read(wxString *filename);

    const wxString& GetName() const { return m_dirname; }

private:
    void     *m_dir;

    wxString m_dirname;
    wxString m_filespec;

    int      m_flags;
};

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxDirData
// ----------------------------------------------------------------------------

wxDirData::wxDirData(const wxString& dirname)
         : m_dirname(dirname)
{
    m_dir = NULL;

    // throw away the trailing slashes
    size_t n = m_dirname.length();
    wxCHECK_RET( n, wxT("empty dir name in wxDir") );

    while ( n > 0 && m_dirname[--n] == '/' )
        ;

    m_dirname.Truncate(n + 1);

    // do open the dir
    //m_dir = opendir(m_dirname.fn_str());
}

wxDirData::~wxDirData()
{
    Close ();
}

void wxDirData::Close()
{
    if ( m_dir )
    {
        if ( svfs_dir_endfind (m_dir) != 0 )
        {
            wxLogLastError(wxT("svfs_dir_endfind"));
        }
        m_dir = NULL;
    }
}

bool wxDirData::Read(wxString *filename)
{
    //dirent *de = NULL;    // just to silence compiler warnings
    int ret;
    char tmpbuf[300];
    bool matches = false;
    size_t flags_search;

    // speed up string concatenation in the loop a bit
    wxString path = m_dirname;
    path += wxT('/');
    path.reserve(path.length() + 255);

    wxString de_d_name;
    de_d_name.reserve(500);
    flags_search = 0;
    if (wxDIR_DIRS & m_flags) {
        flags_search |= SDIR_DIRS;
    }
    if (wxDIR_FILES & m_flags) {
        flags_search |= SDIR_FILES;
    }
    if (NULL == m_dir) {
#ifdef _PACC_VER
// walk around the PalmOS pacc compiler bug
        ret = svfs_dir_findfirst (m_dirname.fn_str().data(), &m_dir, tmpbuf, sizeof (tmpbuf), flags_search);
#else
         ret = svfs_dir_findfirst (m_dirname.fn_str(), &m_dir, tmpbuf, sizeof (tmpbuf), flags_search);
#endif
    } else {
        ret = svfs_dir_findnext (m_dir, tmpbuf, sizeof (tmpbuf));
    }
    for (; ret > 0; ) {

#if wxUSE_UNICODE
        de_d_name = wxString(tmpbuf, *wxConvFileName);
#else
        de_d_name = tmpbuf;
#endif

        // don't return "." and ".." unless asked for
        if ( tmpbuf[0] == '.' &&
             ((tmpbuf[1] == '.' && tmpbuf[2] == '\0') ||
              (tmpbuf[1] == '\0')) )
        {
            if ( !(m_flags & wxDIR_DOTDOT) )
                continue;

            // we found a valid match
            break;
        }

        // check the name
        if ( m_filespec.empty() )
        {
            matches = m_flags & wxDIR_HIDDEN ? true : tmpbuf[0] != '.';
        }
        else
        {
            // test against the pattern
            matches = wxMatchWild(m_filespec, de_d_name,
                                  !(m_flags & wxDIR_HIDDEN));
        }
        if (matches)
            break;
        ret = svfs_dir_findnext (m_dir, tmpbuf, sizeof (tmpbuf));
    }

    *filename = de_d_name;

    return true;
}

// ----------------------------------------------------------------------------
// wxDir construction/destruction
// ----------------------------------------------------------------------------

wxDir::wxDir(const wxString& dirname)
{
    m_data = NULL;
    (void)Open(dirname);
}

bool wxDir::Open(const wxString& dirname)
{
    delete M_DIR;
    m_data = new wxDirData(dirname);

    return true;
}

bool wxDir::IsOpened() const
{
    return m_data != NULL;
}

wxString wxDir::GetName() const
{
    wxString name;
    if ( m_data )
    {
        name = M_DIR->GetName();
        if ( !name.empty() && (name.Last() == wxT('/')) )
        {
            // chop off the last (back)slash
            name.Truncate(name.length() - 1);
        }
    }

    return name;
}

wxDir::~wxDir()
{
    delete M_DIR;
}

// ----------------------------------------------------------------------------
// wxDir enumerating
// ----------------------------------------------------------------------------

bool wxDir::GetFirst(wxString *filename,
                     const wxString& filespec,
                     int flags) const
{
    wxCHECK_MSG( IsOpened(), false, wxT("must wxDir::Open() first") );
    M_DIR->Close();
    M_DIR->SetFileSpec(filespec);
    M_DIR->SetFlags(flags);
    return GetNext(filename);
}

bool wxDir::GetNext(wxString *filename) const
{
    wxCHECK_MSG( IsOpened(), false, wxT("must wxDir::Open() first") );
    wxCHECK_MSG( filename, false, wxT("bad pointer in wxDir::GetNext()") );
    return M_DIR->Read(filename);
}

