/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/dir.cpp
// Purpose:     wxDir implementation for MGL
// Author:      Vaclav Slavik, Vadim Zeitlin
// Modified by:
// Created:     2001/12/09
// RCS-ID:      $Id$
// Copyright:   (c) 1999 Vadim Zeitlin <zeitlin@dptmaths.ens-cachan.fr>
//              (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#ifndef __UNIX__

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
#endif // PCH

#include "wx/dir.h"
#include "wx/filefn.h"          // for wxMatchWild
#include "wx/mgl/private.h"

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

    void SetFileSpec(const wxString& filespec);
    void SetFlags(int flags) { m_flags = flags; }

    void Rewind();
    bool Read(wxString *filename);

    const wxString& GetName() const { return m_dirname; }

private:
    void    *m_dir;

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

    while ( n > 0 && m_dirname[--n] == wxFILE_SEP_PATH ) {}

    m_dirname.Truncate(n + 1);
}

wxDirData::~wxDirData()
{
    if ( m_dir )
        PM_findClose(m_dir);
}

void wxDirData::SetFileSpec(const wxString& filespec)
{
#ifdef __DOS__
    if ( filespec.empty() )
        m_filespec = wxT("*.*");
    else
#endif
    m_filespec = filespec;
}

void wxDirData::Rewind()
{
    if ( m_dir )
    {
        PM_findClose(m_dir);
        m_dir = NULL;
    }
}

bool wxDirData::Read(wxString *filename)
{
    PM_findData data;
    bool matches = false;

    data.dwSize = sizeof(data);

    wxString path = m_dirname;
    path += wxFILE_SEP_PATH;
    path.reserve(path.length() + 255); // speed up string concatenation

    while ( !matches )
    {
        if ( m_dir )
        {
            if ( !PM_findNextFile(m_dir, &data) )
                return false;
        }
        else
        {
            m_dir = PM_findFirstFile(path + m_filespec , &data);
            if ( m_dir == PM_FILE_INVALID )
            {
                m_dir = NULL;
                return false;
            }
        }

        // don't return "." and ".." unless asked for
        if ( data.name[0] == '.' &&
             ((data.name[1] == '.' && data.name[2] == '\0') ||
              (data.name[1] == '\0')) )
        {
            if ( !(m_flags & wxDIR_DOTDOT) )
                continue;

            // we found a valid match
            break;
        }

        // check the type now
        if ( !(m_flags & wxDIR_FILES) && !(data.attrib & PM_FILE_DIRECTORY) )
        {
            // it's a file, but we don't want them
            continue;
        }
        else if ( !(m_flags & wxDIR_DIRS) && (data.attrib & PM_FILE_DIRECTORY) )
        {
            // it's a dir, and we don't want it
            continue;
        }

        matches = m_flags & wxDIR_HIDDEN ? true : !(data.attrib & PM_FILE_HIDDEN);
    }

    *filename = data.name;

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
    m_data = NULL;

    if ( !wxDir::Exists(dirname) )
    {
        wxLogError(_("Directory '%s' doesn't exist!"), dirname.c_str());
        return false;
    }

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
        if ( !name.empty() && (name.Last() == wxFILE_SEP_PATH) )
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

    M_DIR->Rewind();

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

#endif // !__UNIX__
