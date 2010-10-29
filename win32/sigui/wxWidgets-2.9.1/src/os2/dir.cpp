/////////////////////////////////////////////////////////////////////////////
// Name:        os2/dir.cpp
// Purpose:     wxDir implementation for OS/2
// Author:      Vadim Zeitlin
// Modified by: Stefan Neis
// Created:     08.12.99
// RCS-ID:      $Id$
// Copyright:   (c) 1999 Vadim Zeitlin <zeitlin@dptmaths.ens-cachan.fr>
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

#ifndef WX_PRECOMP
    #include "wx/os2/private.h"
    #include "wx/intl.h"
    #include "wx/log.h"
#endif // PCH

#include "wx/dir.h"
#include "wx/filefn.h"          // for wxMatchWild

#include <sys/types.h>

#define INCL_DOSFILEMGR
#define INCL_DOSERRORS
#include <os2.h>

#ifdef __EMX__
#include <dirent.h>
#endif

// ----------------------------------------------------------------------------
// define the types and functions used for file searching
// ----------------------------------------------------------------------------

typedef FILEFINDBUF3                FIND_STRUCT;
typedef HDIR                        FIND_DATA;
typedef ULONG                       FIND_ATTR;

static inline FIND_DATA InitFindData() { return ERROR_INVALID_HANDLE; }

static inline bool IsFindDataOk(
  FIND_DATA                     vFd
)
{
    return vFd != ERROR_INVALID_HANDLE;
}

static inline void FreeFindData(
  FIND_DATA                     vFd
)
{
    if (!::DosFindClose(vFd))
    {
        wxLogLastError(wxT("DosFindClose"));
    }
}

static inline FIND_DATA FindFirst(
  const wxString&               rsSpec
, FIND_STRUCT*                  pFinddata
)
{
    ULONG                       ulFindCount = 1;
    FIND_DATA                   hDir = HDIR_CREATE;
    FIND_ATTR                   rc;

    rc = ::DosFindFirst( rsSpec.c_str()
                        ,&hDir
                        ,0x37 // was: FILE_NORMAL
                        ,pFinddata
                        ,sizeof(FILEFINDBUF3)
                        ,&ulFindCount
                        ,FIL_STANDARD
                       );
    if (rc != 0)
        return InitFindData();
    return hDir;
}

static inline bool FindNext(
  FIND_DATA                         vFd
, FIND_STRUCT*                      pFinddata
)
{
    ULONG                           ulFindCount = 1;

    return ::DosFindNext( vFd
                         ,pFinddata
                         ,sizeof(FILEFINDBUF3)
                         ,&ulFindCount
                         ) == 0;
}

static const wxChar* GetNameFromFindData(
  FIND_STRUCT*                      pFinddata
)
{
    return (wxChar*)pFinddata->achName;
}

static const FIND_ATTR GetAttrFromFindData(
  FIND_STRUCT*                      pFinddata
)
{
    return pFinddata->attrFile;
}

static inline bool IsDir(
  FIND_ATTR                         vAttr
)
{
    return (vAttr & FILE_DIRECTORY) != 0;
}

static inline bool IsHidden(
  FIND_ATTR                         vAttr
)
{
    return (vAttr & (FILE_HIDDEN | FILE_SYSTEM)) != 0;
}

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

#ifndef MAX_PATH
    #define MAX_PATH 260        // from PM++ headers
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
    wxDirData(const wxString& rsDirname);
    ~wxDirData();

    void SetFileSpec(const wxString& rsFilespec) { m_sFilespec = rsFilespec; }
    void SetFlags(int nFlags) { m_nFlags = nFlags; }

    const wxString& GetName() const { return m_sDirname; }
    void Close();
    void Rewind();
    bool Read(wxString* rsFilename);

private:
    FIND_DATA                       m_vFinddata;
    wxString                        m_sDirname;
    wxString                        m_sFilespec;
    int                             m_nFlags;
}; // end of CLASS wxDirData

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxDirData
// ----------------------------------------------------------------------------

wxDirData::wxDirData(
  const wxString&                   rsDirname
)
: m_sDirname(rsDirname)
{
    m_vFinddata = InitFindData();
} // end of wxDirData::wxDirData

wxDirData::~wxDirData()
{
    Close();
} // end of wxDirData::~wxDirData

void wxDirData::Close()
{
    if ( IsFindDataOk(m_vFinddata) )
    {
        FreeFindData(m_vFinddata);
        m_vFinddata = InitFindData();
    }
} // end of wxDirData::Close

void wxDirData::Rewind()
{
    Close();
} // end of wxDirData::Rewind

bool wxDirData::Read(
  wxString*                         psFilename
)
{
    bool                            bFirst = false;

    FILEFINDBUF3                    vFinddata;
    #define PTR_TO_FINDDATA (&vFinddata)

    if (!IsFindDataOk(m_vFinddata))
    {
        //
        // Open first
        //
        wxString                    sFilespec = m_sDirname;

        if ( !wxEndsWithPathSeparator(sFilespec) )
        {
            sFilespec += wxT('\\');
        }
        sFilespec += (!m_sFilespec ? wxT("*.*") : m_sFilespec.c_str());

        m_vFinddata = FindFirst( sFilespec
                                ,PTR_TO_FINDDATA
                               );
        bFirst = true;
    }

    if ( !IsFindDataOk(m_vFinddata) )
    {
        return false;
    }

    const wxChar*                   zName;
    FIND_ATTR                       vAttr;

    for ( ;; )
    {
        if (bFirst)
        {
            bFirst = false;
        }
        else
        {
            if (!FindNext( m_vFinddata
                          ,PTR_TO_FINDDATA
                         ))
            {
                return false;
            }
        }

        zName = GetNameFromFindData(PTR_TO_FINDDATA);
        vAttr = GetAttrFromFindData(PTR_TO_FINDDATA);

        //
        // Don't return "." and ".." unless asked for
        //
        if ( zName[0] == wxT('.') &&
             ((zName[1] == wxT('.') && zName[2] == wxT('\0')) ||
              (zName[1] == wxT('\0'))) )
        {
            if (!(m_nFlags & wxDIR_DOTDOT))
                continue;
        }

        //
        // Check the type now
        //
        if (!(m_nFlags & wxDIR_FILES) && !IsDir(vAttr))
        {
            //
            // It's a file, but we don't want them
            //
            continue;
        }
        else if (!(m_nFlags & wxDIR_DIRS) && IsDir(vAttr) )
        {
            //
            // It's a dir, and we don't want it
            //
            continue;
        }

        //
        // Finally, check whether it's a hidden file
        //
        if (!(m_nFlags & wxDIR_HIDDEN))
        {
            if (IsHidden(vAttr))
            {
                //
                // It's a hidden file, skip it
                //
                continue;
            }
        }
        *psFilename = zName;
        break;
    }
    return true;
} // end of wxDirData::Read

// ----------------------------------------------------------------------------
// wxDir construction/destruction
// ----------------------------------------------------------------------------

wxDir::wxDir(
  const wxString&                   rsDirname
)
{
    m_data = NULL;

    (void)Open(rsDirname);
} // end of wxDir::wxDir

bool wxDir::Open(
  const wxString&                   rsDirname
)
{
    delete M_DIR;
    m_data = new wxDirData(rsDirname);
    return true;
} // end of wxDir::Open

bool wxDir::IsOpened() const
{
    return m_data != NULL;
} // end of wxDir::IsOpen

wxString wxDir::GetName() const
{
    wxString name;
    if ( m_data )
    {
        name = M_DIR->GetName();
        if ( !name.empty() )
        {
            // bring to canonical Windows form
            name.Replace(wxT("/"), wxT("\\"));

            if ( name.Last() == wxT('\\') )
            {
                // chop off the last (back)slash
                name.Truncate(name.length() - 1);
            }
        }
    }

    return name;
}

wxDir::~wxDir()
{
    delete M_DIR;
} // end of wxDir::~wxDir

// ----------------------------------------------------------------------------
// wxDir enumerating
// ----------------------------------------------------------------------------

bool wxDir::GetFirst(
  wxString*                         psFilename
, const wxString&                   rsFilespec
, int                               nFlags
) const
{
    wxCHECK_MSG( IsOpened(), false, wxT("must wxDir::Open() first") );
    M_DIR->Rewind();
    M_DIR->SetFileSpec(rsFilespec);
    M_DIR->SetFlags(nFlags);
    return GetNext(psFilename);
} // end of wxDir::GetFirst

bool wxDir::GetNext(
  wxString*                         psFilename
) const
{
    wxCHECK_MSG( IsOpened(), false, wxT("must wxDir::Open() first") );
    wxCHECK_MSG( psFilename, false, wxT("bad pointer in wxDir::GetNext()") );
    return M_DIR->Read(psFilename);
} // end of wxDir::GetNext

