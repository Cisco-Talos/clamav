///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/volume.cpp
// Purpose:     wxFSVolume - encapsulates system volume information
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

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_FSVOLUME

#include "wx/volume.h"

#ifndef WX_PRECOMP
    #if wxUSE_GUI
        #include "wx/icon.h"
    #endif
    #include "wx/intl.h"
    #include "wx/arrstr.h"
    #include "wx/hashmap.h"
#endif // WX_PRECOMP

#include <VFSMgr.h>
#ifdef __WXPALMOS6__
#include <PalmTypesCompatibility.h>
#else
#include <PalmCompatibility.h>
#endif

#if wxUSE_BASE

//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Globals/Statics
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
static long s_cancelSearch = FALSE;

struct FileInfo
{
    FileInfo(unsigned flag=0, wxFSVolumeKind type=wxFS_VOL_OTHER) :
        m_flags(flag), m_type(type) {}

    FileInfo(const FileInfo& other) { *this = other; }
    FileInfo& operator=(const FileInfo& other)
    {
        m_flags = other.m_flags;
        m_type = other.m_type;
        return *this;
    }

    unsigned m_flags;
    wxFSVolumeKind m_type;
};

WX_DECLARE_STRING_HASH_MAP(FileInfo, FileInfoMap);

// Cygwin bug (?) destructor for global s_fileInfo is called twice...
static FileInfoMap& GetFileInfoMap()
{
    static FileInfoMap s_fileInfo(25);

    return s_fileInfo;
}
#define s_fileInfo (GetFileInfoMap())

//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Local helper functions.
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

//=============================================================================
// Function: GetBasicFlags
// Purpose: Set basic flags, primarily wxFS_VOL_REMOTE and wxFS_VOL_REMOVABLE.
// Notes: - Local and mapped drives are mounted by definition.  We have no
//          way to determine mounted status of network drives, so assume that
//          all drives are mounted, and let the caller decide otherwise.
//        - Other flags are 'best guess' from type of drive.  The system will
//          not report the file attributes with any degree of accuracy.
//=============================================================================
static unsigned GetBasicFlags(const wxChar* filename)
{
    unsigned flags = wxFS_VOL_MOUNTED;

    return flags;
} // GetBasicFlags

//=============================================================================
// Function: FilteredAdd
// Purpose: Add a file to the list if it meets the filter requirement.
// Notes: - See GetBasicFlags for remarks about the Mounted flag.
//=============================================================================
static bool FilteredAdd(wxArrayString& list, const wxChar* filename,
                        unsigned flagsSet, unsigned flagsUnset)
{
    return false;
} // FilteredAdd

//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// wxFSVolume
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

//=============================================================================
// Function: GetVolumes
// Purpose: Generate and return a list of all volumes (drives) available.
// Notes:
//=============================================================================
wxArrayString wxFSVolumeBase::GetVolumes(int flagsSet, int flagsUnset)
{
    wxArrayString list;

    UInt16 refNum;
    UInt32 it = vfsIteratorStart;

    while (it != vfsIteratorStop)
    {
        status_t err = VFSVolumeEnumerate(&refNum, &it);
        if (err == errNone)
        {
            // manual: "Volume labels can be up to 255 characters long."
            char label[256];
            err = VFSVolumeGetLabel(refNum,label,256);
            if (err == errNone)
            {
                list.Add(wxString::FromAscii(label));
            }
        }

        if (err != errNone)
            break;
    }

    return list;
} // GetVolumes

//=============================================================================
// Function: CancelSearch
// Purpose: Instruct an active search to stop.
// Notes: - This will only sensibly be called by a thread other than the one
//          performing the search.  This is the only thread-safe function
//          provided by the class.
//=============================================================================
void wxFSVolumeBase::CancelSearch()
{
} // CancelSearch

//=============================================================================
// Function: constructor
// Purpose: default constructor
//=============================================================================
wxFSVolumeBase::wxFSVolumeBase()
{
} // wxVolume

//=============================================================================
// Function: constructor
// Purpose: constructor that calls Create
//=============================================================================
wxFSVolumeBase::wxFSVolumeBase(const wxString& name)
{
} // wxVolume

//=============================================================================
// Function: Create
// Purpose: Finds, logs in, etc. to the request volume.
//=============================================================================
bool wxFSVolumeBase::Create(const wxString& name)
{
    return false;
} // Create

//=============================================================================
// Function: IsOk
// Purpose: returns true if the volume is legal.
// Notes: For fixed disks, it must exist.  For removable disks, it must also
//        be present.  For Network Shares, it must also be logged in, etc.
//=============================================================================
bool wxFSVolumeBase::IsOk() const
{
    return false;
} // IsOk

//=============================================================================
// Function: GetKind
// Purpose: Return the type of the volume.
//=============================================================================
wxFSVolumeKind wxFSVolumeBase::GetKind() const
{
    return wxFS_VOL_OTHER;
}

//=============================================================================
// Function: GetFlags
// Purpose: Return the caches flags for this volume.
// Notes: - Returns -1 if no flags were cached.
//=============================================================================
int wxFSVolumeBase::GetFlags() const
{
    return -1;
} // GetFlags

#endif // wxUSE_BASE

// ============================================================================
// wxFSVolume
// ============================================================================

#if wxUSE_GUI

void wxFSVolume::InitIcons()
{
}

//=============================================================================
// Function: GetIcon
// Purpose: return the requested icon.
//=============================================================================

wxIcon wxFSVolume::GetIcon(wxFSIconType type) const
{
    return m_icons[type];
} // GetIcon

#endif // wxUSE_GUI

#endif // wxUSE_FSVOLUME
