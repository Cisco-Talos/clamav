///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/prefconf.cpp
// Purpose:     wxPrefConfig implementation
// Author:      Wlodzimierz ABX Skiba
// Modified by:
// Created:     28.12.2004
// RCS-ID:      $Id$
// Copyright:   (c) Wlodzimierz Skiba
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include  "wx/string.h"
#endif //WX_PRECOMP

#if wxUSE_CONFIG && wxUSE_CONFIG_NATIVE

#include "wx/config.h"

// ============================================================================
// implementation
// ============================================================================

/*

http://www.palmos.com/dev/support/docs/protein_books/System_Management/PreferenceConcepts.html

This wxPrefConfig class is a wxConfig wrapper around PalmOS Preferences
functionality. Preferences allow to write any structure into its database so
wxPrefConfig writes there all entries of single group into one Preference.
To optimize read/write operations value of preference is cached. Cache is filled
after each change of the path (including using path to group names in all
operations) and it is flushed on destructor, any path change on or purpose
with Flush().

Meaning of styles:

  wxCONFIG_USE_LOCAL_FILE => store config in "saved" preferences database
                             (not to be backed up during a HotSync operation)
  wxCONFIG_USE_GLOBAL_FILE => store config in "unsaved" preferences database
                             (backed up during a HotSync operation)


Each Preference is an array of chars. First unsigned char describes
number N of chars used for Preference size. Next N chars (string) contains
length of rest of Preference. Preference consists in serie of entries which
should be read in loop until in reaches end of Preference.

  Each entry is an set of chars with following structure:
  1. name (null terminated)
  2. type (single char): b,s,g,l,d (see value)
  3. value
     - for type="b" (bool) it os "0" or "1"
     - for type="s" (string) it is null terminated set of chars
     - for type="g" (subgroup) as for "s" but string is converted to
       uint16_t for id parameter of ::PrefGetAppPreferences()
     - for type="l" (long) as for "s" but string is converted to long
     - for type="d" (double) as for "s" but string is converted to double
     - otherwise it is ""

So all together first Read in group needs 3 reading from Preference:
  1. take the length N of length
  2. take the length M of the group content
  3. take the group content
and all it is in single Preference to not overload Preferences database.
As long as each next Read/Write is performed in the same group then none
access to Preferences is performed. Flushing needs only single writing to
databease because all 3 parts of Preference can be prepared in memory.

NOTE: wxPrefConfig can read/write only its own entries. It is impossible to
know structures of Preferences of other non wxW applications.

*/

// ----------------------------------------------------------------------------
// ctor/dtor
// ----------------------------------------------------------------------------
IMPLEMENT_ABSTRACT_CLASS(wxPrefConfig, wxConfigBase)

wxPrefConfig::wxPrefConfig(const wxString& appName, const wxString& vendorName,
                           const wxString& strLocal, const wxString& strGlobal,
                           long style)
             : wxConfigBase(appName, vendorName, strLocal, strGlobal, style)
{
}

// ----------------------------------------------------------------------------
// path management
// ----------------------------------------------------------------------------

void wxPrefConfig::SetPath(const wxString& strPath)
{
}

// ----------------------------------------------------------------------------
// enumeration (works only with current group)
// ----------------------------------------------------------------------------

bool wxPrefConfig::GetFirstGroup(wxString& str, long& lIndex) const
{
}

bool wxPrefConfig::GetNextGroup(wxString& str, long& lIndex) const
{
    /* TODO */
    return false;
}

bool wxPrefConfig::GetFirstEntry(wxString& str, long& lIndex) const
{
    /* TODO */
    return false;
}

bool wxPrefConfig::GetNextEntry(wxString& str, long& lIndex) const
{
    /* TODO */
    return false;
}

size_t wxPrefConfig::GetNumberOfEntries(bool WXUNUSED(bRecursive)) const
{
    /* TODO */
    return 0;
}

size_t wxPrefConfig::GetNumberOfGroups(bool WXUNUSED(bRecursive)) const
{
    /* TODO */
    return 0;
}

// ----------------------------------------------------------------------------
// tests for existence
// ----------------------------------------------------------------------------

bool wxPrefConfig::HasGroup(const wxString& key) const
{
    /* TODO */
    return false;
}

bool wxPrefConfig::HasEntry(const wxString& key) const
{
    /* TODO */
    return false;
}

wxConfigBase::EntryType wxPrefConfig::GetEntryType(const wxString& key) const
{
    /* TODO */
    return wxConfigBase::Type_Unknown;
}

// ----------------------------------------------------------------------------
// reading/writing
// ----------------------------------------------------------------------------

bool wxPrefConfig::DoReadString(const wxString& key, wxString *pStr) const
{
    /* TODO */
    return false;
}

// this exactly reproduces the string version above except for ExpandEnvVars(),
// we really should avoid this code duplication somehow...

bool wxPrefConfig::DoReadLong(const wxString& key, long *plResult) const
{
    /* TODO */
    return false;
}

#if wxUSE_BASE64
bool wxPrefConfig::DoReadBinary(const wxString& key, wxMemoryBuffer *buf) const
{
    /* TODO */
    return false;
}
#endif // wxUSE_BASE64

bool wxPrefConfig::DoWriteString(const wxString& key, const wxString& szValue)
{
    /* TODO */
    return false;
}

bool wxPrefConfig::DoWriteLong(const wxString& key, long lValue)
{
    /* TODO */
    return false;
}

#if wxUSE_BASE64
bool wxPrefConfig::DoWriteBinary(const wxString& key, const wxMemoryBuffer& buf)
{
    /* TODO */
    return false;
}
#endif // wxUSE_BASE64

// ----------------------------------------------------------------------------
// renaming
// ----------------------------------------------------------------------------

bool wxPrefConfig::RenameEntry(const wxString& oldName, const wxString& newName)
{
    /* TODO */
    return false;
}

bool wxPrefConfig::RenameGroup(const wxString& oldName, const wxString& newName)
{
    /* TODO */
    return false;
}

// ----------------------------------------------------------------------------
// deleting
// ----------------------------------------------------------------------------

bool wxPrefConfig::DeleteEntry(const wxString& value, bool bGroupIfEmptyAlso)
{
    /* TODO */
    return false;
}

bool wxPrefConfig::DeleteGroup(const wxString& key)
{
    /* TODO */
    return false;
}

bool wxPrefConfig::DeleteAll()
{
    /* TODO */
    return false;
}

#endif // wxUSE_CONFIG && wxUSE_CONFIG_NATIVE
