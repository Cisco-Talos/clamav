///////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/prefconf.h
// Purpose:     wxPrefConfig interface
// Author:      Wlodzimierz ABX Skiba
// Modified by:
// Created:     28.12.2004
// RCS-ID:      $Id$
// Copyright:   (c) Wlodzimierz Skiba
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _PREFCONF_H_
#define _PREFCONF_H_

#include "wx/defs.h"

#if wxUSE_CONFIG

// ----------------------------------------------------------------------------
// wxPrefConfig
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_BASE wxPrefConfig : public wxConfigBase
{
public:
  // ctor & dtor
  wxPrefConfig(const wxString& appName = wxEmptyString,
               const wxString& vendorName = wxEmptyString,
               const wxString& localFilename = wxEmptyString,
               const wxString& globalFilename = wxEmptyString,
               long style = wxCONFIG_USE_GLOBAL_FILE);

  // dtor will save unsaved data
  virtual ~wxPrefConfig(){}

  // implement inherited pure virtual functions
  // ------------------------------------------

  // path management
  virtual void SetPath(const wxString& strPath);
  virtual const wxString& GetPath() const { return m_strPath; }

  // entry/subgroup info
  virtual bool GetFirstGroup(wxString& str, long& lIndex) const;
  virtual bool GetNextGroup (wxString& str, long& lIndex) const;
  virtual bool GetFirstEntry(wxString& str, long& lIndex) const;
  virtual bool GetNextEntry (wxString& str, long& lIndex) const;

  // tests for existence
  virtual bool HasGroup(const wxString& strName) const;
  virtual bool HasEntry(const wxString& strName) const;
  virtual EntryType GetEntryType(const wxString& name) const;

  // get number of entries/subgroups in the current group, with or without
  // it's subgroups
  virtual size_t GetNumberOfEntries(bool bRecursive = false) const;
  virtual size_t GetNumberOfGroups(bool bRecursive = false) const;

  virtual bool Flush(bool WXUNUSED(bCurrentOnly) = false) { return true; }

  // rename
  virtual bool RenameEntry(const wxString& oldName, const wxString& newName);
  virtual bool RenameGroup(const wxString& oldName, const wxString& newName);

  // delete
  virtual bool DeleteEntry(const wxString& key, bool bGroupIfEmptyAlso = true);
  virtual bool DeleteGroup(const wxString& key);
  virtual bool DeleteAll();

protected:
  // implement read/write methods
  virtual bool DoReadString(const wxString& key, wxString *pStr) const;
  virtual bool DoReadLong(const wxString& key, long *plResult) const;
  virtual bool DoReadBinary(const wxString& key, wxMemoryBuffer *buf) const;

  virtual bool DoWriteString(const wxString& key, const wxString& szValue);
  virtual bool DoWriteLong(const wxString& key, long lValue);
  virtual bool DoWriteBinary(const wxString& key, const wxMemoryBuffer& buf);

private:
  // current path (not '/' terminated)
  wxString  m_strPath;

  // current path (group) content (cache for read/write)
  wxString m_strGroup;

  // current group modified ?
  bool m_modGroup;

  wxDECLARE_NO_COPY_CLASS(wxPrefConfig);
  DECLARE_ABSTRACT_CLASS(wxPrefConfig)
};

#endif // wxUSE_CONFIG

#endif // _PREFCONF_H_
