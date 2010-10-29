///////////////////////////////////////////////////////////////////////////////
// Name:        wx/msw/stdpaths.h
// Purpose:     wxStandardPaths for OS/2
// Author:      Stefan Neis
// Modified by:
// Created:     2004-11-06
// RCS-ID:      $Id$
// Copyright:   (c) 2004 Stefan Neis <Stefan.Neis@t-online.de>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_OS2_STDPATHS_H_
#define _WX_OS2_STDPATHS_H_

// ----------------------------------------------------------------------------
// wxStandardPaths
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_BASE wxStandardPaths : public wxStandardPathsBase
{
public:
    // set the program installation directory which is /usr/local by default
    //
    // The program directory can be determined automatically from argv[0],
    // this function is automatically called from application initialisation.
    // If you override the initialisation routine, you should call it
    // explicitly yourself.
    static void SetInstallPrefix(const wxString& prefix);

    // get the program installation prefix
    //
    // if the prefix had been previously by SetInstallPrefix, returns that
    // value, otherwise returns /usr/local if it failed
    wxString GetInstallPrefix() const;

    // implement base class pure virtuals
    virtual wxString GetConfigDir() const;
    virtual wxString GetUserConfigDir() const;
    virtual wxString GetDataDir() const;
    virtual wxString GetUserDataDir() const;
    virtual wxString GetPluginsDir() const;

private:
    static wxString m_prefix;
};

#endif // _WX_OS2_STDPATHS_H_
