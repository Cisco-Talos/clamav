/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/mimetype.cpp
// Purpose:     classes and functions to manage MIME types
// Author:      David Webster
// Modified by:
// Created:     01.21.00
// RCS-ID:      $Id$
// Copyright:   Adopted from msw port --(c) 1998 Vadim Zeitlin <zeitlin@dptmaths.ens-cachan.fr>
// Licence:     wxWindows licence (part of wxExtra library)
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_MIMETYPE

#include "wx/os2/mimetype.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/string.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #if wxUSE_GUI
        #include "wx/icon.h"
    #endif
#endif //WX_PRECOMP

#define INCL_DOS
#define INCL_GPI
#define INCL_WIN
#include <os2.h>

#include "wx/file.h"
#include "wx/iconloc.h"
#include "wx/confbase.h"

// other standard headers
#include <ctype.h>

// in case we're compiling in non-GUI mode
class WXDLLEXPORT wxIcon;

// These classes use Windows registry to retrieve the required information.
//
// Keys used (not all of them are documented, so it might actually stop working
// in futur versions of Windows...):
//  1. "HKCR\MIME\Database\Content Type" contains subkeys for all known MIME
//     types, each key has a string value "Extension" which gives (dot preceded)
//     extension for the files of this MIME type.
//
//  2. "HKCR\.ext" contains
//   a) unnamed value containing the "filetype"
//   b) value "Content Type" containing the MIME type
//
// 3. "HKCR\filetype" contains
//   a) unnamed value containing the description
//   b) subkey "DefaultIcon" with single unnamed value giving the icon index in
//      an icon file
//   c) shell\open\command and shell\open\print subkeys containing the commands
//      to open/print the file (the positional parameters are introduced by %1,
//      %2, ... in these strings, we change them to %s ourselves)

// although I don't know of any official documentation which mentions this
// location, uses it, so it isn't likely to change
static const wxChar *MIME_DATABASE_KEY = wxT("MIME\\Database\\Content Type\\");

wxString wxFileTypeImpl::GetCommand(const wxChar *WXUNUSED(verb)) const
{
// TODO: OS/2 doesn't have a registry but uses Prf
/*
    // suppress possible error messages
    wxLogNull nolog;
    wxString strKey;

    if ( wxRegKey(wxRegKey::HKCR, m_ext + wxT("\\shell")).Exists() )
        strKey = m_ext;
    if ( wxRegKey(wxRegKey::HKCR, m_strFileType + wxT("\\shell")).Exists() )
        strKey = m_strFileType;

    if ( !strKey )
    {
        // no info
        return wxEmptyString;
    }

    strKey << wxT("\\shell\\") << verb;
    wxRegKey key(wxRegKey::HKCR, strKey + wxT("\\command"));
    wxString command;
    if ( key.Open() ) {
        // it's the default value of the key
        if ( key.QueryValue(wxT(""), command) ) {
            // transform it from '%1' to '%s' style format string (now also
            // test for %L - apparently MS started using it as well for the
            // same purpose)

            // NB: we don't make any attempt to verify that the string is valid,
            //     i.e. doesn't contain %2, or second %1 or .... But we do make
            //     sure that we return a string with _exactly_ one '%s'!
            bool foundFilename = false;
            size_t len = command.Len();
            for ( size_t n = 0; (n < len) && !foundFilename; n++ ) {
                if ( command[n] == wxT('%') &&
                     (n + 1 < len) &&
                     (command[n + 1] == wxT('1') ||
                      command[n + 1] == wxT('L')) ) {
                    // replace it with '%s'
                    command[n + 1] = wxT('s');

                    foundFilename = true;
                }
            }

#if wxUSE_DDE
            // look whether we must issue some DDE requests to the application
            // (and not just launch it)
            strKey += wxT("\\DDEExec");
            wxRegKey keyDDE(wxRegKey::HKCR, strKey);
            if ( keyDDE.Open() ) {
                wxString ddeCommand, ddeServer, ddeTopic;
                keyDDE.QueryValue(wxT(""), ddeCommand);
                ddeCommand.Replace(wxT("%1"), wxT("%s"));

                wxRegKey(wxRegKey::HKCR, strKey + wxT("\\Application")).
                    QueryValue(wxT(""), ddeServer);
                wxRegKey(wxRegKey::HKCR, strKey + wxT("\\Topic")).
                    QueryValue(wxT(""), ddeTopic);

                // HACK: we use a special feature of wxExecute which exists
                //       just because we need it here: it will establish DDE
                //       conversation with the program it just launched
                command.Prepend(wxT("WX_DDE#"));
                command << wxT('#') << ddeServer
                        << wxT('#') << ddeTopic
                        << wxT('#') << ddeCommand;
            }
            else
#endif // wxUSE_DDE
                if ( !foundFilename ) {
                // we didn't find any '%1' - the application doesn't know which
                // file to open (note that we only do it if there is no DDEExec
                // subkey)
                //
                // HACK: append the filename at the end, hope that it will do
                command << wxT(" %s");
            }
        }
    }
    //else: no such file type or no value, will return empty string

    return command;
*/
   return wxEmptyString;
}

bool
wxFileTypeImpl::GetOpenCommand(wxString *openCmd,
                               const wxFileType::MessageParameters& params)
                               const
{
    wxString cmd;
    if ( m_info ) {
        cmd = m_info->GetOpenCommand();
    }
    else {
        cmd = GetCommand(wxT("open"));
    }

    *openCmd = wxFileType::ExpandCommand(cmd, params);

    return !openCmd->empty();
}

bool
wxFileTypeImpl::GetPrintCommand(wxString *printCmd,
                                const wxFileType::MessageParameters& params)
                                const
{
    wxString cmd;
    if ( m_info ) {
        cmd = m_info->GetPrintCommand();
    }
    else {
        cmd = GetCommand(wxT("print"));
    }

    *printCmd = wxFileType::ExpandCommand(cmd, params);

    return !printCmd->empty();
}

// TODO this function is half implemented
bool wxFileTypeImpl::GetExtensions(wxArrayString& extensions)
{
    if ( m_info ) {
        extensions = m_info->GetExtensions();

        return true;
    }
    else if ( m_ext.empty() ) {
        // the only way to get the list of extensions from the file type is to
        // scan through all extensions in the registry - too slow...
        return false;
    }
    else {
        extensions.Empty();
        extensions.Add(m_ext);

        // it's a lie too, we don't return _all_ extensions...
        return true;
    }
}

bool wxFileTypeImpl::GetMimeType(wxString *mimeType) const
{
    if ( m_info ) {
        // we already have it
        *mimeType = m_info->GetMimeType();

        return true;
    }

    // suppress possible error messages
    wxLogNull nolog;
// TODO:  substitue reg key stuff (maybe make a Prf class for OS/2??)
/*
    wxRegKey key(wxRegKey::HKCR, wxT(".") + m_ext);
    if ( key.Open() && key.QueryValue(wxT("Content Type"), *mimeType) ) {
        return true;
    }
    else {
        return false;
    }
*/
    return false;
}

bool wxFileTypeImpl::GetMimeTypes(wxArrayString& mimeTypes) const
{
    wxString s;

    if (GetMimeType(&s))
    {
        mimeTypes.Clear();
        mimeTypes.Add(s);
        return true;
    }
    else
        return false;
}

bool wxFileTypeImpl::GetIcon(wxIconLocation *WXUNUSED(iconLoc)) const
{
    if ( m_info ) {
        // we don't have icons in the fallback resources
        return false;
    }

    wxString strIconKey;
    strIconKey << m_strFileType << wxT("\\DefaultIcon");

    // suppress possible error messages
    wxLogNull nolog;
//TODO:
/*
    wxRegKey key(wxRegKey::HKCR, strIconKey);

    if ( key.Open() ) {
        wxString strIcon;
        // it's the default value of the key
        if ( key.QueryValue(wxEmptyString, strIcon) ) {
            // the format is the following: <full path to file>, <icon index>
            // NB: icon index may be negative as well as positive and the full
            //     path may contain the environment variables inside '%'
            wxString strFullPath = strIcon.BeforeLast(wxT(',')),
            strIndex = strIcon.AfterLast(wxT(','));

            // index may be omitted, in which case BeforeLast(',') is empty and
            // AfterLast(',') is the whole string
            if ( strFullPath.empty() ) {
                strFullPath = strIndex;
                strIndex = wxT("0");
            }

            if ( iconLoc )
            {
                iconLoc->SetFileName(wxExpandEnvVars(strFullPath));

                iconLoc->SetIndex(wxAtoi(strIndex));
            }

            return true;
        }
    }

    // no such file type or no value or incorrect icon entry
*/
    return false;
}

bool wxFileTypeImpl::GetDescription(wxString *desc) const
{
    if ( m_info ) {
        // we already have it
        *desc = m_info->GetDescription();

        return true;
    }

    // suppress possible error messages
    wxLogNull nolog;
// TODO:
/*
    wxRegKey key(wxRegKey::HKCR, m_strFileType);

    if ( key.Open() ) {
        // it's the default value of the key
        if ( key.QueryValue(wxT(""), *desc) ) {
            return true;
        }
    }
*/
    return false;
}

// extension -> file type
wxFileType *
wxMimeTypesManagerImpl::GetFileTypeFromExtension(const wxString& ext)
{
    // add the leading point if necessary
    wxString str;
    if ( ext[(size_t) 0] != wxT('.') ) {
        str = wxT('.');
    }
    str << ext;

    // suppress possible error messages
    wxLogNull nolog;

    bool knownExtension = false;

    wxString strFileType;
// TODO:
/*
    wxRegKey key(wxRegKey::HKCR, str);
    if ( key.Open() ) {
        // it's the default value of the key
        if ( key.QueryValue(wxT(""), strFileType) ) {
            // create the new wxFileType object
            wxFileType *fileType = new wxFileType;
            fileType->m_impl->Init(strFileType, ext);

            return fileType;
        }
        else {
            // this extension doesn't have a filetype, but it's known to the
            // system and may be has some other useful keys (open command or
            // content-type), so still return a file type object for it
            knownExtension = true;
        }
    }
*/
    // check the fallbacks
    // TODO linear search is potentially slow, perhaps we should use a sorted
    //      array?
    size_t count = m_fallbacks.GetCount();
    for ( size_t n = 0; n < count; n++ ) {
        if ( m_fallbacks[n].GetExtensions().Index(ext) != wxNOT_FOUND ) {
            wxFileType *fileType = new wxFileType;
            fileType->m_impl->Init(m_fallbacks[n]);

            return fileType;
        }
    }

    if ( knownExtension )
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->Init(wxEmptyString, ext);

        return fileType;
    }
    else
    {
        // unknown extension
        return NULL;
    }
}

// MIME type -> extension -> file type
wxFileType *
wxMimeTypesManagerImpl::GetFileTypeFromMimeType(const wxString& mimeType)
{
    wxString strKey = MIME_DATABASE_KEY;
    strKey << mimeType;

    // suppress possible error messages
    wxLogNull nolog;

    wxString ext;
// TODO:
/*
    wxRegKey key(wxRegKey::HKCR, strKey);
    if ( key.Open() ) {
        if ( key.QueryValue(wxT("Extension"), ext) ) {
            return GetFileTypeFromExtension(ext);
        }
    }

    // check the fallbacks
    // TODO linear search is potentially slow, perhaps we should use a sorted
    //      array?
    size_t count = m_fallbacks.GetCount();
    for ( size_t n = 0; n < count; n++ ) {
        if ( wxMimeTypesManager::IsOfType(mimeType,
                                          m_fallbacks[n].GetMimeType()) ) {
            wxFileType *fileType = new wxFileType;
            fileType->m_impl->Init(m_fallbacks[n]);

            return fileType;
        }
    }
*/
    // unknown MIME type
    return NULL;
}

size_t wxMimeTypesManagerImpl::EnumAllFileTypes(wxArrayString& WXUNUSED(mimetypes))
{
    // enumerate all keys under MIME_DATABASE_KEY
// TODO:
/*
    wxRegKey key(wxRegKey::HKCR, MIME_DATABASE_KEY);

    wxString type;
    long cookie;
    bool cont = key.GetFirstKey(type, cookie);
    while ( cont )
    {
        mimetypes.Add(type);

        cont = key.GetNextKey(type, cookie);
    }

    return mimetypes.GetCount();
*/
  return 0;
}

#endif //wxUSE_MIMETYPE
