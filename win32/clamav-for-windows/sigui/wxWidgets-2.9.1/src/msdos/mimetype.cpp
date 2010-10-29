/////////////////////////////////////////////////////////////////////////////
// Name:        src/msdos/mimetype.cpp
// Purpose:     classes and functions to manage MIME types
// Author:      Vadim Zeitlin
// Modified by:
// Created:     23.09.98
// RCS-ID:      $Id$
// Copyright:   (c) 1998 Vadim Zeitlin <zeitlin@dptmaths.ens-cachan.fr>
// Licence:     wxWindows licence (part of wxExtra library)
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_MIMETYPE

#include "wx/msdos/mimetype.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/string.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #if wxUSE_GUI
        #include "wx/icon.h"
    #endif
#endif //WX_PRECOMP

#include "wx/file.h"
#include "wx/confbase.h"

// other standard headers
#include <ctype.h>

// in case we're compiling in non-GUI mode
class WXDLLEXPORT wxIcon;

bool wxFileTypeImpl::SetCommand(const wxString& WXUNUSED(cmd),
                                const wxString& WXUNUSED(verb),
                                bool WXUNUSED(overwriteprompt))
{
    return false;
}

bool wxFileTypeImpl::SetDefaultIcon(const wxString& WXUNUSED(strIcon),
                                    int WXUNUSED(index))
{
    return false;
}

bool wxFileTypeImpl::GetCommand(wxString *WXUNUSED(command),
                                const char *WXUNUSED(verb)) const
{
    return false;
}

bool wxFileTypeImpl::GetExtensions(wxArrayString& WXUNUSED(extensions))
{
    return false;
}

bool wxFileTypeImpl::GetMimeType(wxString *mimeType) const
{
    if ( !m_strFileType.empty() )
    {
        *mimeType = m_strFileType ;
        return true ;
    }
    else
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

bool wxFileTypeImpl::GetIcon(wxIconLocation *WXUNUSED(icon)) const
{
    // no such file type or no value or incorrect icon entry
    return false;
}

bool wxFileTypeImpl::GetDescription(wxString *WXUNUSED(desc)) const
{
    return false;
}

size_t
wxFileTypeImpl::GetAllCommands(wxArrayString * WXUNUSED(verbs),
                               wxArrayString * WXUNUSED(commands),
                               const wxFileType::MessageParameters& WXUNUSED(params)) const
{
    wxFAIL_MSG( wxT("wxFileTypeImpl::GetAllCommands() not yet implemented") );
    return 0;
}

void
wxMimeTypesManagerImpl::Initialize(int WXUNUSED(mailcapStyles),
                                   const wxString& WXUNUSED(extraDir))
{
    wxFAIL_MSG( wxT("wxMimeTypesManagerImpl::Initialize() not yet implemented") );
}

void
wxMimeTypesManagerImpl::ClearData()
{
    wxFAIL_MSG( wxT("wxMimeTypesManagerImpl::ClearData() not yet implemented") );
}

// extension -> file type
wxFileType *
wxMimeTypesManagerImpl::GetFileTypeFromExtension(const wxString& e)
{
    wxString ext = e ;
    ext = ext.Lower() ;
    if ( ext == wxT("txt") )
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->SetFileType(wxT("text/text"));
        fileType->m_impl->SetExt(ext);
        return fileType;
    }
    else if ( ext == wxT("htm") || ext == wxT("html") )
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->SetFileType(wxT("text/html"));
        fileType->m_impl->SetExt(ext);
        return fileType;
    }
    else if ( ext == wxT("gif") )
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->SetFileType(wxT("image/gif"));
        fileType->m_impl->SetExt(ext);
        return fileType;
    }
    else if ( ext == wxT("png" ))
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->SetFileType(wxT("image/png"));
        fileType->m_impl->SetExt(ext);
        return fileType;
    }
    else if ( ext == wxT("jpg" )|| ext == wxT("jpeg") )
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->SetFileType(wxT("image/jpeg"));
        fileType->m_impl->SetExt(ext);
        return fileType;
    }
    else if ( ext == wxT("bmp") )
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->SetFileType(wxT("image/bmp"));
        fileType->m_impl->SetExt(ext);
        return fileType;
    }
    else if ( ext == wxT("tif") || ext == wxT("tiff") )
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->SetFileType(wxT("image/tiff"));
        fileType->m_impl->SetExt(ext);
        return fileType;
    }
    else if ( ext == wxT("xpm") )
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->SetFileType(wxT("image/xpm"));
        fileType->m_impl->SetExt(ext);
        return fileType;
    }
    else if ( ext == wxT("xbm") )
    {
        wxFileType *fileType = new wxFileType;
        fileType->m_impl->SetFileType(wxT("image/xbm"));
        fileType->m_impl->SetExt(ext);
        return fileType;
    }

    // unknown extension
    return NULL;
}

// MIME type -> extension -> file type
wxFileType *
wxMimeTypesManagerImpl::GetFileTypeFromMimeType(const wxString& WXUNUSED(mimeType))
{
    return NULL;
}

size_t wxMimeTypesManagerImpl::EnumAllFileTypes(wxArrayString& WXUNUSED(mimetypes))
{
    // VZ: don't know anything about this for Mac
    wxFAIL_MSG( wxT("wxMimeTypesManagerImpl::EnumAllFileTypes() not yet implemented") );

    return 0;
}

wxFileType *
wxMimeTypesManagerImpl::Associate(const wxFileTypeInfo& WXUNUSED(ftInfo))
{
    wxFAIL_MSG( wxT("wxMimeTypesManagerImpl::Associate() not yet implemented") );

    return NULL;
}

bool
wxMimeTypesManagerImpl::Unassociate(wxFileType *WXUNUSED(ft))
{
    return false;
}

#endif // wxUSE_MIMETYPE
