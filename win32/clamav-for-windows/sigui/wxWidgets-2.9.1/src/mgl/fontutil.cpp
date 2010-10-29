/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/fontutil.cpp
// Purpose:     Font helper functions for MGL
// Author:      Vaclav Slavik
// Created:     2001/04/29
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/hash.h"
    #include "wx/log.h"
#endif

#include "wx/fontutil.h"
#include "wx/encinfo.h"
#include "wx/fontmap.h"
#include "wx/tokenzr.h"

#include "wx/listimpl.cpp"
#include "wx/sysopt.h"
#include "wx/mgl/private.h"
#include "wx/private/fontmgr.h"

#include <mgraph.h>

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxNativeEncodingInfo
// ----------------------------------------------------------------------------

// convert to/from the string representation: format is
//      encoding[;facename]
bool wxNativeEncodingInfo::FromString(const wxString& s)
{
    wxStringTokenizer tokenizer(s, wxT(";"));

    wxString encid = tokenizer.GetNextToken();
    long enc;
    if ( !encid.ToLong(&enc) )
        return false;
    encoding = (wxFontEncoding)enc;

    // ok even if empty
    facename = tokenizer.GetNextToken();

    return true;
}

wxString wxNativeEncodingInfo::ToString() const
{
    wxString s;
    s << (long)encoding;
    if ( !facename.empty() )
    {
        s << wxT(';') << facename;
    }

    return s;
}

// ----------------------------------------------------------------------------
// common functions
// ----------------------------------------------------------------------------

bool wxGetNativeFontEncoding(wxFontEncoding encoding,
                             wxNativeEncodingInfo *info)
{
    wxCHECK_MSG( info, false, wxT("bad pointer in wxGetNativeFontEncoding") );

    if ( encoding == wxFONTENCODING_DEFAULT )
    {
        encoding = wxFont::GetDefaultEncoding();
    }

    switch ( encoding )
    {
        case wxFONTENCODING_ISO8859_1:
        case wxFONTENCODING_ISO8859_2:
        case wxFONTENCODING_ISO8859_3:
        case wxFONTENCODING_ISO8859_4:
        case wxFONTENCODING_ISO8859_5:
        case wxFONTENCODING_ISO8859_6:
        case wxFONTENCODING_ISO8859_7:
        case wxFONTENCODING_ISO8859_8:
        case wxFONTENCODING_ISO8859_9:
        case wxFONTENCODING_ISO8859_10:
        case wxFONTENCODING_ISO8859_11:
        case wxFONTENCODING_ISO8859_13:
        case wxFONTENCODING_ISO8859_14:
        case wxFONTENCODING_ISO8859_15:
            info->mglEncoding = MGL_ENCODING_ISO8859_1 +
                                (encoding - wxFONTENCODING_ISO8859_1);
            break;

        case wxFONTENCODING_KOI8:
            info->mglEncoding = MGL_ENCODING_KOI8;
            break;

        case wxFONTENCODING_CP1250:
        case wxFONTENCODING_CP1251:
        case wxFONTENCODING_CP1252:
        case wxFONTENCODING_CP1253:
        case wxFONTENCODING_CP1254:
        case wxFONTENCODING_CP1255:
        case wxFONTENCODING_CP1256:
        case wxFONTENCODING_CP1257:
            info->mglEncoding = MGL_ENCODING_CP1250 +
                                (encoding - wxFONTENCODING_CP1250);
            break;

        case wxFONTENCODING_SYSTEM:
            info->mglEncoding = MGL_ENCODING_ASCII;
            break;

        default:
            // encoding not known to MGL
            return false;
    }

    info->encoding = encoding;

    return true;
}

bool wxTestFontEncoding(const wxNativeEncodingInfo& info)
{
    if ( !info.facename )
        return true;

    wxFontBundle *bundle = wxFontsManager::Get()->GetBundle(info.facename);
    if ( !bundle )
        return false;
    if ( bundle->GetInfo()->fontLibType == MGL_BITMAPFONT_LIB )
    {
        return (info.mglEncoding == MGL_ENCODING_ASCII ||
                info.mglEncoding == MGL_ENCODING_ISO8859_1 ||
                info.mglEncoding == MGL_ENCODING_ISO8859_15 ||
                info.mglEncoding == MGL_ENCODING_CP1252);
    }
    else
        return true;
}
