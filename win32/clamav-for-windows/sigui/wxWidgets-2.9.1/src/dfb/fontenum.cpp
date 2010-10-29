/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/fontenum.cpp
// Purpose:     wxFontEnumerator class
// Author:      Vaclav Slavik
// Created:     2006-08-10
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/fontenum.h"
#include "wx/private/fontmgr.h"

#if wxUSE_FONTENUM

// ----------------------------------------------------------------------------
// wxFontEnumerator
// ----------------------------------------------------------------------------

bool wxFontEnumerator::EnumerateFacenames(wxFontEncoding encoding,
                                          bool fixedWidthOnly)
{
    // we only support UTF-8 and system (which means "use any"):
    if ( encoding != wxFONTENCODING_SYSTEM && encoding != wxFONTENCODING_UTF8 )
        return false;

    bool found = false;
    const wxFontBundleList& list = wxFontsManager::Get()->GetBundles();

    for ( wxFontBundleList::const_iterator f = list.begin(); f != list.end(); ++f )
    {
        if ( fixedWidthOnly && !(*f)->IsFixed() )
            continue;

        found = true;
        if ( !OnFacename((*f)->GetName()) )
            break; // OnFacename() requests us to stop enumeration
    }

    return found;
}

bool wxFontEnumerator::EnumerateEncodings(const wxString& facename)
{
    return EnumerateEncodingsUTF8(facename);
}

#endif // wxUSE_FONTENUM
