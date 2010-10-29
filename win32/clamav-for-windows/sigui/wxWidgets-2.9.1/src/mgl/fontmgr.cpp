/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/fontmgr.cpp
// Purpose:     font management for wxMGL
// Author:      Vaclav Slavik
// Created:     2006-11-18
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
//              (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif

#include "wx/private/fontmgr.h"
#include "wx/sysopt.h"

#include <mgraph.h>

static int gs_antialiasingThreshold = -1;

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxFontInstance
// ----------------------------------------------------------------------------

wxFontInstance::wxFontInstance(float ptSize, bool aa, font_lib_t *fontLib)
    : wxFontInstanceBase(ptSize, aa)
{
    m_font = MGL_loadFontInstance(fontLib, ptSize, 0.0, 0.0, aa);

    wxASSERT_MSG( m_font, wxT("cannot create font instance") );
}

wxFontInstance::~wxFontInstance()
{
    if ( m_font )
        MGL_unloadFontInstance(m_font);
}

// ----------------------------------------------------------------------------
// wxFontFace
// ----------------------------------------------------------------------------

void wxFontFace::Acquire()
{
    wxFontFaceBase::Acquire();

    if ( m_refCnt == 1 )
    {
        wxCHECK_RET( m_fontLib == NULL, wxT("font lib already created") );

        wxLogTrace("mgl_font", "opening library '%s'", m_fileName.mb_str());
        m_fontLib = MGL_openFontLib(m_fileName.fn_str());
    }
}

void wxFontFace::Release()
{
    wxFontFaceBase::Release();

    if ( m_refCnt == 0 )
    {
        wxCHECK_RET( m_fontLib != NULL, wxT("font lib not created") );

        wxLogTrace("mgl_font", "closing library '%s'", m_fileName.mb_str());
        MGL_closeFontLib(m_fontLib);
        m_fontLib = NULL;
    }
}

wxFontInstance *wxFontFace::GetFontInstance(float ptSize, bool aa)
{
    if ( gs_antialiasingThreshold == -1 )
    {
        gs_antialiasingThreshold = 10;
#if wxUSE_SYSTEM_OPTIONS
        if ( wxSystemOptions::HasOption(wxT("mgl.aa-threshold")) )
            gs_antialiasingThreshold =
                wxSystemOptions::GetOptionInt(wxT("mgl.aa-threshold"));
        wxLogTrace("mgl_font", "AA threshold set to %i", gs_antialiasingThreshold);
#endif
    }

    // Small characters don't look good when antialiased with the algorithm
    // that FreeType uses (mere 2x2 supersampling), so lets disable AA
    // completely for small fonts. Bitmap fonts are not antialiased either.
    if ( ptSize <= gs_antialiasingThreshold ||
         m_fontLib->fontLibType == MGL_BITMAPFONT_LIB )
    {
        aa = false;
    }

    return wxFontFaceBase::GetFontInstance(ptSize, aa);
}

wxFontInstance *wxFontFace::CreateFontInstance(float ptSize, bool aa)
{
    wxASSERT_MSG( m_fontLib, wxT("font library not loaded!") );

    return new wxFontInstance(ptSize, aa, m_fontLib);
}

// ----------------------------------------------------------------------------
// wxFontBundle
// ----------------------------------------------------------------------------

wxFontBundle::wxFontBundle(const font_info_t *info)
    : m_fontInfo(info)
{
    if ( info->regularFace[0] != '\0' )
        m_faces[FaceType_Regular] = new wxFontFace(info->regularFace);

    if ( info->italicFace[0] != '\0' )
        m_faces[FaceType_Italic] = new wxFontFace(info->italicFace);

    if ( info->boldFace[0] != '\0' )
        m_faces[FaceType_Bold] = new wxFontFace(info->boldFace);

    if ( info->boldItalicFace[0] != '\0' )
        m_faces[FaceType_BoldItalic] = new wxFontFace(info->boldItalicFace);

    wxLogTrace("mgl_font", "new family '%s' (r=%s, i=%s, b=%s, bi=%s)\n",
               info->familyName, info->regularFace, info->italicFace,
               info->boldFace, info->boldItalicFace);
}

wxString wxFontBundle::GetName() const
{
    return wxString::FromAscii(m_fontInfo->familyName);
}

bool wxFontBundle::IsFixed() const
{
    return m_fontInfo->isFixed;
}


// ----------------------------------------------------------------------------
// wxFontsManager
// ----------------------------------------------------------------------------

wxString wxFontsManager::GetDefaultFacename(wxFontFamily family) const
{
    switch ( family )
    {
        case wxSCRIPT:
            return wxT("Script");
        case wxDECORATIVE:
            return wxT("Charter");
        case wxROMAN:
            return wxT("Times");
        case wxTELETYPE:
        case wxMODERN:
            return wxT("Courier");
        case wxSWISS:
        case wxDEFAULT:
        default:
            return wxT("Helvetica");
    }
}

static ibool MGLAPI enum_callback(const font_info_t *info, void *cookie)
{
    wxFontsManager *db = (wxFontsManager*)cookie;
    db->AddBundle(new wxFontBundle(info));
    return TRUE;
}

void wxFontsManager::AddAllFonts()
{
    MGL_enumerateFonts(enum_callback, (void*)this);
}
