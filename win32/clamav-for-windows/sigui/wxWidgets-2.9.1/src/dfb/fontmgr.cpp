/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/fontmgr.cpp
// Purpose:     font management for wxDFB
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
    #include "wx/gdicmn.h"
    #include "wx/utils.h"
    #include "wx/log.h"
#endif

#include "wx/fileconf.h"
#include "wx/filename.h"
#include "wx/tokenzr.h"
#include "wx/dir.h"

#include "wx/private/fontmgr.h"
#include "wx/dfb/wrapdfb.h"

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxFontInstance
// ----------------------------------------------------------------------------

// This is a fake "filename" for DirectFB's builtin font (which isn't loaded
// from a file); we can't use empty string, because that's already used for
// "this face is not available" by wxFontsManagerBase
#define BUILTIN_DFB_FONT_FILENAME   "/dev/null"

wxFontInstance::wxFontInstance(float ptSize, bool aa,
                               const wxString& filename)
    : wxFontInstanceBase(ptSize, aa)
{
    // NB: DFB's fract_height value is 32bit integer with the last 6 bit
    //     representing fractional value, hence the multiplication by 64;
    //     1pt=1/72inch, hence "/ 72"
    int pixSize = int(ptSize * wxGetDisplayPPI().y * 64 / 72);

    DFBFontDescription desc;
    desc.flags = (DFBFontDescriptionFlags)(
                    DFDESC_ATTRIBUTES | DFDESC_FRACT_HEIGHT);
    desc.attributes = aa ? DFFA_NONE : DFFA_MONOCHROME;
    desc.fract_height = pixSize;

    if ( filename == BUILTIN_DFB_FONT_FILENAME )
        m_font = wxIDirectFB::Get()->CreateFont(NULL, &desc);
    else
        m_font = wxIDirectFB::Get()->CreateFont(filename.fn_str(), &desc);

    wxASSERT_MSG( m_font, "cannot create font instance" );
}

// ----------------------------------------------------------------------------
// wxFontFace
// ----------------------------------------------------------------------------

wxFontInstance *wxFontFace::CreateFontInstance(float ptSize, bool aa)
{
    return new wxFontInstance(ptSize, aa, m_fileName);
}

// ----------------------------------------------------------------------------
// wxFontBundle
// ----------------------------------------------------------------------------

wxFontBundle::wxFontBundle(const wxString& name,
                           const wxString& fileRegular,
                           const wxString& fileBold,
                           const wxString& fileItalic,
                           const wxString& fileBoldItalic,
                           bool isFixed)
{
    m_name = name;
    m_isFixed = isFixed;

    if ( !fileRegular.empty() )
        m_faces[FaceType_Regular] = new wxFontFace(fileRegular);
    if ( !fileItalic.empty() )
        m_faces[FaceType_Italic] = new wxFontFace(fileItalic);
    if ( !fileBold.empty() )
        m_faces[FaceType_Bold] = new wxFontFace(fileBold);
    if ( !fileBoldItalic.empty() )
        m_faces[FaceType_BoldItalic] = new wxFontFace(fileBoldItalic);
}

// ----------------------------------------------------------------------------
// wxFontsManager
// ----------------------------------------------------------------------------

/*
   The code below looks up and parses font configuration files FontsIndex.
   The files are looked up in directories specified in the WXDFB_FONTPATH
   environment variable (separated with :, similarly to the PATH variable).
   If the variable is not set, $prefix/share/wx/fonts directory is used.
   All subdirectories of directories on the path are scanned for FontsIndex
   files.

   The FontsIndex file is standard wxFileConfig file text file. Each toplevel
   group specifies one font bundle, font's name is the name of group. Group's
   entries look like this:

   [Font Name]
   # font files (at least one of them must be present):
   Regular=RegularFaceFile.ttf
   Italic=ItalicFaceFile.ttf
   Bold=BoldFaceFile.ttf
   BoldItalic=BoldItalicFaceFile.ttf
   # optional tag indicating this font is fixed-with (default is false):
   IsFixed=1

   Additionally, there may be DefaultXXX entries at the toplevel for every
   family XXX and a Default entry that is shortcut for setting all families'
   default, their value is name of the default font:

   # optional tags indicating the default font for given family:
   DefaultDecorative=Font Name
   DefaultRoman=Font Name
   DefaultScript=Font Name
   DefaultSwiss=Font Name
   DefaultModern=Font Name
   DefaultTeletype=Font Name
   # indicate the font that is default for all families (optional):
   Default=Font Name
 */

void wxFontsManager::AddAllFonts()
{
    wxString path;
    if ( !wxGetEnv("WXDFB_FONTPATH", &path) )
        path = wxT(wxINSTALL_PREFIX "/share/wx/fonts");

    wxStringTokenizer tkn(path, wxPATH_SEP);
    while ( tkn.HasMoreTokens() )
    {
        wxString dir = tkn.GetNextToken();

        if ( !wxDir::Exists(dir) )
        {
            wxLogDebug("font directory %s doesn't exist", dir);
            continue;
        }

        wxArrayString indexFiles;
        if ( !wxDir::GetAllFiles(dir, &indexFiles, "FontsIndex") )
            continue;

        for ( wxArrayString::const_iterator i = indexFiles.begin();
              i != indexFiles.end(); ++i )
        {
            AddFontsFromDir(*i);
        }
    }

    if ( GetBundles().empty() )
    {
        // We can fall back to the builtin default font if no other fonts are
        // defined:
        wxLogTrace("font",
                   _("no fonts found in %s, using builtin font"), path);

        AddBundle
        (
          new wxFontBundle
              (
                _("Default font"),
                BUILTIN_DFB_FONT_FILENAME,
                wxEmptyString,
                wxEmptyString,
                wxEmptyString,
                false // IsFixed
              )
        );
    }
}

void wxFontsManager::AddFontsFromDir(const wxString& indexFile)
{
    wxFileName fn(indexFile);
    wxString dir = fn.GetPath();

    if ( !fn.FileExists() )
    {
        wxLogWarning(_("Fonts index file %s disappeared while loading fonts."),
                     indexFile.c_str());
        return;
    }

    wxLogTrace("font", "adding fonts from %s", dir.c_str());

    wxFileConfig cfg(wxEmptyString, wxEmptyString,
                     indexFile, wxEmptyString,
                     wxCONFIG_USE_LOCAL_FILE);

    long i;
    wxString name;
    for ( bool cont = cfg.GetFirstGroup(name, i);
               cont;
               cont = cfg.GetNextGroup(name, i) )
    {
        AddFont(dir, name, cfg);
    }

    // set default fonts for families:
    SetDefaultFonts(cfg);
}

static wxString
ReadFilePath(const wxString& name, const wxString& dir, wxFileConfig& cfg)
{
    wxString p = cfg.Read(name, wxEmptyString);

    if ( p.empty() || wxFileName(p).IsAbsolute() )
        return p;

    return dir + "/" + p;
}

void wxFontsManager::AddFont(const wxString& dir,
                             const wxString& name,
                             wxFileConfig& cfg)
{
    wxLogTrace("font", "adding font '%s'", name.c_str());

    wxConfigPathChanger ch(&cfg, wxString::Format("/%s/", name.c_str()));

    AddBundle
    (
      new wxFontBundle
          (
            name,
            ReadFilePath("Regular", dir, cfg),
            ReadFilePath("Italic", dir, cfg),
            ReadFilePath("Bold", dir, cfg),
            ReadFilePath("BoldItalic", dir, cfg),
            cfg.Read("IsFixed", (long)false)
          )
    );
}

void wxFontsManager::SetDefaultFonts(wxFileConfig& cfg)
{
    wxString name;

    if ( cfg.Read("Default", &name) )
    {
        m_defaultFacenames[wxFONTFAMILY_DECORATIVE] =
        m_defaultFacenames[wxFONTFAMILY_ROMAN] =
        m_defaultFacenames[wxFONTFAMILY_SCRIPT] =
        m_defaultFacenames[wxFONTFAMILY_SWISS] =
        m_defaultFacenames[wxFONTFAMILY_MODERN] =
        m_defaultFacenames[wxFONTFAMILY_TELETYPE] = name;
    }

    if ( cfg.Read("DefaultDecorative", &name) )
        m_defaultFacenames[wxFONTFAMILY_DECORATIVE] = name;
    if ( cfg.Read("DefaultRoman", &name) )
        m_defaultFacenames[wxFONTFAMILY_ROMAN] = name;
    if ( cfg.Read("DefaultScript", &name) )
        m_defaultFacenames[wxFONTFAMILY_SCRIPT] = name;
    if ( cfg.Read("DefaultSwiss", &name) )
        m_defaultFacenames[wxFONTFAMILY_SWISS] = name;
    if ( cfg.Read("DefaultModern", &name) )
        m_defaultFacenames[wxFONTFAMILY_MODERN] = name;
    if ( cfg.Read("DefaultTeletype", &name) )
        m_defaultFacenames[wxFONTFAMILY_TELETYPE] = name;
}
