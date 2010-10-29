/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/fontutil.cpp
// Purpose:     Font helper functions for X11 (GDK/X)
// Author:      Vadim Zeitlin
// Modified by:
// Created:     05.11.99
// RCS-ID:      $Id$
// Copyright:   (c) Vadim Zeitlin
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/fontutil.h"

#ifndef WX_PRECOMP
    #include "wx/hash.h"
    #include "wx/utils.h"
    #include "wx/module.h"
#endif // PCH

#include "wx/fontmap.h"
#include "wx/tokenzr.h"
#include "wx/encinfo.h"

#ifdef __WXGTK20__

#include "wx/gtk/private.h"

// ----------------------------------------------------------------------------
// wxNativeFontInfo
// ----------------------------------------------------------------------------

void wxNativeFontInfo::Init()
{
    description = NULL;
}

int wxNativeFontInfo::GetPointSize() const
{
    return pango_font_description_get_size( description ) / PANGO_SCALE;
}

wxFontStyle wxNativeFontInfo::GetStyle() const
{
    wxFontStyle m_style = wxFONTSTYLE_NORMAL;

    switch (pango_font_description_get_style( description ))
    {
        case PANGO_STYLE_NORMAL:
            m_style = wxFONTSTYLE_NORMAL;
            break;
        case PANGO_STYLE_ITALIC:
            m_style = wxFONTSTYLE_ITALIC;
            break;
        case PANGO_STYLE_OBLIQUE:
            m_style = wxFONTSTYLE_SLANT;
            break;
    }

    return m_style;
}

wxFontWeight wxNativeFontInfo::GetWeight() const
{
    wxFontWeight m_weight = wxFONTWEIGHT_NORMAL;

    switch (pango_font_description_get_weight( description ))
    {
        case PANGO_WEIGHT_ULTRALIGHT:
            m_weight = wxFONTWEIGHT_LIGHT;
            break;
        case PANGO_WEIGHT_LIGHT:
            m_weight = wxFONTWEIGHT_LIGHT;
            break;
        case PANGO_WEIGHT_NORMAL:
            m_weight = wxFONTWEIGHT_NORMAL;
            break;
        case PANGO_WEIGHT_BOLD:
            m_weight = wxFONTWEIGHT_BOLD;
            break;
        case PANGO_WEIGHT_ULTRABOLD:
            m_weight = wxFONTWEIGHT_BOLD;
            break;
        case PANGO_WEIGHT_HEAVY:
            m_weight = wxFONTWEIGHT_BOLD;
            break;
    }

    return m_weight;
}

bool wxNativeFontInfo::GetUnderlined() const
{
    return false;
}

wxString wxNativeFontInfo::GetFaceName() const
{
    wxString tmp = wxGTK_CONV_BACK( pango_font_description_get_family( description ) );

    return tmp;
}

wxFontFamily wxNativeFontInfo::GetFamily() const
{
    return wxFONTFAMILY_SWISS;
}

wxFontEncoding wxNativeFontInfo::GetEncoding() const
{
    return wxFONTENCODING_SYSTEM;
}

// ----------------------------------------------------------------------------
// wxNativeEncodingInfo
// ----------------------------------------------------------------------------

bool wxNativeEncodingInfo::FromString(const wxString& s)
{
    return false;
}

wxString wxNativeEncodingInfo::ToString() const
{
    return wxEmptyString;
}

bool wxTestFontEncoding(const wxNativeEncodingInfo& info)
{
    return true;
}

bool wxGetNativeFontEncoding(wxFontEncoding encoding,
                             wxNativeEncodingInfo *info)
{
    return false;
}

#else
   // __WXGTK20__

#ifdef __X__
    #ifdef __VMS__
        #pragma message disable nosimpint
    #endif

    #include <X11/Xlib.h>

    #ifdef __VMS__
        #pragma message enable nosimpint
    #endif

#elif defined(__WXGTK__)
    // we have to declare struct tm to avoid problems with first forward
    // declaring it in C code (glib.h included from gdk.h does it) and then
    // defining it when time.h is included from the headers below - this is
    // known not to work at least with Sun CC 6.01
    #include <time.h>

    #include <gdk/gdk.h>
#endif


// ----------------------------------------------------------------------------
// private data
// ----------------------------------------------------------------------------

static wxHashTable *g_fontHash = NULL;

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxNativeEncodingInfo
// ----------------------------------------------------------------------------

// convert to/from the string representation: format is
//      encodingid;registry;encoding[;facename]
bool wxNativeEncodingInfo::FromString(const wxString& s)
{
return false;
}

wxString wxNativeEncodingInfo::ToString() const
{
return wxEmptyString;
}

// ----------------------------------------------------------------------------
// common functions
// ----------------------------------------------------------------------------

bool wxGetNativeFontEncoding(wxFontEncoding encoding,
                             wxNativeEncodingInfo *info)
{
    return false;
}

bool wxTestFontEncoding(const wxNativeEncodingInfo& info)
{
return false;
}

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// wxFontModule
// ----------------------------------------------------------------------------

class wxFontModule : public wxModule
{
public:
    bool OnInit();
    void OnExit();

private:
    DECLARE_DYNAMIC_CLASS(wxFontModule)
};

IMPLEMENT_DYNAMIC_CLASS(wxFontModule, wxModule)

bool wxFontModule::OnInit()
{
    g_fontHash = new wxHashTable( wxKEY_STRING );

    return true;
}

void wxFontModule::OnExit()
{
    wxDELETE(g_fontHash);
}

#endif
  // not GTK 2.0
