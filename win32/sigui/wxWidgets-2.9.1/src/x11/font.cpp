/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/font.cpp
// Purpose:     wxFont class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#ifdef __VMS
#pragma message disable nosimpint
#include "wx/vms_x_fix.h"
#endif

#ifdef __VMS
#pragma message enable nosimpint
#endif

#include "wx/font.h"

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/utils.h"       // for wxGetDisplay()
    #include "wx/settings.h"
    #include "wx/gdicmn.h"
#endif

#include "wx/fontutil.h"    // for wxNativeFontInfo
#include "wx/tokenzr.h"
#include "wx/fontenum.h"

#include "wx/x11/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxFont, wxGDIObject)

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// the default size (in points) for the fonts
static const int wxDEFAULT_FONT_SIZE = 12;


#if wxUSE_UNICODE
#else
// ----------------------------------------------------------------------------
// wxXFont
// ----------------------------------------------------------------------------

// For every wxFont, there must be a font for each display and scale requested.
// So these objects are stored in wxFontRefData::m_fonts
class wxXFont : public wxObject
{
public:
    wxXFont();
    virtual ~wxXFont();

    WXFontStructPtr     m_fontStruct;   // XFontStruct
    WXDisplay*          m_display;      // XDisplay
    int                 m_scale;        // Scale * 100
};

wxXFont::wxXFont()
{
    m_fontStruct = (WXFontStructPtr) 0;
    m_display = (WXDisplay*) 0;
    m_scale = 100;
}

wxXFont::~wxXFont()
{
    // Freeing the font used to produce a segv, but
    // appears to be OK now (bug fix in X11?)
    XFontStruct* fontStruct = (XFontStruct*) m_fontStruct;
    XFreeFont((Display*) m_display, fontStruct);
}
#endif

// ----------------------------------------------------------------------------
// wxFontRefData
// ----------------------------------------------------------------------------

class wxFontRefData: public wxGDIRefData
{
friend class wxFont;

public:
    wxFontRefData(int size = wxDEFAULT,
                  wxFontFamily family = wxFONTFAMILY_DEFAULT,
                  wxFontStyle style = wxFONTSTYLE_NORMAL,
                  wxFontWeight weight = wxFONTWEIGHT_NORMAL,
                  bool underlined = false,
                  const wxString& faceName = wxEmptyString,
                  wxFontEncoding encoding = wxFONTENCODING_DEFAULT);

    // copy cstr
    wxFontRefData(const wxFontRefData& data);

    // from XFLD
    wxFontRefData(const wxString& fontname);

    // dstr
    virtual ~wxFontRefData();

    // setters: all of them also take care to modify m_nativeFontInfo if we
    // have it so as to not lose the information not carried by our fields
    void SetPointSize(int pointSize);
    void SetFamily(wxFontFamily family);
    void SetStyle(wxFontStyle style);
    void SetWeight(wxFontWeight weight);
    void SetUnderlined(bool underlined);
    bool SetFaceName(const wxString& facename);
    void SetEncoding(wxFontEncoding encoding);

    // and this one also modifies all the other font data fields
    void SetNativeFontInfo(const wxNativeFontInfo& info);

protected:
    // common part of all ctors
    void Init(int size,
              wxFontFamily family,
              wxFontStyle style,
              wxFontWeight weight,
              bool underlined,
              const wxString& faceName,
              wxFontEncoding encoding);

    // set all fields from (already initialized and valid) m_nativeFontInfo
    void InitFromNative();

    // font attributes
    int           m_pointSize;
    wxFontFamily  m_family;
    wxFontStyle   m_style;
    wxFontWeight  m_weight;
    bool          m_underlined;
    wxString      m_faceName;
    wxFontEncoding m_encoding;   // Unused in Unicode mode

    wxNativeFontInfo m_nativeFontInfo;

    void ClearX11Fonts();

#if wxUSE_UNICODE
#else
    // A list of wxXFonts
    wxList        m_fonts;
#endif
};

#define M_FONTDATA ((wxFontRefData*)m_refData)

// ----------------------------------------------------------------------------
// wxFontRefData
// ----------------------------------------------------------------------------

void wxFontRefData::Init(int pointSize,
                         wxFontFamily family,
                         wxFontStyle style,
                         wxFontWeight weight,
                         bool underlined,
                         const wxString& faceName,
                         wxFontEncoding encoding)
{
    m_family = family == wxFONTFAMILY_DEFAULT ? wxFONTFAMILY_SWISS : family;

    m_faceName = faceName;

    // we accept both wxDEFAULT and wxNORMAL here - should we?
    m_style = style == wxDEFAULT ? wxFONTSTYLE_NORMAL : style;
    m_weight = weight == wxDEFAULT ? wxFONTWEIGHT_NORMAL : weight;

    m_underlined = underlined;
    m_encoding = encoding;

#if wxUSE_UNICODE
    if ( m_nativeFontInfo.description )
        pango_font_description_free(m_nativeFontInfo.description);

    // Create native font info
    m_nativeFontInfo.description = pango_font_description_new();

    // if a face name is specified, use it if it's available, otherwise use
    // just the family
    if ( faceName.empty() || !wxFontEnumerator::IsValidFacename(faceName) )
    {
        // TODO: scan system for valid fonts matching the given family instead
        //       of hardcoding them here
        switch ( m_family )
        {
            case wxFONTFAMILY_TELETYPE:
                m_faceName = wxT("monospace");
                break;

            case wxFONTFAMILY_ROMAN:
                m_faceName = wxT("serif");
                break;

            default:
                m_faceName = wxT("sans");
        }
    }
    else // specified face name is available, use it
    {
        m_faceName = faceName;
    }

    m_nativeFontInfo.SetFaceName(m_faceName);
    m_nativeFontInfo.SetWeight((wxFontWeight)m_weight);
    m_nativeFontInfo.SetStyle((wxFontStyle)m_style);
#endif // wxUSE_UNICODE

    SetPointSize(pointSize);
}

void wxFontRefData::InitFromNative()
{
#if wxUSE_UNICODE
    // Get native info
    PangoFontDescription *desc = m_nativeFontInfo.description;

    // init fields
    m_faceName = wxGTK_CONV_BACK( pango_font_description_get_family( desc ) );

    m_pointSize = pango_font_description_get_size( desc ) / PANGO_SCALE;

    switch (pango_font_description_get_style( desc ))
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

// Not defined in some Pango versions
#define wxPANGO_WEIGHT_SEMIBOLD 600

    switch (pango_font_description_get_weight( desc ))
    {
        case PANGO_WEIGHT_ULTRALIGHT:
        case PANGO_WEIGHT_LIGHT:
            m_weight = wxFONTWEIGHT_LIGHT;
            break;

        default:
            wxFAIL_MSG(wxT("unknown Pango font weight"));
            // fall through

        case PANGO_WEIGHT_NORMAL:
            m_weight = wxFONTWEIGHT_NORMAL;
            break;

        case wxPANGO_WEIGHT_SEMIBOLD:
        case PANGO_WEIGHT_BOLD:
        case PANGO_WEIGHT_ULTRABOLD:
        case PANGO_WEIGHT_HEAVY:
            m_weight = wxFONTWEIGHT_BOLD;
            break;
    }

    if (m_faceName == wxT("monospace"))
    {
        m_family = wxFONTFAMILY_TELETYPE;
    }
    else if (m_faceName == wxT("sans"))
    {
        m_family = wxFONTFAMILY_SWISS;
    }
    else
    {
        m_family = wxFONTFAMILY_UNKNOWN;
    }

    // Pango description are never underlined (?)
    m_underlined = false;

    // Cannot we choose that
    m_encoding = wxFONTENCODING_SYSTEM;
#else // X11
    // get the font parameters from the XLFD
    // -------------------------------------

    m_faceName = m_nativeFontInfo.GetXFontComponent(wxXLFD_FAMILY);

    m_weight = wxFONTWEIGHT_NORMAL;

    wxString w = m_nativeFontInfo.GetXFontComponent(wxXLFD_WEIGHT).Upper();
    if ( !w.empty() && w != wxT('*') )
    {
        // the test below catches all of BOLD, EXTRABOLD, DEMIBOLD, ULTRABOLD
        // and BLACK
        if ( ((w[0u] == wxT('B') && (!wxStrcmp(w.c_str() + 1, wxT("OLD")) ||
                                   !wxStrcmp(w.c_str() + 1, wxT("LACK"))))) ||
             wxStrstr(w.c_str() + 1, wxT("BOLD")) )
        {
            m_weight = wxFONTWEIGHT_BOLD;
        }
        else if ( w == wxT("LIGHT") || w == wxT("THIN") )
        {
            m_weight = wxFONTWEIGHT_LIGHT;
        }
    }

    switch ( wxToupper( m_nativeFontInfo.
                GetXFontComponent(wxXLFD_SLANT)[0u]).GetValue() )
    {
        case wxT('I'):   // italique
            m_style = wxFONTSTYLE_ITALIC;
            break;

        case wxT('O'):   // oblique
            m_style = wxFONTSTYLE_SLANT;
            break;

        default:
            m_style = wxFONTSTYLE_NORMAL;
    }

    long ptSize;
    if ( m_nativeFontInfo.GetXFontComponent(wxXLFD_POINTSIZE).ToLong(&ptSize) )
    {
        // size in XLFD is in 10 point units
        m_pointSize = (int)(ptSize / 10);
    }
    else
    {
        m_pointSize = wxDEFAULT_FONT_SIZE;
    }

    // examine the spacing: if the font is monospaced, assume wxTELETYPE
    // family for compatibility with the old code which used it instead of
    // IsFixedWidth()
    if ( m_nativeFontInfo.GetXFontComponent(wxXLFD_SPACING).Upper() == wxT('M') )
    {
        m_family = wxFONTFAMILY_TELETYPE;
    }
    else // not monospaceed
    {
        // don't even try guessing it, it doesn't work for too many fonts
        // anyhow
        m_family = wxFONTFAMILY_UNKNOWN;
    }

    // X fonts are never underlined...
    m_underlined = false;

    // deal with font encoding
    wxString
        registry = m_nativeFontInfo.GetXFontComponent(wxXLFD_REGISTRY).Upper(),
        encoding = m_nativeFontInfo.GetXFontComponent(wxXLFD_ENCODING).Upper();

    if ( registry == wxT("ISO8859") )
    {
        int cp;
        if ( wxSscanf(encoding, wxT("%d"), &cp) == 1 )
        {
            m_encoding = (wxFontEncoding)(wxFONTENCODING_ISO8859_1 + cp - 1);
        }
    }
    else if ( registry == wxT("MICROSOFT") )
    {
        int cp;
        if ( wxSscanf(encoding, wxT("cp125%d"), &cp) == 1 )
        {
            m_encoding = (wxFontEncoding)(wxFONTENCODING_CP1250 + cp);
        }
    }
    else if ( registry == wxT("KOI8") )
    {
        m_encoding = wxFONTENCODING_KOI8;
    }
    else // unknown encoding
    {
        // may be give a warning here? or use wxFontMapper?
        m_encoding = wxFONTENCODING_SYSTEM;
    }
#endif // Pango/X11
}

wxFontRefData::wxFontRefData( const wxFontRefData& data )
             : wxGDIRefData()
{
    m_pointSize = data.m_pointSize;
    m_family = data.m_family;
    m_style = data.m_style;
    m_weight = data.m_weight;

    m_underlined = data.m_underlined;

    m_faceName = data.m_faceName;
    m_encoding = data.m_encoding;

    m_nativeFontInfo = data.m_nativeFontInfo;
}

wxFontRefData::wxFontRefData(int size, wxFontFamily family, wxFontStyle style,
                             wxFontWeight weight, bool underlined,
                             const wxString& faceName,
                             wxFontEncoding encoding)
{
    Init(size, family, style, weight, underlined, faceName, encoding);
}

wxFontRefData::wxFontRefData(const wxString& fontname)
{
    // VZ: FromString() should really work in both cases, doesn't it?
#if wxUSE_UNICODE
    m_nativeFontInfo.FromString( fontname );
#else
    m_nativeFontInfo.SetXFontName(fontname);
#endif

    InitFromNative();
}

void wxFontRefData::ClearX11Fonts()
{
#if wxUSE_UNICODE
#else
    wxList::compatibility_iterator node = m_fonts.GetFirst();
    while (node)
    {
        wxXFont* f = (wxXFont*) node->GetData();
        delete f;
        node = node->GetNext();
    }
    m_fonts.Clear();
#endif
}

wxFontRefData::~wxFontRefData()
{
    ClearX11Fonts();
}

// ----------------------------------------------------------------------------
// wxFontRefData SetXXX()
// ----------------------------------------------------------------------------

void wxFontRefData::SetPointSize(int pointSize)
{
    // NB: Pango doesn't support point sizes less than 1
    m_pointSize = pointSize == wxDEFAULT || pointSize < 1 ? wxDEFAULT_FONT_SIZE
                                                          : pointSize;

#if wxUSE_UNICODE
    m_nativeFontInfo.SetPointSize(m_pointSize);
#endif
}

void wxFontRefData::SetFamily(wxFontFamily family)
{
    m_family = family;

    // TODO: what are we supposed to do with m_nativeFontInfo here?
}

void wxFontRefData::SetStyle(wxFontStyle style)
{
    m_style = style;

#if wxUSE_UNICODE
    // Get native info
    PangoFontDescription *desc = m_nativeFontInfo.description;

    switch ( style )
    {
        case wxFONTSTYLE_ITALIC:
            pango_font_description_set_style( desc, PANGO_STYLE_ITALIC );
            break;
        case wxFONTSTYLE_SLANT:
            pango_font_description_set_style( desc, PANGO_STYLE_OBLIQUE );
            break;
        default:
            wxFAIL_MSG( wxT("unknown font style") );
            // fall through
        case wxFONTSTYLE_NORMAL:
            pango_font_description_set_style( desc, PANGO_STYLE_NORMAL );
            break;
    }
#endif
}

void wxFontRefData::SetWeight(wxFontWeight weight)
{
    m_weight = weight;
}

void wxFontRefData::SetUnderlined(bool underlined)
{
    m_underlined = underlined;

    // the XLFD doesn't have "underlined" field anyhow
}

bool wxFontRefData::SetFaceName(const wxString& facename)
{
    m_faceName = facename;
    return true;
}

void wxFontRefData::SetEncoding(wxFontEncoding encoding)
{
    m_encoding = encoding;
}

void wxFontRefData::SetNativeFontInfo(const wxNativeFontInfo& info)
{
    // previously cached fonts shouldn't be used
    ClearX11Fonts();

    m_nativeFontInfo = info;

    // set all the other font parameters from the native font info
    InitFromNative();
}

// ----------------------------------------------------------------------------
// wxFont
// ----------------------------------------------------------------------------

wxFont::wxFont(const wxNativeFontInfo& info)
{
#if wxUSE_UNICODE
    Create( info.GetPointSize(),
            info.GetFamily(),
            info.GetStyle(),
            info.GetWeight(),
            info.GetUnderlined(),
            info.GetFaceName(),
            info.GetEncoding() );
#else
    (void) Create(info.GetXFontName());
#endif
}

bool wxFont::Create(int pointSize,
                    wxFontFamily family,
                    wxFontStyle style,
                    wxFontWeight weight,
                    bool underlined,
                    const wxString& faceName,
                    wxFontEncoding encoding)
{
    UnRef();

    m_refData = new wxFontRefData(pointSize, family, style, weight,
                                  underlined, faceName, encoding);

    return true;
}

#if !wxUSE_UNICODE

bool wxFont::Create(const wxString& fontname, wxFontEncoding enc)
{
    if( !fontname )
    {
        *this = wxSystemSettings::GetFont( wxSYS_DEFAULT_GUI_FONT);
        return true;
    }

    m_refData = new wxFontRefData();

    M_FONTDATA->m_nativeFontInfo.SetXFontName(fontname);  // X font name

    wxString tmp;

    wxStringTokenizer tn( fontname, wxT("-") );

    tn.GetNextToken();                           // skip initial empty token
    tn.GetNextToken();                           // foundry


    M_FONTDATA->m_faceName = tn.GetNextToken();  // family

    tmp = tn.GetNextToken().MakeUpper();         // weight
    if (tmp == wxT("BOLD")) M_FONTDATA->m_weight = wxFONTWEIGHT_BOLD;
    if (tmp == wxT("BLACK")) M_FONTDATA->m_weight = wxFONTWEIGHT_BOLD;
    if (tmp == wxT("EXTRABOLD")) M_FONTDATA->m_weight = wxFONTWEIGHT_BOLD;
    if (tmp == wxT("DEMIBOLD")) M_FONTDATA->m_weight = wxFONTWEIGHT_BOLD;
    if (tmp == wxT("ULTRABOLD")) M_FONTDATA->m_weight = wxFONTWEIGHT_BOLD;

    if (tmp == wxT("LIGHT")) M_FONTDATA->m_weight = wxFONTWEIGHT_LIGHT;
    if (tmp == wxT("THIN")) M_FONTDATA->m_weight = wxFONTWEIGHT_LIGHT;

    tmp = tn.GetNextToken().MakeUpper();        // slant
    if (tmp == wxT("I")) M_FONTDATA->m_style = wxFONTSTYLE_ITALIC;
    if (tmp == wxT("O")) M_FONTDATA->m_style = wxFONTSTYLE_ITALIC;

    tn.GetNextToken();                           // set width
    tn.GetNextToken();                           // add. style
    tn.GetNextToken();                           // pixel size

    tmp = tn.GetNextToken();                     // pointsize
    if (tmp != wxT("*"))
    {
        long num = wxStrtol (tmp.c_str(), (wxChar **) NULL, 10);
        M_FONTDATA->m_pointSize = (int)(num / 10);
    }

    tn.GetNextToken();                           // x-res
    tn.GetNextToken();                           // y-res

    tmp = tn.GetNextToken().MakeUpper();         // spacing

    if (tmp == wxT("M"))
        M_FONTDATA->m_family = wxFONTFAMILY_MODERN;
    else if (M_FONTDATA->m_faceName == wxT("TIMES"))
        M_FONTDATA->m_family = wxFONTFAMILY_ROMAN;
    else if (M_FONTDATA->m_faceName == wxT("HELVETICA"))
        M_FONTDATA->m_family = wxFONTFAMILY_SWISS;
    else if (M_FONTDATA->m_faceName == wxT("LUCIDATYPEWRITER"))
        M_FONTDATA->m_family = wxFONTFAMILY_TELETYPE;
    else if (M_FONTDATA->m_faceName == wxT("LUCIDA"))
        M_FONTDATA->m_family = wxFONTFAMILY_DECORATIVE;
    else if (M_FONTDATA->m_faceName == wxT("UTOPIA"))
        M_FONTDATA->m_family = wxFONTFAMILY_SCRIPT;

    tn.GetNextToken();                           // avg width

    // deal with font encoding
    M_FONTDATA->m_encoding = enc;
    if ( M_FONTDATA->m_encoding == wxFONTENCODING_SYSTEM )
    {
        wxString registry = tn.GetNextToken().MakeUpper(),
                 encoding = tn.GetNextToken().MakeUpper();

        if ( registry == wxT("ISO8859") )
        {
            int cp;
            if ( wxSscanf(encoding, wxT("%d"), &cp) == 1 )
            {
                M_FONTDATA->m_encoding =
                    (wxFontEncoding)(wxFONTENCODING_ISO8859_1 + cp - 1);
            }
        }
        else if ( registry == wxT("MICROSOFT") )
        {
            int cp;
            if ( wxSscanf(encoding, wxT("cp125%d"), &cp) == 1 )
            {
                M_FONTDATA->m_encoding =
                    (wxFontEncoding)(wxFONTENCODING_CP1250 + cp);
            }
        }
        else if ( registry == wxT("KOI8") )
        {
            M_FONTDATA->m_encoding = wxFONTENCODING_KOI8;
        }
        //else: unknown encoding - may be give a warning here?
        else
            return false;
    }
    return true;
}
#endif // !wxUSE_UNICODE

wxFont::~wxFont()
{
}

wxGDIRefData *wxFont::CreateGDIRefData() const
{
    return new wxFontRefData;
}

wxGDIRefData *wxFont::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxFontRefData(*static_cast<const wxFontRefData *>(data));
}

// ----------------------------------------------------------------------------
// change the font attributes
// ----------------------------------------------------------------------------

void wxFont::Unshare()
{
    // Don't change shared data
    if (!m_refData)
    {
        m_refData = new wxFontRefData();
    }
    else
    {
        wxFontRefData* ref = new wxFontRefData(*(wxFontRefData*)m_refData);
        UnRef();
        m_refData = ref;
    }
}

// ----------------------------------------------------------------------------
// accessors
// ----------------------------------------------------------------------------

int wxFont::GetPointSize() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid font") );

    return M_FONTDATA->m_pointSize;
}

wxString wxFont::GetFaceName() const
{
    wxCHECK_MSG( Ok(), wxEmptyString, wxT("invalid font") );

    return M_FONTDATA->m_faceName;
}

wxFontFamily wxFont::GetFamily() const
{
    wxCHECK_MSG( Ok(), wxFONTFAMILY_MAX, wxT("invalid font") );

    return M_FONTDATA->m_family;
}

wxFontStyle wxFont::GetStyle() const
{
    wxCHECK_MSG( Ok(), wxFONTSTYLE_MAX, wxT("invalid font") );

    return M_FONTDATA->m_style;
}

wxFontWeight wxFont::GetWeight() const
{
    wxCHECK_MSG( Ok(), wxFONTWEIGHT_MAX, wxT("invalid font") );

    return M_FONTDATA->m_weight;
}

bool wxFont::GetUnderlined() const
{
    wxCHECK_MSG( Ok(), false, wxT("invalid font") );

    return M_FONTDATA->m_underlined;
}

wxFontEncoding wxFont::GetEncoding() const
{
    wxCHECK_MSG( Ok(), wxFONTENCODING_DEFAULT, wxT("invalid font") );

    return M_FONTDATA->m_encoding;
}

const wxNativeFontInfo *wxFont::GetNativeFontInfo() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid font") );

#if wxUSE_UNICODE
#else
    if ( M_FONTDATA->m_nativeFontInfo.GetXFontName().empty() )
        GetInternalFont();
#endif

    return &(M_FONTDATA->m_nativeFontInfo);
}

bool wxFont::IsFixedWidth() const
{
    wxCHECK_MSG( Ok(), false, wxT("invalid font") );

#if wxUSE_UNICODE
   return wxFontBase::IsFixedWidth();
#else
    // Robert, is this right? HasNativeFont doesn't exist.
    if ( true )
    //    if ( M_FONTDATA->HasNativeFont() )
    {
        // the monospace fonts are supposed to have "M" in the spacing field
        wxString spacing = M_FONTDATA->
                            m_nativeFontInfo.GetXFontComponent(wxXLFD_SPACING);

        return spacing.Upper() == wxT('M');
    }
   // Unreaceable code for now
   // return wxFontBase::IsFixedWidth();
#endif

}

// ----------------------------------------------------------------------------
// change font attributes
// ----------------------------------------------------------------------------

void wxFont::SetPointSize(int pointSize)
{
    Unshare();

    M_FONTDATA->SetPointSize(pointSize);
}

void wxFont::SetFamily(wxFontFamily family)
{
    Unshare();

    M_FONTDATA->SetFamily(family);
}

void wxFont::SetStyle(wxFontStyle style)
{
    Unshare();

    M_FONTDATA->SetStyle(style);
}

void wxFont::SetWeight(wxFontWeight weight)
{
    Unshare();

    M_FONTDATA->SetWeight(weight);
}

bool wxFont::SetFaceName(const wxString& faceName)
{
    Unshare();

    return M_FONTDATA->SetFaceName(faceName) &&
        wxFontBase::SetFaceName(faceName);
}

void wxFont::SetUnderlined(bool underlined)
{
    Unshare();

    M_FONTDATA->SetUnderlined(underlined);
}

void wxFont::SetEncoding(wxFontEncoding encoding)
{
    Unshare();

    M_FONTDATA->SetEncoding(encoding);
}

void wxFont::DoSetNativeFontInfo( const wxNativeFontInfo& info )
{
    Unshare();

    M_FONTDATA->SetNativeFontInfo( info );
}

#if !wxUSE_UNICODE

// ----------------------------------------------------------------------------
// X11 implementation
// ----------------------------------------------------------------------------

// Find an existing, or create a new, XFontStruct
// based on this wxFont and the given scale. Append the
// font to list in the private data for future reference.
wxXFont* wxFont::GetInternalFont(double scale, WXDisplay* display) const
{
    if ( !Ok() )
        return NULL;

    long intScale = long(scale * 100.0 + 0.5); // key for wxXFont
    int pointSize = (M_FONTDATA->m_pointSize * 10 * intScale) / 100;

    // search existing fonts first
    wxList::compatibility_iterator node = M_FONTDATA->m_fonts.GetFirst();
    while (node)
    {
        wxXFont* f = (wxXFont*) node->GetData();
        if ((!display || (f->m_display == display)) && (f->m_scale == intScale))
            return f;
        node = node->GetNext();
    }

    wxString xFontName = M_FONTDATA->m_nativeFontInfo.GetXFontName();
    if (xFontName == "-*-*-*-*-*--*-*-*-*-*-*-*-*")
      // wxFont constructor not called with native font info parameter => take M_FONTDATA values
      xFontName.Clear();

    // not found, create a new one
    XFontStruct *font = (XFontStruct *)
                        wxLoadQueryNearestFont(pointSize,
                                               M_FONTDATA->m_family,
                                               M_FONTDATA->m_style,
                                               M_FONTDATA->m_weight,
                                               M_FONTDATA->m_underlined,
                                               wxT(""),
                                               M_FONTDATA->m_encoding,
                                               & xFontName);

    if ( !font )
    {
        wxFAIL_MSG( wxT("Could not allocate even a default font -- something is wrong.") );

        return NULL;
    }

    wxXFont* f = new wxXFont;
    f->m_fontStruct = (WXFontStructPtr)font;
    f->m_display = ( display ? display : wxGetDisplay() );
    f->m_scale = intScale;
    M_FONTDATA->m_fonts.Append(f);

    return f;
}

WXFontStructPtr wxFont::GetFontStruct(double scale, WXDisplay* display) const
{
    wxXFont* f = GetInternalFont(scale, display);

    return (f ? f->m_fontStruct : (WXFontStructPtr) 0);
}

#endif // !wxUSE_UNICODE
