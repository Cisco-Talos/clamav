/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/font.cpp
// Purpose:     wxFont class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
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

#ifdef __VMS
#pragma message disable nosimpint
#include "wx/vms_x_fix.h"
#endif
#include <Xm/Xm.h>
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
#include "wx/motif/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxFont, wxGDIObject)

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

// For every wxFont, there must be a font for each display and scale requested.
// So these objects are stored in wxFontRefData::m_fonts
class wxXFont : public wxObject
{
public:
    wxXFont();
    virtual ~wxXFont();

#if !wxMOTIF_NEW_FONT_HANDLING
    WXFontStructPtr     m_fontStruct;   // XFontStruct
#endif
#if !wxMOTIF_USE_RENDER_TABLE
    WXFontList          m_fontList;     // Motif XmFontList
#else // if wxMOTIF_USE_RENDER_TABLE
    WXRenderTable       m_renderTable;  // Motif XmRenderTable
    WXRendition         m_rendition;    // Motif XmRendition
#endif
    WXDisplay*          m_display;      // XDisplay
    int                 m_scale;        // Scale * 100
};

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
                  wxFontEncoding encoding = wxFONTENCODING_DEFAULT)
    {
        Init(size, family, style, weight, underlined, faceName, encoding);
    }

    wxFontRefData(const wxFontRefData& data)
    {
        Init(data.m_pointSize, data.m_family, data.m_style, data.m_weight,
             data.m_underlined, data.m_faceName, data.m_encoding);
    }

    virtual ~wxFontRefData();

protected:
    // common part of all ctors
    void Init(int size,
              wxFontFamily family,
              wxFontStyle style,
              wxFontWeight weight,
              bool underlined,
              const wxString& faceName,
              wxFontEncoding encoding);

    // font attributes
    int           m_pointSize;
    wxFontFamily  m_family;
    wxFontStyle   m_style;
    wxFontWeight  m_weight;
    bool          m_underlined;
    wxString      m_faceName;
    wxFontEncoding m_encoding;

    wxNativeFontInfo m_nativeFontInfo;

    // A list of wxXFonts
    wxList        m_fonts;
};

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxXFont
// ----------------------------------------------------------------------------

wxXFont::wxXFont()
{
#if !wxMOTIF_NEW_FONT_HANDLING
    m_fontStruct = (WXFontStructPtr) 0;
#endif
#if !wxMOTIF_USE_RENDER_TABLE
    m_fontList = (WXFontList) 0;
#else // if wxMOTIF_USE_RENDER_TABLE
    m_renderTable = (WXRenderTable) 0;
    m_rendition   = (WXRendition) 0;
#endif
    m_display = (WXDisplay*) 0;
    m_scale = 100;
}

wxXFont::~wxXFont()
{
#if !wxMOTIF_USE_RENDER_TABLE
    if (m_fontList)
        XmFontListFree ((XmFontList) m_fontList);
    m_fontList = NULL;
#else // if wxMOTIF_USE_RENDER_TABLE
    if (m_renderTable)
        XmRenderTableFree ((XmRenderTable) m_renderTable);
    m_renderTable = NULL;
#endif

    // TODO: why does freeing the font produce a segv???
    // Note that XFreeFont wasn't called in wxWin 1.68 either.
    // MBN: probably some interaction with fonts being still
    //      in use in some widgets...
    // XFontStruct* fontStruct = (XFontStruct*) m_fontStruct;
    //        XFreeFont((Display*) m_display, fontStruct);
}

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
    if (family == wxDEFAULT)
        m_family = wxFONTFAMILY_SWISS;
    else
        m_family = family;

    m_faceName = faceName;

    if (style == wxDEFAULT)
        m_style = wxFONTSTYLE_NORMAL;
    else
        m_style = style;

    if (weight == wxDEFAULT)
        m_weight = wxFONTWEIGHT_NORMAL;
    else
        m_weight = weight;

    if (pointSize == wxDEFAULT)
        m_pointSize = 12;
    else
        m_pointSize = pointSize;

    m_underlined = underlined;
    m_encoding = encoding;
}

wxFontRefData::~wxFontRefData()
{
    wxList::compatibility_iterator node = m_fonts.GetFirst();
    while (node)
    {
        wxXFont* f = (wxXFont*) node->GetData();
        delete f;
        node = node->GetNext();
    }
    m_fonts.Clear();
}

#define M_FONTDATA ((wxFontRefData*)m_refData)

// ----------------------------------------------------------------------------
// wxFont
// ----------------------------------------------------------------------------

wxFont::wxFont(const wxNativeFontInfo& info)
{
    (void)Create(info.GetXFontName());
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
        long num = wxStrtol (tmp.mb_str(), (wxChar **) NULL, 10);
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

void wxFont::SetPointSize(int pointSize)
{
    Unshare();

    M_FONTDATA->m_pointSize = pointSize;
    M_FONTDATA->m_nativeFontInfo.GetXFontName().Clear(); // invalid now
}

void wxFont::SetFamily(wxFontFamily family)
{
    Unshare();

    M_FONTDATA->m_family = family;
    M_FONTDATA->m_nativeFontInfo.GetXFontName().Clear(); // invalid now
}

void wxFont::SetStyle(wxFontStyle style)
{
    Unshare();

    M_FONTDATA->m_style = style;
    M_FONTDATA->m_nativeFontInfo.GetXFontName().Clear(); // invalid now
}

void wxFont::SetWeight(wxFontWeight weight)
{
    Unshare();

    M_FONTDATA->m_weight = weight;
    M_FONTDATA->m_nativeFontInfo.GetXFontName().Clear(); // invalid now
}

bool wxFont::SetFaceName(const wxString& faceName)
{
    Unshare();

    M_FONTDATA->m_faceName = faceName;
    M_FONTDATA->m_nativeFontInfo.GetXFontName().Clear(); // invalid now

    return wxFontBase::SetFaceName(faceName);
}

void wxFont::SetUnderlined(bool underlined)
{
    Unshare();

    M_FONTDATA->m_underlined = underlined;
}

void wxFont::SetEncoding(wxFontEncoding encoding)
{
    Unshare();

    M_FONTDATA->m_encoding = encoding;
    M_FONTDATA->m_nativeFontInfo.GetXFontName().Clear(); // invalid now
}

void wxFont::DoSetNativeFontInfo(const wxNativeFontInfo& info)
{
    Unshare();

    M_FONTDATA->m_nativeFontInfo = info;
}

// ----------------------------------------------------------------------------
// query font attributes
// ----------------------------------------------------------------------------

int wxFont::GetPointSize() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid font") );

    return M_FONTDATA->m_pointSize;
}

wxString wxFont::GetFaceName() const
{
    wxCHECK_MSG( Ok(), wxEmptyString, wxT("invalid font") );

    return M_FONTDATA->m_faceName ;
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

    if(M_FONTDATA->m_nativeFontInfo.GetXFontName().empty())
        GetInternalFont();

    return &(M_FONTDATA->m_nativeFontInfo);
}

// ----------------------------------------------------------------------------
// real implementation
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

    // not found, create a new one
    wxString xFontSpec;
    XFontStruct *font = (XFontStruct *)
                        wxLoadQueryNearestFont(pointSize,
                                               M_FONTDATA->m_family,
                                               M_FONTDATA->m_style,
                                               M_FONTDATA->m_weight,
                                               M_FONTDATA->m_underlined,
                                               wxT(""),
                                               M_FONTDATA->m_encoding,
                                               &xFontSpec);

    if ( !font )
    {
        wxFAIL_MSG( wxT("Could not allocate even a default font -- something is wrong.") );

        return NULL;
    }

    wxXFont* f = new wxXFont;
#if wxMOTIF_NEW_FONT_HANDLING
    XFreeFont( (Display*) display, font );
#else
    f->m_fontStruct = (WXFontStructPtr)font;
#endif
    f->m_display = ( display ? display : wxGetDisplay() );
    f->m_scale = intScale;

#if wxMOTIF_USE_RENDER_TABLE
    XmRendition rendition;
    XmRenderTable renderTable;
    Arg args[5];
    int count = 0;

#if wxMOTIF_NEW_FONT_HANDLING
    char* fontSpec = wxStrdup(xFontSpec.mb_str());
    XtSetArg( args[count], XmNfontName, fontSpec ); ++count;
    XtSetArg( args[count], XmNfontType, XmFONT_IS_FONTSET ); ++count;
#else
    XtSetArg( args[count], XmNfont, font ); ++count;
#endif
    XtSetArg( args[count], XmNunderlineType,
              GetUnderlined() ? XmSINGLE_LINE : XmNO_LINE ); ++count;
    rendition = XmRenditionCreate( XmGetXmDisplay( (Display*)f->m_display ),
                                   (XmStringTag)"",
                                   args, count );
    renderTable = XmRenderTableAddRenditions( NULL, &rendition, 1,
                                              XmMERGE_REPLACE );

    f->m_renderTable = (WXRenderTable)renderTable;
    f->m_rendition = (WXRendition)rendition;
    wxASSERT( f->m_renderTable != NULL );
#else // if !wxMOTIF_USE_RENDER_TABLE
    f->m_fontList = XmFontListCreate ((XFontStruct*) font, XmSTRING_DEFAULT_CHARSET);
    wxASSERT( f->m_fontList != NULL );
#endif

    M_FONTDATA->m_fonts.Append(f);

    return f;
}

#if !wxMOTIF_NEW_FONT_HANDLING

WXFontStructPtr wxFont::GetFontStruct(double scale, WXDisplay* display) const
{
    wxXFont* f = GetInternalFont(scale, display);

    return (f ? f->m_fontStruct : (WXFontStructPtr) 0);
}

#endif

#if !wxMOTIF_USE_RENDER_TABLE

WXFontList wxFont::GetFontList(double scale, WXDisplay* display) const
{
    wxXFont* f = GetInternalFont(scale, display);

    return (f ? f->m_fontList : (WXFontList) 0);
}

#else // if wxMOTIF_USE_RENDER_TABLE

WXRenderTable wxFont::GetRenderTable(WXDisplay* display) const
{
    wxXFont* f = GetInternalFont(1.0, display);

    return (f ? f->m_renderTable : (WXRenderTable) 0);
}

#endif // wxMOTIF_USE_RENDER_TABLE

WXFontType wxFont::GetFontType(WXDisplay* display) const
{
#if wxMOTIF_USE_RENDER_TABLE
    return Ok() ? GetRenderTable(display) : NULL;
#else
    return Ok() ? GetFontList(1.0, display) : NULL;
#endif
}

WXFontType wxFont::GetFontTypeC(WXDisplay* display) const
{
#if wxMOTIF_USE_RENDER_TABLE
    return Ok() ? GetRenderTable(display) : NULL;
#else
    return Ok() ? XmFontListCopy( (XmFontList)GetFontList(1.0, display) ) : NULL;
#endif
}

/*static*/ WXString wxFont::GetFontTag()
{
#if wxMOTIF_USE_RENDER_TABLE
    return (WXString)XmNrenderTable;
#else
    return (WXString)XmNfontList;
#endif
}

#if wxMOTIF_USE_RENDER_TABLE

WXFontSet wxFont::GetFontSet(double scale, WXDisplay* display) const
{
    wxXFont* f = GetInternalFont(scale, display);

    if( !f ) return (WXFontSet) 0;

    Arg args[2];
    int count = 0;

    XtSetArg( args[count], XmNfont, 0 ); ++count;
    XmRenditionRetrieve( (XmRendition) f->m_rendition, args, count );

    return (WXFontSet) args[0].value;
}

void wxGetTextExtent(WXDisplay* display, const wxFont& font, double scale,
                     const wxString& str,
                     int* width, int* height, int* ascent, int* descent)
{
    XRectangle ink, logical;
    WXFontSet fset = font.GetFontSet(scale, display);

    XmbTextExtents( (XFontSet)fset, str.mb_str(), str.length(), &ink, &logical);

    if( width ) *width = logical.width;
    if( height ) *height = logical.height;
    if( ascent ) *ascent = -logical.y;
    if( descent ) *descent = logical.height + logical.y;
}

#else // if !wxMOTIF_USE_RENDER_TABLE

void wxGetTextExtent(WXDisplay* display, const wxFont& font,
                     double scale, const wxString& str,
                     int* width, int* height, int* ascent, int* descent)
{
    WXFontStructPtr pFontStruct = font.GetFontStruct(scale, display);

    int direction, ascent2, descent2;
    XCharStruct overall;
    int slen = str.length();

    XTextExtents((XFontStruct*) pFontStruct,
                 const_cast<char*>((const char *)str.mb_str()), slen,
                 &direction, &ascent2, &descent2, &overall);

    if ( width )
        *width = (overall.width);
    if ( height )
        *height = (ascent2 + descent2);
    if ( descent )
        *descent = descent2;
    if ( ascent )
        *ascent = ascent2;
}

#endif // !wxMOTIF_USE_RENDER_TABLE
