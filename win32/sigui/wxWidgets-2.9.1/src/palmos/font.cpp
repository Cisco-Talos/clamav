/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/font.cpp
// Purpose:     wxFont class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/14/04
// RCS-ID:      $Id$
// Copyright:   (c) wxWidgets team
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

#include "wx/font.h"

#ifndef WX_PRECOMP
    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/log.h"
    #include "wx/encinfo.h"
#endif // WX_PRECOMP

#include "wx/fontutil.h"
#include "wx/fontmap.h"

#include "wx/tokenzr.h"

#if wxUSE_EXTENDED_RTTI

wxBEGIN_ENUM( wxFontFamily )
    wxENUM_MEMBER( wxDEFAULT )
    wxENUM_MEMBER( wxDECORATIVE )
    wxENUM_MEMBER( wxROMAN )
    wxENUM_MEMBER( wxSCRIPT )
    wxENUM_MEMBER( wxSWISS )
    wxENUM_MEMBER( wxMODERN )
    wxENUM_MEMBER( wxTELETYPE )
wxEND_ENUM( wxFontFamily )

wxBEGIN_ENUM( wxFontStyle )
    wxENUM_MEMBER( wxNORMAL )
    wxENUM_MEMBER( wxITALIC )
    wxENUM_MEMBER( wxSLANT )
wxEND_ENUM( wxFontStyle )

wxBEGIN_ENUM( wxFontWeight )
    wxENUM_MEMBER( wxNORMAL )
    wxENUM_MEMBER( wxLIGHT )
    wxENUM_MEMBER( wxBOLD )
wxEND_ENUM( wxFontWeight )

IMPLEMENT_DYNAMIC_CLASS_WITH_COPY_XTI(wxFont, wxGDIObject,"wx/font.h")

wxBEGIN_PROPERTIES_TABLE(wxFont)
    wxPROPERTY( Size,int, SetPointSize, GetPointSize, 12 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Family, int  , SetFamily, GetFamily, (int)wxDEFAULT , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // wxFontFamily
    wxPROPERTY( Style, int , SetStyle, GetStyle, (int)wxNORMAL , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // wxFontStyle
    wxPROPERTY( Weight, int , SetWeight, GetWeight, (int)wxNORMAL , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // wxFontWeight
    wxPROPERTY( Underlined, bool , SetUnderlined, GetUnderlined, false , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Face, wxString , SetFaceName, GetFaceName, EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Encoding, wxFontEncoding , SetEncoding, GetEncoding, wxFONTENCODING_DEFAULT , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
wxEND_PROPERTIES_TABLE()

wxCONSTRUCTOR_6( wxFont , int , Size , int , Family , int , Style , int , Weight , bool , Underlined , wxString , Face )

wxBEGIN_HANDLERS_TABLE(wxFont)
wxEND_HANDLERS_TABLE()

#else
    IMPLEMENT_DYNAMIC_CLASS(wxFont, wxGDIObject)
#endif


// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// wxFontRefData - the internal description of the font
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxFontRefData: public wxGDIRefData
{
public:
    // constructors
    wxFontRefData()
    {
        Init(-1, wxSize(0, 0), false, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL,
             wxFONTWEIGHT_NORMAL, false, wxEmptyString,
             wxFONTENCODING_DEFAULT);
    }

    wxFontRefData(int size,
                  const wxSize& pixelSize,
                  bool sizeUsingPixels,
                  wxFontFamily family,
                  wxFontStyle style,
                  wxFontWeight weight,
                  bool underlined,
                  const wxString& faceName,
                  wxFontEncoding encoding)
    {
        Init(size, pixelSize, sizeUsingPixels, family, style, weight,
             underlined, faceName, encoding);
    }

    wxFontRefData(const wxNativeFontInfo& info, WXHFONT hFont = 0)
    {
        Init(info, hFont);
    }

    wxFontRefData(const wxFontRefData& data)
    {
        if ( data.m_nativeFontInfoOk )
        {
            Init(data.m_nativeFontInfo);
        }
        else
        {
            Init(data.m_pointSize, data.m_pixelSize, data.m_sizeUsingPixels,
                 data.m_family, data.m_style, data.m_weight,
                 data.m_underlined, data.m_faceName, data.m_encoding);
        }
    }

    virtual ~wxFontRefData();

    // operations
    bool Alloc(wxFont *font);

    void Free();

    // all wxFont accessors
    int GetPointSize() const
    {
        return m_nativeFontInfoOk ? m_nativeFontInfo.GetPointSize()
                                  : m_pointSize;
    }

    wxSize GetPixelSize() const
    {
        return m_nativeFontInfoOk ? m_nativeFontInfo.GetPixelSize()
                                  : m_pixelSize;
    }

    bool IsUsingSizeInPixels() const
    {
        return m_nativeFontInfoOk ? true : m_sizeUsingPixels;
    }

    int GetFamily() const
    {
        return m_family;
    }

    int GetStyle() const
    {
        return m_nativeFontInfoOk ? m_nativeFontInfo.GetStyle()
                                  : m_style;
    }

    int GetWeight() const
    {
        return m_nativeFontInfoOk ? m_nativeFontInfo.GetWeight()
                                  : m_weight;
    }

    bool GetUnderlined() const
    {
        return m_nativeFontInfoOk ? m_nativeFontInfo.GetUnderlined()
                                  : m_underlined;
    }

    wxString GetFaceName() const
    {
        wxString s;
        if ( m_nativeFontInfoOk )
            s = m_nativeFontInfo.GetFaceName();
        else
            s = m_faceName;

        return s;
    }

    wxFontEncoding GetEncoding() const
    {
        return m_nativeFontInfoOk ? m_nativeFontInfo.GetEncoding()
                                  : m_encoding;
    }

    WXHFONT GetHFONT() const { return m_hFont; }

    // ... and setters
    void SetPointSize(int pointSize)
    {
        if ( m_nativeFontInfoOk )
        {
            m_nativeFontInfo.SetPointSize(pointSize);
        }
        else
        {
            m_pointSize = pointSize;
            m_sizeUsingPixels = false;
        }
    }

    void SetPixelSize(const wxSize& pixelSize)
    {
        if ( m_nativeFontInfoOk )
        {
            m_nativeFontInfo.SetPixelSize(pixelSize);
        }
        else
        {
            m_pixelSize = pixelSize;
            m_sizeUsingPixels = true;
        }
    }

    void SetFamily(wxFontFamily family)
    {
        m_family = family;
    }

    void SetStyle(wxFontStyle style)
    {
        if ( m_nativeFontInfoOk )
            m_nativeFontInfo.SetStyle((wxFontStyle)style);
        else
            m_style = style;
    }

    void SetWeight(wxFontWeight weight)
    {
        if ( m_nativeFontInfoOk )
            m_nativeFontInfo.SetWeight((wxFontWeight)weight);
        else
            m_weight = weight;
    }

    bool SetFaceName(const wxString& faceName)
    {
        if ( m_nativeFontInfoOk )
            m_nativeFontInfo.SetFaceName(faceName);
        else
            m_faceName = faceName;
    }

    void SetUnderlined(bool underlined)
    {
        if ( m_nativeFontInfoOk )
            m_nativeFontInfo.SetUnderlined(underlined);
        else
            m_underlined = underlined;
    }

    void SetEncoding(wxFontEncoding encoding)
    {
        if ( m_nativeFontInfoOk )
            m_nativeFontInfo.SetEncoding(encoding);
        else
            m_encoding = encoding;
    }

    // native font info tests
    bool HasNativeFontInfo() const { return m_nativeFontInfoOk; }

    const wxNativeFontInfo& GetNativeFontInfo() const
        { return m_nativeFontInfo; }

protected:
    // common part of all ctors
    void Init(int size,
              const wxSize& pixelSize,
              bool sizeUsingPixels,
              wxFontFamily family,
              wxFontStyle style,
              wxFontWeight weight,
              bool underlined,
              const wxString& faceName,
              wxFontEncoding encoding);

    void Init(const wxNativeFontInfo& info, WXHFONT hFont = 0);

    // font characterstics
    int           m_pointSize;
    wxSize        m_pixelSize;
    bool          m_sizeUsingPixels;
    wxFontFamily  m_family;
    wxFontStyle   m_style;
    wxFontWeight  m_weight;
    bool          m_underlined;
    wxString      m_faceName;
    wxFontEncoding m_encoding;

    // Windows font handle
    WXHFONT       m_hFont;

    // Native font info
    wxNativeFontInfo m_nativeFontInfo;
    bool             m_nativeFontInfoOk;
};

#define M_FONTDATA ((wxFontRefData*)m_refData)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxFontRefData
// ----------------------------------------------------------------------------

void wxFontRefData::Init(int pointSize,
                         const wxSize& pixelSize,
                         bool sizeUsingPixels,
                         wxFontFamily family,
                         wxFontStyle style,
                         wxFontWeight weight,
                         bool underlined,
                         const wxString& faceName,
                         wxFontEncoding encoding)
{
}

void wxFontRefData::Init(const wxNativeFontInfo& info, WXHFONT hFont)
{
}

wxFontRefData::~wxFontRefData()
{
}

bool wxFontRefData::Alloc(wxFont *font)
{
    return false;
}

void wxFontRefData::Free()
{
}

// ----------------------------------------------------------------------------
// wxNativeFontInfo
// ----------------------------------------------------------------------------

void wxNativeFontInfo::SetPixelSize(const wxSize& pixelSize)
{
}

// ----------------------------------------------------------------------------
// wxFont
// ----------------------------------------------------------------------------

bool wxFont::Create(const wxNativeFontInfo& info, WXHFONT hFont)
{
    return false;
}

wxFont::wxFont(const wxString& fontdesc)
{
}

/* Constructor for a font. Note that the real construction is done
 * in wxDC::SetFont, when information is available about scaling etc.
 */
bool wxFont::DoCreate(int pointSize,
                      const wxSize& pixelSize,
                      bool sizeUsingPixels,
                      wxFontFamily family,
                      wxFontStyle style,
                      wxFontWeight weight,
                      bool underlined,
                      const wxString& faceName,
                      wxFontEncoding encoding)
{
    return false;
}

wxFont::~wxFont()
{
}

// ----------------------------------------------------------------------------
// real implementation
// ----------------------------------------------------------------------------
wxGDIRefData *wxFont::CreateGDIRefData() const
{
    return new wxFontRefData();
}

wxGDIRefData *wxFont::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxFontRefData(*static_cast<const wxFontRefData *>(data));
}

bool wxFont::RealizeResource()
{
    return false;
}

bool wxFont::FreeResource(bool WXUNUSED(force))
{
    return false;
}

WXHANDLE wxFont::GetResourceHandle() const
{
    return (WXHANDLE)0;
}

bool wxFont::IsFree() const
{
    return false;
}

// ----------------------------------------------------------------------------
// change font attribute: we recreate font when doing it
// ----------------------------------------------------------------------------

void wxFont::SetPointSize(int pointSize)
{
}

void wxFont::SetPixelSize(const wxSize& pixelSize)
{
}

void wxFont::SetFamily(wxFontFamily family)
{
}

void wxFont::SetStyle(wxFontStyle style)
{
}

void wxFont::SetWeight(wxFontWeight weight)
{
}

bool wxFont::SetFaceName(const wxString& faceName)
{
    return true;
}

void wxFont::SetUnderlined(bool underlined)
{
}

void wxFont::SetEncoding(wxFontEncoding encoding)
{
}

void wxFont::DoSetNativeFontInfo(const wxNativeFontInfo& info)
{
}

// ----------------------------------------------------------------------------
// accessors
// ----------------------------------------------------------------------------

int wxFont::GetPointSize() const
{
    return 0;
}

wxSize wxFont::GetPixelSize() const
{
    return wxSize(0,0);
}

bool wxFont::IsUsingSizeInPixels() const
{
    return false;
}

wxFontFamily wxFont::GetFamily() const
{
    return wxFONTFAMILY_ROMAN;
}

wxFontStyle wxFont::GetStyle() const
{
    return wxFONTSTYLE_NORMAL;
}

wxFontWeight wxFont::GetWeight() const
{
    return wxFONTWEIGHT_NORMAL;
}

bool wxFont::GetUnderlined() const
{
    return false;
}

wxString wxFont::GetFaceName() const
{
    return wxEmptyString;
}

wxFontEncoding wxFont::GetEncoding() const
{
    return wxFONTENCODING_SYSTEM;
}

const wxNativeFontInfo *wxFont::GetNativeFontInfo() const
{
    return NULL;
}

wxString wxFont::GetNativeFontInfoDesc() const
{
    wxCHECK_MSG( Ok(), wxEmptyString, wxT("invalid font") );

    // be sure we have an HFONT associated...
    wxConstCast(this, wxFont)->RealizeResource();
    return wxFontBase::GetNativeFontInfoDesc();
}

wxString wxFont::GetNativeFontInfoUserDesc() const
{
    wxCHECK_MSG( Ok(), wxEmptyString, wxT("invalid font") );

    // be sure we have an HFONT associated...
    wxConstCast(this, wxFont)->RealizeResource();
    return wxFontBase::GetNativeFontInfoUserDesc();
}

bool wxFont::IsFixedWidth() const
{
    return false;
}
