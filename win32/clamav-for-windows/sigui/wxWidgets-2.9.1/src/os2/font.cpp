/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/font.cpp
// Purpose:     wxFont class
// Author:      David Webster
// Modified by:
// Created:     10/06/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/font.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/log.h"
#endif // WX_PRECOMP

#include "wx/os2/private.h"

#include "wx/fontutil.h"
#include "wx/fontmap.h"
#include "wx/encinfo.h"

#include "wx/tokenzr.h"

#include <malloc.h>

IMPLEMENT_DYNAMIC_CLASS(wxFont, wxGDIObject)

// ----------------------------------------------------------------------------
// wxFontRefData - the internal description of the font
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxFontRefData: public wxGDIRefData
{
public:
    wxFontRefData()
    {
        Init(-1, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL, false,
             wxEmptyString, wxFONTENCODING_DEFAULT);
    }

    wxFontRefData( int             nSize
                  ,wxFontFamily    nFamily
                  ,wxFontStyle     nStyle
                  ,wxFontWeight    nWeight
                  ,bool            bUnderlined
                  ,const wxString& sFaceName
                  ,wxFontEncoding  vEncoding
                 )
    {
        Init( nSize
             ,nFamily
             ,nStyle
             ,nWeight
             ,bUnderlined
             ,sFaceName
             ,vEncoding
            );
    }

    wxFontRefData( const wxNativeFontInfo& rInfo
                  ,WXHFONT                 hFont = 0
                  ,WXHANDLE                hPS   = 0
                 )
    {
        Init( rInfo
             ,hFont
             ,hPS
            );
    }

    wxFontRefData(const wxFontRefData& rData)
    {
        Init( rData.m_nPointSize
             ,rData.m_nFamily
             ,rData.m_nStyle
             ,rData.m_nWeight
             ,rData.m_bUnderlined
             ,rData.m_sFaceName
             ,rData.m_vEncoding
            );
        m_nFontId = rData.m_nFontId;
    }

    virtual ~wxFontRefData();

    //
    // Operations
    //
    bool Alloc(wxFont* pFont);
    void Free(void);

    //
    // All wxFont accessors
    //
    inline int GetPointSize(void) const
    {
        //
        // We don't use the actual native font point size since it is
        // the chosen physical font, which is usually only and approximation
        // of the desired outline font.  The actual displayable point size
        // is the one stored in the refData
        //
        return m_nPointSize;
    }

    inline wxFontFamily GetFamily(void) const
    {
        return m_nFamily;
    }

    inline wxFontStyle GetStyle(void) const
    {
        return m_bNativeFontInfoOk ? m_vNativeFontInfo.GetStyle()
                                   : m_nStyle;
    }

    inline wxFontWeight GetWeight(void) const
    {
        return m_bNativeFontInfoOk ? m_vNativeFontInfo.GetWeight()
                                   : m_nWeight;
    }

    inline bool GetUnderlined(void) const
    {
        return m_bNativeFontInfoOk ? m_vNativeFontInfo.GetUnderlined()
                                   : m_bUnderlined;
    }

    inline wxString GetFaceName(void) const
    {
        wxString                    sFaceName;

        if (m_bNativeFontInfoOk)
            sFaceName = m_vNativeFontInfo.GetFaceName();
        else
            sFaceName = m_sFaceName;

        return sFaceName;
    }

    inline wxFontEncoding GetEncoding(void) const
    {
        return m_bNativeFontInfoOk ? m_vNativeFontInfo.GetEncoding()
                                   : m_vEncoding;
    }

    inline WXHFONT      GetHFONT(void) const { return m_hFont; }
    inline HPS          GetPS(void) const { return m_hPS; }
    inline PFONTMETRICS GetFM(void) const { return m_pFM; }
    inline int          GetNumFonts(void) const { return m_nNumFonts; }

    // ... and setters
    inline void SetPointSize(int nPointSize)
    {
        if (m_bNativeFontInfoOk)
            m_vNativeFontInfo.SetPointSize(nPointSize);
        else
            m_nPointSize = nPointSize;
    }

    inline void SetFamily(wxFontFamily nFamily)
    {
        m_nFamily = nFamily;
    }

    inline void SetStyle(wxFontStyle nStyle)
    {
        if (m_bNativeFontInfoOk)
            m_vNativeFontInfo.SetStyle(nStyle);
        else
            m_nStyle = nStyle;
    }

    inline void SetWeight(wxFontWeight nWeight)
    {
        if (m_bNativeFontInfoOk)
            m_vNativeFontInfo.SetWeight(nWeight);
        else
            m_nWeight = nWeight;
    }

    inline bool SetFaceName(const wxString& sFaceName)
    {
        if (m_bNativeFontInfoOk)
            return m_vNativeFontInfo.SetFaceName(sFaceName);
        else
            m_sFaceName = sFaceName;
        return true;
    }

    inline void SetUnderlined(bool bUnderlined)
    {
        if (m_bNativeFontInfoOk)
            m_vNativeFontInfo.SetUnderlined(bUnderlined);
        else
            m_bUnderlined = bUnderlined;
    }

    inline void SetEncoding(wxFontEncoding vEncoding)
    {
        if (m_bNativeFontInfoOk)
            m_vNativeFontInfo.SetEncoding(vEncoding);
        else
            m_vEncoding = vEncoding;
    }

    inline void SetPS(HPS hPS)
    {
        m_hPS = hPS;
    }

    inline void SetFM(PFONTMETRICS pFM)
    {
        m_pFM = pFM;
    }

    inline void SetNumFonts(int nNumFonts)
    {
        m_nNumFonts = nNumFonts;
    }

    //
    // Native font info tests
    //
    bool HasNativeFontInfo() const { return m_bNativeFontInfoOk; }

    const wxNativeFontInfo& GetNativeFontInfo() const
        { return m_vNativeFontInfo; }

protected:
    //
    // Common part of all ctors
    //
    void Init( int             nSize
              ,wxFontFamily    nFamily
              ,wxFontStyle     nStyle
              ,wxFontWeight    nWeight
              ,bool            bUnderlined
              ,const wxString& rsFaceName
              ,wxFontEncoding  vEncoding
             );

    void Init( const wxNativeFontInfo& rInfo
              ,WXHFONT                 hFont = 0
              ,WXHANDLE                hPS   = 0
             );
    //
    // If true, the pointer to the actual font is temporary and SHOULD NOT BE
    // DELETED by destructor
    //
    bool                            m_bTemporary;
    int                             m_nFontId;

    //
    // Font characterstics
    //
    int                             m_nPointSize;
    wxFontFamily                    m_nFamily;
    wxFontStyle                     m_nStyle;
    wxFontWeight                    m_nWeight;
    bool                            m_bUnderlined;
    wxString                        m_sFaceName;
    wxFontEncoding                  m_vEncoding;
    WXHFONT                         m_hFont;

    //
    // Native font info
    //
    wxNativeFontInfo                m_vNativeFontInfo;
    bool                            m_bNativeFontInfoOk;

    //
    // Some PM specific stuff
    //
    PFONTMETRICS                    m_pFM;         // array of FONTMETRICS structs
    int                             m_nNumFonts;   // number of fonts in array
    HPS                             m_hPS;         // PS handle this font belongs to
    FATTRS                          m_vFattrs;     // Current fattrs struct
    FACENAMEDESC                    m_vFname;      // Current facename struct
    bool                            m_bInternalPS; // Internally generated PS?
}; // end of CLASS wxFontRefData

#define M_FONTDATA ((wxFontRefData*)m_refData)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxFontRefData
// ----------------------------------------------------------------------------

void wxFontRefData::Init(
  int                               nPointSize
, wxFontFamily                      nFamily
, wxFontStyle                       nStyle
, wxFontWeight                      nWeight
, bool                              bUnderlined
, const wxString&                   rsFaceName
, wxFontEncoding                    vEncoding
)
{
    m_nStyle      = nStyle;
    m_nPointSize  = nPointSize;
    m_nFamily     = nFamily;
    m_nStyle      = nStyle;
    m_nWeight     = nWeight;
    m_bUnderlined = bUnderlined;
    m_sFaceName   = rsFaceName;
    m_vEncoding   = vEncoding;
    m_hFont       = 0;

    m_bNativeFontInfoOk = false;

    m_nFontId     = 0;
    m_bTemporary  = false;
    m_pFM         = (PFONTMETRICS)NULL;
    m_hPS         = NULLHANDLE;
    m_nNumFonts   = 0;
} // end of wxFontRefData::Init

void wxFontRefData::Init(
  const wxNativeFontInfo&           rInfo
, WXHFONT                           hFont //this is the FontId -- functions as the hFont for OS/2
, WXHANDLE                          hPS   // Presentation Space we are using
)
{
    //
    // hFont may be zero, or it be passed in case we really want to
    // use the exact font created in the underlying system
    // (for example where we can't guarantee conversion from HFONT
    // to LOGFONT back to HFONT)
    //
    m_hFont = hFont;
    m_nFontId = (int)hFont;

    m_bNativeFontInfoOk = true;
    m_vNativeFontInfo = rInfo;

    if (hPS == NULLHANDLE)
    {
        m_hPS = ::WinGetPS(HWND_DESKTOP);
        m_bInternalPS = true;
    }
    else
        m_hPS = (HPS)hPS;

    m_nFontId     = 0;
    m_bTemporary  = false;
    m_pFM         = (PFONTMETRICS)NULL;
    m_nNumFonts   = 0;
} // end of wxFontRefData::Init

wxFontRefData::~wxFontRefData()
{
    Free();
}

bool wxFontRefData::Alloc( wxFont* pFont )
{
    wxString                        sFaceName;
    long                            flId = m_hFont;
    long                            lRc;
    ERRORID                         vError;
    wxString                        sError;

    if (!m_bNativeFontInfoOk)
    {
        wxFillLogFont( &m_vNativeFontInfo.fa
                      ,&m_vNativeFontInfo.fn
                      ,&m_hPS
                      ,&m_bInternalPS
                      ,&flId
                      ,sFaceName
                      ,pFont
                     );
        m_bNativeFontInfoOk = true;
    }
    else
    {
        if (flId == 0L)
            flId = 1L;
        else
            flId++;
        if (flId > 254)
            flId = 1L;
    }
    if((lRc = ::GpiCreateLogFont( m_hPS
                                 ,NULL
                                 ,flId
                                 ,&m_vNativeFontInfo.fa
                                )) != GPI_ERROR)
    {
       m_hFont = (WXHFONT)flId;
       m_nFontId = flId;
    }
    if (!m_hFont)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(wxT("CreateFont"));
    }

    ::GpiSetCharSet(m_hPS, flId); // sets font for presentation space
    ::GpiQueryFontMetrics(m_hPS, sizeof(FONTMETRICS), &m_vNativeFontInfo.fm);

    //
    // Set refData members with the results
    //
    memcpy(&m_vFattrs, &m_vNativeFontInfo.fa, sizeof(m_vFattrs));
    memcpy(&m_vFname, &m_vNativeFontInfo.fn, sizeof(m_vFname));
    //
    // Going to leave the point size alone.  Mostly we use outline fonts
    // that can be set to any point size inside of Presentation Parameters,
    // regardless of whether or not the actual font is registered in the system.
    // The GpiCreateLogFont will do enough by selecting the right family,
    // and face name.
    //
    if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Times New Roman") == 0)
        m_nFamily = wxFONTFAMILY_ROMAN;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Times New Roman MT 30") == 0)
        m_nFamily = wxFONTFAMILY_ROMAN;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "@Times New Roman MT 30") == 0)
        m_nFamily = wxFONTFAMILY_ROMAN;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Tms Rmn") == 0)
        m_nFamily = wxFONTFAMILY_ROMAN;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "WarpSans") == 0)
        m_nFamily = wxFONTFAMILY_DECORATIVE;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Helvetica") == 0)
        m_nFamily = wxFONTFAMILY_SWISS;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Helv") == 0)
        m_nFamily = wxFONTFAMILY_SWISS;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Script") == 0)
        m_nFamily = wxFONTFAMILY_SCRIPT;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Courier New") == 0)
        m_nFamily = wxFONTFAMILY_TELETYPE;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Courier") == 0)
        m_nFamily = wxFONTFAMILY_TELETYPE;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "System Monospaced") == 0)
        m_nFamily = wxFONTFAMILY_TELETYPE;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "System VIO") == 0)
        m_nFamily = wxFONTFAMILY_MODERN;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "System Proportional") == 0)
        m_nFamily = wxFONTFAMILY_MODERN;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Arial") == 0)
        m_nFamily = wxFONTFAMILY_SWISS;
    else if (strcmp(m_vNativeFontInfo.fm.szFamilyname, "Swiss") == 0)
        m_nFamily = wxFONTFAMILY_SWISS;
    else
        m_nFamily = wxFONTFAMILY_SWISS;

    if (m_vNativeFontInfo.fa.fsSelection & FATTR_SEL_ITALIC)
        m_nStyle = wxFONTSTYLE_ITALIC;
    else
        m_nStyle = wxFONTSTYLE_NORMAL;
    switch(m_vNativeFontInfo.fn.usWeightClass)
    {
        case FWEIGHT_DONT_CARE:
            m_nWeight = wxFONTWEIGHT_NORMAL;
            break;

        case FWEIGHT_NORMAL:
            m_nWeight = wxFONTWEIGHT_NORMAL;
            break;

        case FWEIGHT_LIGHT:
            m_nWeight = wxFONTWEIGHT_LIGHT;
            break;

        case FWEIGHT_BOLD:
            m_nWeight = wxFONTWEIGHT_BOLD;
            break;

        case FWEIGHT_ULTRA_BOLD:
            m_nWeight = wxFONTWEIGHT_MAX;
            break;

        default:
            m_nWeight = wxFONTWEIGHT_NORMAL;
    }
    m_bUnderlined = ((m_vNativeFontInfo.fa.fsSelection & FATTR_SEL_UNDERSCORE) != 0);
    m_sFaceName = (wxChar*)m_vNativeFontInfo.fa.szFacename;
    m_vEncoding = wxGetFontEncFromCharSet(m_vNativeFontInfo.fa.usCodePage);

    //
    // We don't actuall keep the font around if using a temporary PS
    //
    if (m_bInternalPS)
    {
        if(m_hFont)
            ::GpiDeleteSetId( m_hPS
                             ,flId
                            );

        ::WinReleasePS(m_hPS);
    }
    else
        //
        // Select the font into the Presentation space
        //
        ::GpiSetCharSet(m_hPS, flId); // sets font for presentation space
    return true;
} // end of wxFontRefData::Alloc

void wxFontRefData::Free()
{
    if (m_pFM)
        delete [] m_pFM;
    m_pFM = (PFONTMETRICS)NULL;

    if ( m_hFont )
    {
        ::GpiDeleteSetId(m_hPS, 1L); /* delete the logical font          */
        m_nFontId = 0;
        m_hFont   = 0;
    }
    if (m_bInternalPS)
        ::WinReleasePS(m_hPS);
    m_hPS = NULLHANDLE;
} // end of wxFontRefData::Free

// ----------------------------------------------------------------------------
// wxNativeFontInfo
// ----------------------------------------------------------------------------

void wxNativeFontInfo::Init()
{
    memset(&fa, '\0', sizeof(FATTRS));
} // end of wxNativeFontInfo::Init

int wxNativeFontInfo::GetPointSize() const
{
    return fm.lEmHeight;
} // end of wxNativeFontInfo::GetPointSize

wxFontStyle wxNativeFontInfo::GetStyle() const
{
    return fa.fsSelection & FATTR_SEL_ITALIC ? wxFONTSTYLE_ITALIC : wxFONTSTYLE_NORMAL;
} // end of wxNativeFontInfo::GetStyle

wxFontWeight wxNativeFontInfo::GetWeight() const
{
    switch(fn.usWeightClass)
    {
        case FWEIGHT_DONT_CARE:
            return wxFONTWEIGHT_NORMAL;

        case FWEIGHT_NORMAL:
            return wxFONTWEIGHT_NORMAL;

        case FWEIGHT_LIGHT:
            return wxFONTWEIGHT_LIGHT;

        case FWEIGHT_BOLD:
            return wxFONTWEIGHT_BOLD;

        case FWEIGHT_ULTRA_BOLD:
            return wxFONTWEIGHT_MAX;
    }
    return wxFONTWEIGHT_NORMAL;
} // end of wxNativeFontInfo::GetWeight

bool wxNativeFontInfo::GetUnderlined() const
{
    return ((fa.fsSelection & FATTR_SEL_UNDERSCORE) != 0);
} // end of wxNativeFontInfo::GetUnderlined

wxString wxNativeFontInfo::GetFaceName() const
{
    return (wxChar*)fm.szFacename;
} // end of wxNativeFontInfo::GetFaceName

wxFontFamily wxNativeFontInfo::GetFamily() const
{
    int                             nFamily;

    //
    // Extract family from facename
    //
    if (strcmp(fm.szFamilyname, "Times New Roman") == 0)
        nFamily = wxFONTFAMILY_ROMAN;
    else if (strcmp(fm.szFamilyname, "Times New Roman MT 30") == 0)
        nFamily = wxFONTFAMILY_ROMAN;
    else if (strcmp(fm.szFamilyname, "@Times New Roman MT 30") == 0)
        nFamily = wxFONTFAMILY_ROMAN;
    else if (strcmp(fm.szFamilyname, "Tms Rmn") == 0)
        nFamily = wxFONTFAMILY_ROMAN;
    else if (strcmp(fm.szFamilyname, "WarpSans") == 0)
        nFamily = wxFONTFAMILY_DECORATIVE;
    else if (strcmp(fm.szFamilyname, "Helvetica") == 0)
        nFamily = wxFONTFAMILY_SWISS;
    else if (strcmp(fm.szFamilyname, "Helv") == 0)
        nFamily = wxFONTFAMILY_SWISS;
    else if (strcmp(fm.szFamilyname, "Script") == 0)
        nFamily = wxFONTFAMILY_SCRIPT;
    else if (strcmp(fm.szFamilyname, "Courier New") == 0)
        nFamily = wxFONTFAMILY_TELETYPE;
    else if (strcmp(fm.szFamilyname, "Courier") == 0)
        nFamily = wxFONTFAMILY_TELETYPE;
    else if (strcmp(fm.szFamilyname, "System Monospaced") == 0)
        nFamily = wxFONTFAMILY_TELETYPE;
    else if (strcmp(fm.szFamilyname, "System VIO") == 0)
        nFamily = wxFONTFAMILY_MODERN;
    else if (strcmp(fm.szFamilyname, "System Proportional") == 0)
        nFamily = wxFONTFAMILY_MODERN;
    else if (strcmp(fm.szFamilyname, "Arial") == 0)
        nFamily = wxFONTFAMILY_SWISS;
    else if (strcmp(fm.szFamilyname, "Swiss") == 0)
        nFamily = wxFONTFAMILY_SWISS;
    else
        nFamily = wxFONTFAMILY_SWISS;
    return (wxFontFamily)nFamily;
} // end of wxNativeFontInfo::GetFamily

wxFontEncoding wxNativeFontInfo::GetEncoding() const
{
    return wxGetFontEncFromCharSet(fa.usCodePage);
} // end of wxNativeFontInfo::GetEncoding

void wxNativeFontInfo::SetPointSize(
  int                               nPointsize
)
{
    fm.lEmHeight = (LONG)nPointsize;
} // end of wxNativeFontInfo::SetPointSize

void wxNativeFontInfo::SetStyle(
  wxFontStyle                       eStyle
)
{
    switch (eStyle)
    {
        default:
            wxFAIL_MSG( wxT("unknown font style") );
            // fall through

        case wxFONTSTYLE_NORMAL:
            break;

        case wxFONTSTYLE_ITALIC:
        case wxFONTSTYLE_SLANT:
            fa.fsSelection |= FATTR_SEL_ITALIC;
            break;
    }
} // end of wxNativeFontInfo::SetStyle

void wxNativeFontInfo::SetWeight(
  wxFontWeight                      eWeight
)
{
    switch (eWeight)
    {
        default:
            wxFAIL_MSG( wxT("unknown font weight") );
            // fall through

        case wxFONTWEIGHT_NORMAL:
            fn.usWeightClass = FWEIGHT_NORMAL;
            break;

        case wxFONTWEIGHT_LIGHT:
            fn.usWeightClass = FWEIGHT_LIGHT;
            break;

        case wxFONTWEIGHT_BOLD:
            fn.usWeightClass = FWEIGHT_BOLD;
            break;
    }
} // end of wxNativeFontInfo::SetWeight

void wxNativeFontInfo::SetUnderlined(
  bool                              bUnderlined
)
{
    if(bUnderlined)
        fa.fsSelection |= FATTR_SEL_UNDERSCORE;
} // end of wxNativeFontInfo::SetUnderlined

bool wxNativeFontInfo::SetFaceName(
  const wxString&                   sFacename
)
{
    wxStrlcpy((wxChar*)fa.szFacename, sFacename, WXSIZEOF(fa.szFacename));
    return true;
} // end of wxNativeFontInfo::SetFaceName

void wxNativeFontInfo::SetFamily(
  wxFontFamily                      eFamily
)
{
    wxString                        sFacename;

    switch (eFamily)
    {
        case wxFONTFAMILY_SCRIPT:
            sFacename = wxT("Tms Rmn");
            break;

        case wxFONTFAMILY_DECORATIVE:
            sFacename = wxT("WarpSans");
            break;

        case wxFONTFAMILY_ROMAN:
            sFacename = wxT("Tms Rmn");
            break;

        case wxFONTFAMILY_TELETYPE:
            sFacename = wxT("Courier") ;
            break;

        case wxFONTFAMILY_MODERN:
            sFacename = wxT("System VIO") ;
            break;

        case wxFONTFAMILY_SWISS:
            sFacename = wxT("Helv") ;
            break;

        case wxFONTFAMILY_DEFAULT:
        default:
            sFacename = wxT("System VIO") ;
    }

    if (!wxStrlen((wxChar*)fa.szFacename) )
    {
        SetFaceName(sFacename);
    }
} // end of wxNativeFontInfo::SetFamily

void wxNativeFontInfo::SetEncoding( wxFontEncoding eEncoding )
{
    wxNativeEncodingInfo            vInfo;

    if ( !wxGetNativeFontEncoding( eEncoding
                                  ,&vInfo
                                 ))
    {
        if (wxFontMapper::Get()->GetAltForEncoding( eEncoding
                                               ,&vInfo
                                              ))
        {
            if (!vInfo.facename.empty())
            {
                //
                // If we have this encoding only in some particular facename, use
                // the facename - it is better to show the correct characters in a
                // wrong facename than unreadable text in a correct one
                //
                SetFaceName(vInfo.facename);
            }
        }
        else
        {
            // unsupported encoding, replace with the default
            vInfo.charset = 850;
        }
    }
    fa.usCodePage = (USHORT)vInfo.charset;
} // end of wxNativeFontInfo::SetFaceName

bool wxNativeFontInfo::FromString( const wxString& rsStr )
{
    long                            lVal;

    wxStringTokenizer               vTokenizer(rsStr, wxT(";"));

    //
    // First the version
    //
    wxString                        sToken = vTokenizer.GetNextToken();

    if (sToken != wxT('0'))
        return false;

    sToken = vTokenizer.GetNextToken();
    if (!sToken.ToLong(&lVal))
        return false;
    fm.lEmHeight = lVal;

    sToken = vTokenizer.GetNextToken();
    if (!sToken.ToLong(&lVal))
        return false;
    fa.lAveCharWidth = lVal;

    sToken = vTokenizer.GetNextToken();
    if (!sToken.ToLong(&lVal))
        return false;
    fa.fsSelection = (USHORT)lVal;

    sToken = vTokenizer.GetNextToken();
    if (!sToken.ToLong(&lVal))
        return false;
    fa.fsType = (USHORT)lVal;

    sToken = vTokenizer.GetNextToken();
    if (!sToken.ToLong(&lVal))
        return false;
    fa.fsFontUse = (USHORT)lVal;

    sToken = vTokenizer.GetNextToken();
    if (!sToken.ToLong(&lVal))
        return false;
    fa.idRegistry = (USHORT)lVal;

    sToken = vTokenizer.GetNextToken();
    if (!sToken.ToLong(&lVal))
        return false;
    fa.usCodePage = (USHORT)lVal;

    sToken = vTokenizer.GetNextToken();
    if (!sToken.ToLong(&lVal))
        return false;
    fa.lMatch = lVal;

    sToken = vTokenizer.GetNextToken();
    if (!sToken.ToLong(&lVal))
        return false;
    fn.usWeightClass = (USHORT)lVal;

    sToken = vTokenizer.GetNextToken();
    if(!sToken)
        return false;
    wxStrcpy((wxChar*)fa.szFacename, sToken.c_str());
    return true;
} // end of wxNativeFontInfo::FromString

wxString wxNativeFontInfo::ToString() const
{
    wxString sStr;

    sStr.Printf(wxT("%d;%ld;%ld;%ld;%d;%d;%d;%d;%d;%ld;%d;%s"),
                0, // version, in case we want to change the format later
                fm.lEmHeight,
                fa.lAveCharWidth,
                fa.lMaxBaselineExt,
                fa.fsSelection,
                fa.fsType,
                fa.fsFontUse,
                fa.idRegistry,
                fa.usCodePage,
                fa.lMatch,
                fn.usWeightClass,
                (char *)fa.szFacename);
    return sStr;
} // end of wxNativeFontInfo::ToString

// ----------------------------------------------------------------------------
// wxFont
// ----------------------------------------------------------------------------

bool wxFont::Create( const wxNativeFontInfo& rInfo,
                     WXHFONT hFont )
{
    UnRef();
    m_refData = new wxFontRefData( rInfo
                                  ,hFont
                                 );
    RealizeResource();
    return true;
} // end of wxFont::Create

wxFont::wxFont(
  const wxString&                   rsFontdesc
)
{
    wxNativeFontInfo                vInfo;

    if (vInfo.FromString(rsFontdesc))
        (void)Create(vInfo);
} // end of wxFont::wxFont

// ----------------------------------------------------------------------------
// Constructor for a font. Note that the real construction is done
// in wxDC::SetFont, when information is available about scaling etc.
// ----------------------------------------------------------------------------
bool wxFont::Create( int             nPointSize,
                     wxFontFamily nFamily,
                     wxFontStyle nStyle,
                     wxFontWeight nWeight,
                     bool            bUnderlined,
                     const wxString& rsFaceName,
                     wxFontEncoding  vEncoding )
{
    UnRef();

    //
    // wxDEFAULT is a valid value for the font size too so we must treat it
    // specially here (otherwise the size would be 70 == wxDEFAULT value)
    //
    if (nPointSize == wxDEFAULT)
    {
        nPointSize = wxNORMAL_FONT->GetPointSize();
    }
    m_refData = new wxFontRefData( nPointSize
                                  ,nFamily
                                  ,nStyle
                                  ,nWeight
                                  ,bUnderlined
                                  ,rsFaceName
                                  ,vEncoding
                                 );
    RealizeResource();
    return true;
} // end of wxFont::Create

wxFont::~wxFont()
{
} // end of wxFont::~wxFont

// ----------------------------------------------------------------------------
// real implementation
// Boris' Kovalenko comments:
//   Because OS/2 fonts are associated with PS we can not create the font
//   here, but we may check that font definition is true
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
    if ( GetResourceHandle() )
    {
        return true;
    }
    return M_FONTDATA->Alloc(this);
} // end of wxFont::RealizeResource

bool wxFont::FreeResource( bool WXUNUSED(bForce) )
{
    if (GetResourceHandle())
    {
        M_FONTDATA->Free();
        return true;
    }
    return false;
} // end of wxFont::FreeResource

WXHANDLE wxFont::GetResourceHandle() const
{
    return GetHFONT();
} // end of wxFont::GetResourceHandle

WXHFONT wxFont::GetHFONT() const
{
    return M_FONTDATA ? M_FONTDATA->GetHFONT() : 0;
} // end of wxFont::GetHFONT

bool wxFont::IsFree() const
{
    return M_FONTDATA && (M_FONTDATA->GetHFONT() == 0);
} // end of wxFont::IsFree

// ----------------------------------------------------------------------------
// change font attribute: we recreate font when doing it
// ----------------------------------------------------------------------------

void wxFont::SetPointSize(
  int                               nPointSize
)
{
    AllocExclusive();

    M_FONTDATA->SetPointSize(nPointSize);

    RealizeResource();
} // end of wxFont::SetPointSize

void wxFont::SetFamily(
  wxFontFamily                      nFamily
)
{
    AllocExclusive();

    M_FONTDATA->SetFamily(nFamily);

    RealizeResource();
} // end of wxFont::SetFamily

void wxFont::SetStyle(
  wxFontStyle                       nStyle
)
{
    AllocExclusive();

    M_FONTDATA->SetStyle(nStyle);

    RealizeResource();
} // end of wxFont::SetStyle

void wxFont::SetWeight(
  wxFontWeight                      nWeight
)
{
    AllocExclusive();

    M_FONTDATA->SetWeight(nWeight);

    RealizeResource();
} // end of wxFont::SetWeight

bool wxFont::SetFaceName(
  const wxString&                   rsFaceName
)
{
    AllocExclusive();

    bool refdataok = M_FONTDATA->SetFaceName(rsFaceName);

    RealizeResource();

    return refdataok && wxFontBase::SetFaceName(rsFaceName);
} // end of wxFont::SetFaceName

void wxFont::SetUnderlined(
  bool                              bUnderlined
)
{
    AllocExclusive();

    M_FONTDATA->SetUnderlined(bUnderlined);

    RealizeResource();
} // end of wxFont::SetUnderlined

void wxFont::SetEncoding(
  wxFontEncoding                    vEncoding
)
{
    AllocExclusive();

    M_FONTDATA->SetEncoding(vEncoding);

    RealizeResource();
} // end of wxFont::SetEncoding

void wxFont::DoSetNativeFontInfo(
  const wxNativeFontInfo&           rInfo
)
{
    AllocExclusive();

    FreeResource();

    *M_FONTDATA = wxFontRefData(rInfo);

    RealizeResource();
}

// ----------------------------------------------------------------------------
// accessors
// ----------------------------------------------------------------------------

int wxFont::GetPointSize() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid font") );

    return M_FONTDATA->GetPointSize();
} // end of wxFont::GetPointSize

wxFontFamily wxFont::GetFamily() const
{
    wxCHECK_MSG( Ok(), wxFONTFAMILY_MAX, wxT("invalid font") );

    return M_FONTDATA->GetFamily();
} // end of wxFont::GetFamily

wxFontStyle wxFont::GetStyle() const
{
    wxCHECK_MSG( Ok(), wxFONTSTYLE_MAX, wxT("invalid font") );

    return M_FONTDATA->GetStyle();
} // end of wxFont::GetStyle

wxFontWeight wxFont::GetWeight() const
{
    wxCHECK_MSG( Ok(), wxFONTWEIGHT_MAX, wxT("invalid font") );

    return M_FONTDATA->GetWeight();
}

bool wxFont::GetUnderlined() const
{
    wxCHECK_MSG( Ok(), false, wxT("invalid font") );

    return M_FONTDATA->GetUnderlined();
} // end of wxFont::GetUnderlined

wxString wxFont::GetFaceName() const
{
    wxCHECK_MSG( Ok(), wxEmptyString, wxT("invalid font") );

    return M_FONTDATA->GetFaceName();
} // end of wxFont::GetFaceName

wxFontEncoding wxFont::GetEncoding() const
{
    wxCHECK_MSG( Ok(), wxFONTENCODING_DEFAULT, wxT("invalid font") );

    return M_FONTDATA->GetEncoding();
} // end of wxFont::GetEncoding

const wxNativeFontInfo* wxFont::GetNativeFontInfo() const
{
    return M_FONTDATA->HasNativeFontInfo() ? &(M_FONTDATA->GetNativeFontInfo())
                                           : NULL;
} // end of wxFont::GetNativeFontInfo

//
// Internal use only method to set the FONTMETRICS array
//
void wxFont::SetFM( PFONTMETRICS pFM, int nNumFonts )
{
    M_FONTDATA->SetFM(pFM);
    M_FONTDATA->SetNumFonts(nNumFonts);
} // end of wxFont::SetFM


void wxFont::SetPS( HPS hPS )
{
    AllocExclusive();

    M_FONTDATA->SetPS(hPS);

    RealizeResource();
} // end of wxFont::SetPS
