///////////////////////////////////////////////////////////////////////////////
// Name:        msw/fontutil.cpp
// Purpose:     font-related helper functions for wxMSW
// Author:      Modified by David Webster for OS/2
// Modified by:
// Created:     01.03.00
// RCS-ID:      $Id$
// Copyright:   (c) 1999 Vadim Zeitlin <zeitlin@dptmaths.ens-cachan.fr>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#define DEBUG_PRINTF(NAME)                            \
    {                                                 \
        static int raz=0;                             \
        printf( #NAME " %i\n",raz); fflush(stdout);   \
        raz++;                                        \
    }

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/string.h"
    #include "wx/log.h"
    #include "wx/intl.h"
#endif //WX_PRECOMP

#include "wx/os2/private.h"

#include "wx/fontutil.h"
#include "wx/fontmap.h"
#include "wx/encinfo.h"

#include "wx/tokenzr.h"

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxNativeEncodingInfo
// ----------------------------------------------------------------------------

// convert to/from the string representation: format is
//      encodingid;facename[;charset]

bool wxNativeEncodingInfo::FromString( const wxString& rsStr )
{
    wxStringTokenizer               vTokenizer(rsStr, wxT(";"));
    wxString                        sEncid = vTokenizer.GetNextToken();
    long                            lEnc;

    if (!sEncid.ToLong(&lEnc))
        return FALSE;
    encoding = (wxFontEncoding)lEnc;
    facename = vTokenizer.GetNextToken();
    if (!facename)
        return FALSE;

    wxString                        sTmp = vTokenizer.GetNextToken();

    if (!sTmp)
    {
        charset = 850;
    }
    else
    {
        if ( wxSscanf(sTmp, wxT("%u"), &charset) != 1 )
        {
            // should be a number!
            return FALSE;
        }
    }
    return true;
} // end of wxNativeEncodingInfo::FromString

wxString wxNativeEncodingInfo::ToString() const
{
    wxString                        sStr;

    sStr << (long)encoding << wxT(';') << facename;

    if (charset != 850)
    {
        sStr << wxT(';') << charset;
    }
    return sStr;
} // end of wxNativeEncodingInfo::ToString

// ----------------------------------------------------------------------------
// helper functions
// ----------------------------------------------------------------------------

bool wxGetNativeFontEncoding( wxFontEncoding vEncoding,
                              wxNativeEncodingInfo* pInfo )
{
    wxCHECK_MSG(pInfo, FALSE, wxT("bad pointer in wxGetNativeFontEncoding") );
    if (vEncoding == wxFONTENCODING_DEFAULT)
    {
        vEncoding = wxFont::GetDefaultEncoding();
    }
    switch (vEncoding)
    {
        case wxFONTENCODING_ISO8859_1:
        case wxFONTENCODING_ISO8859_15:
        case wxFONTENCODING_CP1250:
            pInfo->charset = 1250;
            break;

        case wxFONTENCODING_ISO8859_2:
        case wxFONTENCODING_CP1252:
            pInfo->charset = 1252;
            break;

        case wxFONTENCODING_ISO8859_4:
        case wxFONTENCODING_ISO8859_10:
            pInfo->charset = 921; // what is baltic?
            break;

        case wxFONTENCODING_ISO8859_5:
        case wxFONTENCODING_CP1251:
            pInfo->charset = 1251;
            break;

        case wxFONTENCODING_ISO8859_6:
            pInfo->charset = 864;
            break;

        case wxFONTENCODING_ISO8859_7:
            pInfo->charset = 869;
            break;

        case wxFONTENCODING_ISO8859_8:
            pInfo->charset = 862;
            break;

        case wxFONTENCODING_ISO8859_9:
            pInfo->charset = 857;
            break;

        case wxFONTENCODING_ISO8859_11:
            pInfo->charset = 874; // what is thai
            break;

        case wxFONTENCODING_CP437:
            pInfo->charset = 437;
            break;

        default:
            wxFAIL_MSG(wxT("unsupported encoding"));
            // fall through

        case wxFONTENCODING_SYSTEM:
            pInfo->charset = 850;
            break;
    }
    return true;
} // end of wxGetNativeFontEncoding

wxFontEncoding wxGetFontEncFromCharSet(
  int                               nCharSet
)
{
    wxFontEncoding                  eFontEncoding;

    switch (nCharSet)
    {
        default:
        case 1250:
            eFontEncoding = wxFONTENCODING_CP1250;
            break;

        case 1252:
            eFontEncoding = wxFONTENCODING_CP1252;
            break;

        case 921:
            eFontEncoding = wxFONTENCODING_ISO8859_4;
            break;

        case 1251:
            eFontEncoding = wxFONTENCODING_CP1251;
            break;

        case 864:
            eFontEncoding = wxFONTENCODING_ISO8859_6;
            break;

        case 869:
            eFontEncoding = wxFONTENCODING_ISO8859_7;
            break;

        case 862:
            eFontEncoding = wxFONTENCODING_ISO8859_8;
            break;

        case 857:
            eFontEncoding = wxFONTENCODING_ISO8859_9;
            break;

        case 874:
            eFontEncoding = wxFONTENCODING_ISO8859_11;
            break;

        case 437:
            eFontEncoding = wxFONTENCODING_CP437;
            break;
    }
    return eFontEncoding;
} // end of wxGetNativeFontEncoding

bool wxTestFontEncoding( const wxNativeEncodingInfo& rInfo )
{
    FATTRS vLogFont;
    HPS    hPS;

    hPS = ::WinGetPS(HWND_DESKTOP);

    memset(&vLogFont, '\0', sizeof(FATTRS));           // all default values
    vLogFont.usRecordLength = sizeof(FATTRS);
    vLogFont.usCodePage = (USHORT)rInfo.charset;
    vLogFont.lMaxBaselineExt = 0L;                    // Outline fonts should use 0
    vLogFont.lAveCharWidth = 0L;                      // Outline fonts should use 0
    vLogFont.fsFontUse = FATTR_FONTUSE_OUTLINE |      // only outline fonts allowed
                         FATTR_FONTUSE_TRANSFORMABLE; // may be transformed

    wxStrlcpy((wxChar*)vLogFont.szFacename, rInfo.facename.c_str(), WXSIZEOF(vLogFont.szFacename));

    if (!::GpiCreateLogFont( hPS
                            ,NULL
                            ,1L
                            ,&vLogFont
                           ))
    {
        ::WinReleasePS(hPS);
        return FALSE;
    }
    ::WinReleasePS(hPS);
    return true;
} // end of wxTestFontEncoding

// ----------------------------------------------------------------------------
// wxFont <-> LOGFONT conversion
// ----------------------------------------------------------------------------

void wxConvertVectorFontSize(
  FIXED                             fxPointSize
, PFATTRS                           pFattrs
)
{
    HPS                             hPS;
    HDC                             hDC;
    LONG                            lXFontResolution;
    LONG                            lYFontResolution;
    SIZEF                           vSizef;

    hPS = WinGetScreenPS(HWND_DESKTOP); // Screen presentation space

    //
    //   Query device context for the screen and then query
    //   the resolution of the device for the device context.
    //

    hDC = GpiQueryDevice(hPS);
    DevQueryCaps( hDC, CAPS_HORIZONTAL_FONT_RES, (LONG)1, &lXFontResolution);
    DevQueryCaps( hDC, CAPS_VERTICAL_FONT_RES, (LONG)1, &lYFontResolution);

    //
    //   Calculate the size of the character box, based on the
    //   point size selected and the resolution of the device.
    //   The size parameters are of type FIXED, NOT int.
    //   NOTE: 1 point == 1/72 of an inch.
    //

    // multiply first to avoid getting vSizef.cx,cy = 0 since fxPointSize
    // is normally < 72 and FontResolution is typically ca. 100
    vSizef.cx = (FIXED)( (fxPointSize * lXFontResolution) / 72 );
    vSizef.cy = (FIXED)( (fxPointSize * lYFontResolution) / 72 );

    if (pFattrs)
    {
        pFattrs->lMaxBaselineExt = MAKELONG( HIUSHORT( vSizef.cy ), 0 );
        pFattrs->lAveCharWidth   = MAKELONG( HIUSHORT( vSizef.cx ), 0 );
    }
    WinReleasePS(hPS);

} // end of wxConvertVectorPointSize

void wxFillLogFont( LOGFONT*      pFattrs,  // OS2 GPI FATTRS
                    PFACENAMEDESC pFaceName,
                    HPS*          phPS,
                    bool*         pbInternalPS,
                    long*         pflId,
                    wxString&     sFaceName,
                    wxFont*       pFont )
{
    LONG         lNumFonts = 0L;       // For system font count
    ERRORID      vError;               // For logging API errors
    LONG         lTemp = 0L;
    bool         bInternalPS = false;  // if we have to create one
    PFONTMETRICS pFM = NULL;

    //
    // Initial house cleaning to free data buffers and ensure we have a
    // functional PS to work with
    //
    if (!*phPS)
    {
        *phPS = ::WinGetPS(HWND_DESKTOP);
        bInternalPS = true;
    }

    //
    // Determine the number of fonts.
    //
    if((lNumFonts = ::GpiQueryFonts( *phPS
                                    ,QF_PUBLIC | QF_PRIVATE
                                    ,NULL
                                    ,&lTemp
                                    ,(LONG) sizeof(FONTMETRICS)
                                    ,NULL
                                   )) < 0L)
    {
        ERRORID                     vError;
        wxString                    sError;

        vError = ::WinGetLastError(wxGetInstance());
        sError = wxPMErrorToStr(vError);
        return;
    }

    //
    // Allocate space for the font metrics.
    //
    pFM = new FONTMETRICS[lNumFonts + 1];

    //
    // Retrieve the font metrics.
    //
    lTemp = lNumFonts;
    lTemp = ::GpiQueryFonts( *phPS
                            ,QF_PUBLIC
                            ,NULL
                            ,&lTemp
                            ,(LONG) sizeof(FONTMETRICS)
                            ,pFM
                           );
    pFont->SetFM( pFM
                 ,(int)lNumFonts
                );

    //
    // Initialize FATTR and FACENAMEDESC
    //
    pFattrs->usRecordLength = sizeof(FATTRS);
    pFattrs->fsFontUse = FATTR_FONTUSE_OUTLINE;       // only outline fonts allowed
    pFattrs->fsType = 0;
    pFattrs->lMaxBaselineExt = pFattrs->lAveCharWidth = 0;
    pFattrs->idRegistry = 0;
    pFattrs->lMatch = 0;

    pFaceName->usSize = sizeof(FACENAMEDESC);
    pFaceName->usWeightClass = FWEIGHT_DONT_CARE;
    pFaceName->usWidthClass = FWIDTH_DONT_CARE;
    pFaceName->usReserved = 0;
    pFaceName->flOptions = 0;

    //
    // This does the actual selection of fonts
    //
    wxOS2SelectMatchingFontByName( pFattrs
                                  ,pFaceName
                                  ,pFM
                                  ,(int)lNumFonts
                                  ,pFont
                                 );
    //
    // We should now have the correct FATTRS set with the selected
    // font, so now we need to generate an ID
    //
    long                            lNumLids = ::GpiQueryNumberSetIds(*phPS);

    if(lNumLids )
    {
        long                        alTypes[255];
        STR8                        azNames[255];
        long                        alIds[255];

        memset(alIds, 0, sizeof(long) * 255);
        if(!::GpiQuerySetIds( *phPS
                             ,lNumLids
                             ,alTypes
                             ,azNames
                             ,alIds
                            ))
        {
            if (bInternalPS)
                ::WinReleasePS(*phPS);
            return;
        }
        if (*pflId == 0L)
            *pflId = 1L;
        for(unsigned long LCNum = 0; LCNum < (unsigned long)lNumLids; LCNum++)
            if(alIds[LCNum] == *pflId)
               ++*pflId;
        if(*pflId > 254)  // wow, no id available!
        {
            if (bInternalPS)
               ::WinReleasePS(*phPS);
           return;
        }
    }
    else
        *pflId = 1L;
    //
    // Release and delete the current font
    //
    ::GpiSetCharSet(*phPS, LCID_DEFAULT);/* release the font before deleting */
    ::GpiDeleteSetId(*phPS, 1L);         /* delete the logical font          */

    //
    // Now build a facestring
    //
    char                            zFacename[128];

    strcpy(zFacename, pFattrs->szFacename);

    if(::GpiQueryFaceString( *phPS
                            ,zFacename
                            ,pFaceName
                            ,FACESIZE
                            ,pFattrs->szFacename
                           ) == GPI_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
    }
    sFaceName = (wxChar*)zFacename;
    *pbInternalPS = bInternalPS;

    //
    // That's it, we now have everything we need to actually create the font
    //
} // end of wxFillLogFont

void wxOS2SelectMatchingFontByName(
  PFATTRS                           pFattrs
, PFACENAMEDESC                     pFaceName
, PFONTMETRICS                      pFM
, int                               nNumFonts
, const wxFont*                     pFont
)
{
    int                             i;
    int                             nPointSize;
    int                             nIs;
    int                             nMinDiff0;
    int                             anDiff[16];
    int                             anMinDiff[16];
    int                             nIndex = 0;
    wxChar                          zFontFaceName[FACESIZE];
    wxString                        sFaceName;
    USHORT                          usWeightClass;
    int                             fsSelection = 0;

    nMinDiff0 = 0xf000;
    for(i = 0;i < 16; i++)
        anMinDiff[i] = nMinDiff0;

    switch (pFont->GetFamily())
    {
        case wxSCRIPT:
            sFaceName = wxT("Tms Rmn");
            break;

        case wxDECORATIVE:
            sFaceName = wxT("WarpSans");
            break;

        case wxROMAN:
            sFaceName = wxT("Tms Rmn");
            break;

        case wxTELETYPE:
            sFaceName = wxT("Courier") ;
            break;

        case wxMODERN:
            sFaceName = wxT("System VIO") ;
            break;

        case wxSWISS:
            sFaceName = wxT("Helv") ;
            break;

        case wxDEFAULT:
        default:
            sFaceName = wxT("System VIO") ;
    }

    switch (pFont->GetWeight())
    {
        default:
            wxFAIL_MSG(wxT("unknown font weight"));
            // fall through
            usWeightClass = FWEIGHT_DONT_CARE;
            break;

        case wxNORMAL:
            usWeightClass = FWEIGHT_NORMAL;
            break;

        case wxLIGHT:
            usWeightClass = FWEIGHT_LIGHT;
            break;

        case wxBOLD:
            usWeightClass = FWEIGHT_BOLD;
            break;

         case wxFONTWEIGHT_MAX:
            usWeightClass = FWEIGHT_ULTRA_BOLD;
            break;
    }
    pFaceName->usWeightClass = usWeightClass;

    switch (pFont->GetStyle())
    {
        case wxITALIC:
        case wxSLANT:
            fsSelection = FM_SEL_ITALIC;
            pFaceName->flOptions = FTYPE_ITALIC;
            break;

        default:
            wxFAIL_MSG(wxT("unknown font slant"));
            // fall through

        case wxNORMAL:
            fsSelection  = 0;
            break;
    }

    wxStrlcpy(zFontFaceName, sFaceName.c_str(), WXSIZEOF(zFontFaceName));
    nPointSize = pFont->GetPointSize();

    //
    // Matching logic to find the right FM struct
    //
    nIndex = 0;
    for(i = 0, nIs = 0; i < nNumFonts; i++)
    {
        int                         nEmHeight = 0;
        int                         nXHeight = 0;

        anDiff[0] = wxGpiStrcmp((wxChar*)pFM[i].szFacename, zFontFaceName);
        anDiff[1] = abs(pFM[i].lEmHeight - nPointSize);
        anDiff[2] = abs(pFM[i].usWeightClass -  usWeightClass);
        anDiff[3] = abs((pFM[i].fsSelection & 0x2f) -  fsSelection);
        if(anDiff[0] == 0)
        {
            nEmHeight = (int)pFM[i].lEmHeight;
            nXHeight  =(int)pFM[i].lXHeight;
            if( (nIs & 0x01) == 0)
            {
                nIs = 1;
                nIndex = i;
                anMinDiff[1] = anDiff[1];
                anMinDiff[2] = anDiff[2];
                anMinDiff[3] = anDiff[3];
            }
            else if(anDiff[3] < anMinDiff[3])
            {
                nIndex = i;
                anMinDiff[3] = anDiff[3];
            }
            else if(anDiff[2] < anMinDiff[2])
            {
                nIndex = i;
                anMinDiff[2] = anDiff[2];
            }
            else if(anDiff[1] < anMinDiff[1])
            {
                nIndex = i;
                anMinDiff[1] = anDiff[1];
            }
            anMinDiff[0] = 0;
        }
        else if(anDiff[0] < anMinDiff[0])
        {
              nIs = 2;
              nIndex = i;
              anMinDiff[3] = anDiff[3];
              anMinDiff[2] = anDiff[2];
              anMinDiff[1] = anDiff[1];
              anMinDiff[0] = anDiff[0];
        }
        else if(anDiff[0] == anMinDiff[0])
        {
            if(anDiff[3] < anMinDiff[3])
            {
                nIndex = i;
                anMinDiff[3] = anDiff[3];
                nIs = 2;
            }
            else if(anDiff[2] < anMinDiff[2])
            {
                nIndex = i;
                anMinDiff[2] = anDiff[2];
                nIs = 2;
            }
            else if(anDiff[1] < anMinDiff[1])
            {
                nIndex = i;
                anMinDiff[1] = anDiff[1];
                nIs = 2;
            }
        }
    }

    //
    // Fill in the FATTRS with the best match from FONTMETRICS
    //
    pFattrs->usRecordLength  = sizeof(FATTRS);              // Sets size of structure
    pFattrs->lMatch          = pFM[nIndex].lMatch;          // Force match
    pFattrs->idRegistry      = 0;
    pFattrs->usCodePage      = 0;
    pFattrs->fsFontUse       = 0;
    pFattrs->fsType          = 0;
    pFattrs->lMaxBaselineExt = 0;
    pFattrs->lAveCharWidth   = 0;
    wxStrcpy((wxChar*)pFattrs->szFacename, (wxChar*)pFM[nIndex].szFacename);
    if (pFont->GetWeight() == wxNORMAL)
        pFattrs->fsSelection = 0;
    else
        pFattrs->fsSelection = FATTR_SEL_BOLD;

    if (pFont->GetStyle() == wxITALIC || pFont->GetStyle() == wxSLANT)
        pFattrs->fsSelection |= FATTR_SEL_ITALIC;

    if (pFont->GetUnderlined())
        pFattrs->fsSelection |= FATTR_SEL_UNDERSCORE;
} // end of wxOS2SelectMatchingFontByName

wxFont wxCreateFontFromLogFont(
  const LOGFONT*                    pLogFont
, const PFONTMETRICS                pFM
, PFACENAMEDESC                     pFaceName
)
{
    wxNativeFontInfo                vInfo;

    vInfo.fa = *pLogFont;
    vInfo.fm = *pFM;
    vInfo.fn = *pFaceName;
    return wxFont(vInfo);
} // end of wxCreateFontFromLogFont

int wxGpiStrcmp(
  wxChar*                           s0
, wxChar*                           s1
)
{   int                             l0;
    int                             l1;
    int                             l;
    int                             d;
    int                             d1;
    int                             i;
    int                             rc;

    rc = 0;
    if(s0 == NULL)
    {
        if(s1 == NULL)
            return 0;
        else
            return 32;
    }
    else if(s1 == NULL)
        return 32;

    l0 = wxStrlen(s0);
    l1 = wxStrlen(s1);
    l  = l0;
    if(l0 != l1)
    {
        rc++;
        if(l1 < l0)
            l = l1;
    }
    for(i=0;i<l;i++)
    {
        d = s0[i]-s1[i];
        if(!d)
            continue;
        d1 = wxToupper(s0[i]) - wxToupper(s1[i]);
        if(!d1)
            continue;
        rc += abs(d);
    }
    return rc;
}
