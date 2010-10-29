/////////////////////////////////////////////////////////////////////////////
// Name:        src/common/cmndata.cpp
// Purpose:     Common GDI data
// Author:      Julian Smart
// Modified by:
// Created:     01/02/97
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

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/cmndata.h"

#ifndef WX_PRECOMP
    #if defined(__WXMSW__)
        #include "wx/msw/wrapcdlg.h"
    #endif // MSW
    #include <stdio.h>
    #include "wx/string.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/log.h"
    #include "wx/gdicmn.h"
#endif

#include "wx/tokenzr.h"
#include "wx/prntbase.h"
#include "wx/printdlg.h"

#if wxUSE_FONTDLG
    #include "wx/fontdlg.h"
#endif // wxUSE_FONTDLG

#if wxUSE_PRINTING_ARCHITECTURE

#include "wx/paper.h"


IMPLEMENT_DYNAMIC_CLASS(wxPrintData, wxObject)
IMPLEMENT_DYNAMIC_CLASS(wxPrintDialogData, wxObject)
IMPLEMENT_DYNAMIC_CLASS(wxPageSetupDialogData, wxObject)

#endif // wxUSE_PRINTING_ARCHITECTURE

IMPLEMENT_DYNAMIC_CLASS(wxFontData, wxObject)
IMPLEMENT_DYNAMIC_CLASS(wxColourData, wxObject)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxColourData
// ----------------------------------------------------------------------------

wxColourData::wxColourData()
{
    m_chooseFull = false;
    m_dataColour.Set(0,0,0);
    // m_custColours are wxNullColours initially
}

wxColourData::wxColourData(const wxColourData& data)
            : wxObject()
{
    (*this) = data;
}

wxColourData::~wxColourData()
{
}

void wxColourData::SetCustomColour(int i, const wxColour& colour)
{
    wxCHECK_RET( i >= 0 && i < NUM_CUSTOM, wxT("custom colour index out of range") );

    m_custColours[i] = colour;
}

wxColour wxColourData::GetCustomColour(int i) const
{
    wxCHECK_MSG( i >= 0 && i < NUM_CUSTOM, wxColour(0,0,0),
                 wxT("custom colour index out of range") );

    return m_custColours[i];
}

wxColourData& wxColourData::operator=(const wxColourData& data)
{
    for ( int i = 0; i < NUM_CUSTOM; i++)
        m_custColours[i] = data.m_custColours[i];

    m_dataColour = data.m_dataColour;
    m_chooseFull = data.m_chooseFull;

    return *this;
}

// ----------------------------------------------------------------------------
// [de]serialization
// ----------------------------------------------------------------------------

// separator used between different fields
static const char wxCOL_DATA_SEP = ',';

wxString wxColourData::ToString() const
{
    wxString str(m_chooseFull ? '1' : '0');

    for ( int i = 0; i < NUM_CUSTOM; i++ )
    {
        str += wxCOL_DATA_SEP;

        const wxColour& clr = m_custColours[i];
        if ( clr.IsOk() )
            str += clr.GetAsString(wxC2S_HTML_SYNTAX);
    }

    return str;
}

bool wxColourData::FromString(const wxString& str)
{
    wxStringTokenizer tokenizer(str, wxCOL_DATA_SEP);
    wxString token = tokenizer.GetNextToken();
    m_chooseFull = token == '1';
    bool success = m_chooseFull || token == '0';
    for (int i = 0; success && i < NUM_CUSTOM; i++)
    {
        token = tokenizer.GetNextToken();
        if (token.empty())
            m_custColours[i] = wxNullColour;
        else
            success = m_custColours[i].Set(token);
    }
    return success;
}

// ----------------------------------------------------------------------------
// Font data
// ----------------------------------------------------------------------------

wxFontData::wxFontData()
{
    // Intialize colour to black.
    m_fontColour = wxNullColour;

    m_showHelp = false;
    m_allowSymbols = true;
    m_enableEffects = true;
    m_minSize = 0;
    m_maxSize = 0;

    m_encoding = wxFONTENCODING_SYSTEM;
}

wxFontData::~wxFontData()
{
}

#if wxUSE_FONTDLG

wxFontDialogBase::~wxFontDialogBase()
{
}

#endif // wxUSE_FONTDLG

#if wxUSE_PRINTING_ARCHITECTURE
// ----------------------------------------------------------------------------
// Print data
// ----------------------------------------------------------------------------

wxPrintData::wxPrintData()
{
    m_bin = wxPRINTBIN_DEFAULT;
    m_media = wxPRINTMEDIA_DEFAULT;
    m_printMode = wxPRINT_MODE_PRINTER;
    m_printOrientation = wxPORTRAIT;
    m_printOrientationReversed = false;
    m_printNoCopies = 1;
    m_printCollate = false;

    // New, 24/3/99
    m_printerName = wxEmptyString;
    m_colour = true;
    m_duplexMode = wxDUPLEX_SIMPLEX;
    m_printQuality = wxPRINT_QUALITY_HIGH;

    // we intentionally don't initialize paper id and size at all, like this
    // the default system settings will be used for them
    m_paperId = wxPAPER_NONE;
    m_paperSize = wxDefaultSize;

    m_privData = NULL;
    m_privDataLen = 0;

    m_nativeData = wxPrintFactory::GetFactory()->CreatePrintNativeData();
}

wxPrintData::wxPrintData(const wxPrintData& printData)
    : wxObject()
{
    m_nativeData = NULL;
    m_privData = NULL;
    (*this) = printData;
}

void wxPrintData::SetPrivData( char *privData, int len )
{
    wxDELETEA(m_privData);
    m_privDataLen = len;
    if (m_privDataLen > 0)
    {
        m_privData = new char[m_privDataLen];
        memcpy( m_privData, privData, m_privDataLen );
    }
}

wxPrintData::~wxPrintData()
{
    m_nativeData->m_ref--;
    if (m_nativeData->m_ref == 0)
        delete m_nativeData;

    if (m_privData)
        delete [] m_privData;
}

void wxPrintData::ConvertToNative()
{
    m_nativeData->TransferFrom( *this ) ;
}

void wxPrintData::ConvertFromNative()
{
    m_nativeData->TransferTo( *this ) ;
}

wxPrintData& wxPrintData::operator=(const wxPrintData& data)
{
    if ( &data == this )
        return *this;

    m_printNoCopies = data.m_printNoCopies;
    m_printCollate = data.m_printCollate;
    m_printOrientation = data.m_printOrientation;
    m_printOrientationReversed = data.m_printOrientationReversed;
    m_printerName = data.m_printerName;
    m_colour = data.m_colour;
    m_duplexMode = data.m_duplexMode;
    m_printQuality = data.m_printQuality;
    m_paperId = data.m_paperId;
    m_paperSize = data.m_paperSize;
    m_bin = data.m_bin;
    m_media = data.m_media;
    m_printMode = data.m_printMode;
    m_filename = data.m_filename;

    // UnRef old m_nativeData
    if (m_nativeData)
    {
        m_nativeData->m_ref--;
        if (m_nativeData->m_ref == 0)
            delete m_nativeData;
    }
    // Set Ref new one
    m_nativeData = data.GetNativeData();
    m_nativeData->m_ref++;

    wxDELETEA(m_privData);
    m_privDataLen = data.GetPrivDataLen();
    if (m_privDataLen > 0)
    {
        m_privData = new char[m_privDataLen];
        memcpy( m_privData, data.GetPrivData(), m_privDataLen );
    }

    return *this;
}

// Is this data OK for showing the print dialog?
bool wxPrintData::IsOk() const
{
    m_nativeData->TransferFrom( *this );

    return m_nativeData->Ok();
}

// ----------------------------------------------------------------------------
// Print dialog data
// ----------------------------------------------------------------------------

wxPrintDialogData::wxPrintDialogData()
{
    m_printFromPage = 0;
    m_printToPage = 0;
    m_printMinPage = 0;
    m_printMaxPage = 0;
    m_printNoCopies = 1;
    m_printAllPages = false;
    m_printCollate = false;
    m_printToFile = false;
    m_printSelection = false;
    m_printEnableSelection = false;
    m_printEnablePageNumbers = true;

    wxPrintFactory* factory = wxPrintFactory::GetFactory();
    m_printEnablePrintToFile = ! factory->HasOwnPrintToFile();

    m_printEnableHelp = false;
}

wxPrintDialogData::wxPrintDialogData(const wxPrintDialogData& dialogData)
    : wxObject()
{
    (*this) = dialogData;
}

wxPrintDialogData::wxPrintDialogData(const wxPrintData& printData)
{
    m_printFromPage = 1;
    m_printToPage = 0;
    m_printMinPage = 1;
    m_printMaxPage = 9999;
    m_printNoCopies = 1;
    // On Mac the Print dialog always defaults to "All Pages"
#ifdef __WXMAC__
    m_printAllPages = true;
#else
    m_printAllPages = false;
#endif
    m_printCollate = false;
    m_printToFile = false;
    m_printSelection = false;
    m_printEnableSelection = false;
    m_printEnablePageNumbers = true;
    m_printEnablePrintToFile = true;
    m_printEnableHelp = false;
    m_printData = printData;
}

wxPrintDialogData::~wxPrintDialogData()
{
}

void wxPrintDialogData::operator=(const wxPrintDialogData& data)
{
    m_printFromPage = data.m_printFromPage;
    m_printToPage = data.m_printToPage;
    m_printMinPage = data.m_printMinPage;
    m_printMaxPage = data.m_printMaxPage;
    m_printNoCopies = data.m_printNoCopies;
    m_printAllPages = data.m_printAllPages;
    m_printCollate = data.m_printCollate;
    m_printToFile = data.m_printToFile;
    m_printSelection = data.m_printSelection;
    m_printEnableSelection = data.m_printEnableSelection;
    m_printEnablePageNumbers = data.m_printEnablePageNumbers;
    m_printEnableHelp = data.m_printEnableHelp;
    m_printEnablePrintToFile = data.m_printEnablePrintToFile;
    m_printData = data.m_printData;
}

void wxPrintDialogData::operator=(const wxPrintData& data)
{
    m_printData = data;
}

// ----------------------------------------------------------------------------
// wxPageSetupDialogData
// ----------------------------------------------------------------------------

wxPageSetupDialogData::wxPageSetupDialogData()
{
    m_paperSize = wxSize(0,0);

    CalculatePaperSizeFromId();

    m_minMarginTopLeft =
    m_minMarginBottomRight =
    m_marginTopLeft =
    m_marginBottomRight = wxPoint(0,0);

    // Flags
    m_defaultMinMargins = false;
    m_enableMargins = true;
    m_enableOrientation = true;
    m_enablePaper = true;
    m_enablePrinter = true;
    m_enableHelp = false;
    m_getDefaultInfo = false;
}

wxPageSetupDialogData::wxPageSetupDialogData(const wxPageSetupDialogData& dialogData)
    : wxObject()
{
    (*this) = dialogData;
}

wxPageSetupDialogData::wxPageSetupDialogData(const wxPrintData& printData)
{
    m_paperSize = wxSize(0,0);
    m_minMarginTopLeft =
    m_minMarginBottomRight =
    m_marginTopLeft =
    m_marginBottomRight = wxPoint(0,0);

    // Flags
    m_defaultMinMargins = false;
    m_enableMargins = true;
    m_enableOrientation = true;
    m_enablePaper = true;
    m_enablePrinter = true;
    m_enableHelp = false;
    m_getDefaultInfo = false;

    m_printData = printData;

    // The wxPrintData paper size overrides these values, unless the size cannot
    // be found.
    CalculatePaperSizeFromId();
}

wxPageSetupDialogData::~wxPageSetupDialogData()
{
}

wxPageSetupDialogData& wxPageSetupDialogData::operator=(const wxPageSetupDialogData& data)
{
    m_paperSize = data.m_paperSize;
    m_minMarginTopLeft = data.m_minMarginTopLeft;
    m_minMarginBottomRight = data.m_minMarginBottomRight;
    m_marginTopLeft = data.m_marginTopLeft;
    m_marginBottomRight = data.m_marginBottomRight;
    m_defaultMinMargins = data.m_defaultMinMargins;
    m_enableMargins = data.m_enableMargins;
    m_enableOrientation = data.m_enableOrientation;
    m_enablePaper = data.m_enablePaper;
    m_enablePrinter = data.m_enablePrinter;
    m_getDefaultInfo = data.m_getDefaultInfo;
    m_enableHelp = data.m_enableHelp;

    m_printData = data.m_printData;

    return *this;
}

wxPageSetupDialogData& wxPageSetupDialogData::operator=(const wxPrintData& data)
{
    m_printData = data;
    CalculatePaperSizeFromId();

    return *this;
}

// If a corresponding paper type is found in the paper database, will set the m_printData
// paper size id member as well.
void wxPageSetupDialogData::SetPaperSize(const wxSize& sz)
{
    m_paperSize = sz;

    CalculateIdFromPaperSize();
}

// Sets the wxPrintData id, plus the paper width/height if found in the paper database.
void wxPageSetupDialogData::SetPaperSize(wxPaperSize id)
{
    m_printData.SetPaperId(id);

    CalculatePaperSizeFromId();
}

void wxPageSetupDialogData::SetPrintData(const wxPrintData& printData)
{
    m_printData = printData;
    CalculatePaperSizeFromId();
}

// Use paper size defined in this object to set the wxPrintData
// paper id
void wxPageSetupDialogData::CalculateIdFromPaperSize()
{
    wxASSERT_MSG( (wxThePrintPaperDatabase != NULL),
                  wxT("wxThePrintPaperDatabase should not be NULL. Do not create global print dialog data objects.") );

    wxSize sz = GetPaperSize();

    wxPaperSize id = wxThePrintPaperDatabase->GetSize(wxSize(sz.x* 10, sz.y * 10));
    if (id != wxPAPER_NONE)
    {
        m_printData.SetPaperId(id);
    }
}

// Use paper id in wxPrintData to set this object's paper size
void wxPageSetupDialogData::CalculatePaperSizeFromId()
{
    wxASSERT_MSG( (wxThePrintPaperDatabase != NULL),
                  wxT("wxThePrintPaperDatabase should not be NULL. Do not create global print dialog data objects.") );

    wxSize sz = wxThePrintPaperDatabase->GetSize(m_printData.GetPaperId());

    if (sz != wxSize(0, 0))
    {
        // sz is in 10ths of a mm, while paper size is in mm
        m_paperSize.x = sz.x / 10;
        m_paperSize.y = sz.y / 10;
    }
}

#endif // wxUSE_PRINTING_ARCHITECTURE
