/////////////////////////////////////////////////////////////////////////////
// Name:        src/html/winpars.cpp
// Purpose:     wxHtmlParser class (generic parser)
// Author:      Vaclav Slavik
// RCS-ID:      $Id$
// Copyright:   (c) 1999 Vaclav Slavik
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_HTML && wxUSE_STREAMS

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/dc.h"
    #include "wx/log.h"
    #include "wx/settings.h"
#endif

#include "wx/html/htmldefs.h"
#include "wx/html/winpars.h"
#include "wx/html/htmlwin.h"
#include "wx/fontmap.h"
#include "wx/uri.h"


//-----------------------------------------------------------------------------
// wxHtmlWinParser
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxHtmlWinParser, wxHtmlParser)

wxList wxHtmlWinParser::m_Modules;

wxHtmlWinParser::wxHtmlWinParser(wxHtmlWindowInterface *wndIface)
{
    m_tmpStrBuf = NULL;
    m_tmpStrBufSize = 0;
    m_windowInterface = wndIface;
    m_Container = NULL;
    m_DC = NULL;
    m_CharHeight = m_CharWidth = 0;
    m_UseLink = false;
#if !wxUSE_UNICODE
    m_nbsp = 0;
    m_EncConv = NULL;
    m_InputEnc = wxFONTENCODING_ISO8859_1;
    m_OutputEnc = wxFONTENCODING_DEFAULT;
#endif
    m_whitespaceMode = Whitespace_Normal;
    m_lastWordCell = NULL;
    m_posColumn = 0;

    {
        int i, j, k, l, m;
        for (i = 0; i < 2; i++)
            for (j = 0; j < 2; j++)
                for (k = 0; k < 2; k++)
                    for (l = 0; l < 2; l++)
                        for (m = 0; m < 7; m++)
                        {
                            m_FontsTable[i][j][k][l][m] = NULL;
                            m_FontsFacesTable[i][j][k][l][m] = wxEmptyString;
#if !wxUSE_UNICODE
                            m_FontsEncTable[i][j][k][l][m] = wxFONTENCODING_DEFAULT;
#endif
                        }

        SetFonts(wxEmptyString, wxEmptyString, NULL);
    }

    // fill in wxHtmlParser's tables:
    wxList::compatibility_iterator node = m_Modules.GetFirst();
    while (node)
    {
        wxHtmlTagsModule *mod = (wxHtmlTagsModule*) node->GetData();
        mod->FillHandlersTable(this);
        node = node->GetNext();
    }
}

wxHtmlWinParser::~wxHtmlWinParser()
{
    int i, j, k, l, m;

    for (i = 0; i < 2; i++)
        for (j = 0; j < 2; j++)
            for (k = 0; k < 2; k++)
                for (l = 0; l < 2; l++)
                    for (m = 0; m < 7; m++)
                    {
                        if (m_FontsTable[i][j][k][l][m] != NULL)
                            delete m_FontsTable[i][j][k][l][m];
                    }
#if !wxUSE_UNICODE
    delete m_EncConv;
#endif
    delete[] m_tmpStrBuf;
}

void wxHtmlWinParser::AddModule(wxHtmlTagsModule *module)
{
    m_Modules.Append(module);
}

void wxHtmlWinParser::RemoveModule(wxHtmlTagsModule *module)
{
    m_Modules.DeleteObject(module);
}

// build all HTML font sizes (1..7) from the given base size
static void wxBuildFontSizes(int *sizes, int size)
{
    // using a fixed factor (1.2, from CSS2) is a bad idea as explained at
    // http://www.w3.org/TR/CSS21/fonts.html#font-size-props but this is by far
    // simplest thing to do so still do it like this for now
    sizes[0] = int(size * 0.75); // exception to 1.2 rule, otherwise too small
    sizes[1] = int(size * 0.83);
    sizes[2] = size;
    sizes[3] = int(size * 1.2);
    sizes[4] = int(size * 1.44);
    sizes[5] = int(size * 1.73);
    sizes[6] = int(size * 2);
}

static int wxGetDefaultHTMLFontSize()
{
    // base the default font size on the size of the default system font but
    // also ensure that we have a font of reasonable size, otherwise small HTML
    // fonts are unreadable
    int size = wxNORMAL_FONT->GetPointSize();
    if ( size < 10 )
        size = 10;
    return size;
}

void wxHtmlWinParser::SetFonts(const wxString& normal_face,
                               const wxString& fixed_face,
                               const int *sizes)
{
    static int default_sizes[7] = { 0 };
    if ( !sizes )
    {
        if ( !default_sizes[0] )
            wxBuildFontSizes(default_sizes, wxGetDefaultHTMLFontSize());

        sizes = default_sizes;
    }

    int i, j, k, l, m;

    for (i = 0; i < 7; i++)
        m_FontsSizes[i] = sizes[i];

    m_FontFaceFixed = fixed_face;
    m_FontFaceNormal = normal_face;

#if !wxUSE_UNICODE
    SetInputEncoding(m_InputEnc);
#endif

    for (i = 0; i < 2; i++)
        for (j = 0; j < 2; j++)
            for (k = 0; k < 2; k++)
                for (l = 0; l < 2; l++)
                    for (m = 0; m < 7; m++) {
                        if (m_FontsTable[i][j][k][l][m] != NULL)
                        {
                            delete m_FontsTable[i][j][k][l][m];
                            m_FontsTable[i][j][k][l][m] = NULL;
                        }
                    }
}

void wxHtmlWinParser::SetStandardFonts(int size,
                                       const wxString& normal_face,
                                       const wxString& fixed_face)
{
    if (size == -1)
        size = wxGetDefaultHTMLFontSize();

    int f_sizes[7];
    wxBuildFontSizes(f_sizes, size);

    wxString normal = normal_face;
    if ( normal.empty() )
        normal = wxNORMAL_FONT->GetFaceName();

    SetFonts(normal, fixed_face, f_sizes);
}

void wxHtmlWinParser::InitParser(const wxString& source)
{
    wxHtmlParser::InitParser(source);
    wxASSERT_MSG(m_DC != NULL, wxT("no DC assigned to wxHtmlWinParser!!"));

    m_FontBold = m_FontItalic = m_FontUnderlined = m_FontFixed = FALSE;
    m_FontSize = 3; //default one
    CreateCurrentFont();           // we're selecting default font into

    // we're not using GetCharWidth/Height() because of
    // differences under X and win
    wxCoord w,h;
    m_DC->GetTextExtent( wxT("H"), &w, &h);
    m_CharWidth = w;
    m_CharHeight = h;

    m_UseLink = false;
    m_Link = wxHtmlLinkInfo( wxEmptyString );
    m_LinkColor.Set(0, 0, 0xFF);
    m_ActualColor.Set(0, 0, 0);
    m_Align = wxHTML_ALIGN_LEFT;
    m_ScriptMode = wxHTML_SCRIPT_NORMAL;
    m_ScriptBaseline = 0;
    m_tmpLastWasSpace = false;
    m_lastWordCell = NULL;

    // open the toplevel container that contains everything else and that
    // is never closed (this makes parser's life easier):
    OpenContainer();

    // then open the first container into which page's content will go:
    OpenContainer();

#if !wxUSE_UNICODE
    wxString charset = ExtractCharsetInformation(source);
    if (!charset.empty())
    {
        wxFontEncoding enc = wxFontMapper::Get()->CharsetToEncoding(charset);
        if (enc != wxFONTENCODING_SYSTEM)
          SetInputEncoding(enc);
    }
#endif

    m_Container->InsertCell(new wxHtmlColourCell(m_ActualColor));
    wxColour windowColour = wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW) ;

    m_Container->InsertCell
                 (
                   new wxHtmlColourCell
                       (
                         m_windowInterface
                            ? m_windowInterface->GetHTMLBackgroundColour()
                            : windowColour,
                         wxHTML_CLR_BACKGROUND
                       )
                  );

    m_Container->InsertCell(new wxHtmlFontCell(CreateCurrentFont()));
}

void wxHtmlWinParser::DoneParser()
{
    m_Container = NULL;
#if !wxUSE_UNICODE
    SetInputEncoding(wxFONTENCODING_ISO8859_1); // for next call
#endif
    wxHtmlParser::DoneParser();
}

#if WXWIN_COMPATIBILITY_2_6
wxHtmlWindow *wxHtmlWinParser::GetWindow()
{
    if (!m_windowInterface)
        return NULL;
    return wxDynamicCast(m_windowInterface->GetHTMLWindow(), wxHtmlWindow);
}
#endif

wxObject* wxHtmlWinParser::GetProduct()
{
    wxHtmlContainerCell *top;

    CloseContainer();
    OpenContainer();

    top = m_Container;
    while (top->GetParent()) top = top->GetParent();
    top->RemoveExtraSpacing(true, true);

    return top;
}

wxFSFile *wxHtmlWinParser::OpenURL(wxHtmlURLType type,
                                   const wxString& url) const
{
    if ( !m_windowInterface )
        return wxHtmlParser::OpenURL(type, url);

    wxString myurl(url);
    wxHtmlOpeningStatus status;
    for (;;)
    {
        wxString myfullurl(myurl);

        // consider url as absolute path first
        wxURI current(myurl);
        myfullurl = current.BuildUnescapedURI();

        // if not absolute then ...
        if( current.IsReference() )
        {
            wxString basepath = GetFS()->GetPath();
            wxURI base(basepath);

            // ... try to apply base path if valid ...
            if( !base.IsReference() )
            {
                wxURI path(myfullurl);
                path.Resolve( base );
                myfullurl = path.BuildUnescapedURI();
            }
            else
            {
                // ... or force such addition if not included already
                if( !current.GetPath().Contains(base.GetPath()) )
                {
                    basepath += myurl;
                    wxURI connected( basepath );
                    myfullurl = connected.BuildUnescapedURI();
                }
            }
        }

        wxString redirect;
        status = m_windowInterface->OnHTMLOpeningURL(type, myfullurl, &redirect);
        if ( status != wxHTML_REDIRECT )
            break;

        myurl = redirect;
    }

    if ( status == wxHTML_BLOCK )
        return NULL;

    int flags = wxFS_READ;
    if (type == wxHTML_URL_IMAGE)
        flags |= wxFS_SEEKABLE;

    return GetFS()->OpenFile(myurl, flags);
}

#define NBSP_UNICODE_VALUE  (wxChar(160))
#if !wxUSE_UNICODE
    #define CUR_NBSP_VALUE m_nbsp
#else
    #define CUR_NBSP_VALUE NBSP_UNICODE_VALUE
#endif

void wxHtmlWinParser::AddText(const wxString& txt)
{
#if !wxUSE_UNICODE
    if ( m_nbsp == 0 )
        m_nbsp = GetEntitiesParser()->GetCharForCode(NBSP_UNICODE_VALUE);
#endif

    if ( m_whitespaceMode == Whitespace_Normal )
    {
        int templen = 0;

        size_t lng = txt.length();
        if (lng+1 > m_tmpStrBufSize)
        {
            delete[] m_tmpStrBuf;
            m_tmpStrBuf = new wxChar[lng+1];
            m_tmpStrBufSize = lng+1;
        }
        wxChar *temp = m_tmpStrBuf;

        wxString::const_iterator i = txt.begin();
        const wxString::const_iterator end = txt.end();

        if (m_tmpLastWasSpace)
        {
            while ( (i < end) &&
                    (*i == wxT('\n') || *i == wxT('\r') || *i == wxT(' ') ||
                     *i == wxT('\t')) )
            {
                ++i;
            }
        }

        while (i < end)
        {
            size_t x = 0;
            const wxChar d = temp[templen++] = *i;
            if ((d == wxT('\n')) || (d == wxT('\r')) || (d == wxT(' ')) || (d == wxT('\t')))
            {
                ++i, ++x;
                while ( (i < end) &&
                        (*i == wxT('\n') || *i == wxT('\r') ||
                         *i == wxT(' ') || *i == wxT('\t')) )
                {
                    ++i;
                    ++x;
                }
            }
            else
            {
                ++i;
            }

            if (x)
            {
                temp[templen-1] = wxT(' ');
                FlushWordBuf(temp, templen);
                m_tmpLastWasSpace = true;
            }
        }

        if (templen && (templen > 1 || temp[0] != wxT(' ')))
        {
            FlushWordBuf(temp, templen);
            m_tmpLastWasSpace = false;
        }
    }
    else // m_whitespaceMode == Whitespace_Pre
    {
        if ( txt.find(CUR_NBSP_VALUE) != wxString::npos )
        {
            // we need to substitute spaces for &nbsp; here just like we
            // did in the Whitespace_Normal branch above
            wxString txt2(txt);
            txt2.Replace(CUR_NBSP_VALUE, ' ');
            AddPreBlock(txt2);
        }
        else
        {
            AddPreBlock(txt);
        }

        // don't eat any whitespace in <pre> block
        m_tmpLastWasSpace = false;
    }
}

void wxHtmlWinParser::FlushWordBuf(wxChar *buf, int& len)
{
    buf[len] = 0;

    for ( int i = 0; i < len; i++ )
    {
        if ( buf[i] == CUR_NBSP_VALUE )
            buf[i] = ' ';
    }

#if !wxUSE_UNICODE
    if (m_EncConv)
        m_EncConv->Convert(buf);
#endif

    AddWord(wxString(buf, len));

    len = 0;
}

void wxHtmlWinParser::AddWord(wxHtmlWordCell *word)
{
    ApplyStateToCell(word);

    m_Container->InsertCell(word);
    word->SetPreviousWord(m_lastWordCell);
    m_lastWordCell = word;
}

void wxHtmlWinParser::AddPreBlock(const wxString& text)
{
    if ( text.find('\t') != wxString::npos )
    {
        wxString text2;
        text2.reserve(text.length());

        const wxString::const_iterator end = text.end();
        wxString::const_iterator copyFrom = text.begin();
        size_t pos = 0;
        int posColumn = m_posColumn;
        for ( wxString::const_iterator i = copyFrom; i != end; ++i, ++pos )
        {
            if ( *i == '\t' )
            {
                if ( copyFrom != i )
                    text2.append(copyFrom, i);

                const unsigned SPACES_PER_TAB = 8;
                const size_t expandTo = SPACES_PER_TAB - posColumn % SPACES_PER_TAB;
                text2.append(expandTo, ' ');

                posColumn += expandTo;
                copyFrom = i + 1;
            }
            else
            {
                ++posColumn;
            }
        }
        if ( copyFrom != text.end() )
            text2.append(copyFrom, text.end());

        AddWord(new wxHtmlWordWithTabsCell(text2, text, m_posColumn, *(GetDC())));

        m_posColumn = posColumn;
    }
    else
    {
        // no special formatting needed
        AddWord(text);
        m_posColumn += text.length();
    }
}


wxHtmlContainerCell* wxHtmlWinParser::OpenContainer()
{
    m_Container = new wxHtmlContainerCell(m_Container);
    m_Container->SetAlignHor(m_Align);
    m_posColumn = 0;
    m_tmpLastWasSpace = true;
        /* to avoid space being first character in paragraph */
    return m_Container;
}



wxHtmlContainerCell* wxHtmlWinParser::SetContainer(wxHtmlContainerCell *c)
{
    m_tmpLastWasSpace = true;
        /* to avoid space being first character in paragraph */
    return m_Container = c;
}



wxHtmlContainerCell* wxHtmlWinParser::CloseContainer()
{
    m_Container = m_Container->GetParent();
    return m_Container;
}


void wxHtmlWinParser::SetFontSize(int s)
{
    if (s < 1)
        s = 1;
    else if (s > 7)
        s = 7;
    m_FontSize = s;
}


void wxHtmlWinParser::SetDC(wxDC *dc, double pixel_scale, double font_scale)
{
    m_DC = dc;
    m_PixelScale = pixel_scale;
    m_FontScale = font_scale;
}

void wxHtmlWinParser::SetFontPointSize(int pt)
{
    if (pt <= m_FontsSizes[0])
        m_FontSize = 1;
    else if (pt >= m_FontsSizes[6])
        m_FontSize = 7;
    else
    {
        // Find the font closest to the given value with a simple linear search
        // (binary search is not worth it here for so small number of elements)
        for ( int n = 0; n < 6; n++ )
        {
            if ( (pt > m_FontsSizes[n]) && (pt <= m_FontsSizes[n + 1]) )
            {
                // In this range, find out which entry it is closest to
                if ( (pt - m_FontsSizes[n]) < (m_FontsSizes[n + 1] - pt) )
                    m_FontSize = n;
                else
                    m_FontSize = n + 1;

                break;
            }
        }
    }
}

wxFont* wxHtmlWinParser::CreateCurrentFont()
{
    int fb = GetFontBold(),
        fi = GetFontItalic(),
        fu = GetFontUnderlined(),
        ff = GetFontFixed(),
        fs = GetFontSize() - 1 /*remap from <1;7> to <0;6>*/ ;

    wxString face = ff ? m_FontFaceFixed : m_FontFaceNormal;
    wxString *faceptr = &(m_FontsFacesTable[fb][fi][fu][ff][fs]);
    wxFont **fontptr = &(m_FontsTable[fb][fi][fu][ff][fs]);
#if !wxUSE_UNICODE
    wxFontEncoding *encptr = &(m_FontsEncTable[fb][fi][fu][ff][fs]);
#endif

    if (*fontptr != NULL && (*faceptr != face
#if !wxUSE_UNICODE
                             || *encptr != m_OutputEnc
#endif
                            ))
    {
        wxDELETE(*fontptr);
    }

    if (*fontptr == NULL)
    {
        *faceptr = face;
        *fontptr = new wxFont(
                       (int) (m_FontsSizes[fs] * m_FontScale),
                       ff ? wxMODERN : wxSWISS,
                       fi ? wxITALIC : wxNORMAL,
                       fb ? wxBOLD : wxNORMAL,
                       fu ? true : false, face
#if wxUSE_UNICODE
                       );
#else
                       , m_OutputEnc);
        *encptr = m_OutputEnc;
#endif
    }
    m_DC->SetFont(**fontptr);
    return (*fontptr);
}



void wxHtmlWinParser::SetLink(const wxHtmlLinkInfo& link)
{
    m_Link = link;
    m_UseLink = (link.GetHref() != wxEmptyString);
}

void wxHtmlWinParser::SetFontFace(const wxString& face)
{
    if (GetFontFixed())
        m_FontFaceFixed = face;
    else
        m_FontFaceNormal = face;

#if !wxUSE_UNICODE
    if (m_InputEnc != wxFONTENCODING_DEFAULT)
        SetInputEncoding(m_InputEnc);
#endif
}

void wxHtmlWinParser::ApplyStateToCell(wxHtmlCell *cell)
{
    // set the link:
    if (m_UseLink)
        cell->SetLink(GetLink());

    // apply current script mode settings:
    cell->SetScriptMode(GetScriptMode(), GetScriptBaseline());
}


#if !wxUSE_UNICODE
void wxHtmlWinParser::SetInputEncoding(wxFontEncoding enc)
{
    // the character used for non-breakable space may change:
    m_nbsp = 0;

    m_InputEnc = m_OutputEnc = wxFONTENCODING_DEFAULT;
    wxDELETE(m_EncConv);

    if (enc == wxFONTENCODING_DEFAULT)
        return;

    wxFontEncoding altfix, altnorm;
    bool availfix, availnorm;

    availnorm = wxFontMapper::Get()->IsEncodingAvailable(enc, m_FontFaceNormal);
    availfix = wxFontMapper::Get()->IsEncodingAvailable(enc, m_FontFaceFixed);

    if (availnorm && availfix)
    {
        // exact match?
        m_OutputEnc = enc;
    }

    else if (wxFontMapper::Get()->GetAltForEncoding(enc, &altnorm, m_FontFaceNormal, false) &&
             wxFontMapper::Get()->GetAltForEncoding(enc, &altfix, m_FontFaceFixed, false) &&
             altnorm == altfix)
    {
        // alternatives?
        m_OutputEnc = altnorm;
    }
    else if (availnorm)
    {
        // at least normal face?
        m_OutputEnc = enc;
    }
    else if (wxFontMapper::Get()->GetAltForEncoding(enc, &altnorm, m_FontFaceNormal, false))
    {
        m_OutputEnc = altnorm;
    }
    else
    {
#ifndef __WXMAC__
        // okay, let's convert to ISO_8859-1, available always
        m_OutputEnc = wxFONTENCODING_DEFAULT;
#else
        m_OutputEnc = wxLocale::GetSystemEncoding() ;
#endif
    }

    m_InputEnc = enc;
    if (m_OutputEnc == wxFONTENCODING_DEFAULT)
    {
        GetEntitiesParser()->SetEncoding(wxFONTENCODING_SYSTEM);
    }
    else
    {
        GetEntitiesParser()->SetEncoding(m_OutputEnc);
    }

    if (m_InputEnc == m_OutputEnc)
        return;

    m_EncConv = new wxEncodingConverter();
    if (!m_EncConv->Init(m_InputEnc,
                           (m_OutputEnc == wxFONTENCODING_DEFAULT) ?
                                      wxFONTENCODING_ISO8859_1 : m_OutputEnc,
                           wxCONVERT_SUBSTITUTE))
    { // total failure :-(
        wxLogError(_("Failed to display HTML document in %s encoding"),
                   wxFontMapper::GetEncodingName(enc).c_str());
        m_InputEnc = m_OutputEnc = wxFONTENCODING_DEFAULT;
        wxDELETE(m_EncConv);
    }
}
#endif




//-----------------------------------------------------------------------------
// wxHtmlWinTagHandler
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxHtmlWinTagHandler, wxHtmlTagHandler)

//-----------------------------------------------------------------------------
// wxHtmlTagsModule
//-----------------------------------------------------------------------------

// NB: This is *NOT* winpars.cpp's initialization and shutdown code!!
//     This module is an ancestor for tag handlers modules defined
//     in m_*.cpp files with TAGS_MODULE_BEGIN...TAGS_MODULE_END construct.
//
//     Do not add any winpars.cpp shutdown or initialization code to it,
//     create a new module instead!

IMPLEMENT_DYNAMIC_CLASS(wxHtmlTagsModule, wxModule)

bool wxHtmlTagsModule::OnInit()
{
    wxHtmlWinParser::AddModule(this);
    return true;
}

void wxHtmlTagsModule::OnExit()
{
    wxHtmlWinParser::RemoveModule(this);
}

#endif
