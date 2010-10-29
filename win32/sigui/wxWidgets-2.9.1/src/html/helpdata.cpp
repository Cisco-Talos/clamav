/////////////////////////////////////////////////////////////////////////////
// Name:        src/html/helpdata.cpp
// Purpose:     wxHtmlHelpData
// Notes:       Based on htmlhelp.cpp, implementing a monolithic
//              HTML Help controller class,  by Vaclav Slavik
// Author:      Harm van der Heijden and Vaclav Slavik
// RCS-ID:      $Id$
// Copyright:   (c) Harm van der Heijden and Vaclav Slavik
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_HTML && wxUSE_STREAMS

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#include <ctype.h>

#include "wx/html/helpdata.h"
#include "wx/tokenzr.h"
#include "wx/wfstream.h"
#include "wx/busyinfo.h"
#include "wx/encconv.h"
#include "wx/fontmap.h"
#include "wx/html/htmlpars.h"
#include "wx/html/htmldefs.h"
#include "wx/html/htmlfilt.h"
#include "wx/filename.h"

#include "wx/arrimpl.cpp"
WX_DEFINE_OBJARRAY(wxHtmlBookRecArray)
WX_DEFINE_OBJARRAY(wxHtmlHelpDataItems)

//-----------------------------------------------------------------------------
// static helper functions
//-----------------------------------------------------------------------------

// Reads one line, stores it into buf and returns pointer to new line or NULL.
static const wxChar* ReadLine(const wxChar *line, wxChar *buf, size_t bufsize)
{
    wxChar *writeptr = buf;
    wxChar *endptr = buf + bufsize - 1;
    const wxChar *readptr = line;

    while (*readptr != 0 && *readptr != wxT('\r') && *readptr != wxT('\n') &&
           writeptr != endptr)
        *(writeptr++) = *(readptr++);
    *writeptr = 0;
    while (*readptr == wxT('\r') || *readptr == wxT('\n'))
        readptr++;
    if (*readptr == 0)
        return NULL;
    else
        return readptr;
}



static int
wxHtmlHelpIndexCompareFunc(wxHtmlHelpDataItem **a, wxHtmlHelpDataItem **b)
{
    wxHtmlHelpDataItem *ia = *a;
    wxHtmlHelpDataItem *ib = *b;

    if (ia == NULL)
        return -1;
    if (ib == NULL)
        return 1;

    if (ia->parent == ib->parent)
    {
        return ia->name.CmpNoCase(ib->name);
    }
    else if (ia->level == ib->level)
    {
        return wxHtmlHelpIndexCompareFunc(&ia->parent, &ib->parent);
    }
    else
    {
        wxHtmlHelpDataItem *ia2 = ia;
        wxHtmlHelpDataItem *ib2 = ib;

        while (ia2->level > ib2->level)
        {
            ia2 = ia2->parent;
        }
        while (ib2->level > ia2->level)
        {
            ib2 = ib2->parent;
        }

        wxASSERT(ia2);
        wxASSERT(ib2);
        int res = wxHtmlHelpIndexCompareFunc(&ia2, &ib2);
        if (res != 0)
            return res;
        else if (ia->level > ib->level)
            return 1;
        else
            return -1;
    }
}

//-----------------------------------------------------------------------------
// HP_Parser
//-----------------------------------------------------------------------------

class HP_Parser : public wxHtmlParser
{
public:
    HP_Parser()
    {
        GetEntitiesParser()->SetEncoding(wxFONTENCODING_ISO8859_1);
    }

    wxObject* GetProduct() { return NULL; }

protected:
    virtual void AddText(const wxString& WXUNUSED(txt)) {}

    wxDECLARE_NO_COPY_CLASS(HP_Parser);
};


//-----------------------------------------------------------------------------
// HP_TagHandler
//-----------------------------------------------------------------------------

class HP_TagHandler : public wxHtmlTagHandler
{
    private:
        wxString m_name, m_page;
        int m_level;
        int m_id;
        int m_index;
        int m_count;
        wxHtmlHelpDataItem *m_parentItem;
        wxHtmlBookRecord *m_book;

        wxHtmlHelpDataItems *m_data;

    public:
        HP_TagHandler(wxHtmlBookRecord *b) : wxHtmlTagHandler()
        {
            m_data = NULL;
            m_book = b;
            m_name = m_page = wxEmptyString;
            m_level = 0;
            m_id = wxID_ANY;
            m_count = 0;
            m_parentItem = NULL;
        }
        wxString GetSupportedTags() { return wxT("UL,OBJECT,PARAM"); }
        bool HandleTag(const wxHtmlTag& tag);

        void Reset(wxHtmlHelpDataItems& data)
        {
            m_data = &data;
            m_count = 0;
            m_level = 0;
            m_parentItem = NULL;
        }

    wxDECLARE_NO_COPY_CLASS(HP_TagHandler);
};


bool HP_TagHandler::HandleTag(const wxHtmlTag& tag)
{
    if (tag.GetName() == wxT("UL"))
    {
        wxHtmlHelpDataItem *oldparent = m_parentItem;
        m_level++;
        m_parentItem = (m_count > 0) ? &(*m_data)[m_data->size()-1] : NULL;
        ParseInner(tag);
        m_level--;
        m_parentItem = oldparent;
        return true;
    }
    else if (tag.GetName() == wxT("OBJECT"))
    {
        m_name = m_page = wxEmptyString;
        ParseInner(tag);

#if 0
         if (!page.IsEmpty())
        /* Valid HHW's file may contain only two object tags:

           <OBJECT type="text/site properties">
               <param name="ImageType" value="Folder">
           </OBJECT>

           or

           <OBJECT type="text/sitemap">
               <param name="Name" value="main page">
               <param name="Local" value="another.htm">
           </OBJECT>

           We're interested in the latter. !page.IsEmpty() is valid
           condition because text/site properties does not contain Local param
        */
#endif
        if (tag.GetParam(wxT("TYPE")) == wxT("text/sitemap"))
        {
            wxHtmlHelpDataItem *item = new wxHtmlHelpDataItem();
            item->parent = m_parentItem;
            item->level = m_level;
            item->id = m_id;
            item->page = m_page;
            item->name = m_name;

            item->book = m_book;
            m_data->Add(item);
            m_count++;
        }

        return true;
    }
    else
    { // "PARAM"
        if (m_name.empty() && tag.GetParam(wxT("NAME")) == wxT("Name"))
            m_name = tag.GetParam(wxT("VALUE"));
        if (tag.GetParam(wxT("NAME")) == wxT("Local"))
            m_page = tag.GetParam(wxT("VALUE"));
        if (tag.GetParam(wxT("NAME")) == wxT("ID"))
            tag.GetParamAsInt(wxT("VALUE"), &m_id);
        return false;
    }
}


//-----------------------------------------------------------------------------
// wxHtmlHelpData
//-----------------------------------------------------------------------------

wxString wxHtmlBookRecord::GetFullPath(const wxString &page) const
{
    if (wxIsAbsolutePath(page))
        return page;
    else
        return m_BasePath + page;
}

wxString wxHtmlHelpDataItem::GetIndentedName() const
{
    wxString s;
    for (int i = 1; i < level; i++)
        s << wxT("   ");
    s << name;
    return s;
}


IMPLEMENT_DYNAMIC_CLASS(wxHtmlHelpData, wxObject)

wxHtmlHelpData::wxHtmlHelpData()
{
}

wxHtmlHelpData::~wxHtmlHelpData()
{
}

bool wxHtmlHelpData::LoadMSProject(wxHtmlBookRecord *book, wxFileSystem& fsys,
                                   const wxString& indexfile,
                                   const wxString& contentsfile)
{
    wxFSFile *f;
    wxHtmlFilterHTML filter;
    wxString buf;
    wxString string;

    HP_Parser parser;
    HP_TagHandler *handler = new HP_TagHandler(book);
    parser.AddTagHandler(handler);

    f = ( contentsfile.empty() ? NULL : fsys.OpenFile(contentsfile) );
    if (f)
    {
        buf.clear();
        buf = filter.ReadFile(*f);
        delete f;
        handler->Reset(m_contents);
        parser.Parse(buf);
    }
    else
    {
        wxLogError(_("Cannot open contents file: %s"), contentsfile.c_str());
    }

    f = ( indexfile.empty() ? NULL : fsys.OpenFile(indexfile) );
    if (f)
    {
        buf.clear();
        buf = filter.ReadFile(*f);
        delete f;
        handler->Reset(m_index);
        parser.Parse(buf);
    }
    else if (!indexfile.empty())
    {
        wxLogError(_("Cannot open index file: %s"), indexfile.c_str());
    }
    return true;
}

inline static void CacheWriteInt32(wxOutputStream *f, wxInt32 value)
{
    wxInt32 x = wxINT32_SWAP_ON_BE(value);
    f->Write(&x, sizeof(x));
}

inline static wxInt32 CacheReadInt32(wxInputStream *f)
{
    wxInt32 x;
    f->Read(&x, sizeof(x));
    return wxINT32_SWAP_ON_BE(x);
}

inline static void CacheWriteString(wxOutputStream *f, const wxString& str)
{
    const wxWX2MBbuf mbstr = str.mb_str(wxConvUTF8);
    size_t len = strlen((const char*)mbstr)+1;
    CacheWriteInt32(f, len);
    f->Write((const char*)mbstr, len);
}

inline static wxString CacheReadString(wxInputStream *f)
{
    size_t len = (size_t)CacheReadInt32(f);
    wxCharBuffer str(len-1);
    f->Read(str.data(), len);
    return wxString(str, wxConvUTF8);
}

#define CURRENT_CACHED_BOOK_VERSION     5

// Additional flags to detect incompatibilities of the runtime environment:
#define CACHED_BOOK_FORMAT_FLAGS \
                     (wxUSE_UNICODE << 0)


bool wxHtmlHelpData::LoadCachedBook(wxHtmlBookRecord *book, wxInputStream *f)
{
    int i, st, newsize;
    wxInt32 version;

    /* load header - version info : */
    version = CacheReadInt32(f);

    if (version != CURRENT_CACHED_BOOK_VERSION)
    {
        // NB: We can just silently return false here and don't worry about
        //     it anymore, because AddBookParam will load the MS project in
        //     absence of (properly versioned) .cached file and automatically
        //     create new .cached file immediately afterward.
        return false;
    }

    if (CacheReadInt32(f) != CACHED_BOOK_FORMAT_FLAGS)
        return false;

    /* load contents : */
    st = m_contents.size();
    newsize = st + CacheReadInt32(f);
    m_contents.Alloc(newsize);
    for (i = st; i < newsize; i++)
    {
        wxHtmlHelpDataItem *item = new wxHtmlHelpDataItem;
        item->level = CacheReadInt32(f);
        item->id = CacheReadInt32(f);
        item->name = CacheReadString(f);
        item->page = CacheReadString(f);
        item->book = book;
        m_contents.Add(item);
    }

    /* load index : */
    st = m_index.size();
    newsize = st + CacheReadInt32(f);
    m_index.Alloc(newsize);
    for (i = st; i < newsize; i++)
    {
        wxHtmlHelpDataItem *item = new wxHtmlHelpDataItem;
        item->name = CacheReadString(f);
        item->page = CacheReadString(f);
        item->level = CacheReadInt32(f);
        item->book = book;
        int parentShift = CacheReadInt32(f);
        if (parentShift != 0)
            item->parent = &m_index[m_index.size() - parentShift];
        m_index.Add(item);
    }
    return true;
}


bool wxHtmlHelpData::SaveCachedBook(wxHtmlBookRecord *book, wxOutputStream *f)
{
    int i;
    wxInt32 cnt;

    /* save header - version info : */
    CacheWriteInt32(f, CURRENT_CACHED_BOOK_VERSION);
    CacheWriteInt32(f, CACHED_BOOK_FORMAT_FLAGS);

    /* save contents : */
    int len = m_contents.size();
    for (cnt = 0, i = 0; i < len; i++)
        if (m_contents[i].book == book && m_contents[i].level > 0)
            cnt++;
    CacheWriteInt32(f, cnt);

    for (i = 0; i < len; i++)
    {
        if (m_contents[i].book != book || m_contents[i].level == 0)
            continue;
        CacheWriteInt32(f, m_contents[i].level);
        CacheWriteInt32(f, m_contents[i].id);
        CacheWriteString(f, m_contents[i].name);
        CacheWriteString(f, m_contents[i].page);
    }

    /* save index : */
    len = m_index.size();
    for (cnt = 0, i = 0; i < len; i++)
        if (m_index[i].book == book && m_index[i].level > 0)
            cnt++;
    CacheWriteInt32(f, cnt);

    for (i = 0; i < len; i++)
    {
        if (m_index[i].book != book || m_index[i].level == 0)
            continue;
        CacheWriteString(f, m_index[i].name);
        CacheWriteString(f, m_index[i].page);
        CacheWriteInt32(f, m_index[i].level);
        // save distance to parent item, if any:
        if (m_index[i].parent == NULL)
        {
            CacheWriteInt32(f, 0);
        }
        else
        {
            int cnt2 = 0;
            wxHtmlHelpDataItem *parent = m_index[i].parent;
            for (int j = i-1; j >= 0; j--)
            {
                if (m_index[j].book == book && m_index[j].level > 0)
                    cnt2++;
                if (&m_index[j] == parent)
                    break;
            }
            wxASSERT(cnt2 > 0);
            CacheWriteInt32(f, cnt2);
        }
    }
    return true;
}


void wxHtmlHelpData::SetTempDir(const wxString& path)
{
    if (path.empty())
        m_tempPath = path;
    else
    {
        if (wxIsAbsolutePath(path)) m_tempPath = path;
        else m_tempPath = wxGetCwd() + wxT("/") + path;

        if (m_tempPath[m_tempPath.length() - 1] != wxT('/'))
            m_tempPath << wxT('/');
    }
}



static wxString SafeFileName(const wxString& s)
{
    wxString res(s);
    res.Replace(wxT("#"), wxT("_"));
    res.Replace(wxT(":"), wxT("_"));
    res.Replace(wxT("\\"), wxT("_"));
    res.Replace(wxT("/"), wxT("_"));
    return res;
}

bool wxHtmlHelpData::AddBookParam(const wxFSFile& bookfile,
                                  wxFontEncoding encoding,
                                  const wxString& title, const wxString& contfile,
                                  const wxString& indexfile, const wxString& deftopic,
                                  const wxString& path)
{
    wxFileSystem fsys;
    wxFSFile *fi;
    wxHtmlBookRecord *bookr;

    int IndexOld = m_index.size(),
        ContentsOld = m_contents.size();

    if (!path.empty())
        fsys.ChangePathTo(path, true);

    size_t booksCnt = m_bookRecords.GetCount();
    for (size_t i = 0; i < booksCnt; i++)
    {
        if ( m_bookRecords[i].GetBookFile() == bookfile.GetLocation() )
            return true; // book is (was) loaded
    }

    bookr = new wxHtmlBookRecord(bookfile.GetLocation(), fsys.GetPath(), title, deftopic);

    wxHtmlHelpDataItem *bookitem = new wxHtmlHelpDataItem;
    bookitem->level = 0;
    bookitem->id = 0;
    bookitem->page = deftopic;
    bookitem->name = title;
    bookitem->book = bookr;

    // store the contents index for later
    int cont_start = m_contents.size();

    m_contents.Add(bookitem);

    // Try to find cached binary versions:
    // 1. save file as book, but with .hhp.cached extension
    // 2. same as 1. but in temp path
    // 3. otherwise or if cache load failed, load it from MS.

    fi = fsys.OpenFile(bookfile.GetLocation() + wxT(".cached"));

    if (fi == NULL ||
#if wxUSE_DATETIME
          fi->GetModificationTime() < bookfile.GetModificationTime() ||
#endif // wxUSE_DATETIME
          !LoadCachedBook(bookr, fi->GetStream()))
    {
        if (fi != NULL) delete fi;
        fi = fsys.OpenFile(m_tempPath + wxFileNameFromPath(bookfile.GetLocation()) + wxT(".cached"));
        if (m_tempPath.empty() || fi == NULL ||
#if wxUSE_DATETIME
            fi->GetModificationTime() < bookfile.GetModificationTime() ||
#endif // wxUSE_DATETIME
            !LoadCachedBook(bookr, fi->GetStream()))
        {
            LoadMSProject(bookr, fsys, indexfile, contfile);
            if (!m_tempPath.empty())
            {
                wxFileOutputStream *outs = new wxFileOutputStream(m_tempPath +
                                                  SafeFileName(wxFileNameFromPath(bookfile.GetLocation())) + wxT(".cached"));
                SaveCachedBook(bookr, outs);
                delete outs;
            }
        }
    }

    if (fi != NULL) delete fi;

    // Now store the contents range
    bookr->SetContentsRange(cont_start, m_contents.size());

    // MS HTML Help files [written by MS HTML Help Workshop] are broken
    // in that the data are iso-8859-1 (including HTML entities), but must
    // be interpreted as being in language's windows charset. Correct the
    // differences here and also convert to wxConvLocal in ANSI build
    if (encoding != wxFONTENCODING_SYSTEM)
    {
        #if wxUSE_UNICODE
            #define CORRECT_STR(str, conv) \
                str = wxString((str).mb_str(wxConvISO8859_1), conv)
        #else
            #define CORRECT_STR(str, conv) \
                str = wxString((str).wc_str(conv), wxConvLocal)
        #endif
        wxCSConv conv(encoding);
        size_t IndexCnt = m_index.size();
        size_t ContentsCnt = m_contents.size();
        size_t i;
        for (i = IndexOld; i < IndexCnt; i++)
        {
            CORRECT_STR(m_index[i].name, conv);
        }
        for (i = ContentsOld; i < ContentsCnt; i++)
        {
            CORRECT_STR(m_contents[i].name, conv);
        }
        #undef CORRECT_STR
    }

    m_bookRecords.Add(bookr);
    if (!m_index.empty())
    {
        m_index.Sort(wxHtmlHelpIndexCompareFunc);
    }

    return true;
}


bool wxHtmlHelpData::AddBook(const wxString& book)
{
    wxString extension(book.Right(4).Lower());
    if (extension == wxT(".zip") ||
#if wxUSE_LIBMSPACK
        extension == wxT(".chm") /*compressed html help book*/ ||
#endif
        extension == wxT(".htb") /*html book*/)
    {
        wxFileSystem fsys;
        wxString s;
        bool rt = false;

#if wxUSE_LIBMSPACK
        if (extension == wxT(".chm"))
            s = fsys.FindFirst(book + wxT("#chm:*.hhp"), wxFILE);
        else
#endif
            s = fsys.FindFirst(book + wxT("#zip:*.hhp"), wxFILE);

        while (!s.empty())
        {
            if (AddBook(s)) rt = true;
            s = fsys.FindNext();
        }

        return rt;
    }

    wxFSFile *fi;
    wxFileSystem fsys;

    wxString title = _("noname"),
             safetitle,
             start = wxEmptyString,
             contents = wxEmptyString,
             index = wxEmptyString,
             charset = wxEmptyString;

    fi = fsys.OpenFile(book);
    if (fi == NULL)
    {
        wxLogError(_("Cannot open HTML help book: %s"), book.c_str());
        return false;
    }
    fsys.ChangePathTo(book);

    const wxChar *lineptr;
    wxChar linebuf[300];
    wxString tmp;
    wxHtmlFilterPlainText filter;
    tmp = filter.ReadFile(*fi);
    lineptr = tmp.c_str();

    do
    {
        lineptr = ReadLine(lineptr, linebuf, 300);

        for (wxChar *ch = linebuf; *ch != wxT('\0') && *ch != wxT('='); ch++)
           *ch = (wxChar)wxTolower(*ch);

        if (wxStrstr(linebuf, wxT("title=")) == linebuf)
            title = linebuf + wxStrlen(wxT("title="));
        if (wxStrstr(linebuf, wxT("default topic=")) == linebuf)
            start = linebuf + wxStrlen(wxT("default topic="));
        if (wxStrstr(linebuf, wxT("index file=")) == linebuf)
            index = linebuf + wxStrlen(wxT("index file="));
        if (wxStrstr(linebuf, wxT("contents file=")) == linebuf)
            contents = linebuf + wxStrlen(wxT("contents file="));
        if (wxStrstr(linebuf, wxT("charset=")) == linebuf)
            charset = linebuf + wxStrlen(wxT("charset="));
    } while (lineptr != NULL);

    wxFontEncoding enc = wxFONTENCODING_SYSTEM;
#if wxUSE_FONTMAP
    if (charset != wxEmptyString)
        enc = wxFontMapper::Get()->CharsetToEncoding(charset);
#endif

    bool rtval = AddBookParam(*fi, enc,
                              title, contents, index, start, fsys.GetPath());
    delete fi;

    return rtval;
}

wxString wxHtmlHelpData::FindPageByName(const wxString& x)
{
    int i;

    bool has_non_ascii = false;
    wxString::const_iterator it;
    for (it = x.begin(); it != x.end(); ++it)
    {
        wxUniChar ch = *it;
        if (!ch.IsAscii())
        {
            has_non_ascii = true;
            break;
        }
    }

    int cnt = m_bookRecords.GetCount();

    if (!has_non_ascii)
    {
      wxFileSystem fsys;
      wxFSFile *f;
      // 1. try to open given file:
      for (i = 0; i < cnt; i++)
      {
        f = fsys.OpenFile(m_bookRecords[i].GetFullPath(x));
        if (f)
        {
            wxString url = m_bookRecords[i].GetFullPath(x);
            delete f;
            return url;
        }
      }
    }


    // 2. try to find a book:
    for (i = 0; i < cnt; i++)
    {
        if (m_bookRecords[i].GetTitle() == x)
            return m_bookRecords[i].GetFullPath(m_bookRecords[i].GetStart());
    }

    // 3. try to find in contents:
    cnt = m_contents.size();
    for (i = 0; i < cnt; i++)
    {
        if (m_contents[i].name == x)
            return m_contents[i].GetFullPath();
    }


    // 4. try to find in index:
    cnt = m_index.size();
    for (i = 0; i < cnt; i++)
    {
        if (m_index[i].name == x)
            return m_index[i].GetFullPath();
    }

    // 4b. if still not found, try case-insensitive comparison
    for (i = 0; i < cnt; i++)
    {
        if (m_index[i].name.CmpNoCase(x) == 0)
            return m_index[i].GetFullPath();
    }

    return wxEmptyString;
}

wxString wxHtmlHelpData::FindPageById(int id)
{
    size_t cnt = m_contents.size();
    for (size_t i = 0; i < cnt; i++)
    {
        if (m_contents[i].id == id)
        {
            return m_contents[i].GetFullPath();
        }
    }

    return wxEmptyString;
}


//----------------------------------------------------------------------------------
// wxHtmlSearchStatus functions
//----------------------------------------------------------------------------------

wxHtmlSearchStatus::wxHtmlSearchStatus(wxHtmlHelpData* data, const wxString& keyword,
                                       bool case_sensitive, bool whole_words_only,
                                       const wxString& book)
{
    m_Data = data;
    m_Keyword = keyword;
    wxHtmlBookRecord* bookr = NULL;
    if (book != wxEmptyString)
    {
        // we have to search in a specific book. Find it first
        int i, cnt = data->m_bookRecords.GetCount();
        for (i = 0; i < cnt; i++)
            if (data->m_bookRecords[i].GetTitle() == book)
            {
                bookr = &(data->m_bookRecords[i]);
                m_CurIndex = bookr->GetContentsStart();
                m_MaxIndex = bookr->GetContentsEnd();
                break;
            }
        // check; we won't crash if the book doesn't exist, but it's Bad Anyway.
        wxASSERT(bookr);
    }
    if (! bookr)
    {
        // no book specified; search all books
        m_CurIndex = 0;
        m_MaxIndex = m_Data->m_contents.size();
    }
    m_Engine.LookFor(keyword, case_sensitive, whole_words_only);
    m_Active = (m_CurIndex < m_MaxIndex);
}

bool wxHtmlSearchStatus::Search()
{
    wxFSFile *file;
    int i = m_CurIndex;  // shortcut
    bool found = false;
    wxString thepage;

    if (!m_Active)
    {
        // sanity check. Illegal use, but we'll try to prevent a crash anyway
        wxASSERT(m_Active);
        return false;
    }

    m_Name = wxEmptyString;
    m_CurItem = NULL;
    thepage = m_Data->m_contents[i].page;

    m_Active = (++m_CurIndex < m_MaxIndex);
    // check if it is same page with different anchor:
    if (!m_LastPage.empty())
    {
        const wxChar *p1, *p2;
        for (p1 = thepage.c_str(), p2 = m_LastPage.c_str();
             *p1 != 0 && *p1 != wxT('#') && *p1 == *p2; p1++, p2++) {}

        m_LastPage = thepage;

        if (*p1 == 0 || *p1 == wxT('#'))
            return false;
    }
    else m_LastPage = thepage;

    wxFileSystem fsys;
    file = fsys.OpenFile(m_Data->m_contents[i].book->GetFullPath(thepage));
    if (file)
    {
        if (m_Engine.Scan(*file))
        {
            m_Name = m_Data->m_contents[i].name;
            m_CurItem = &m_Data->m_contents[i];
            found = true;
        }
        delete file;
    }
    return found;
}








//--------------------------------------------------------------------------------
// wxHtmlSearchEngine
//--------------------------------------------------------------------------------

void wxHtmlSearchEngine::LookFor(const wxString& keyword, bool case_sensitive, bool whole_words_only)
{
    m_CaseSensitive = case_sensitive;
    m_WholeWords = whole_words_only;
    m_Keyword = keyword;

    if (!m_CaseSensitive)
        m_Keyword.LowerCase();
}


static inline bool WHITESPACE(wxChar c)
{
    return c == wxT(' ') || c == wxT('\n') || c == wxT('\r') || c == wxT('\t');
}

// replace continuous spaces by one single space
static inline wxString CompressSpaces(const wxString & str)
{
    wxString buf;
    buf.reserve( str.size() );

    bool space_counted = false;
    for( const wxChar * pstr = str.c_str(); *pstr; ++pstr )
    {
        wxChar ch = *pstr;
        if( WHITESPACE( ch ) )
        {
            if( space_counted )
            {
                continue;
            }
            ch = wxT(' ');
            space_counted = true;
        }
        else
        {
            space_counted = false;
        }
        buf += ch;
    }

    return buf;
}

bool wxHtmlSearchEngine::Scan(const wxFSFile& file)
{
    wxASSERT_MSG(!m_Keyword.empty(), wxT("wxHtmlSearchEngine::LookFor must be called before scanning!"));

    wxHtmlFilterHTML filter;
    wxString bufStr = filter.ReadFile(file);

    if (!m_CaseSensitive)
        bufStr.LowerCase();

    {   // remove html tags
        wxString bufStrCopy;
        bufStrCopy.reserve( bufStr.size() );
        bool insideTag = false;
        for (const wxChar * pBufStr = bufStr.c_str(); *pBufStr; ++pBufStr)
        {
            wxChar c = *pBufStr;
            if (insideTag)
            {
                if (c == wxT('>'))
                {
                    insideTag = false;
                    // replace the tag by an empty space
                    c = wxT(' ');
                }
                else
                    continue;
            }
            else if (c == wxT('<'))
            {
                wxChar nextCh = *(pBufStr + 1);
                if (nextCh == wxT('/') || !WHITESPACE(nextCh))
                {
                    insideTag = true;
                    continue;
                }
            }
            bufStrCopy += c;
        }
        bufStr.swap( bufStrCopy );
    }

    wxString keyword = m_Keyword;

    if (m_WholeWords)
    {
        // insert ' ' at the beginning and at the end
        keyword.insert( 0, wxT(" ") );
        keyword.append( wxT(" ") );
        bufStr.insert( 0, wxT(" ") );
        bufStr.append( wxT(" ") );
    }

    // remove continuous spaces
    keyword = CompressSpaces( keyword );
    bufStr = CompressSpaces( bufStr );

    // finally do the search
    return bufStr.find( keyword ) != wxString::npos;
}

#endif
