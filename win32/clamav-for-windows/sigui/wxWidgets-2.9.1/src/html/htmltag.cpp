/////////////////////////////////////////////////////////////////////////////
// Name:        src/html/htmltag.cpp
// Purpose:     wxHtmlTag class (represents single tag)
// Author:      Vaclav Slavik
// RCS-ID:      $Id$
// Copyright:   (c) 1999 Vaclav Slavik
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_HTML

#include "wx/html/htmltag.h"

#ifndef WX_PRECOMP
    #include "wx/colour.h"
    #include "wx/wxcrtvararg.h"
#endif

#include "wx/html/htmlpars.h"
#include "wx/html/styleparams.h"

#include "wx/vector.h"

#include <stdio.h> // for vsscanf
#include <stdarg.h>

//-----------------------------------------------------------------------------
// wxHtmlTagsCache
//-----------------------------------------------------------------------------

struct wxHtmlCacheItem
{
    // this is "pos" value passed to wxHtmlTag's constructor.
    // it is position of '<' character of the tag
    wxString::const_iterator Key;

    // Tag type
    enum Type
    {
        Type_Normal, // normal tag with a matching ending tag
        Type_NoMatchingEndingTag, // there's no ending tag for this tag
        Type_EndingTag // this is ending tag </..>
    };
    Type type;

    // end positions for the tag:
    // end1 is '<' of ending tag,
    // end2 is '>' or both are
    wxString::const_iterator End1, End2;

    // name of this tag
    wxChar *Name;
};

// NB: this is an empty class and not typedef because of forward declaration
class wxHtmlTagsCacheData : public wxVector<wxHtmlCacheItem>
{
};

bool wxIsCDATAElement(const wxChar *tag)
{
    return (wxStrcmp(tag, wxT("SCRIPT")) == 0) ||
           (wxStrcmp(tag, wxT("STYLE")) == 0);
}

bool wxIsCDATAElement(const wxString& tag)
{
    return (wxStrcmp(tag.wx_str(), wxS("SCRIPT")) == 0) ||
           (wxStrcmp(tag.wx_str(), wxS("STYLE")) == 0);
}

wxHtmlTagsCache::wxHtmlTagsCache(const wxString& source)
{
    m_Cache = new wxHtmlTagsCacheData;
    m_CachePos = 0;

    wxChar tagBuffer[256];

    const wxString::const_iterator end = source.end();
    for ( wxString::const_iterator pos = source.begin(); pos < end; ++pos )
    {
        if (*pos == wxT('<'))   // tag found:
        {
            // don't cache comment tags
            if ( wxHtmlParser::SkipCommentTag(pos, source.end()) )
                continue;

            size_t tg = Cache().size();
            Cache().push_back(wxHtmlCacheItem());

            wxString::const_iterator stpos = pos++;
            Cache()[tg].Key = stpos;

            int i;
            for ( i = 0;
                  pos < end && i < (int)WXSIZEOF(tagBuffer) - 1 &&
                  *pos != wxT('>') && !wxIsspace(*pos);
                  ++i, ++pos )
            {
                tagBuffer[i] = (wxChar)wxToupper(*pos);
            }
            tagBuffer[i] = wxT('\0');

            Cache()[tg].Name = new wxChar[i+1];
            memcpy(Cache()[tg].Name, tagBuffer, (i+1)*sizeof(wxChar));

            while (pos < end && *pos != wxT('>'))
                ++pos;

            if ((stpos+1) < end && *(stpos+1) == wxT('/')) // ending tag:
            {
                Cache()[tg].type = wxHtmlCacheItem::Type_EndingTag;
                // find matching begin tag:
                for (i = tg; i >= 0; i--)
                {
                    if ((Cache()[i].type == wxHtmlCacheItem::Type_NoMatchingEndingTag) && (wxStrcmp(Cache()[i].Name, tagBuffer+1) == 0))
                    {
                        Cache()[i].type = wxHtmlCacheItem::Type_Normal;
                        Cache()[i].End1 = stpos;
                        Cache()[i].End2 = pos + 1;
                        break;
                    }
                }
            }
            else
            {
                Cache()[tg].type = wxHtmlCacheItem::Type_NoMatchingEndingTag;

                if (wxIsCDATAElement(tagBuffer))
                {
                    // store the orig pos in case we are missing the closing
                    // tag (see below)
                    const wxString::const_iterator old_pos = pos;
                    bool foundCloseTag = false;

                    // find next matching tag
                    int tag_len = wxStrlen(tagBuffer);
                    while (pos < end)
                    {
                        // find the ending tag
                        while (pos + 1 < end &&
                               (*pos != '<' || *(pos+1) != '/'))
                            ++pos;
                        if (*pos == '<')
                            ++pos;

                        // see if it matches
                        int match_pos = 0;
                        while (pos < end && match_pos < tag_len )
                        {
                            wxChar c = *pos;
                            if ( c == '>' || c == '<' )
                                break;

                            // cast to wxChar needed to suppress warning in
                            // Unicode build
                            if ((wxChar)wxToupper(c) == tagBuffer[match_pos])
                            {
                                ++match_pos;
                            }
                            else if (c == wxT(' ') || c == wxT('\n') ||
                                c == wxT('\r') || c == wxT('\t'))
                            {
                                // need to skip over these
                            }
                            else
                            {
                                match_pos = 0;
                            }
                            ++pos;
                        }

                        // found a match
                        if (match_pos == tag_len)
                        {
                            pos = pos - tag_len - 3;
                            foundCloseTag = true;
                            break;
                        }
                        else // keep looking for the closing tag
                        {
                            ++pos;
                        }
                    }
                    if (!foundCloseTag)
                    {
                        // we didn't find closing tag; this means the markup
                        // is incorrect and the best thing we can do is to
                        // ignore the unclosed tag and continue parsing as if
                        // it didn't exist:
                        pos = old_pos;
                    }
                }
            }
        }
    }

    // ok, we're done, now we'll free .Name members of cache - we don't need it anymore:
    for ( wxHtmlTagsCacheData::iterator i = Cache().begin();
          i != Cache().end(); ++i )
    {
        wxDELETEA(i->Name);
    }
}

wxHtmlTagsCache::~wxHtmlTagsCache()
{
    delete m_Cache;
}

void wxHtmlTagsCache::QueryTag(const wxString::const_iterator& at,
                               const wxString::const_iterator& inputEnd,
                               wxString::const_iterator *end1,
                               wxString::const_iterator *end2,
                               bool *hasEnding)
{
    if (Cache().empty())
        return;

    if (Cache()[m_CachePos].Key != at)
    {
        int delta = (at < Cache()[m_CachePos].Key) ? -1 : 1;
        do
        {
            m_CachePos += delta;

            if ( m_CachePos < 0 || m_CachePos >= (int)Cache().size() )
            {
                if ( m_CachePos < 0 )
                    m_CachePos = 0;
                else
                    m_CachePos = Cache().size() - 1;
                // something is very wrong with HTML, give up by returning an
                // impossibly large value which is going to be ignored by the
                // caller
                *end1 =
                *end2 = inputEnd;
                *hasEnding = true;
                return;
            }
        }
        while (Cache()[m_CachePos].Key != at);
    }

    switch ( Cache()[m_CachePos].type )
    {
        case wxHtmlCacheItem::Type_Normal:
            *end1 = Cache()[m_CachePos].End1;
            *end2 = Cache()[m_CachePos].End2;
            *hasEnding = true;
            break;

        case wxHtmlCacheItem::Type_EndingTag:
            wxFAIL_MSG("QueryTag called for ending tag - can't be");
            // but if it does happen, fall through, better than crashing

        case wxHtmlCacheItem::Type_NoMatchingEndingTag:
            // If input HTML is invalid and there's no closing tag for this
            // one, pretend that it runs all the way to the end of input
            *end1 = inputEnd;
            *end2 = inputEnd;
            *hasEnding = false;
            break;
    }
}




//-----------------------------------------------------------------------------
// wxHtmlTag
//-----------------------------------------------------------------------------

wxHtmlTag::wxHtmlTag(wxHtmlTag *parent,
                     const wxString *source,
                     const wxString::const_iterator& pos,
                     const wxString::const_iterator& end_pos,
                     wxHtmlTagsCache *cache,
                     wxHtmlEntitiesParser *entParser)
{
    /* Setup DOM relations */

    m_Next = NULL;
    m_FirstChild = m_LastChild = NULL;
    m_Parent = parent;
    if (parent)
    {
        m_Prev = m_Parent->m_LastChild;
        if (m_Prev == NULL)
            m_Parent->m_FirstChild = this;
        else
            m_Prev->m_Next = this;
        m_Parent->m_LastChild = this;
    }
    else
        m_Prev = NULL;

    /* Find parameters and their values: */

    wxChar c wxDUMMY_INITIALIZE(0);

    // fill-in name, params and begin pos:
    wxString::const_iterator i(pos+1);

    // find tag's name and convert it to uppercase:
    while ((i < end_pos) &&
           ((c = *(i++)) != wxT(' ') && c != wxT('\r') &&
             c != wxT('\n') && c != wxT('\t') &&
             c != wxT('>') && c != wxT('/')))
    {
        if ((c >= wxT('a')) && (c <= wxT('z')))
            c -= (wxT('a') - wxT('A'));
        m_Name << c;
    }

    // if the tag has parameters, read them and "normalize" them,
    // i.e. convert to uppercase, replace whitespaces by spaces and
    // remove whitespaces around '=':
    if (*(i-1) != wxT('>'))
    {
        #define IS_WHITE(c) (c == wxT(' ') || c == wxT('\r') || \
                             c == wxT('\n') || c == wxT('\t'))
        wxString pname, pvalue;
        wxChar quote;
        enum
        {
            ST_BEFORE_NAME = 1,
            ST_NAME,
            ST_BEFORE_EQ,
            ST_BEFORE_VALUE,
            ST_VALUE
        } state;

        quote = 0;
        state = ST_BEFORE_NAME;
        while (i < end_pos)
        {
            c = *(i++);

            if (c == wxT('>') && !(state == ST_VALUE && quote != 0))
            {
                if (state == ST_BEFORE_EQ || state == ST_NAME)
                {
                    m_ParamNames.Add(pname);
                    m_ParamValues.Add(wxGetEmptyString());
                }
                else if (state == ST_VALUE && quote == 0)
                {
                    m_ParamNames.Add(pname);
                    if (entParser)
                        m_ParamValues.Add(entParser->Parse(pvalue));
                    else
                        m_ParamValues.Add(pvalue);
                }
                break;
            }
            switch (state)
            {
                case ST_BEFORE_NAME:
                    if (!IS_WHITE(c))
                    {
                        pname = c;
                        state = ST_NAME;
                    }
                    break;
                case ST_NAME:
                    if (IS_WHITE(c))
                        state = ST_BEFORE_EQ;
                    else if (c == wxT('='))
                        state = ST_BEFORE_VALUE;
                    else
                        pname << c;
                    break;
                case ST_BEFORE_EQ:
                    if (c == wxT('='))
                        state = ST_BEFORE_VALUE;
                    else if (!IS_WHITE(c))
                    {
                        m_ParamNames.Add(pname);
                        m_ParamValues.Add(wxGetEmptyString());
                        pname = c;
                        state = ST_NAME;
                    }
                    break;
                case ST_BEFORE_VALUE:
                    if (!IS_WHITE(c))
                    {
                        if (c == wxT('"') || c == wxT('\''))
                            quote = c, pvalue = wxGetEmptyString();
                        else
                            quote = 0, pvalue = c;
                        state = ST_VALUE;
                    }
                    break;
                case ST_VALUE:
                    if ((quote != 0 && c == quote) ||
                        (quote == 0 && IS_WHITE(c)))
                    {
                        m_ParamNames.Add(pname);
                        if (quote == 0)
                        {
                            // VS: backward compatibility, no real reason,
                            //     but wxHTML code relies on this... :(
                            pvalue.MakeUpper();
                        }
                        if (entParser)
                            m_ParamValues.Add(entParser->Parse(pvalue));
                        else
                            m_ParamValues.Add(pvalue);
                        state = ST_BEFORE_NAME;
                    }
                    else
                        pvalue << c;
                    break;
            }
        }

        #undef IS_WHITE
    }
    m_Begin = i;
    cache->QueryTag(pos, source->end(), &m_End1, &m_End2, &m_hasEnding);
    if (m_End1 > end_pos) m_End1 = end_pos;
    if (m_End2 > end_pos) m_End2 = end_pos;

#if WXWIN_COMPATIBILITY_2_8
    m_sourceStart = source->begin();
#endif

    // Try to parse any style parameters that can be handled simply by
    // converting them to the equivalent HTML 3 attributes: this is a far cry
    // from perfect but better than nothing.
    static const struct EquivAttr
    {
        const char *style;
        const char *attr;
    } equivAttrs[] =
    {
        { "text-align",         "ALIGN"         },
        { "width",              "WIDTH"         },
        { "vertical-align",     "VALIGN"        },
        { "background",         "BGCOLOR"       },
    };

    wxHtmlStyleParams styleParams(*this);
    for ( unsigned n = 0; n < WXSIZEOF(equivAttrs); n++ )
    {
        const EquivAttr& ea = equivAttrs[n];
        if ( styleParams.HasParam(ea.style) && !HasParam(ea.attr) )
        {
            m_ParamNames.Add(ea.attr);
            m_ParamValues.Add(styleParams.GetParam(ea.style));
        }
    }
}

wxHtmlTag::~wxHtmlTag()
{
    wxHtmlTag *t1, *t2;
    t1 = m_FirstChild;
    while (t1)
    {
        t2 = t1->GetNextSibling();
        delete t1;
        t1 = t2;
    }
}

bool wxHtmlTag::HasParam(const wxString& par) const
{
    return (m_ParamNames.Index(par, false) != wxNOT_FOUND);
}

wxString wxHtmlTag::GetParam(const wxString& par, bool with_quotes) const
{
    int index = m_ParamNames.Index(par, false);
    if (index == wxNOT_FOUND)
        return wxGetEmptyString();
    if (with_quotes)
    {
        // VS: backward compatibility, seems to be never used by wxHTML...
        wxString s;
        s << wxT('"') << m_ParamValues[index] << wxT('"');
        return s;
    }
    else
        return m_ParamValues[index];
}

int wxHtmlTag::ScanParam(const wxString& par,
                         const char *format,
                         void *param) const
{
    wxString parval = GetParam(par);
    return wxSscanf(parval, format, param);
}

int wxHtmlTag::ScanParam(const wxString& par,
                         const wchar_t *format,
                         void *param) const
{
    wxString parval = GetParam(par);
    return wxSscanf(parval, format, param);
}

/* static */
bool wxHtmlTag::ParseAsColour(const wxString& str, wxColour *clr)
{
    wxCHECK_MSG( clr, false, wxT("invalid colour argument") );

    // handle colours defined in HTML 4.0 first:
    if (str.length() > 1 && str[0] != wxT('#'))
    {
        #define HTML_COLOUR(name, r, g, b)              \
            if (str.IsSameAs(wxS(name), false))         \
                { clr->Set(r, g, b); return true; }
        HTML_COLOUR("black",   0x00,0x00,0x00)
        HTML_COLOUR("silver",  0xC0,0xC0,0xC0)
        HTML_COLOUR("gray",    0x80,0x80,0x80)
        HTML_COLOUR("white",   0xFF,0xFF,0xFF)
        HTML_COLOUR("maroon",  0x80,0x00,0x00)
        HTML_COLOUR("red",     0xFF,0x00,0x00)
        HTML_COLOUR("purple",  0x80,0x00,0x80)
        HTML_COLOUR("fuchsia", 0xFF,0x00,0xFF)
        HTML_COLOUR("green",   0x00,0x80,0x00)
        HTML_COLOUR("lime",    0x00,0xFF,0x00)
        HTML_COLOUR("olive",   0x80,0x80,0x00)
        HTML_COLOUR("yellow",  0xFF,0xFF,0x00)
        HTML_COLOUR("navy",    0x00,0x00,0x80)
        HTML_COLOUR("blue",    0x00,0x00,0xFF)
        HTML_COLOUR("teal",    0x00,0x80,0x80)
        HTML_COLOUR("aqua",    0x00,0xFF,0xFF)
        #undef HTML_COLOUR
    }

    // then try to parse #rrggbb representations or set from other well
    // known names (note that this doesn't strictly conform to HTML spec,
    // but it doesn't do real harm -- but it *must* be done after the standard
    // colors are handled above):
    if (clr->Set(str))
        return true;

    return false;
}

bool wxHtmlTag::GetParamAsColour(const wxString& par, wxColour *clr) const
{
    const wxString str = GetParam(par);
    return !str.empty() && ParseAsColour(str, clr);
}

bool wxHtmlTag::GetParamAsInt(const wxString& par, int *clr) const
{
    if ( !HasParam(par) )
        return false;

    long i;
    if ( !GetParam(par).ToLong(&i) )
        return false;

    *clr = (int)i;
    return true;
}

wxString wxHtmlTag::GetAllParams() const
{
    // VS: this function is for backward compatibility only,
    //     never used by wxHTML
    wxString s;
    size_t cnt = m_ParamNames.GetCount();
    for (size_t i = 0; i < cnt; i++)
    {
        s << m_ParamNames[i];
        s << wxT('=');
        if (m_ParamValues[i].Find(wxT('"')) != wxNOT_FOUND)
            s << wxT('\'') << m_ParamValues[i] << wxT('\'');
        else
            s << wxT('"') << m_ParamValues[i] << wxT('"');
    }
    return s;
}

wxHtmlTag *wxHtmlTag::GetFirstSibling() const
{
    if (m_Parent)
        return m_Parent->m_FirstChild;
    else
    {
        wxHtmlTag *cur = (wxHtmlTag*)this;
        while (cur->m_Prev)
            cur = cur->m_Prev;
        return cur;
    }
}

wxHtmlTag *wxHtmlTag::GetLastSibling() const
{
    if (m_Parent)
        return m_Parent->m_LastChild;
    else
    {
        wxHtmlTag *cur = (wxHtmlTag*)this;
        while (cur->m_Next)
            cur = cur->m_Next;
        return cur;
    }
}

wxHtmlTag *wxHtmlTag::GetNextTag() const
{
    if (m_FirstChild) return m_FirstChild;
    if (m_Next) return m_Next;
    wxHtmlTag *cur = m_Parent;
    if (!cur) return NULL;
    while (cur->m_Parent && !cur->m_Next)
        cur = cur->m_Parent;
    return cur->m_Next;
}

#endif
