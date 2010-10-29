/////////////////////////////////////////////////////////////////////////////
// Name:        src/xml/xml.cpp
// Purpose:     wxXmlDocument - XML parser & data holder class
// Author:      Vaclav Slavik
// Created:     2000/03/05
// RCS-ID:      $Id$
// Copyright:   (c) 2000 Vaclav Slavik
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_XML

#include "wx/xml/xml.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/app.h"
#endif

#include "wx/wfstream.h"
#include "wx/datstrm.h"
#include "wx/zstream.h"
#include "wx/strconv.h"
#include "wx/scopedptr.h"

#include "expat.h" // from Expat

// DLL options compatibility check:
WX_CHECK_BUILD_OPTIONS("wxXML")


IMPLEMENT_CLASS(wxXmlDocument, wxObject)


// a private utility used by wxXML
static bool wxIsWhiteOnly(const wxString& buf);


//-----------------------------------------------------------------------------
//  wxXmlNode
//-----------------------------------------------------------------------------

wxXmlNode::wxXmlNode(wxXmlNode *parent,wxXmlNodeType type,
                     const wxString& name, const wxString& content,
                     wxXmlAttribute *attrs, wxXmlNode *next, int lineNo)
    : m_type(type), m_name(name), m_content(content),
      m_attrs(attrs), m_parent(parent),
      m_children(NULL), m_next(next),
      m_lineNo(lineNo)
{
    if (m_parent)
    {
        if (m_parent->m_children)
        {
            m_next = m_parent->m_children;
            m_parent->m_children = this;
        }
        else
            m_parent->m_children = this;
    }
}

wxXmlNode::wxXmlNode(wxXmlNodeType type, const wxString& name,
                     const wxString& content,
                     int lineNo)
    : m_type(type), m_name(name), m_content(content),
      m_attrs(NULL), m_parent(NULL),
      m_children(NULL), m_next(NULL),
      m_lineNo(lineNo)
{}

wxXmlNode::wxXmlNode(const wxXmlNode& node)
{
    m_next = NULL;
    m_parent = NULL;
    DoCopy(node);
}

wxXmlNode::~wxXmlNode()
{
    wxXmlNode *c, *c2;
    for (c = m_children; c; c = c2)
    {
        c2 = c->m_next;
        delete c;
    }

    wxXmlAttribute *p, *p2;
    for (p = m_attrs; p; p = p2)
    {
        p2 = p->GetNext();
        delete p;
    }
}

wxXmlNode& wxXmlNode::operator=(const wxXmlNode& node)
{
    wxDELETE(m_attrs);
    wxDELETE(m_children);
    DoCopy(node);
    return *this;
}

void wxXmlNode::DoCopy(const wxXmlNode& node)
{
    m_type = node.m_type;
    m_name = node.m_name;
    m_content = node.m_content;
    m_lineNo = node.m_lineNo;
    m_children = NULL;

    wxXmlNode *n = node.m_children;
    while (n)
    {
        AddChild(new wxXmlNode(*n));
        n = n->GetNext();
    }

    m_attrs = NULL;
    wxXmlAttribute *p = node.m_attrs;
    while (p)
    {
       AddAttribute(p->GetName(), p->GetValue());
       p = p->GetNext();
    }
}

bool wxXmlNode::HasAttribute(const wxString& attrName) const
{
    wxXmlAttribute *attr = GetAttributes();

    while (attr)
    {
        if (attr->GetName() == attrName) return true;
        attr = attr->GetNext();
    }

    return false;
}

bool wxXmlNode::GetAttribute(const wxString& attrName, wxString *value) const
{
    wxCHECK_MSG( value, false, "value argument must not be NULL" );

    wxXmlAttribute *attr = GetAttributes();

    while (attr)
    {
        if (attr->GetName() == attrName)
        {
            *value = attr->GetValue();
            return true;
        }
        attr = attr->GetNext();
    }

    return false;
}

wxString wxXmlNode::GetAttribute(const wxString& attrName, const wxString& defaultVal) const
{
    wxString tmp;
    if (GetAttribute(attrName, &tmp))
        return tmp;

    return defaultVal;
}

void wxXmlNode::AddChild(wxXmlNode *child)
{
    if (m_children == NULL)
        m_children = child;
    else
    {
        wxXmlNode *ch = m_children;
        while (ch->m_next) ch = ch->m_next;
        ch->m_next = child;
    }
    child->m_next = NULL;
    child->m_parent = this;
}

// inserts a new node in front of 'followingNode'
bool wxXmlNode::InsertChild(wxXmlNode *child, wxXmlNode *followingNode)
{
    wxCHECK_MSG( child, false, "cannot insert a NULL node!" );
    wxCHECK_MSG( child->m_parent == NULL, false, "node already has a parent" );
    wxCHECK_MSG( child->m_next == NULL, false, "node already has m_next" );
    wxCHECK_MSG( followingNode == NULL || followingNode->GetParent() == this,
                 false,
                 "wxXmlNode::InsertChild - followingNode has incorrect parent" );

    // this is for backward compatibility, NULL was allowed here thanks to
    // the confusion about followingNode's meaning
    if ( followingNode == NULL )
        followingNode = m_children;

    if ( m_children == followingNode )
    {
        child->m_next = m_children;
        m_children = child;
    }
    else
    {
        wxXmlNode *ch = m_children;
        while ( ch && ch->m_next != followingNode )
            ch = ch->m_next;
        if ( !ch )
        {
            wxFAIL_MSG( "followingNode has this node as parent, but couldn't be found among children" );
            return false;
        }

        child->m_next = followingNode;
        ch->m_next = child;
    }

    child->m_parent = this;
    return true;
}

// inserts a new node right after 'precedingNode'
bool wxXmlNode::InsertChildAfter(wxXmlNode *child, wxXmlNode *precedingNode)
{
    wxCHECK_MSG( child, false, "cannot insert a NULL node!" );
    wxCHECK_MSG( child->m_parent == NULL, false, "node already has a parent" );
    wxCHECK_MSG( child->m_next == NULL, false, "node already has m_next" );
    wxCHECK_MSG( precedingNode == NULL || precedingNode->m_parent == this, false,
                 "precedingNode has wrong parent" );

    if ( precedingNode )
    {
        child->m_next = precedingNode->m_next;
        precedingNode->m_next = child;
    }
    else // precedingNode == NULL
    {
        wxCHECK_MSG( m_children == NULL, false,
                     "NULL precedingNode only makes sense when there are no children" );

        child->m_next = m_children;
        m_children = child;
    }

    child->m_parent = this;
    return true;
}

bool wxXmlNode::RemoveChild(wxXmlNode *child)
{
    if (m_children == NULL)
        return false;
    else if (m_children == child)
    {
        m_children = child->m_next;
        child->m_parent = NULL;
        child->m_next = NULL;
        return true;
    }
    else
    {
        wxXmlNode *ch = m_children;
        while (ch->m_next)
        {
            if (ch->m_next == child)
            {
                ch->m_next = child->m_next;
                child->m_parent = NULL;
                child->m_next = NULL;
                return true;
            }
            ch = ch->m_next;
        }
        return false;
    }
}

void wxXmlNode::AddAttribute(const wxString& name, const wxString& value)
{
    AddProperty(name, value);
}

void wxXmlNode::AddAttribute(wxXmlAttribute *attr)
{
    AddProperty(attr);
}

bool wxXmlNode::DeleteAttribute(const wxString& name)
{
    return DeleteProperty(name);
}

void wxXmlNode::AddProperty(const wxString& name, const wxString& value)
{
    AddProperty(new wxXmlAttribute(name, value, NULL));
}

void wxXmlNode::AddProperty(wxXmlAttribute *attr)
{
    if (m_attrs == NULL)
        m_attrs = attr;
    else
    {
        wxXmlAttribute *p = m_attrs;
        while (p->GetNext()) p = p->GetNext();
        p->SetNext(attr);
    }
}

bool wxXmlNode::DeleteProperty(const wxString& name)
{
    wxXmlAttribute *attr;

    if (m_attrs == NULL)
        return false;

    else if (m_attrs->GetName() == name)
    {
        attr = m_attrs;
        m_attrs = attr->GetNext();
        attr->SetNext(NULL);
        delete attr;
        return true;
    }

    else
    {
        wxXmlAttribute *p = m_attrs;
        while (p->GetNext())
        {
            if (p->GetNext()->GetName() == name)
            {
                attr = p->GetNext();
                p->SetNext(attr->GetNext());
                attr->SetNext(NULL);
                delete attr;
                return true;
            }
            p = p->GetNext();
        }
        return false;
    }
}

wxString wxXmlNode::GetNodeContent() const
{
    wxXmlNode *n = GetChildren();

    while (n)
    {
        if (n->GetType() == wxXML_TEXT_NODE ||
            n->GetType() == wxXML_CDATA_SECTION_NODE)
            return n->GetContent();
        n = n->GetNext();
    }
    return wxEmptyString;
}

int wxXmlNode::GetDepth(wxXmlNode *grandparent) const
{
    const wxXmlNode *n = this;
    int ret = -1;

    do
    {
        ret++;
        n = n->GetParent();
        if (n == grandparent)
            return ret;

    } while (n);

    return wxNOT_FOUND;
}

bool wxXmlNode::IsWhitespaceOnly() const
{
    return wxIsWhiteOnly(m_content);
}



//-----------------------------------------------------------------------------
//  wxXmlDocument
//-----------------------------------------------------------------------------

wxXmlDocument::wxXmlDocument()
    : m_version(wxS("1.0")), m_fileEncoding(wxS("utf-8")), m_root(NULL)
{
#if !wxUSE_UNICODE
    m_encoding = wxS("UTF-8");
#endif
}

wxXmlDocument::wxXmlDocument(const wxString& filename, const wxString& encoding)
              :wxObject(), m_root(NULL)
{
    if ( !Load(filename, encoding) )
    {
        wxDELETE(m_root);
    }
}

wxXmlDocument::wxXmlDocument(wxInputStream& stream, const wxString& encoding)
              :wxObject(), m_root(NULL)
{
    if ( !Load(stream, encoding) )
    {
        wxDELETE(m_root);
    }
}

wxXmlDocument::wxXmlDocument(const wxXmlDocument& doc)
              :wxObject()
{
    DoCopy(doc);
}

wxXmlDocument& wxXmlDocument::operator=(const wxXmlDocument& doc)
{
    wxDELETE(m_root);
    DoCopy(doc);
    return *this;
}

void wxXmlDocument::DoCopy(const wxXmlDocument& doc)
{
    m_version = doc.m_version;
#if !wxUSE_UNICODE
    m_encoding = doc.m_encoding;
#endif
    m_fileEncoding = doc.m_fileEncoding;

    if (doc.m_root)
        m_root = new wxXmlNode(*doc.m_root);
    else
        m_root = NULL;
}

bool wxXmlDocument::Load(const wxString& filename, const wxString& encoding, int flags)
{
    wxFileInputStream stream(filename);
    if (!stream.Ok())
        return false;
    return Load(stream, encoding, flags);
}

bool wxXmlDocument::Save(const wxString& filename, int indentstep) const
{
    wxFileOutputStream stream(filename);
    if (!stream.Ok())
        return false;
    return Save(stream, indentstep);
}



//-----------------------------------------------------------------------------
//  wxXmlDocument loading routines
//-----------------------------------------------------------------------------

// converts Expat-produced string in UTF-8 into wxString using the specified
// conv or keep in UTF-8 if conv is NULL
static wxString CharToString(wxMBConv *conv,
                             const char *s, size_t len = wxString::npos)
{
#if !wxUSE_UNICODE
    if ( conv )
    {
        // there can be no embedded NULs in this string so we don't need the
        // output length, it will be NUL-terminated
        const wxWCharBuffer wbuf(
            wxConvUTF8.cMB2WC(s, len == wxString::npos ? wxNO_LEN : len, NULL));

        return wxString(wbuf, *conv);
    }
    // else: the string is wanted in UTF-8
#endif // !wxUSE_UNICODE

    wxUnusedVar(conv);
    return wxString::FromUTF8Unchecked(s, len);
}

// returns true if the given string contains only whitespaces
bool wxIsWhiteOnly(const wxString& buf)
{
    for ( wxString::const_iterator i = buf.begin(); i != buf.end(); ++i )
    {
        wxChar c = *i;
        if ( c != wxS(' ') && c != wxS('\t') && c != wxS('\n') && c != wxS('\r'))
            return false;
    }
    return true;
}


struct wxXmlParsingContext
{
    wxXmlParsingContext()
        : conv(NULL),
          root(NULL),
          node(NULL),
          lastChild(NULL),
          lastAsText(NULL),
          removeWhiteOnlyNodes(false)
    {}

    XML_Parser parser;
    wxMBConv  *conv;
    wxXmlNode *root;
    wxXmlNode *node;                    // the node being parsed
    wxXmlNode *lastChild;               // the last child of "node"
    wxXmlNode *lastAsText;              // the last _text_ child of "node"
    wxString   encoding;
    wxString   version;
    bool       removeWhiteOnlyNodes;
};

// checks that ctx->lastChild is in consistent state
#define ASSERT_LAST_CHILD_OK(ctx)                                   \
    wxASSERT( ctx->lastChild == NULL ||                             \
              ctx->lastChild->GetNext() == NULL );                  \
    wxASSERT( ctx->lastChild == NULL ||                             \
              ctx->lastChild->GetParent() == ctx->node )

extern "C" {
static void StartElementHnd(void *userData, const char *name, const char **atts)
{
    wxXmlParsingContext *ctx = (wxXmlParsingContext*)userData;
    wxXmlNode *node = new wxXmlNode(wxXML_ELEMENT_NODE,
                                    CharToString(ctx->conv, name),
                                    wxEmptyString,
                                    XML_GetCurrentLineNumber(ctx->parser));
    const char **a = atts;

    // add node attributes
    while (*a)
    {
        node->AddAttribute(CharToString(ctx->conv, a[0]), CharToString(ctx->conv, a[1]));
        a += 2;
    }

    if (ctx->root == NULL)
    {
        ctx->root = node;
    }
    else
    {
        ASSERT_LAST_CHILD_OK(ctx);
        ctx->node->InsertChildAfter(node, ctx->lastChild);
    }

    ctx->lastAsText = NULL;
    ctx->lastChild = NULL; // our new node "node" has no children yet

    ctx->node = node;
}

static void EndElementHnd(void *userData, const char* WXUNUSED(name))
{
    wxXmlParsingContext *ctx = (wxXmlParsingContext*)userData;

    // we're exiting the last children of ctx->node->GetParent() and going
    // back one level up, so current value of ctx->node points to the last
    // child of ctx->node->GetParent()
    ctx->lastChild = ctx->node;

    ctx->node = ctx->node->GetParent();
    ctx->lastAsText = NULL;
}

static void TextHnd(void *userData, const char *s, int len)
{
    wxXmlParsingContext *ctx = (wxXmlParsingContext*)userData;
    wxString str = CharToString(ctx->conv, s, len);

    if (ctx->lastAsText)
    {
        ctx->lastAsText->SetContent(ctx->lastAsText->GetContent() + str);
    }
    else
    {
        bool whiteOnly = false;
        if (ctx->removeWhiteOnlyNodes)
            whiteOnly = wxIsWhiteOnly(str);

        if (!whiteOnly)
        {
            wxXmlNode *textnode =
                new wxXmlNode(wxXML_TEXT_NODE, wxS("text"), str,
                              XML_GetCurrentLineNumber(ctx->parser));

            ASSERT_LAST_CHILD_OK(ctx);
            ctx->node->InsertChildAfter(textnode, ctx->lastChild);
            ctx->lastChild= ctx->lastAsText = textnode;
        }
    }
}

static void StartCdataHnd(void *userData)
{
    wxXmlParsingContext *ctx = (wxXmlParsingContext*)userData;

    wxXmlNode *textnode =
        new wxXmlNode(wxXML_CDATA_SECTION_NODE, wxS("cdata"), wxS(""),
                      XML_GetCurrentLineNumber(ctx->parser));

    ASSERT_LAST_CHILD_OK(ctx);
    ctx->node->InsertChildAfter(textnode, ctx->lastChild);
    ctx->lastChild= ctx->lastAsText = textnode;
}

static void EndCdataHnd(void *userData)
{
    wxXmlParsingContext *ctx = (wxXmlParsingContext*)userData;

    // we need to reset this pointer so that subsequent text nodes don't append
    // their contents to this one but create new wxXML_TEXT_NODE objects (or
    // not create anything at all if only white space follows the CDATA section
    // and wxXMLDOC_KEEP_WHITESPACE_NODES is not used as is commonly the case)
    ctx->lastAsText = NULL;
}

static void CommentHnd(void *userData, const char *data)
{
    wxXmlParsingContext *ctx = (wxXmlParsingContext*)userData;

    if (ctx->node)
    {
        wxXmlNode *commentnode =
            new wxXmlNode(wxXML_COMMENT_NODE,
                          wxS("comment"), CharToString(ctx->conv, data),
                          XML_GetCurrentLineNumber(ctx->parser));

        ASSERT_LAST_CHILD_OK(ctx);
        ctx->node->InsertChildAfter(commentnode, ctx->lastChild);
        ctx->lastChild = commentnode;
    }
    //else: ctx->node == NULL happens if there is a comment before
    //      the root element. We current don't have a way to represent
    //      these in wxXmlDocument (FIXME).

    ctx->lastAsText = NULL;
}

static void DefaultHnd(void *userData, const char *s, int len)
{
    // XML header:
    if (len > 6 && memcmp(s, "<?xml ", 6) == 0)
    {
        wxXmlParsingContext *ctx = (wxXmlParsingContext*)userData;

        wxString buf = CharToString(ctx->conv, s, (size_t)len);
        int pos;
        pos = buf.Find(wxS("encoding="));
        if (pos != wxNOT_FOUND)
            ctx->encoding = buf.Mid(pos + 10).BeforeFirst(buf[(size_t)pos+9]);
        pos = buf.Find(wxS("version="));
        if (pos != wxNOT_FOUND)
            ctx->version = buf.Mid(pos + 9).BeforeFirst(buf[(size_t)pos+8]);
    }
}

static int UnknownEncodingHnd(void * WXUNUSED(encodingHandlerData),
                              const XML_Char *name, XML_Encoding *info)
{
    // We must build conversion table for expat. The easiest way to do so
    // is to let wxCSConv convert as string containing all characters to
    // wide character representation:
    wxCSConv conv(name);
    char mbBuf[2];
    wchar_t wcBuf[10];
    size_t i;

    mbBuf[1] = 0;
    info->map[0] = 0;
    for (i = 0; i < 255; i++)
    {
        mbBuf[0] = (char)(i+1);
        if (conv.MB2WC(wcBuf, mbBuf, 2) == (size_t)-1)
        {
            // invalid/undefined byte in the encoding:
            info->map[i+1] = -1;
        }
        info->map[i+1] = (int)wcBuf[0];
    }

    info->data = NULL;
    info->convert = NULL;
    info->release = NULL;

    return 1;
}

} // extern "C"

bool wxXmlDocument::Load(wxInputStream& stream, const wxString& encoding, int flags)
{
#if wxUSE_UNICODE
    (void)encoding;
#else
    m_encoding = encoding;
#endif

    const size_t BUFSIZE = 1024;
    char buf[BUFSIZE];
    wxXmlParsingContext ctx;
    bool done;
    XML_Parser parser = XML_ParserCreate(NULL);

    ctx.encoding = wxS("UTF-8"); // default in absence of encoding=""
    ctx.conv = NULL;
#if !wxUSE_UNICODE
    if ( encoding.CmpNoCase(wxS("UTF-8")) != 0 )
        ctx.conv = new wxCSConv(encoding);
#endif
    ctx.removeWhiteOnlyNodes = (flags & wxXMLDOC_KEEP_WHITESPACE_NODES) == 0;
    ctx.parser = parser;

    XML_SetUserData(parser, (void*)&ctx);
    XML_SetElementHandler(parser, StartElementHnd, EndElementHnd);
    XML_SetCharacterDataHandler(parser, TextHnd);
    XML_SetCdataSectionHandler(parser, StartCdataHnd, EndCdataHnd);;
    XML_SetCommentHandler(parser, CommentHnd);
    XML_SetDefaultHandler(parser, DefaultHnd);
    XML_SetUnknownEncodingHandler(parser, UnknownEncodingHnd, NULL);

    bool ok = true;
    do
    {
        size_t len = stream.Read(buf, BUFSIZE).LastRead();
        done = (len < BUFSIZE);
        if (!XML_Parse(parser, buf, len, done))
        {
            wxString error(XML_ErrorString(XML_GetErrorCode(parser)),
                           *wxConvCurrent);
            wxLogError(_("XML parsing error: '%s' at line %d"),
                       error.c_str(),
                       (int)XML_GetCurrentLineNumber(parser));
            ok = false;
            break;
        }
    } while (!done);

    if (ok)
    {
        if (!ctx.version.empty())
            SetVersion(ctx.version);
        if (!ctx.encoding.empty())
            SetFileEncoding(ctx.encoding);
        SetRoot(ctx.root);
    }
    else
    {
        delete ctx.root;
    }

    XML_ParserFree(parser);
#if !wxUSE_UNICODE
    if ( ctx.conv )
        delete ctx.conv;
#endif

    return ok;

}



//-----------------------------------------------------------------------------
//  wxXmlDocument saving routines
//-----------------------------------------------------------------------------

// helpers for XML generation
namespace
{

// write string to output:
bool OutputString(wxOutputStream& stream,
                  const wxString& str,
                  wxMBConv *convMem,
                  wxMBConv *convFile)
{
    if (str.empty())
        return true;

#if wxUSE_UNICODE
    wxUnusedVar(convMem);
    if ( !convFile )
        convFile = &wxConvUTF8;

    const wxScopedCharBuffer buf(str.mb_str(*convFile));
    if ( !buf.length() )
    {
        // conversion failed, can't write this string in an XML file in this
        // (presumably non-UTF-8) encoding
        return false;
    }

    stream.Write(buf, buf.length());
#else // !wxUSE_UNICODE
    if ( convFile && convMem )
    {
        wxString str2(str.wc_str(*convMem), *convFile);
        stream.Write(str2.mb_str(), str2.length());
    }
    else // no conversions to do
    {
        stream.Write(str.mb_str(), str.length());
    }
#endif // wxUSE_UNICODE/!wxUSE_UNICODE

    return stream.IsOk();
}

// flags for OutputStringEnt()
enum
{
    XML_ESCAPE_QUOTES = 1
};

// Same as above, but create entities first.
// Translates '<' to "&lt;", '>' to "&gt;" and '&' to "&amp;"
bool OutputStringEnt(wxOutputStream& stream,
                     const wxString& str,
                     wxMBConv *convMem,
                     wxMBConv *convFile,
                     int flags = 0)
{
    const size_t len = str.length();
    size_t i,
           last = 0;
    for (i = 0; i < len; i++)
    {
        wxChar c = str.GetChar(i);
        if (c == wxS('<') || c == wxS('>') ||
            (c == wxS('&') && str.substr(i+1, 4) != wxS("amp;")) ||
            ((flags & XML_ESCAPE_QUOTES) && c == wxS('"')))
        {
            if ( !OutputString(stream, str.substr(last, i - last),
                               convMem, convFile) )
                return false;

            const char *escaped;
            switch ( c )
            {
                case wxS('<'):
                    escaped = "&lt;";
                    break;
                case wxS('>'):
                    escaped = "&gt;";
                    break;
                case wxS('&'):
                    escaped = "&amp;";
                    break;
                case wxS('"'):
                    escaped = "&quot;";
                    break;
                default:
                    wxFAIL_MSG( "logic error in the code" );
                    return false;
            }

            if ( !OutputString(stream, escaped, convMem, convFile) )
                return false;

            last = i + 1;
        }
    }

    return OutputString(stream, str.substr(last, i - last), convMem, convFile);
}

bool OutputIndentation(wxOutputStream& stream,
                       int indent,
                       wxMBConv *convMem,
                       wxMBConv *convFile)
{
    wxString str(wxS("\n"));
    str += wxString(indent, wxS(' '));
    return OutputString(stream, str, convMem, convFile);
}

bool OutputNode(wxOutputStream& stream,
                wxXmlNode *node,
                int indent,
                wxMBConv *convMem,
                wxMBConv *convFile,
                int indentstep)
{
    bool rc;
    switch (node->GetType())
    {
        case wxXML_CDATA_SECTION_NODE:
            rc = OutputString(stream, wxS("<![CDATA["), convMem, convFile) &&
                 OutputString(stream, node->GetContent(), convMem, convFile) &&
                 OutputString(stream, wxS("]]>"), convMem, convFile);
            break;

        case wxXML_TEXT_NODE:
            rc = OutputStringEnt(stream, node->GetContent(), convMem, convFile);
            break;

        case wxXML_ELEMENT_NODE:
            rc = OutputString(stream, wxS("<"), convMem, convFile) &&
                 OutputString(stream, node->GetName(), convMem, convFile);

            if ( rc )
            {
                for ( wxXmlAttribute *attr = node->GetAttributes();
                      attr && rc;
                      attr = attr->GetNext() )
                {
                    rc = OutputString(stream,
                                      wxS(" ") + attr->GetName() +  wxS("=\""),
                                      convMem, convFile) &&
                         OutputStringEnt(stream, attr->GetValue(),
                                         convMem, convFile,
                                         XML_ESCAPE_QUOTES) &&
                         OutputString(stream, wxS("\""), convMem, convFile);
                }
            }

            if ( node->GetChildren() )
            {
                rc = OutputString(stream, wxS(">"), convMem, convFile);

                wxXmlNode *prev = NULL;
                for ( wxXmlNode *n = node->GetChildren();
                      n && rc;
                      n = n->GetNext() )
                {
                    if ( indentstep >= 0 && n->GetType() != wxXML_TEXT_NODE )
                    {
                        rc = OutputIndentation(stream, indent + indentstep,
                                               convMem, convFile);
                    }

                    if ( rc )
                        rc = OutputNode(stream, n, indent + indentstep,
                                        convMem, convFile, indentstep);

                    prev = n;
                }

                if ( rc && indentstep >= 0 &&
                        prev && prev->GetType() != wxXML_TEXT_NODE )
                {
                    rc = OutputIndentation(stream, indent, convMem, convFile);
                }

                if ( rc )
                {
                    rc = OutputString(stream, wxS("</"), convMem, convFile) &&
                         OutputString(stream, node->GetName(),
                                      convMem, convFile) &&
                         OutputString(stream, wxS(">"), convMem, convFile);
                }
            }
            else // no children, output "<foo/>"
            {
                rc = OutputString(stream, wxS("/>"), convMem, convFile);
            }
            break;

        case wxXML_COMMENT_NODE:
            rc = OutputString(stream, wxS("<!--"), convMem, convFile) &&
                 OutputString(stream, node->GetContent(), convMem, convFile) &&
                 OutputString(stream, wxS("-->"), convMem, convFile);
            break;

        default:
            wxFAIL_MSG("unsupported node type");
            rc = false;
    }

    return rc;
}

} // anonymous namespace

bool wxXmlDocument::Save(wxOutputStream& stream, int indentstep) const
{
    if ( !IsOk() )
        return false;

    wxScopedPtr<wxMBConv> convMem, convFile;

#if wxUSE_UNICODE
    convFile.reset(new wxCSConv(GetFileEncoding()));
#else
    if ( GetFileEncoding().CmpNoCase(GetEncoding()) != 0 )
    {
        convFile.reset(new wxCSConv(GetFileEncoding()));
        convMem.reset(new wxCSConv(GetEncoding()));
    }
    //else: file and in-memory encodings are the same, no conversion needed
#endif

    return OutputString(stream,
                        wxString::Format
                        (
                         wxS("<?xml version=\"%s\" encoding=\"%s\"?>\n"),
                         GetVersion(), GetFileEncoding()
                        ),
                        convMem.get(),
                        convFile.get()) &&
           OutputNode(stream, GetRoot(), 0,
                      convMem.get(), convFile.get(), indentstep) &&
           OutputString(stream, wxS("\n"), convMem.get(), convFile.get());
}

#endif // wxUSE_XML
