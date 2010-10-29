/////////////////////////////////////////////////////////////////////////////
// Name:        src/html/htmlfilt.cpp
// Purpose:     wxHtmlFilter - input filter for translating into HTML format
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
    #include "wx/log.h"
    #include "wx/intl.h"
#endif

#include "wx/strconv.h"
#include "wx/sstream.h"
#include "wx/html/htmlfilt.h"
#include "wx/html/htmlwin.h"

// utility function: read entire contents of an wxInputStream into a wxString
//
// TODO: error handling?
static void ReadString(wxString& str, wxInputStream* s, wxMBConv& conv)
{
    wxStringOutputStream out(&str, conv);
    s->Read(out);
}

/*

There is code for several default filters:

*/

IMPLEMENT_ABSTRACT_CLASS(wxHtmlFilter, wxObject)

//--------------------------------------------------------------------------------
// wxHtmlFilterPlainText
//          filter for text/plain or uknown
//--------------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxHtmlFilterPlainText, wxHtmlFilter)

bool wxHtmlFilterPlainText::CanRead(const wxFSFile& WXUNUSED(file)) const
{
    return true;
}



wxString wxHtmlFilterPlainText::ReadFile(const wxFSFile& file) const
{
    wxInputStream *s = file.GetStream();
    wxString doc, doc2;

    if (s == NULL) return wxEmptyString;
    ReadString(doc, s, wxConvISO8859_1);

    doc.Replace(wxT("&"), wxT("&amp;"), true);
    doc.Replace(wxT("<"), wxT("&lt;"), true);
    doc.Replace(wxT(">"), wxT("&gt;"), true);
    doc2 = wxT("<HTML><BODY><PRE>\n") + doc + wxT("\n</PRE></BODY></HTML>");
    return doc2;
}





//--------------------------------------------------------------------------------
// wxHtmlFilterImage
//          filter for image/*
//--------------------------------------------------------------------------------

class wxHtmlFilterImage : public wxHtmlFilter
{
    DECLARE_DYNAMIC_CLASS(wxHtmlFilterImage)

    public:
        virtual bool CanRead(const wxFSFile& file) const;
        virtual wxString ReadFile(const wxFSFile& file) const;
};

IMPLEMENT_DYNAMIC_CLASS(wxHtmlFilterImage, wxHtmlFilter)



bool wxHtmlFilterImage::CanRead(const wxFSFile& file) const
{
    return (file.GetMimeType().Left(6) == wxT("image/"));
}



wxString wxHtmlFilterImage::ReadFile(const wxFSFile& file) const
{
    wxString res = wxT("<HTML><BODY><IMG SRC=\"") + file.GetLocation() + wxT("\"></BODY></HTML>");
    return res;
}




//--------------------------------------------------------------------------------
// wxHtmlFilterHTML
//          filter for text/html
//--------------------------------------------------------------------------------


IMPLEMENT_DYNAMIC_CLASS(wxHtmlFilterHTML, wxHtmlFilter)

bool wxHtmlFilterHTML::CanRead(const wxFSFile& file) const
{
//    return (file.GetMimeType() == "text/html");
// This is true in most case but some page can return:
// "text/html; char-encoding=...."
// So we use Find instead
  return (file.GetMimeType().Find(wxT("text/html")) == 0);
}



wxString wxHtmlFilterHTML::ReadFile(const wxFSFile& file) const
{
    wxInputStream *s = file.GetStream();
    wxString doc;

    if (s == NULL)
    {
        wxLogError(_("Cannot open HTML document: %s"), file.GetLocation().c_str());
        return wxEmptyString;
    }

    // NB: We convert input file to wchar_t here in Unicode mode, based on
    //     either Content-Type header or <meta> tags. In ANSI mode, we don't
    //     do it as it is done by wxHtmlParser (for this reason, we add <meta>
    //     tag if we used Content-Type header).
#if wxUSE_UNICODE
    int charsetPos;
    if ((charsetPos = file.GetMimeType().Find(wxT("; charset="))) != wxNOT_FOUND)
    {
        wxString charset = file.GetMimeType().Mid(charsetPos + 10);
        wxCSConv conv(charset);
        ReadString(doc, s, conv);
    }
    else
    {
        size_t size = s->GetSize();
        wxCharBuffer buf( size+1 );
        s->Read( buf.data(), size );
        *(buf.data() + size) = 0;
        wxString tmpdoc( buf, wxConvISO8859_1);

        wxString charset = wxHtmlParser::ExtractCharsetInformation(tmpdoc);
        if (charset.empty())
            doc = tmpdoc;
        else
        {
            wxCSConv conv(charset);
            doc = wxString( buf, conv );
        }
    }
#else // !wxUSE_UNICODE
    ReadString(doc, s, wxConvLibc);
    // add meta tag if we obtained this through http:
    if (!file.GetMimeType().empty())
    {
        wxString hdr;
        wxString mime = file.GetMimeType();
        hdr.Printf(wxT("<meta http-equiv=\"Content-Type\" content=\"%s\">"), mime.c_str());
        return hdr+doc;
    }
#endif

    return doc;
}




///// Module:

class wxHtmlFilterModule : public wxModule
{
    DECLARE_DYNAMIC_CLASS(wxHtmlFilterModule)

    public:
        virtual bool OnInit()
        {
            wxHtmlWindow::AddFilter(new wxHtmlFilterHTML);
            wxHtmlWindow::AddFilter(new wxHtmlFilterImage);
            return true;
        }
        virtual void OnExit() {}
};

IMPLEMENT_DYNAMIC_CLASS(wxHtmlFilterModule, wxModule)

#endif
