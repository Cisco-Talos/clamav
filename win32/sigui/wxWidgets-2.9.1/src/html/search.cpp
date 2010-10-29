/////////////////////////////////////////////////////////////////////////////
// Name:        search.cpp
// Purpose:     search engine
// Author:      Vaclav Slavik
// RCS-ID:      $Id$
// Copyright:   (c) 1999 Vaclav Slavik
// Licence:     wxWindows Licence
/////////////////////////////////////////////////////////////////////////////



#ifdef __GNUG__
#pragma implementation
#endif

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/defs.h"
#if wxUSE_HTML

#ifndef WXPRECOMP
#endif

#include "wx/html/helpdata.h"


//--------------------------------------------------------------------------------
// wxSearchEngine
//--------------------------------------------------------------------------------

void wxSearchEngine::LookFor(const wxString& keyword)
{
    if (m_Keyword) delete[] m_Keyword;
    m_Keyword = new wxChar[keyword.Length() + 1];
    wxStrcpy(m_Keyword, keyword.c_str());
    for (int i = wxStrlen(m_Keyword) - 1; i >= 0; i--)
        if ((m_Keyword[i] >= wxT('A')) && (m_Keyword[i] <= wxT('Z')))
            m_Keyword[i] += wxT('a') - wxT('A');
}



bool wxSearchEngine::Scan(wxInputStream *stream)
{
    wxASSERT_MSG(m_Keyword != NULL, _("wxSearchEngine::LookFor must be called before scanning!"));

    int i, j;
    int lng = stream ->GetSize();
    int wrd = wxStrlen(m_Keyword);
    bool found = FALSE;
    char *buf = new char[lng + 1];
    stream -> Read(buf, lng);
    buf[lng] = 0;

    for (i = 0; i < lng; i++)
        if ((buf[i] >= 'A') && (buf[i] <= 'Z')) buf[i] += 'a' - 'A';

    for (i = 0; i < lng - wrd; i++) {
        j = 0;
        while ((j < wrd) && (buf[i + j] == m_Keyword[j])) j++;
        if (j == wrd) {found = TRUE; break;}
    }

    delete[] buf;
    return found;
}

#endif
