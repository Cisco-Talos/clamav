/*
  Converts hhp (HTML Help Workshop) files into cached
  version for faster reading

  Usage: hhp2cached file.hhp [file2.hhp ...]

*/

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#include "wx/html/helpdata.h"


class MyApp : public wxApp
{
public:
    virtual bool OnInit();
};

IMPLEMENT_APP(MyApp);

bool MyApp::OnInit()
{
    for (int i = 1; i < argc; i++)
    {
        wxHtmlHelpData data;
        wxPrintf(wxT("Processing %s...\n"), argv[i]);
        data.SetTempDir(wxPathOnly(argv[i]));
        data.AddBook(argv[i]);
    }

    return false;
}
