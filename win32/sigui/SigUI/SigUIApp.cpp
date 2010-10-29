/***************************************************************
 * Purpose:   Code for Application Class
 *
 *  Copyright (C) 2010 Sourcefire, Inc.
 *
 *  Authors: Török Edwin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 **************************************************************/

#include "wx_pch.h"

#include <wx/cmdline.h>

#include "SigUIApp.h"
#include "SigUIMain.h"
#include "installdb.h"
IMPLEMENT_APP(SigUIApp);

static const wxCmdLineEntryDesc g_cmdLineDesc [] =
{
    {wxCMD_LINE_SWITCH, "i", "install", "install databases specified on stdin", wxCMD_LINE_VAL_NONE, wxCMD_LINE_PARAM_OPTIONAL },
    {wxCMD_LINE_SWITCH, "v", "verbose", "verbose log messages", wxCMD_LINE_VAL_NONE, wxCMD_LINE_PARAM_OPTIONAL },
    {wxCMD_LINE_SWITCH, "w", "write-conf", "copy&validate stdin to freshclam.conf", wxCMD_LINE_VAL_NONE, wxCMD_LINE_PARAM_OPTIONAL },
    {wxCMD_LINE_NONE, NULL, NULL, NULL, wxCMD_LINE_VAL_NONE, wxCMD_LINE_PARAM_OPTIONAL}
};

int SigUIApp::OnRun()
{
    if (conf_mode) {
	return SigUICopy::writeFreshclamConf() ? 0 : 101;
    }

    if (install_mode) {
        SigUICopy Copy;
        return Copy.installDBs() ? 0 : 100;
    }

    return wxApp::OnRun();
}

bool SigUIApp::OnInit()
{
    if (!wxApp::OnInit())
	return false;

    if (verbose_mode) {
	wxLog::SetVerbose();
    }

    if (install_mode || conf_mode)
        return true;

    //(*AppInitialize
    SigUIFrame* Frame = new SigUIFrame(0);
    Frame->Show();
    SetTopWindow(Frame);
    return true;
}

void SigUIApp::OnInitCmdLine(wxCmdLineParser& parser)
{
    parser.SetDesc (g_cmdLineDesc);
    parser.SetSwitchChars (wxT("-"));
}

bool SigUIApp::OnCmdLineParsed(wxCmdLineParser& parser)
{
    install_mode = parser.Found(wxT("i"));
    verbose_mode = parser.Found(wxT("v"));
    conf_mode = parser.Found(wxT("w"));

    return true;
}


