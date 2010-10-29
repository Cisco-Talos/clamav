/////////////////////////////////////////////////////////////////////////////
// Name:        execmon.cpp
// Purpose:     A simple execution monitor to test if wx samples crash at startup or not
// Author:      Francesco Montorsi
// Modified by:
// Created:     25/3/09
// RCS-ID:      $Id$
// Copyright:   (c) 2009 Francesco Montorsi
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

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/log.h"
#endif // WX_PRECOMP

#include "wx/cmdline.h"
#include "wx/vector.h"
#include "wx/process.h"
#include "wx/sstream.h"
#include "wx/utils.h"
#include "wx/filename.h"
#include "wx/app.h"
#include "wx/log.h"

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// utility classes
// ----------------------------------------------------------------------------

class MonitoredProcess : public wxProcess
{
public:
    MonitoredProcess()
        { Redirect(); m_crashed=false; m_exitCode=0; }

    void OnTerminate(int WXUNUSED(pid), int status)
    {
        wxStringOutputStream out, err;
        if (GetInputStream()) out.Write(*GetInputStream());
        if (GetErrorStream()) err.Write(*GetErrorStream());

        //wxPrintf("%s\n", stdout.GetString());
        //wxPrintf("%s\n", stderr.GetString());

        // when wx programs assert on wxGTK/wxMac, they put on stderr a message like:
        //    [Debug] date somefilename.pp(nnnn): assert "xxxxx" failed in yyyy
        // but then the assert dialog pop-ups and thus the app doesn't exit
        // FIXME: make assertion detection work also under other platforms
        //        see http://trac.wxwidgets.org/ticket/10697
        m_crashed = out.GetString().Contains("assert") ||
                    err.GetString().Contains("assert");
        m_exitCode = status;
    }

    void Kill()
    {
        wxProcess::Kill(GetPid());

        // wxProcess::Kill doesn't trigger a call to OnTerminate() normally...
        // but we still need to call it!
        OnTerminate(0, -1);
    }

    bool Crashed() const
        { return m_crashed; }

    int GetExitCode() const
        { return m_exitCode; }

private:
    bool m_crashed;
    int m_exitCode;
};

class MonitorData
{
public:
    MonitorData(const wxString& cmd) : program(cmd) {}

    wxString program;
    MonitoredProcess process;
};

// ----------------------------------------------------------------------------
// the real main
// ----------------------------------------------------------------------------

bool TestExec(const wxVector<wxFileName>& programs, long timeout)
{
    size_t i;
    wxVector<MonitorData*> data;

    // run all programs specified as command line parameters
    wxArrayLong procID;
    for (i=0; i<programs.size(); i++)
    {
        MonitorData *dt = new MonitorData(programs[i].GetFullPath());

        long pid = wxExecute(programs[i].GetFullPath(), wxEXEC_ASYNC, &dt->process);
        if (pid == 0)
        {
            wxLogError("could not run the program '%s'", programs[i].GetFullPath());
        }
        else
        {
            wxLogMessage("started program '%s' (pid %d)...",
                         programs[i].GetFullPath(), pid);
            wxASSERT(dt->process.GetPid() == pid);

            data.push_back(dt);
        }
    }

    // sleep some moments
    wxSleep(timeout);

    // check if all processes are still running
    bool allok = true;
    for (i=0; i<data.size(); i++)
    {
        MonitoredProcess& proc = data[i]->process;
        const wxString& prog = data[i]->program;

        if (wxProcess::Exists(proc.GetPid()))
            proc.Kill();
        else
        {
            // this typically never happens, at least when running wx-programs
            // built with debug builds of wx (see MonitoredProcess::OnTerminate;
            // even if an asserts fail the app doesn't automatically close!):

            wxLogMessage("program '%s' (pid %d) is NOT running anymore...",
                         prog, proc.GetPid());
            allok = false;
        }

        if (data[i]->process.Crashed())
        {
            allok = false;
            wxLogMessage("program '%s' (pid %d) crashed...",
                         prog, proc.GetPid());
        }
        else
            wxLogMessage("program '%s' (pid %d) ended with exit code %d...",
                         prog, proc.GetPid(), proc.GetExitCode());
    }

    return allok;
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------

int main(int argc, char **argv)
{
    wxApp::CheckBuildOptions(WX_BUILD_OPTIONS_SIGNATURE, "execmon");

    wxInitializer initializer;
    if ( !initializer )
    {
        fprintf(stderr, "Failed to initialize the wxWidgets library, aborting.");
        return -1;
    }

    static const wxCmdLineEntryDesc cmdLineDesc[] =
    {
        { wxCMD_LINE_SWITCH, "h", "help",
            "show this help message",
            wxCMD_LINE_VAL_NONE, wxCMD_LINE_OPTION_HELP },
        { wxCMD_LINE_OPTION, "t", "timeout",
            "kills all processes still alive after 'num' seconds",
            wxCMD_LINE_VAL_NUMBER, 0 },
        { wxCMD_LINE_PARAM, "", "",
            "program-to-run",
            wxCMD_LINE_VAL_STRING, wxCMD_LINE_PARAM_MULTIPLE },

        { wxCMD_LINE_NONE }
    };

    wxLog::DisableTimestamp();

    wxCmdLineParser parser(cmdLineDesc, argc, argv);
    switch ( parser.Parse() )
    {
    case -1:
        // help was shown
        break;

    case 0:
        {
            // check arguments
            wxVector<wxFileName> programs;
            for (unsigned int i=0; i<parser.GetParamCount(); i++)
            {
                wxFileName fn(parser.GetParam(i));
                if (!fn.IsAbsolute())
                    fn.MakeAbsolute();

                programs.push_back(fn);
            }

            long timeout;
            if (!parser.Found("t", &timeout))
                timeout = 3;

            return TestExec(programs, timeout) ? 0 : 1;
        }
        break;

    default:
        // syntax error
        break;
    }

    return 0;
}

