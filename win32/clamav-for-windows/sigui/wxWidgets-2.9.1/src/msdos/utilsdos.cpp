/////////////////////////////////////////////////////////////////////////////
// Name:        src/msdos/utils.cpp
// Purpose:     DOS implementations of utility functions
// Author:      Vaclav Slavik, M.J.Wetherell
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
//              (c) 2005 M.J.Wetherell
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/utils.h"

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/app.h"
#endif

#include "wx/apptrait.h"
#include "wx/process.h"
#include "wx/confbase.h"        // for wxExpandEnvVars()
#include "wx/cmdline.h"
#include "wx/filename.h"
#include "wx/wfstream.h"

#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <dos.h>
#include <process.h>

//----------------------------------------------------------------------------
// Sleep
//----------------------------------------------------------------------------

void wxSleep(int nSecs)
{
    wxMilliSleep(1000 * nSecs);
}

void wxMilliSleep(unsigned long milliseconds)
{
#if HAVE_USLEEP || defined __DJGPP__
    usleep(milliseconds * 1000);
#elif defined __WATCOMC__
    delay(milliseconds);
#else
    clock_t start = clock();
    while ((clock() - start) * 1000 / CLOCKS_PER_SEC < (clock_t)milliseconds)
    {
        // yield if in a multitasking environment
        // "Release Current Virtual Machine's Time Slice" in DPMI 1.0
        REGS r;
        memset(&r, 0, sizeof(r));
        r.x.ax = 0x1680;
        int386(0x2f, &r, &r);
    }
#endif
}

void wxMicroSleep(unsigned long microseconds)
{
#if HAVE_USLEEP || defined __DJGPP__
    usleep(microseconds);
#else
    wxMilliSleep(microseconds/1000);
#endif
}

//----------------------------------------------------------------------------
// Get/Set environment variables
//----------------------------------------------------------------------------

bool wxGetEnv(const wxString& var, wxString *value)
{
    // wxGetenv is defined as getenv()
    wxChar *p = wxGetenv(var);
    if ( !p )
        return false;

    if ( value )
        *value = p;

    return true;
}

static bool wxDoSetEnv(const wxString& variable, const char *value)
{
    wxString s = variable;
    if ( value )
        s << wxT('=') << value;

    // transform to ANSI
    const char *p = s.mb_str();

    // the string will be free()d by libc
    char *buf = (char *)malloc(strlen(p) + 1);
    strcpy(buf, p);

    return putenv(buf) == 0;
}

bool wxSetEnv(const wxString& variable, const wxString& value)
{
    return wxDoSetEnv(variable, value.mb_str());
}

bool wxUnsetEnv(const wxString& variable)
{
    return wxDoSetEnv(variable, NULL);
}


//----------------------------------------------------------------------------
// Hostname, username, home directory
//----------------------------------------------------------------------------

// Based on the MSW implementation
//
// Respects the following environment variables in this order: %HomeDrive% +
// %HomePath%, %UserProfile%, $HOME. Otherwise takes program's directory if
// wxApp has been initialised, otherwise returns ".".
//
const wxChar* wxGetHomeDir(wxString *home)
{
    wxString& strDir = *home;

    strDir.clear();

    // try HOMEDRIVE/PATH
    const wxChar *szHome = wxGetenv(wxT("HOMEDRIVE"));
    if ( szHome != NULL )
        strDir << szHome;
    szHome = wxGetenv(wxT("HOMEPATH"));

    if ( szHome != NULL )
    {
        strDir << szHome;

        // the idea is that under NT these variables have default values of
        // "%systemdrive%:" and "\\". As we don't want to create our config
        // files in the root directory of the system drive, we will create it
        // in our program's dir. However, if the user took care to set
        // HOMEPATH to something other than "\\", we suppose that he knows
        // what he is doing and use the supplied value.
        if ( wxStrcmp(szHome, wxT("\\")) == 0 )
            strDir.clear();
    }

    if ( strDir.empty() )
    {
        // If we have a valid USERPROFILE directory, as is the case in
        // Windows NT, 2000 and XP, we should use that as our home directory.
        szHome = wxGetenv(wxT("USERPROFILE"));

        if ( szHome != NULL )
            strDir = szHome;
    }

    if ( strDir.empty() )
    {
        // If we have a valid HOME directory, as is used on many machines
        // that have unix utilities on them, we should use that.
        szHome = wxGetenv(wxT("HOME"));

        if ( szHome != NULL )
        {
            strDir = szHome;
            // when msys sets %HOME% it uses '/' (cygwin uses '\\')
            strDir.Replace(wxT("/"), wxT("\\"));
        }
    }

    if ( !strDir.empty() )
    {
        // sometimes the value of HOME may be "%USERPROFILE%", so reexpand the
        // value once again, it shouldn't hurt anyhow
        strDir = wxExpandEnvVars(strDir);
    }
    else // fall back to the program directory
    {
        if ( wxTheApp )
        {
            wxString prog(wxTheApp->argv[0]);
#ifdef __DJGPP__
            // djgpp startup code switches the slashes around, so restore them
            prog.Replace(wxT("/"), wxT("\\"));
#endif
            // it needs to be a full path to be usable
            if ( prog.compare(1, 2, wxT(":\\")) == 0 )
                wxFileName::SplitPath(prog, &strDir, NULL, NULL);
        }
        if ( strDir.empty() )
        {
            strDir = wxT(".");
        }
    }

    return strDir.c_str();
}

wxString wxGetUserHome(const wxString& user)
{
    wxString home;

    if (user.empty() || user == wxGetUserId())
        wxGetHomeDir(&home);

    return home;
}

// returns %UserName%, $USER or just "user"
//
bool wxGetUserId(wxChar *buf, int n)
{
    const wxChar *user = wxGetenv(wxT("UserName"));

    if (!user)
        user = wxGetenv(wxT("USER"));

    if (!user)
        user = wxT("user");

    wxStrlcpy(buf, user, n);
    return true;
}

bool wxGetUserName(wxChar *buf, int n)
{
    return wxGetUserId(buf, n);
}

// returns %ComputerName%, or $HOSTNAME, or "host"
//
bool wxGetHostName(wxChar *buf, int n)
{
    const wxChar *host = wxGetenv(wxT("ComputerName"));

    if (!host)
        host = wxGetenv(wxT("HOSTNAME"));

    if (!host)
        host = wxT("host");

    wxStrlcpy(buf, host, n);
    return true;
}

// adds %UserDnsDomain% to wxGetHostName()
//
bool wxGetFullHostName(wxChar *buf, int n)
{
    wxGetHostName(buf, n);

    const wxChar *domain = wxGetenv(wxT("UserDnsDomain"));

    if (domain)
        wxStrncat(wxStrncat(buf, wxT("."), n), domain, n);

    return true;
}

//----------------------------------------------------------------------------
// Processes
//----------------------------------------------------------------------------

unsigned long wxGetProcessId()
{
    return (unsigned long)getpid();
}

int wxKill(long pid, wxSignal sig, wxKillError *rc, int WXUNUSED(flags))
{
    int result = -1;

    if (pid != (long)wxGetProcessId())
    {
        result = raise(sig);
        if (rc)
            *rc = result == 0 ? wxKILL_OK : wxKILL_BAD_SIGNAL;
    }
    else
    {
        wxLogDebug(wxT("wxKill can only send signals to the current process under MSDOS"));
        if (rc)
            *rc = wxKILL_NO_PROCESS;
    }

    return result;
}

bool wxShell(const wxString& command /*=wxEmptyString*/)
{
    // FIXME: suspend/resume gui
    int result = system(command);

    if (result == -1)
    {
        wxLogSysError(_("can't execute '%s'"), command.c_str());
    }

    return result == 0;
}

long wxExecute(const wxString& command, int flags, wxProcess *process)
{
    // FIXME: shouldn't depend on wxCmdLineParser
    wxArrayString args(wxCmdLineParser::ConvertStringToArgs(command));
    size_t n = args.size();
    wxChar **argv = new wxChar*[n + 1];

    argv[n] = NULL;
    while (n-- > 0)
        argv[n] = const_cast<wxChar*>((const char *)args[n].c_str());

    long result = wxExecute(argv, flags, process);

    delete [] argv;
    return result;
}

#if wxUSE_STREAMS

// A wxFFileInputStream that deletes the file in it's destructor
//
class wxTempFileInStream : public wxFFileInputStream
{
public:
    wxTempFileInStream(const wxString& name)
        : wxFFileInputStream(name, wxT("rt"))
    { }

    virtual ~wxTempFileInStream()
    {
        m_file->Close();
        wxRemoveFile(m_file->GetName());
    }
};

// A file descriptor that can be redirected to a file
//
class wxRedirectableFd
{
public:
    wxRedirectableFd(int fd) : m_fd(fd), m_dup(-1) { }
    ~wxRedirectableFd();

    // Redirect the descriptor to a file, similar to ANSI C's freopen, but
    // for low level descriptors. The desctructor un-redirects. If O_CREAT
    // is in the flags then the destructor will delete the file unless it is
    // given away with Release().
    bool Reopen(const wxString& name, int flags);

    // un-redirect the redirected file descriptor, closing the file, and give
    // away the filename without deleting it
    wxString Release();

private:
    // un-redirect the descriptor, closing the file
    void Restore();

    int m_fd;
    int m_dup;
    wxString m_name;
};

wxRedirectableFd::~wxRedirectableFd()
{
    Restore();
    if (!m_name.empty())
        wxRemoveFile(m_name);
}

bool wxRedirectableFd::Reopen(const wxString& name, int flags)
{
    wxASSERT(m_dup == -1);
    bool result = false;

    // save a duplicate so that the descriptor can be closed now and
    // restored later
    m_dup = dup(m_fd);

    if (m_dup != -1)
    {
        int tmp = open(name.mb_str(), flags);

        if (tmp != -1)
        {
            close(m_fd);

            if (flags & O_CREAT)
                m_name = name;

            result = dup2(tmp, m_fd) == m_fd;
            close(tmp);
        }
    }

    if (!result)
    {
        wxLogSysError(_("error opening '%s'"), name.c_str());
    }

    return result;
}

void wxRedirectableFd::Restore()
{
    if (m_dup != -1)
    {
        close(m_fd);
        dup2(m_dup, m_fd);
        close(m_dup);
        m_dup = -1;
    }
}

wxString wxRedirectableFd::Release()
{
    Restore();
    wxString name = m_name;
    m_name.clear();
    return name;
}

#endif // wxUSE_STREAMS

// wxExecute implementation
//
long wxExecute(wxChar **argv, int flags, wxProcess *process)
{
#if wxUSE_STREAMS
    const int STDIN = 0;
    const int STDOUT = 1;
    const int STDERR = 2;

    wxRedirectableFd in(STDIN), out(STDOUT), err(STDERR);
    bool redirect = process && process->IsRedirected() && (flags & wxEXEC_SYNC);

    if (redirect)
    {
        // close stdin/out/err and reopen them as files
        if (!in.Reopen(wxT("NUL"), O_RDONLY | O_TEXT))
            return -1;

        if (!out.Reopen(wxFileName::CreateTempFileName(wxT("out")),
                        O_CREAT | O_WRONLY | O_TRUNC | O_TEXT))
            return -1;

        if (!err.Reopen(wxFileName::CreateTempFileName(wxT("err")),
                        O_CREAT | O_WRONLY | O_TRUNC | O_TEXT))
            return -1;
    }
#endif // wxUSE_STREAMS

    // FIXME: suspend/resume gui
    int mode = flags & wxEXEC_SYNC ? P_WAIT : P_NOWAIT;
    int result = spawnvp(mode, argv[0], argv);

    if (result == -1)
    {
        wxLogSysError(_("can't execute '%s'"), argv[0]);
    }

#if wxUSE_STREAMS
    if (redirect)
        process->SetPipeStreams(new wxTempFileInStream(out.Release()),
                                new wxFFileOutputStream(wxT("NUL"), wxT("wt")),
                                new wxTempFileInStream(err.Release()));
#endif // wxUSE_STREAMS

    return result;
}


//----------------------------------------------------------------------------
// OS-related
//----------------------------------------------------------------------------

wxString wxGetOsDescription()
{
    wxString osname(wxT("DOS"));
    return osname;
}

wxOperatingSystemId wxGetOsVersion(int *verMaj, int *verMin)
{
    if ( verMaj )
        *verMaj = _osmajor;
    if ( verMin )
        *verMin = _osminor;

    return wxOS_DOS;
}

bool wxIsPlatform64Bit()
{
    return false;
}

