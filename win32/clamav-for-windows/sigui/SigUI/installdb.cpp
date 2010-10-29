/***************************************************************
 * Purpose:  Test and install ClamAV databases 
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
#include "SigUIApp.h"
#include <wx/log.h>
#include <wx/dynlib.h>
#include <wx/wfstream.h>
#include <wx/txtstrm.h>
#include <wx/filename.h>
#include <wx/stdpaths.h>
#include <wx/dir.h>
#include <wx/evtloop.h>

#include "../../../../libclamav/clamav.h"
#include "installdb.h"

static wxString GetExecPath()
{
    wxFileName exec(wxStandardPaths::Get().GetExecutablePath());
    return exec.GetPathWithSep();
}

class ClamAVLibrary {
    public:
	ClamAVLibrary() {
	    wxFileName dll(GetExecPath(), "libclamav");
	    m_libclamav.Load(dll.GetFullPath());
	    m_ok = m_libclamav.IsLoaded();
	    if (!m_ok)
		return;
	    m_ok = InitializeMethods();
	}
	bool IsOK() const { return m_ok; }

	wxDL_METHOD_DEFINE(int, cl_init, (unsigned opts),(opts), CL_ENULLARG)
	wxDL_METHOD_DEFINE(int, cl_load,(const char *path, struct cl_engine *engine, unsigned int *signo, unsigned int dboptions),
			   (path, engine, signo, dboptions), CL_ENULLARG)
	wxDL_METHOD_DEFINE(struct cl_engine*, cl_engine_new,(void),(), NULL)
	wxDL_METHOD_DEFINE(int, cl_engine_free, (struct cl_engine *engine),(engine), CL_ENULLARG)
	wxDL_METHOD_DEFINE(int, cl_engine_compile, (struct cl_engine *engine),(engine), CL_ENULLARG)
	wxDL_METHOD_DEFINE(const char*, cl_strerror, (int clerror),(clerror), "")
	wxDL_VOIDMETHOD_DEFINE(cl_engine_set_clcb_sigload, (struct cl_engine *engine, clcb_sigload callback, void *context),
			       (engine,callback,context))

    private:
	wxDynamicLibrary m_libclamav;
	bool m_ok;

	bool InitializeMethods() {
	    wxDL_METHOD_LOAD(m_libclamav, cl_init);
	    wxDL_METHOD_LOAD(m_libclamav, cl_load);
	    wxDL_METHOD_LOAD(m_libclamav, cl_engine_new);
	    wxDL_METHOD_LOAD(m_libclamav, cl_engine_free);
	    wxDL_METHOD_LOAD(m_libclamav, cl_engine_compile);
	    wxDL_METHOD_LOAD(m_libclamav, cl_strerror);
	    wxDL_METHOD_LOAD(m_libclamav, cl_engine_set_clcb_sigload);
	    return true;
	}
};

#define cli_strbcasestr(s, e) (!s.CmpNoCase(e))
//TODO: keep in sync with readdb.h
#define CLI_DBEXT(ext)				\
    (						\
	cli_strbcasestr(ext, ".db")    ||	\
	cli_strbcasestr(ext, ".db2")   ||	\
	cli_strbcasestr(ext, ".db3")   ||	\
	cli_strbcasestr(ext, ".hdb")   ||	\
	cli_strbcasestr(ext, ".hdu")   ||	\
	cli_strbcasestr(ext, ".fp")    ||	\
	cli_strbcasestr(ext, ".mdb")   ||	\
	cli_strbcasestr(ext, ".mdu")   ||	\
	cli_strbcasestr(ext, ".ndb")   ||	\
	cli_strbcasestr(ext, ".ndu")   ||	\
	cli_strbcasestr(ext, ".ldb")   ||	\
	cli_strbcasestr(ext, ".ldu")   ||	\
	cli_strbcasestr(ext, ".sdb")   ||	\
	cli_strbcasestr(ext, ".zmd")   ||	\
	cli_strbcasestr(ext, ".rmd")   ||	\
	cli_strbcasestr(ext, ".pdb")   ||	\
	cli_strbcasestr(ext, ".gdb")   ||	\
	cli_strbcasestr(ext, ".wdb")   ||	\
	cli_strbcasestr(ext, ".cbc")   ||	\
	cli_strbcasestr(ext, ".ftm")   ||	\
	cli_strbcasestr(ext, ".cfg")   ||	\
	cli_strbcasestr(ext, ".cvd")   ||	\
	cli_strbcasestr(ext, ".cld")   ||	\
	cli_strbcasestr(ext, ".cdb")   ||	\
	cli_strbcasestr(ext, ".idb")		\
    )

bool SigUICopy::validate_dbname(const wxString &name, bool all)
{
    //TODO: check that it is convertible to ASCII
    wxString ext = "." + name.AfterLast('.');
    // forbid CLD and .cfg
    // TODO: forbid CVD too? freshclam should be used for those
    if (!all && (!ext.CmpNoCase(".cld") || !ext.CmpNoCase(".cfg")))
	return false;
    return CLI_DBEXT(ext) || !ext.CmpNoCase(".ign2");
}

SigUICopy::SigUICopy()
    : cnt(0), max(0), progress(new wxProgressDialog(
	    _("Signature verification and installation"),
	    _("Preparing"),
	    100,
	    NULL,
	    wxPD_AUTO_HIDE | wxPD_SMOOTH | wxPD_CAN_ABORT |
	    wxPD_ELAPSED_TIME | wxPD_ESTIMATED_TIME | wxPD_REMAINING_TIME))
{}

bool SigUICopy::canceled(void)
{
    if (progress->WasCancelled()) {
	wxLogMessage(_("User aborted operation"));
	return true;
    }
    return false;
}

bool SigUICopy::installDBs(void)
{
    wxEventLoopGuarantor ensureEventLoop;
    progress->SetTransparent(200);
    progress->Show();
    wxTheApp->SetTopWindow(progress);
    wxBusyCursor wait;

    wxString current = GetExecPath();
    wxFileName staging(current, "staging_dir");
    wxString stagingPath = staging.GetFullPath();

    if (wxFileName::DirExists(stagingPath)) {
	if (!wxFileName::Rmdir(stagingPath, wxPATH_RMDIR_RECURSIVE)) {
	    wxLogWarning(_("Can't remove temporary directory %s"), stagingPath);
	}
    }

    if (!wxMkdir(stagingPath)) {
	wxLogError(_("Failed to create directory %s"), stagingPath);
	progress->Close();
	return false;
    }

    bool OK = copySignatures(stagingPath) && loadDB(stagingPath) && installDB(stagingPath, current);

    if (!wxFileName::Rmdir(stagingPath, wxPATH_RMDIR_RECURSIVE)) {
	wxLogWarning(_("Can't remove temporary directory %s"), stagingPath);
    }

    if (!OK) {
	wxLogError(_("Failed to verify and install databases\n"));
    }
    progress->Destroy();
    return OK;
}

/* copy file and count lines */
static long
myCopyFile(const wxString &src,
           const wxString &dst)
{
    long lines = 0;
    wxFile fileOut;
    wxFile fileIn(src, wxFile::read);

    if (!fileIn.IsOpened())
	return -1;
    if (!fileOut.Create(dst, true) )
        return -1;

    char buf[4096];
    while (true) {
	long i;
        ssize_t count = fileIn.Read(buf, sizeof(buf));
        if (count == wxInvalidOffset )
            return -1;
	if (!count)
	    break;//EOF

	for (i=0;i<count;i++)
	    if (buf[i] == '\n')
		lines++;

        if ( fileOut.Write(buf, count) < (size_t)count )
            return -1;
    }

    return fileIn.Close() && fileOut.Close() ? lines : -1;
}

bool SigUICopy::copySignatures(const wxString &staging)
{
    bool OK = true;
    wxFFileInputStream in_stdin(stdin);
    wxTextInputStream in(in_stdin);
    wxArrayString all_dbs;

    progress->Pulse(_("Copying databases to temporary directory"));
    progress->Fit();
    max = 0;
    while (!in_stdin.Eof() && in_stdin.IsOk()) {
	progress->Pulse();
	if (canceled())
	    return false;
	wxString line = in.ReadLine();
	if (line.empty())
	    continue;
	wxFileName source(line);
	wxString dbname = source.GetFullName();

	if (!validate_dbname(dbname)) {
	    wxLogError(_("Unknown database extension for: %s!"), dbname);
	    OK = false;
	    // keep processing the other DBs
	    continue;
	}
	if (!source.FileExists()) {
	    wxLogError(_("Cannot find file %s!"), line);
	    OK = false;
	    continue;
	}

	//TODO:check for dup filenames
	wxFileName dest(staging, source.GetFullName());
	long n = myCopyFile(source.GetFullPath(), dest.GetFullPath());
	if (n < 0) {
	    wxLogError(_("Cannot copy %s to temporary location %s\n"), source.GetFullPath(), dest.GetFullPath());
	    OK = false;
	}
	if (!dbname.AfterLast('.').CmpNoCase(".cbc"))
	    max += 1;
	else
	    max += n;
    }
    progress->Pulse();
    return OK;
}

int SigUICopy::sigprogress(const char* WXUNUSED(type), const char* WXUNUSED(name), void *context)
{
    SigUICopy *p = (SigUICopy*)context;
    if (++p->cnt % 1000)
	return 0;

    bool canceled;
    if (p->cnt > p->max)
	canceled = !p->progress->Pulse();
    else
	canceled = !p->progress->Update(p->cnt);
    if (canceled) {
	wxLogMessage(_("User aborted"));
	longjmp(p->env, 1);
    }

    return 0;
}

bool SigUICopy::loadDB(const wxString& dir)
{
    struct cl_engine *engine;
    int ret;
    bool OK = true;

    ClamAVLibrary libclamav;
    progress->Pulse(_("Loading libclamav"));
    progress->Fit();
    if (!libclamav.IsOK()) {
	//TODO: make this check earlier!
	wxLogError(_("Unable to load libclamav.dll"));
	return false;
    }

    if ((ret = libclamav.cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
	wxLogError(_("Can't initialize libclamav: %s"), libclamav.cl_strerror(ret));
	return false;
    }
    //TODO: how about filenames that are not convertible to C strings?
    //libclamav doesn't support these, should test what happens
    if (!(engine = libclamav.cl_engine_new())) {
	wxLogError(_("Can't create new engine"));
	return false;
    }

    cnt = 0;
    if (!max)
	max = 1;
    progress->SetRange(max);
    libclamav.cl_engine_set_clcb_sigload(engine, sigprogress, this);
    unsigned sigs = 0;
    do {
	if (canceled()) {
	    OK = false;
	    break;
	}

	progress->Update(0, _("Loading signatures ..."));
	progress->Fit();
	if (setjmp(env) == 0) {
	    if ((ret = libclamav.cl_load(dir.mb_str(), engine, &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
		wxLogError(_("Failed to load signatures: %s\n"),
			   libclamav.cl_strerror(ret));
		OK = false;
		break;
	    }
	} else {
	    OK = false;
	    break;
	}

	progress->Pulse(_("Compiling signatures ..."));
	progress->Fit();
	if (canceled()) {
	    OK = false;
	    break;
	}

	if ((ret = libclamav.cl_engine_compile(engine)) != CL_SUCCESS) {
	    wxLogError(_("Failed to compile signatures: %s"),
		       libclamav.cl_strerror(ret));
	    OK = false;
	    break;
	}
    } while (0);

    libclamav.cl_engine_free(engine);
    if (canceled())
	return false;

    if (OK) {
	progress->Pulse(_("Successfully loaded all signatures"));
	progress->Fit();
    }
    return OK;
}

bool SigUICopy::installDB(const wxString& staging, const wxString &dest)
{
    bool OK = true;
    wxDir dir(staging);
    if (!dir.IsOpened()) {
	wxLogError(_("Cannot open directory %s"), staging);
	return false;
    }

    progress->Pulse(_("Installing signatures"));
    progress->Fit();
    if (canceled())
	return false;

    wxString filename;
    bool cont = dir.GetFirst(&filename);
    while (cont) {
	wxFileName dst(dest, filename);
	wxFileName src(staging, filename);

	progress->Pulse();

	if (wxRename(src.GetFullPath(), dst.GetFullPath())) {
	    if (!wxRemoveFile(dst.GetFullPath())) {
		//TODO: maybe rename to .bak, and restore later if failed?
		wxLogWarning(_("Cannot remove %s\n"), dst.GetFullPath());
	    }
	    if (wxRename(src.GetFullPath(), dst.GetFullPath())) {
		wxLogError(_("Cannot rename %s -> %s\n"), src.GetFullPath(), dst.GetFullPath());
		OK = false;
		break;
	    }
	}
	cont = dir.GetNext(&filename);
    }
    progress->Pulse(_("Successfully installed"));
    progress->Fit();
    // TODO: on failure delete all that we moved!
    return OK;
}

bool SigUICopy::writeFreshclamConf()
{
    wxFile fileTemp;
    wxString tempname = wxFileName::CreateTempFileName(GetExecPath(), &fileTemp);
    if (tempname.IsEmpty()) {
	wxLogError(_("Cannot create temporary file!"));
	return false;
    }
    wxLogVerbose(_("Reading config file from stdin"));

    char buffer[1024];
    long n;
    while (1) {
	n = read(0, buffer, sizeof(buffer));
	if (n < 0) {
	    if (errno == EBADF) {
		wxLogError(_("No input provided! Use SigUI -w </path/to/freshclam.conf"));
		return false;
	    }
	    wxLogError(_("read() failed: %d"), errno);
	    return false;
	}
	if (n == 0)
	    break;
	if (fileTemp.Write(buffer, n) != (size_t)n) {
	    wxLogError(_("failed to write"));
	    return false;
	}
    }
    fileTemp.Close();

    // freshclam -V --config-file validates the config file and prints version!
    wxString cmd;
    cmd << "\"" << GetExecPath() << "freshclam.exe\" -V --config-file=\""
	<< tempname << "\"";

    wxLogVerbose(_("Validating config file with freshclam: %s"), tempname);

    wxArrayString output;
    wxArrayString errors;
    if (wxExecute(cmd, output, errors, wxEXEC_BLOCK) != 0) {
	wxLogVerbose(_("Config file is not valid: %s"), tempname);
	for (unsigned i=0;i<errors.GetCount();i++)
	    wxLogError(_("freshclam: %s"), errors[i]);
	wxLogError(_("Configuration file provided is not valid!"));
	wxRemoveFile(tempname);
	return false;
    }
    wxLogVerbose(_("Config file is valid: %s"), tempname);

    wxString conf = GetExecPath() + "freshclam.conf";

    wxRemoveFile(conf);
    wxRenameFile(tempname, conf);

    if (!wxRemoveFile(tempname))
	return false;
    wxLogVerbose(_("Config file updated"));
    return true;
}


