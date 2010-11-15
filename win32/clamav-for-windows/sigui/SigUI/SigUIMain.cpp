/***************************************************************
 * Purpose:   Code for Application Frame
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

#ifdef __BORLANDC__
#pragma hdrstop
#endif //__BORLANDC__

#include "../../../../libclamav/version.h"
#include "SigUIMain.h"
#include "installdb.h"
#include <wx/clipbrd.h>
#include <wx/textdlg.h>
#include <wx/uri.h>
#include <wx/socket.h>
#include <wx/tokenzr.h>
#include <wx/txtstrm.h>
#include <wx/filename.h>
#include <wx/stdpaths.h>
#include <wx/dir.h>
#include <wx/hashset.h>

#if wxUSE_DRAG_AND_DROP
class DropFiles : public wxFileDropTarget
{
public:
    DropFiles(wxControlWithItems *owner)
	:m_owner(owner) {}

    virtual bool OnDropFiles(wxCoord WXUNUSED(x), wxCoord WXUNUSED(y),
                             const wxArrayString& filenames)
    {
        unsigned n = filenames.GetCount();
        for (unsigned i=0;i<n;i++) {
            if (!wxFile::Exists(filenames[i])) {
		//TODO: show error
		return false;
	    }
	}
        for (unsigned i=0;i<n;i++) {
	    m_owner->Append(filenames[i]);
        }
	return true;
    }

private:
    wxControlWithItems *m_owner;
};
#endif

class HostnameValidator : public wxTextValidator
{
    protected:
	virtual wxString IsValid(const wxString &val) const {
	    if (val.length() == 1)
            return "";//characters
	    wxURI uri;
	    if (!uri.Create("http://" + val))
		return _("Invalid URI: %s");
	    if (uri.HasFragment() ||
		uri.HasPath() ||
		uri.HasPort() ||
		uri.HasQuery() ||
		!uri.HasServer() ||
		uri.HasUserInfo())
		return _("Invalid hostname: %s");
	    return "";
	}
    public:
	HostnameValidator(wxString *valPtr=NULL)
	    :wxTextValidator(wxFILTER_NONE, valPtr) {}
	virtual wxObject *Clone() const {
	    HostnameValidator *v = new HostnameValidator();
	    v->Copy(*this);
	    return v;
	}
};

SigUIFrame::~SigUIFrame()
{
    delete watcher;
    delete icon;
    delete editor;
}

void SigUIFrame::OnClose(wxCloseEvent& event)
{
    if (event.CanVeto()) {
	if (!Validate() || !TransferDataFromWindow()) {
	    wxLogWarning(_("Validation failed"));
	    event.Veto();
	    return;
	}
	if (!m_sig_candidates->IsEmpty()) {
	    int answer = wxMessageBox(_("You have added new signatures that have not been installed yet\n"
					"Are you sure you want to exit?"),
				      _("There are new signatures"),
				      wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION, this);
	    if (answer == wxNO) {
		event.Veto();
		return;
	    }
	}

	if (editor->Save(true)) {
	    int answer = wxMessageBox(_("There are unsaved changes that will be lost if you exit the application\n"
					"Save changes?"),
				      _("There are unsaved changes"),
				      wxYES_NO | wxCANCEL | wxCANCEL_DEFAULT | wxICON_QUESTION, this);
	    switch (answer) {
		case wxYES:
		    editor->Save();
		    break;
		case wxNO:
		    // exiting and loosing changes
		    break;
		default:
		    event.Veto();
		    return;
	    }
	}
    }

//    icon->RemoveIcon();
    Destroy();
}

void SigUIFrame::OnQuit(wxCommandEvent& WXUNUSED(event))
{
    Destroy();
}

void SigUIFrame::OnAbout(wxCommandEvent& WXUNUSED(event))
{
}

void SigUIFrame::m_proxyOnCheckBox( wxCommandEvent& event )
{
    bool enable = m_proxy->IsChecked();
    m_proxy_server->Enable(enable);
    m_proxy_port->Enable(enable);
    m_proxyauth->Enable(enable);
    m_proxyauthOnCheckBox(event);
}

void SigUIFrame::m_proxyauthOnCheckBox( wxCommandEvent& WXUNUSED(event) )
{
    bool enable = m_proxyauth->IsEnabled() && m_proxyauth->IsChecked();
    m_proxy_user->Enable(enable);
    m_proxy_password->Enable(enable);
}

class URLValidator : public wxTextValidator
{
    public:
	virtual wxString IsValid(const wxString &val) const {
	    if (val.IsEmpty())
		return _("Empty URLs are not valid: %s");
	    if (val.length() == 1)
		return "";//characters
	    //bb #2343
	    if (!*val.mb_str())
            return _("URL can't contain non-ASCII characters, please URLencode it: %s");

	    if (val.StartsWith("\\\\")) {
		if (!wxFileName::FileExists(val))
		    return _("UNC path doesn't exist: %s");
		return "";
	    }

	    wxURI uri;
	    if (!uri.Create(val))
		return _("Invalid URI: %s");
	    if (uri.HasUserInfo())
		return _("User not supported in URL: %s");
	    if (uri.HasQuery())
		return _("Query parameters not supported in URL: %s");
	    if (uri.HasFragment())
		return _("Fragment not supported in URL: %s");

	    if (uri.GetScheme() == "file") {
		if (!wxFileName::FileExists(uri.GetPath()))
		    return _("file doesn't exist: %s");
		return "";
	    }
	    if (uri.GetScheme() == "http" && uri.IsReference())
		return _("URL not absolute: %s");
	    if (uri.GetScheme() != "http" && uri.GetScheme() != "file")
		return _("Only HTTP URLs accepted: %s");
	    if (!uri.HasServer())
		return _("URL must specify a server: %s");
	    if (!uri.HasPath())
		return _("URL must specify a path: %s");
	    if (!SigUICopy::validate_dbname(uri.GetPath(), false))
		return _("Extension is not a valid virus signature database extension: %s");
	    return "";
	}
    public:
	URLValidator(wxString *valPtr=NULL)
	    :wxTextValidator(wxFILTER_NONE, valPtr) {}
	virtual wxObject *Clone() const {
	    URLValidator *v = new URLValidator();
	    v->Copy(*this);
	    return v;
	}
};

class URLEntryDialog : public wxTextEntryDialog
{
    public:
    URLEntryDialog(wxWindow* parent, const wxString& message, const wxString& caption = "Please enter text", const wxString& defaultValue = "", long style = wxOK | wxCANCEL | wxCENTRE, const wxPoint& pos = wxDefaultPosition)
	: wxTextEntryDialog(parent, message, caption, defaultValue, style, pos) {
	    URLValidator validator(&m_value);
	    SetTextValidator(validator);
	}
};

#if wxUSE_DRAG_AND_DROP
class DropURLs : public wxDropTarget
{
public:
    DropURLs(wxControlWithItems *owner)
	: m_owner(owner)
    {
	SetDataObject(new wxURLDataObject);
    }

    virtual wxDragResult OnDragOver(wxCoord WXUNUSED(x), wxCoord WXUNUSED(y),
				    wxDragResult WXUNUSED(def))
    {
	return wxDragLink;
    }

    virtual wxDragResult OnData(wxCoord WXUNUSED(x), wxCoord WXUNUSED(y), wxDragResult def)
    {
        if (!GetData())
	    return wxDragNone;

	wxString url = ((wxURLDataObject*)GetDataObject())->GetURL();
	url.Trim();
	url.Trim(false);

	wxArrayString good;

	wxStringTokenizer tokenizer(url);//tokenize lines
	while (tokenizer.HasMoreTokens()) {
	    wxString token = tokenizer.GetNextToken();
	    token.Trim();

	    URLValidator urlv;
	    wxString err = urlv.IsValid(token);
	    if (!err.IsEmpty()) {
		wxString buf;
		buf.Printf(err, token.c_str());
		wxMessageBox(buf, _("Validation conflict"),
			     wxOK | wxICON_EXCLAMATION, m_owner);
		return wxDragError;
	    }
	    good.Add(token);
	}
	for (unsigned i=0;i<good.GetCount();i++)
	    m_owner->Append(good[i]);

        return def;
    }
private:
    wxControlWithItems *m_owner;
};
#endif

WX_DECLARE_HASH_SET(wxString, wxStringHash, wxStringEqual, StringSet);

static wxString GetBasename(wxString path)
{
    return wxFileName(path).GetFullName().MakeLower();
}

void SigUIFrame::GetFreshclamDBnames(StringSet *set)
{
    set->insert("main.cvd");
    set->insert("daily.cvd");
    set->insert("bytecode.cvd");
    for (unsigned i=0;i<m_urls->GetCount();i++) {
	set->insert( GetBasename(m_urls->GetString(i)) );
    }
}

void SigUIFrame::m_custom_addOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    URLEntryDialog dlg(this, "Custom virus signatures source HTTP or file URL:", "Input http:// file:// URL or UNC path:");
    if (dlg.ShowModal() == wxID_OK) {
	wxString str = dlg.GetValue();
	if (str.StartsWith("\\\\")) {
	    wxLogWarning(_("You specified an UNC path, make sure the SYSTEM account can access it!\n"
			   "(SYSTEM account usually can't access network shares)"));
	    str = "file://" + str;//freshclam remove file:// so it should be fine
	}

	// look for duplicate basename (since it will they will just overwrite
	// eachother in the DBdir)
	StringSet db_set;
	GetFreshclamDBnames(&db_set);
	wxString basename = GetBasename(str);

	if (db_set.count(basename)) {
	    wxLogWarning(_("Adding this database (%s) will overwrite existing database (%s)!\n"
			   "You should remove one of them from the custom signatures list"),
			 str, basename);
	}

	m_urls->Append(str);
	m_custom_remove->Enable();
    }
}

void SigUIFrame::m_custom_removeOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    int n = m_urls->GetSelection();
    if (n == wxNOT_FOUND)
	return;
    m_urls->Delete(n);
    if (m_urls->IsEmpty())
	m_custom_remove->Disable();
}

static wxString GetExecPath()
{
    wxFileName exec(wxStandardPaths::Get().GetExecutablePath());
    return exec.GetPathWithSep();
}

static wxFileSystemWatcher *watcher;
void SigUIApp::OnEventLoopEnter(wxEventLoopBase *WXUNUSED(loop))
{
    watcher = new wxFileSystemWatcher();
    watcher->SetOwner(GetTopWindow());
    watcher->Add(GetExecPath(), wxFSW_EVENT_CREATE | wxFSW_EVENT_MODIFY |
		 wxFSW_EVENT_WARNING | wxFSW_EVENT_ERROR);
}

void SigUIFrame::m_save_settingsOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    if (!Validate() || !TransferDataFromWindow()) {
        wxLogWarning(_("Validation failed"));
        return;
    }
    editor->Save();
    wxLogMessage(_("Settings saved"));
}

static wxString GetConfigFile()
{
    return GetExecPath() + "freshclam.conf";
}
SigUIFrame::SigUIFrame(wxFrame *frame)
    : GUIFrame(frame), val_bytecode(true), watcher(0)
{
    #ifdef _WIN32
    SetIcon(wxIcon(wxT("aaaa")));
    #endif

    icon = new wxTaskBarIcon();
    icon->Connect(wxEVT_TASKBAR_BALLOON_TIMEOUT, wxTaskBarIconEventHandler(SigUIFrame::OnBalloon), NULL, this);
    icon->Connect(wxEVT_TASKBAR_BALLOON_CLICK, wxTaskBarIconEventHandler(SigUIFrame::OnBalloon), NULL, this);

    this->Connect(wxEVT_FSWATCHER, wxFileSystemWatcherEventHandler(SigUIFrame::OnChange));

    this->Connect(wxEVT_END_PROCESS, wxProcessEventHandler(SigUIFrame::OnTerminateInstall));

    this->SetStatusBar(statusBar);
    statusBar->SetStatusText(REPO_VERSION, 1);

//    m_sig_files->SetDropTarget(new DropFiles(m_sig_files));
//    m_urls->SetDropTarget(new DropURLs(m_urls));


    editor = new ConfigEditor(GetConfigFile());
    editor->RegisterText("HTTPProxyServer", &val_proxy_server, m_proxy_server, "hostname or IP address");
    editor->RegisterInt("HTTPProxyPort", &val_proxy_port, m_proxy_port);
    editor->RegisterText("HTTPProxyUsername", &val_proxy_username, m_proxy_user);
    editor->RegisterText("HTTPProxyPassword", &val_proxy_password, m_proxy_password);
    editor->RegisterText("DatabaseMirror", &val_mirror, m_mirror, "db.COUNTRYCODE.clamav.net");
    editor->RegisterStatic("DatabaseMirror", "database.clamav.net");
    editor->RegisterBool("Bytecode", &val_bytecode, m_bytecode);
    editor->RegisterList("DatabaseCustomURL", m_urls);

    HostnameValidator mirrorValidator(&val_mirror);
    m_mirror->SetValidator(mirrorValidator);

    HostnameValidator proxyValidator(&val_proxy_server);
    m_proxy_server->SetValidator(proxyValidator);

    editor->Load();
    if (!val_proxy_port)
        val_proxy_port = 8080;//default

    TransferDataToWindow();

    if (!val_proxy_server.empty()) {
	m_proxy->SetValue(true);
	if (!val_proxy_username.empty() && !val_proxy_password.empty())
	    m_proxyauth->SetValue(true);
    }

    // update enabled status
    wxCommandEvent event;
    m_proxyOnCheckBox(event);

    if (!m_urls->IsEmpty())
	m_custom_remove->Enable();

	m_proxy->SetFocus();

    // keyboard shortcuts
    wxAcceleratorEntry entries[1];
    entries[0].Set(wxACCEL_CTRL, (int)'S', wxID_SAVE);

    wxAcceleratorTable accel(sizeof(entries)/sizeof(entries[0]), entries);
    this->SetAcceleratorTable(accel);

    //prevent window from being resizing below minimum
    this->GetSizer()->SetSizeHints(this);
    show_db(true);
}

void SigUIFrame::OnBalloon(wxTaskBarIconEvent& WXUNUSED(event))
{
    if (icon->IsIconInstalled())
	icon->RemoveIcon();
}

void SigUIFrame::OnChange(wxFileSystemWatcherEvent &event)
{
    if (event.IsError()) {
	wxLogVerbose("fswatcher error: %s", event.GetErrorDescription());
	return;
    }
    wxLogVerbose("event on %s", event.GetPath().GetFullPath());
    switch (event.GetChangeType()) {
	default:
	    break;
	case wxFSW_EVENT_CREATE:
	case wxFSW_EVENT_MODIFY:
	    wxFileName filename = event.GetPath();
	    if (filename.GetName() != "lastupd")
		return;
	    show_db(false);
	    break;
    }
}

void SigUIFrame::show_db(bool first)
{
    wxLogNull logNo;
    char msg[512];
    wxFileName filename(GetExecPath() + "lastupd");
    if (!filename.IsFileReadable())
	return;
    wxFile file(filename.GetFullPath());
    if (!file.IsOpened())
	return;
    memset(&msg, 0, sizeof(msg));
    if (file.Read(msg, sizeof(msg) - 1) <= 0)
	return;

    wxString line = wxString(msg).BeforeFirst('\n');
    wxString text = statusBar->GetStatusText(0);
    statusBar->SetStatusText(line, 0);
    if (first || lastmsg == msg)
	return;
    lastmsg = msg;
    //only show when changed, and not the first time
    if (icon->IsIconInstalled())
	icon->RemoveIcon();//remove old balloon
    icon->SetIcon(GetIcon());
    line = wxString(msg).AfterFirst('\n');
#ifdef _WIN32
    icon->ShowBalloon("ClamAV database reloaded",
		      line, wxICON_INFORMATION);
#endif
    wxFileName filename0(GetExecPath() + "forcerld");
    wxLogVerbose("Reload delta: %s", filename.GetModificationTime().Subtract( filename0.GetModificationTime() ).Format());
}

void SigUIFrame::tabsOnNotebookPageChanged( wxNotebookEvent& event )
{
    event.Skip();
}

void SigUIFrame::GUIFrameOnIdle(wxIdleEvent& WXUNUSED(event))
{
    wxArrayString dbfiles;
    wxDir dir(GetExecPath());
    if (!dir.IsOpened())
	return;
    wxString filename;
    bool cont = dir.GetFirst(&filename);
    while (cont) {
	if (SigUICopy::validate_dbname(filename, true))
	    dbfiles.Add(filename);
	cont = dir.GetNext(&filename);
    }
    dbfiles.Sort();

    wxArrayString old_dbfiles = m_installed_sigs->GetStrings();
    if (old_dbfiles != dbfiles) {
	m_installed_sigs->Clear();
	m_installed_sigs->Append(dbfiles);
    }
}

class MyProcess : public wxProcess
{
    public:
	MyProcess(MyProcessOutput *parent) :
	    m_parent(parent) { }
	virtual void OnTerminate(int pid, int status)
	{
	    wxProcessEvent event(0,pid,status);
	    m_parent->OnTerminate(event);
	}
    private:
	MyProcessOutput *m_parent;
};

void SigUIFrame::reload()
{
    wxFileName filename(GetExecPath() + "forcerld");
    if (!filename.FileExists()) {
	wxFile file;
	if (!file.Create(filename.GetFullPath(), true)) {
	    wxLogMessage(_("Cannot signal reload"));
	    return;
	}
    } else {
	filename.Touch();
    }

    wxLogMessage(_("Database reload queued"));
}

void SigUIFrame::m_run_freshclamOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    MyProcessOutput *output = new MyProcessOutput(this);
    wxProcess *process = new MyProcess(output);
    process->Redirect();

    wxString cmd;
    cmd << "\"" << GetExecPath() << "freshclam.exe\" -v --config-file=\""
	<< GetConfigFile() << "\" --datadir=\"" << GetExecPath() << "\"";
    //wxMessageBox(cmd);
    long pid = wxExecute(cmd, wxEXEC_ASYNC, process);
    if (!pid) {
	wxLogError("Failed to launch freshclam");
	delete process;
	return;
    }
    process->SetPid(pid);
    process->CloseOutput();

    wxInputStream *in = process->GetInputStream();
    if (!in)
    {
        wxLogError("Failed to connect to child output");
        return;
    }

    output->SetProcess(process);
    output->ShowModal();
    reload();
}

MyProcessOutput::MyProcessOutput(wxWindow *parent)
    : ProcessOutput(parent), m_process(0), m_wakeup(this)
{
    this->Connect(wxEVT_END_PROCESS, wxProcessEventHandler(MyProcessOutput::OnTerminate));
    this->Connect(wxEVT_TIMER, wxTimerEventHandler(MyProcessOutput::OnTimer),NULL, this);
    this->GetSizer()->SetSizeHints(this);
    this->SetDoubleBuffered(true);
}

void MyProcessOutput::SetProcess(wxProcess *process)
{
    m_process = process;
}

void MyProcessOutput::ProcessOutputOnInitDialog( wxInitDialogEvent& WXUNUSED(event) )
{
    m_wakeup.Start(100);
}

void MyProcessOutput::ProcessOutputOnClose(wxCloseEvent &event)
{
    if (m_process) {
        if (event.CanVeto()) {
            event.Veto();
            return;
        }
        m_process->Detach();
    }
    EndModal(wxOK);
}

void MyProcessOutput::OnTimer(wxTimerEvent& WXUNUSED(event))
{
    wxWakeUpIdle();
}

bool MyProcessOutput::processInput()
{
    if (!m_process)
        return false;
    bool hasInput = false;
    m_logoutput->Freeze();
    while (m_process->IsInputAvailable()) {
        wxInputStream *in = m_process->GetInputStream();
        wxString msg;
	int c;
	static bool clear = false;

	do {
	    c = in->GetC();
	    if (in->Eof())
		break;
	    if (c >= 128)
		c = '?';
	    msg << (char)c;
	} while (c != '\r' && c != '\n');

	msg.Trim();
	msg.Trim(false);
	if (!msg.empty()) {
	    bool scroll = false;
	    if (clear && m_logoutput->GetCount() > 0)
		m_logoutput->Delete(m_logoutput->GetCount()-1);
	    else
		scroll = true;
	    m_logoutput->Append(msg);
	    m_logoutput->ScrollLines(1);
	}
	clear = c == '\r';
        hasInput = true;
    }
    while (m_process->IsErrorAvailable()) {
        wxTextInputStream tis(*m_process->GetErrorStream());
        wxString msg;
        msg << tis.ReadLine();
	msg.Trim();
	if (!msg.empty()) {
	    m_logoutput->Append(msg);
	    m_logoutput->ScrollLines(1);
	}
        hasInput = true;
    }
    m_logoutput->Thaw();
    return hasInput;
}

void MyProcessOutput::ProcessOutputOnIdle( wxIdleEvent& event )
{
    if (processInput())
	event.RequestMore();
}

void MyProcessOutput::OnTerminate(wxProcessEvent &event)
{
    m_wakeup.Stop();
    // show all output
    while (processInput()) {}

    int exit = event.GetExitCode();
    delete m_process;
    m_process = 0;

    m_cancel_process->SetLabel(_("&Close window"));
    wxString msg;
    msg << "Freshclam exited with code: " << exit;
    m_logoutput->Append(msg);
}

void MyProcessOutput::m_cancel_processOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    if (m_process) {
	long pid = m_process->GetPid();
	wxLogVerbose("terminate pid %ld", pid);
	if (!wxProcess::Exists(pid)) {
	    wxLogVerbose("process doesn't exist anymore");
	    return;
	}
	int answer = wxMessageBox(_("Are you sure you want to forcefully terminate freshclam?"),
                           _("Force terminate freshclam?"),
				  wxYES_NO | wxNO_DEFAULT | wxICON_QUESTION, this);
	if (answer != wxYES)
	    return;
	wxLogVerbose("kill pid %ld", pid);
	wxKillError rc =  wxProcess::Kill(pid, wxSIGKILL);
	if (rc != wxKILL_OK) {
	    wxLogVerbose("kill pid %ld failed: %d", pid, rc);
	    wxLogWarning(_("Failed to terminate process"));
	    return;
	}
	wxLogVerbose("killed pid %ld", pid);
/*	wxProcessEvent event(0,pid,255);
	OnTerminate(event);*/
	return;
    }
    // this is really the close button now
    EndModal(wxOK);
}

void SigUIFrame::m_local_addOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    //TODO: keep in sync with DBEXT
    wxString wildcard = "ClamAV database files (*.cbc, *.cdb, *.cfg, *.cld, *.cvd, *.db, *.fp, *.ftm, *.gdb, *.hdb, *.hdu, *.idb, *.ldb, *.ldu, *.mdb, *.mdu, *.ndb, *.ndu, *.pdb, *.rmd, *.sdb, *.wdb, *.zmd)|*.cbc;*.cdb;*.cfg;*.cld;*.cvd;*.db;*.fp;*.ftm;*.gdb;*.hdb;*.hdu;*.idb;*.ldb;*.ldu;*.mdb;*.mdu;*.ndb;*.ndu;*.pdb;*.rmd;*.sdb;*.wdb;*.zmd";
    wxFileDialog dlg(this, _("Choose a virus signature file"),
		     wxEmptyString, wxEmptyString,
		     wildcard,
		     wxFD_OPEN | wxFD_FILE_MUST_EXIST | wxFD_MULTIPLE | wxFD_CHANGE_DIR);
    dlg.CentreOnParent();
    if (dlg.ShowModal() == wxID_OK) {
	wxArrayString paths;
	dlg.GetPaths(paths);
	StringSet db_set;
	GetFreshclamDBnames(&db_set);

	for (unsigned i=0;i<paths.GetCount();i++) {
	    wxString path = paths[i];
	    if (m_sig_candidates->FindString(path, false) != wxNOT_FOUND) {
		wxLogWarning(_("File already added: %s"), path);
		continue;
	    }
	    if (db_set.count(GetBasename(path))) {
		wxLogWarning(_("File is managed by freshclam. On next update it will be overwritten: %s"), path);
	    }

	    m_sig_candidates->Append(path);
	}
	m_local_remove->Enable(!m_sig_candidates->IsEmpty());
	m_install->Enable(!m_sig_candidates->IsEmpty());
    }
}

void SigUIFrame::m_local_removeOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    wxArrayInt selections;
    int n = m_sig_candidates->GetSelections(selections);
    while ( n > 0 )
    {
        m_sig_candidates->Delete(selections[--n]);
    }
    m_local_remove->Enable(!m_sig_candidates->IsEmpty());
    m_install->Enable(!m_sig_candidates->IsEmpty());
}

void SigUIFrame::OnTerminateInstall(wxProcessEvent &event)
{
    wxEndBusyCursor();
    wxWakeUpIdle();
    if (event.GetExitCode() == 0) {
	m_sig_candidates->Clear();
	wxLogMessage(_("Successfully installed new virus signatures\n"));
	reload();
    } else {
	bool had_errors = false;
	wxInputStream *err = m_siginst_process->GetErrorStream();
	wxTextInputStream tis(*err);

	while (!err->Eof()) {
	    wxString line = tis.ReadLine();
	    line.Trim();
	    if (!line.IsEmpty()) {
		wxLogWarning("%s", line);
		had_errors = true;
	    }
	}
	if (had_errors) {
	    wxLogError(_("Errors encountered during virus signature install"));
	}
    }
    delete m_siginst_process;

    m_panel_sigman->Enable();
}

void SigUIFrame::m_installOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    wxWakeUpIdle();
    wxBeginBusyCursor();
    m_panel_sigman->Disable();

    wxFileName exec(wxStandardPaths::Get().GetExecutablePath());
    m_siginst_process = new wxProcess(this);
    m_siginst_process->Redirect();

    long pid = wxExecute("\"" + exec.GetFullPath() + "\" -i", wxEXEC_ASYNC | wxEXEC_NOHIDE, m_siginst_process);
    if (!pid) {
	wxLogError(_("Failed to reexecute self for installing the virus signatures!"));
	return;
    }
    m_siginst_process->SetPid(pid);

    wxOutputStream *out = m_siginst_process->GetOutputStream();
    for (unsigned i=0;i<m_sig_candidates->GetCount();i++) {
	wxString str = m_sig_candidates->GetString(i) + "\n";
	const char *s = str.mb_str();
	if (*s) {
	    out->Write(s, strlen(s));
	} else {
	    // see bb #2343
	    wxLogError(_("Filenames with non-ASCII characters not yet supported: %s"), str);
	    return;
	}
    }
    m_siginst_process->CloseOutput();
    wxWakeUpIdle();
}

void SigUIFrame::m_deleteOnButtonClick( wxCommandEvent& WXUNUSED(event) )
{
    wxArrayInt selections;
    int n = m_installed_sigs->GetSelections(selections);
    while ( n > 0 )
    {
	wxString file = m_installed_sigs->GetString(selections[--n]);
	if (file.CmpNoCase("daily.cvd") == 0 ||
	    file.CmpNoCase("daily.cld") == 0) {
	    wxLogError(_("daily.cvd and daily.cld cannot be removed!"));
	    continue;
	}

	wxString msg;
	msg.Printf(_("Are you sure you want to delete  %s?"), file);
	int answer = wxMessageBox(msg, _("Delete virus signature database"),
				  wxYES_NO | wxCANCEL | wxNO_DEFAULT | wxICON_QUESTION, this);
	if (answer == wxCANCEL)
	    break;
	if (answer != wxYES)
	    continue;

	if (file.AfterLast('.').CmpNoCase("cvd") == 0 ||
	    file.AfterLast('.').CmpNoCase("cld") == 0) {
	    msg.Printf(_("This is an important database file, managed by freshclam.\nAre you sure you want to delete %s?"),
		       file);
	    answer = wxMessageBox(msg, _("Delete important virus signature database"),
				  wxYES_NO | wxCANCEL | wxNO_DEFAULT | wxICON_QUESTION, this);
	    if (answer == wxCANCEL)
		break;
	    if (answer != wxYES)
		continue;
	}

	wxFileName filepath(GetExecPath(), file);
	if (!wxRemoveFile(filepath.GetFullPath())) {
	    wxLogError(_("Can't remove file %s"), filepath.GetFullPath());
	} else
	    reload();
    }

    wxWakeUpIdle();
}

void SigUIFrame::m_bytecodeOnCheckBox( wxCommandEvent& WXUNUSED(event) )
{
    bool enable = m_bytecode->IsChecked();
    if (!enable) {
	int answer = wxMessageBox(_("It is NOT recommended to disable bytecode.\n"
				    "Are you sure you want to disable it?"),
				  _("Disabling important signature database"),
				  wxYES_NO | wxCANCEL | wxNO_DEFAULT | wxICON_QUESTION, this);
	if (answer != wxYES)
	    m_bytecode->SetValue(true);
    }
}
