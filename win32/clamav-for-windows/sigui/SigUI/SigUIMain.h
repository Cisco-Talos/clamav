/***************************************************************
 * Purpose:   Defines Application Frame
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


#ifndef SIGUIMAIN_H
#define SIGUIMAIN_H

#include "SigUIApp.h"
#include "GUIFrame.h"
#include "ConfigEditor.h"

class StringSet;
class SigUIFrame: public GUIFrame
{
    public:
        SigUIFrame(wxFrame *frame);
        ~SigUIFrame();
    private:
	ConfigEditor *editor;
	wxString      val_proxy_server;
	int           val_proxy_port;
	wxString      val_proxy_username;
	wxString      val_proxy_password;
	wxString      val_mirror;
	bool          val_bytecode;
	wxProcess     *m_siginst_process;
	wxFileSystemWatcher *watcher;
	wxTaskBarIcon       *icon;
	wxString            lastmsg;

        virtual void OnClose(wxCloseEvent& event);
        virtual void OnQuit(wxCommandEvent& event);
        virtual void OnAbout(wxCommandEvent& event);
        virtual void m_proxyauthOnCheckBox( wxCommandEvent& event );
        virtual void m_proxyOnCheckBox( wxCommandEvent& event );
        virtual void m_proxy_autodetOnButtonClick( wxCommandEvent& event );
	virtual void m_custom_addOnButtonClick( wxCommandEvent& event );
	virtual void m_custom_removeOnButtonClick( wxCommandEvent& event );
	virtual void m_save_settingsOnButtonClick( wxCommandEvent& event );
	virtual void m_run_freshclamOnButtonClick( wxCommandEvent& event );
	virtual void m_local_addOnButtonClick( wxCommandEvent& event );
	virtual void m_local_removeOnButtonClick( wxCommandEvent& event );
	virtual void m_installOnButtonClick( wxCommandEvent& event );
	virtual void m_deleteOnButtonClick( wxCommandEvent& event );
	virtual void m_bytecodeOnCheckBox( wxCommandEvent& event );
	virtual void GUIFrameOnIdle( wxIdleEvent& event );
	void tabsOnNotebookPageChanged( wxNotebookEvent& event );
	void OnTerminateInstall(wxProcessEvent &event);
	void OnChange(wxFileSystemWatcherEvent &event);
	void GetFreshclamDBnames(StringSet *set);
	void OnBalloon(wxTaskBarIconEvent& event);
	void reload(void);
	void show_db(bool first);
};

class MyProcessOutput : public ProcessOutput
{
    public:
	MyProcessOutput(wxWindow *parent);
	void SetProcess(wxProcess *process);
	virtual void ProcessOutputOnIdle( wxIdleEvent& event );
	virtual void m_cancel_processOnButtonClick( wxCommandEvent& event );
	virtual void OnTerminate(wxProcessEvent& event);
	virtual void OnTimer(wxTimerEvent &event);
	virtual void ProcessOutputOnClose(wxCloseEvent &event);
	virtual void ProcessOutputOnInitDialog( wxInitDialogEvent& event );

    private:
	wxProcess *m_process;
	wxTimer m_wakeup;
	bool processInput(void);
};

#endif // SIGUIMAIN_H
