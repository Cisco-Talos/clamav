///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Sep  8 2010)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __GUIFrame__
#define __GUIFrame__

#include <wx/intl.h>

#include <wx/statusbr.h>
#include <wx/gdicmn.h>
#include <wx/font.h>
#include <wx/colour.h>
#include <wx/settings.h>
#include <wx/string.h>
#include <wx/checkbox.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/spinctrl.h>
#include <wx/button.h>
#include <wx/gbsizer.h>
#include <wx/sizer.h>
#include <wx/statbox.h>
#include <wx/combobox.h>
#include <wx/listbox.h>
#include <wx/panel.h>
#include <wx/bitmap.h>
#include <wx/image.h>
#include <wx/icon.h>
#include <wx/notebook.h>
#include <wx/frame.h>
#include <wx/dialog.h>

///////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
/// Class GUIFrame
///////////////////////////////////////////////////////////////////////////////
class GUIFrame : public wxFrame 
{
	private:
	
	protected:
		wxStatusBar* statusBar;
		wxNotebook* tabs;
		wxPanel* m_panel_updater;
		wxGridBagSizer* gbSizer5;
		wxCheckBox* m_proxy;
		wxStaticText* m_staticText2;
		wxTextCtrl* m_proxy_server;
		wxStaticText* m_staticText3;
		wxSpinCtrl* m_proxy_port;
		wxCheckBox* m_proxyauth;
		wxStaticText* m_staticText4;
		wxTextCtrl* m_proxy_user;
		wxStaticText* m_staticText5;
		wxTextCtrl* m_proxy_password;
		wxButton* m_proxy_autodet;
		
		wxStaticText* m_staticText6;
		wxComboBox* m_mirror;
		wxCheckBox* m_bytecode;
		wxListBox* m_urls;
		wxButton* m_custom_add;
		wxButton* m_custom_remove;
		wxButton* m_save_settings;
		
		wxButton* m_run_freshclam;
		wxPanel* m_panel_sigman;
		wxListBox* m_sig_candidates;
		wxButton* m_local_add;
		wxButton* m_local_remove;
		wxButton* m_install;
		wxListBox* m_installed_sigs;
		wxButton* m_delete;
		
		// Virtual event handlers, overide them in your derived class
		virtual void OnClose( wxCloseEvent& event ) = 0;
		virtual void GUIFrameOnIdle( wxIdleEvent& event ) = 0;
		virtual void tabsOnNotebookPageChanged( wxNotebookEvent& event ) = 0;
		virtual void m_proxyOnCheckBox( wxCommandEvent& event ) = 0;
		virtual void m_proxyauthOnCheckBox( wxCommandEvent& event ) = 0;
		virtual void m_proxy_autodetOnButtonClick( wxCommandEvent& event ) = 0;
		virtual void m_bytecodeOnCheckBox( wxCommandEvent& event ) = 0;
		virtual void m_custom_addOnButtonClick( wxCommandEvent& event ) = 0;
		virtual void m_custom_removeOnButtonClick( wxCommandEvent& event ) = 0;
		virtual void m_save_settingsOnButtonClick( wxCommandEvent& event ) = 0;
		virtual void m_run_freshclamOnButtonClick( wxCommandEvent& event ) = 0;
		virtual void m_local_addOnButtonClick( wxCommandEvent& event ) = 0;
		virtual void m_local_removeOnButtonClick( wxCommandEvent& event ) = 0;
		virtual void m_installOnButtonClick( wxCommandEvent& event ) = 0;
		virtual void m_deleteOnButtonClick( wxCommandEvent& event ) = 0;
		
	
	public:
		
		GUIFrame( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Signature configuration UI"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 590,674 ), long style = wxDEFAULT_FRAME_STYLE|wxTAB_TRAVERSAL );
		~GUIFrame();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class ProcessOutput
///////////////////////////////////////////////////////////////////////////////
class ProcessOutput : public wxDialog 
{
	private:
	
	protected:
		wxListBox* m_logoutput;
		wxButton* m_cancel_process;
		
		// Virtual event handlers, overide them in your derived class
		virtual void ProcessOutputOnClose( wxCloseEvent& event ) = 0;
		virtual void ProcessOutputOnIdle( wxIdleEvent& event ) = 0;
		virtual void ProcessOutputOnInitDialog( wxInitDialogEvent& event ) = 0;
		virtual void m_cancel_processOnButtonClick( wxCommandEvent& event ) = 0;
		
	
	public:
		
		ProcessOutput( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Freshclam output"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxDefaultSize, long style = wxDEFAULT_DIALOG_STYLE|wxCLIP_CHILDREN|wxTAB_TRAVERSAL );
		~ProcessOutput();
	
};

#endif //__GUIFrame__
