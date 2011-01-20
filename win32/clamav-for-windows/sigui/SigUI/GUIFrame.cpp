///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Sep  8 2010)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif //__BORLANDC__

#ifndef WX_PRECOMP
#include <wx/wx.h>
#endif //WX_PRECOMP

#include "GUIFrame.h"

///////////////////////////////////////////////////////////////////////////

GUIFrame::GUIFrame( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxFrame( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	this->SetExtraStyle( wxWS_EX_VALIDATE_RECURSIVELY );
	
	statusBar = this->CreateStatusBar( 2, wxST_SIZEGRIP, wxID_ANY );
	wxBoxSizer* bSizer1;
	bSizer1 = new wxBoxSizer( wxVERTICAL );
	
	tabs = new wxNotebook( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0|wxTAB_TRAVERSAL );
	m_panel_updater = new wxPanel( tabs, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer4;
	bSizer4 = new wxBoxSizer( wxVERTICAL );
	
	wxStaticBoxSizer* sbSizer1;
	sbSizer1 = new wxStaticBoxSizer( new wxStaticBox( m_panel_updater, wxID_ANY, _("Proxy settings") ), wxVERTICAL );
	
	gbSizer5 = new wxGridBagSizer( 0, 0 );
	gbSizer5->SetFlexibleDirection( wxBOTH );
	gbSizer5->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_proxy = new wxCheckBox( m_panel_updater, wxID_ANY, _("&Proxy required for Internet access"), wxDefaultPosition, wxDefaultSize, 0 );
	m_proxy->SetToolTip( _("Configure freshclam to use a proxy for fetching the updates") );
	
	gbSizer5->Add( m_proxy, wxGBPosition( 0, 0 ), wxGBSpan( 1, 2 ), wxALL, 5 );
	
	m_staticText2 = new wxStaticText( m_panel_updater, wxID_ANY, _("Proxy server:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText2->Wrap( -1 );
	gbSizer5->Add( m_staticText2, wxGBPosition( 1, 0 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	m_proxy_server = new wxTextCtrl( m_panel_updater, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_proxy_server->Enable( false );
	m_proxy_server->SetToolTip( _("hostname or IP address of proxy server") );
	
	gbSizer5->Add( m_proxy_server, wxGBPosition( 1, 1 ), wxGBSpan( 1, 1 ), wxALL|wxEXPAND, 5 );
	
	m_staticText3 = new wxStaticText( m_panel_updater, wxID_ANY, _("Proxy port:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText3->Wrap( -1 );
	gbSizer5->Add( m_staticText3, wxGBPosition( 2, 0 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	m_proxy_port = new wxSpinCtrl( m_panel_updater, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxSP_ARROW_KEYS, 0, 65536, 3128 );
	m_proxy_port->Enable( false );
	m_proxy_port->SetToolTip( _("port of proxy server") );
	
	gbSizer5->Add( m_proxy_port, wxGBPosition( 2, 1 ), wxGBSpan( 1, 1 ), wxALL|wxEXPAND, 5 );
	
	m_proxyauth = new wxCheckBox( m_panel_updater, wxID_ANY, _("A&uthentication required"), wxDefaultPosition, wxDefaultSize, 0 );
	m_proxyauth->Enable( false );
	m_proxyauth->SetToolTip( _("Configure freshclam to authenticate to the proxy server") );
	
	gbSizer5->Add( m_proxyauth, wxGBPosition( 3, 0 ), wxGBSpan( 1, 2 ), wxALL, 5 );
	
	m_staticText4 = new wxStaticText( m_panel_updater, wxID_ANY, _("Proxy username:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText4->Wrap( -1 );
	gbSizer5->Add( m_staticText4, wxGBPosition( 4, 0 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	m_proxy_user = new wxTextCtrl( m_panel_updater, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
	m_proxy_user->Enable( false );
	m_proxy_user->SetToolTip( _("username for proxy authentication") );
	
	gbSizer5->Add( m_proxy_user, wxGBPosition( 4, 1 ), wxGBSpan( 1, 1 ), wxALL|wxEXPAND, 5 );
	
	m_staticText5 = new wxStaticText( m_panel_updater, wxID_ANY, _("Proxy password:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText5->Wrap( -1 );
	gbSizer5->Add( m_staticText5, wxGBPosition( 5, 0 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	m_proxy_password = new wxTextCtrl( m_panel_updater, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_proxy_password->Enable( false );
	m_proxy_password->SetToolTip( _("password for proxy authentication") );
	
	gbSizer5->Add( m_proxy_password, wxGBPosition( 5, 1 ), wxGBSpan( 1, 1 ), wxALL|wxEXPAND, 5 );
	
	m_proxy_autodet = new wxButton( m_panel_updater, wxID_ANY, _("R&etrieve system proxy settings"), wxDefaultPosition, wxDefaultSize, 0 );
	m_proxy_autodet->SetToolTip( _("Copy system proxy setting to freshclam's") );
	
	gbSizer5->Add( m_proxy_autodet, wxGBPosition( 6, 0 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	
	wxStaticText* m_customControl3 = new wxStaticText(m_panel_updater, wxID_ANY, wxT(""));
	gbSizer5->AddGrowableCol(1);
	gbSizer5->Add( m_customControl3, wxGBPosition( 6, 1 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	sbSizer1->Add( gbSizer5, 1, wxALL|wxEXPAND, 5 );
	
	bSizer4->Add( sbSizer1, 0, wxALL|wxEXPAND, 5 );
	
	wxStaticBoxSizer* sbSizer2;
	sbSizer2 = new wxStaticBoxSizer( new wxStaticBox( m_panel_updater, wxID_ANY, _("Signature sources") ), wxVERTICAL );
	
	wxFlexGridSizer* fgSizer1;
	fgSizer1 = new wxFlexGridSizer( 2, 2, 0, 0 );
	fgSizer1->AddGrowableCol( 1 );
	fgSizer1->SetFlexibleDirection( wxBOTH );
	fgSizer1->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText6 = new wxStaticText( m_panel_updater, wxID_ANY, _("Download Official Signatures from mirror:"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText6->Wrap( -1 );
	fgSizer1->Add( m_staticText6, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_mirror = new wxComboBox( m_panel_updater, wxID_ANY, _("db.local.win.clamav.net"), wxDefaultPosition, wxDefaultSize, 0, NULL, 0 );
	m_mirror->Append( _("db.at.clamav.net") );
	m_mirror->Append( _("db.au.clamav.net") );
	m_mirror->Append( _("db.ba.clamav.net") );
	m_mirror->Append( _("db.br.clamav.net") );
	m_mirror->Append( _("db.by.clamav.net") );
	m_mirror->Append( _("db.ca.clamav.net") );
	m_mirror->Append( _("db.ch.clamav.net") );
	m_mirror->Append( _("db.cn.clamav.net") );
	m_mirror->Append( _("db.cy.clamav.net") );
	m_mirror->Append( _("db.cz.clamav.net") );
	m_mirror->Append( _("db.de.clamav.net") );
	m_mirror->Append( _("db.dk.clamav.net") );
	m_mirror->Append( _("db.ee.clamav.net") );
	m_mirror->Append( _("db.es.clamav.net") );
	m_mirror->Append( _("db.fi.clamav.net") );
	m_mirror->Append( _("db.fr.clamav.net") );
	m_mirror->Append( _("db.gl.clamav.net") );
	m_mirror->Append( _("db.gr.clamav.net") );
	m_mirror->Append( _("db.hk.clamav.net") );
	m_mirror->Append( _("db.hu.clamav.net") );
	m_mirror->Append( _("db.id.clamav.net") );
	m_mirror->Append( _("db.ie.clamav.net") );
	m_mirror->Append( _("db.in.clamav.net") );
	m_mirror->Append( _("db.it.clamav.net") );
	m_mirror->Append( _("db.jp.clamav.net") );
	m_mirror->Append( _("db.kr.clamav.net") );
	m_mirror->Append( _("db.li.clamav.net") );
	m_mirror->Append( _("db.lt.clamav.net") );
	m_mirror->Append( _("db.mt.clamav.net") );
	m_mirror->Append( _("db.nl.clamav.net") );
	m_mirror->Append( _("db.no.clamav.net") );
	m_mirror->Append( _("db.pl.clamav.net") );
	m_mirror->Append( _("db.pt.clamav.net") );
	m_mirror->Append( _("db.ro.clamav.net") );
	m_mirror->Append( _("db.ru.clamav.net") );
	m_mirror->Append( _("db.se.clamav.net") );
	m_mirror->Append( _("db.si.clamav.net") );
	m_mirror->Append( _("db.sk.clamav.net") );
	m_mirror->Append( _("db.th.clamav.net") );
	m_mirror->Append( _("db.tr.clamav.net") );
	m_mirror->Append( _("db.tw.clamav.net") );
	m_mirror->Append( _("db.ua.clamav.net") );
	m_mirror->Append( _("db.uk.clamav.net") );
	m_mirror->Append( _("db.us.clamav.net") );
	m_mirror->Append( _("db.local.clamav.net") );
	m_mirror->SetToolTip( _("Choose mirror (db.COUNTRYCODE.clamav.net)") );
	
	fgSizer1->Add( m_mirror, 1, wxALIGN_CENTER_VERTICAL|wxALL|wxEXPAND, 5 );
	
	m_bytecode = new wxCheckBox( m_panel_updater, wxID_ANY, _("Official bytecode signatures"), wxDefaultPosition, wxDefaultSize, 0 );
	m_bytecode->SetValue(true); 
	fgSizer1->Add( m_bytecode, 0, wxALL, 5 );
	
	sbSizer2->Add( fgSizer1, 0, wxEXPAND, 5 );
	
	wxStaticBoxSizer* sbSizer3;
	sbSizer3 = new wxStaticBoxSizer( new wxStaticBox( m_panel_updater, wxID_ANY, _("Custom signature URLs") ), wxVERTICAL );
	
	wxGridBagSizer* gbSizer6;
	gbSizer6 = new wxGridBagSizer( 0, 0 );
	gbSizer6->AddGrowableCol( 0 );
	gbSizer6->AddGrowableRow( 2 );
	gbSizer6->SetFlexibleDirection( wxBOTH );
	gbSizer6->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_urls = new wxListBox( m_panel_updater, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, NULL, wxLB_NEEDED_SB|wxLB_SINGLE ); 
	m_urls->SetToolTip( _("URLs from where custom signatures are downloaded") );
	
	gbSizer6->Add( m_urls, wxGBPosition( 0, 0 ), wxGBSpan( 3, 1 ), wxALL|wxEXPAND, 5 );
	
	m_custom_add = new wxButton( m_panel_updater, wxID_ANY, _("&Add"), wxDefaultPosition, wxDefaultSize, 0 );
	m_custom_add->SetToolTip( _("Add a new custom signature URL") );
	
	gbSizer6->Add( m_custom_add, wxGBPosition( 0, 1 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	m_custom_remove = new wxButton( m_panel_updater, wxID_ANY, _("&Remove"), wxDefaultPosition, wxDefaultSize, 0 );
	m_custom_remove->Enable( false );
	m_custom_remove->SetToolTip( _("Remove a custom signature URL") );
	
	gbSizer6->Add( m_custom_remove, wxGBPosition( 1, 1 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	sbSizer3->Add( gbSizer6, 1, wxEXPAND, 5 );
	
	sbSizer2->Add( sbSizer3, 1, wxEXPAND, 5 );
	
	bSizer4->Add( sbSizer2, 1, wxALL|wxEXPAND, 5 );
	
	wxBoxSizer* bSizer41;
	bSizer41 = new wxBoxSizer( wxHORIZONTAL );
	
	m_save_settings = new wxButton( m_panel_updater, wxID_SAVE, _("&Save settings"), wxDefaultPosition, wxDefaultSize, 0 );
	m_save_settings->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), 70, 90, 92, false, wxEmptyString ) );
	m_save_settings->SetToolTip( _("Save proxy and signature source settings to freshclam.conf") );
	
	bSizer41->Add( m_save_settings, 0, wxALL|wxALIGN_CENTER_HORIZONTAL, 5 );
	
	
	bSizer41->Add( 10, 0, 1, wxEXPAND, 5 );
	
	m_run_freshclam = new wxButton( m_panel_updater, wxID_ANY, _("Run &freshclam to test configuration"), wxDefaultPosition, wxDefaultSize, 0 );
	m_run_freshclam->SetToolTip( _("Runs freshclam database updater") );
	
	bSizer41->Add( m_run_freshclam, 0, wxALL, 5 );
	
	bSizer4->Add( bSizer41, 0, wxALIGN_CENTER_HORIZONTAL, 5 );
	
	m_panel_updater->SetSizer( bSizer4 );
	m_panel_updater->Layout();
	bSizer4->Fit( m_panel_updater );
	tabs->AddPage( m_panel_updater, _("Updater configuration"), true );
	m_panel_sigman = new wxPanel( tabs, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer7;
	bSizer7 = new wxBoxSizer( wxVERTICAL );
	
	wxStaticBoxSizer* sbSizer4;
	sbSizer4 = new wxStaticBoxSizer( new wxStaticBox( m_panel_sigman, wxID_ANY, _("New signatures") ), wxVERTICAL );
	
	wxGridBagSizer* gbSizer61;
	gbSizer61 = new wxGridBagSizer( 0, 0 );
	gbSizer61->AddGrowableCol( 0 );
	gbSizer61->AddGrowableRow( 2 );
	gbSizer61->SetFlexibleDirection( wxBOTH );
	gbSizer61->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_sig_candidates = new wxListBox( m_panel_sigman, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, NULL, wxLB_EXTENDED|wxLB_HSCROLL|wxLB_NEEDED_SB ); 
	m_sig_candidates->SetToolTip( _("signature files to be added (candidates)") );
	
	gbSizer61->Add( m_sig_candidates, wxGBPosition( 0, 0 ), wxGBSpan( 3, 1 ), wxALL|wxEXPAND, 5 );
	
	m_local_add = new wxButton( m_panel_sigman, wxID_ANY, _("&Add"), wxDefaultPosition, wxDefaultSize, 0 );
	m_local_add->SetToolTip( _("Add new signature file candidate") );
	
	gbSizer61->Add( m_local_add, wxGBPosition( 0, 1 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	m_local_remove = new wxButton( m_panel_sigman, wxID_ANY, _("&Remove"), wxDefaultPosition, wxDefaultSize, 0 );
	m_local_remove->Enable( false );
	m_local_remove->SetToolTip( _("Remove a signature file candidate") );
	
	gbSizer61->Add( m_local_remove, wxGBPosition( 1, 1 ), wxGBSpan( 1, 1 ), wxALL, 5 );
	
	sbSizer4->Add( gbSizer61, 1, wxEXPAND, 5 );
	
	bSizer7->Add( sbSizer4, 1, wxALL|wxEXPAND, 5 );
	
	m_install = new wxButton( m_panel_sigman, wxID_ANY, _("Verify and &Install signatures"), wxDefaultPosition, wxDefaultSize, 0 );
	m_install->Enable( false );
	m_install->SetToolTip( _("Check that the signature files are well formed and install them in ClamAV's database directory") );
	
	bSizer7->Add( m_install, 0, wxALL|wxALIGN_CENTER_HORIZONTAL, 5 );
	
	wxStaticBoxSizer* sbSizer5;
	sbSizer5 = new wxStaticBoxSizer( new wxStaticBox( m_panel_sigman, wxID_ANY, _("Installed signatures") ), wxHORIZONTAL );
	
	m_installed_sigs = new wxListBox( m_panel_sigman, wxID_ANY, wxDefaultPosition, wxDefaultSize, 0, NULL, wxLB_EXTENDED|wxLB_HSCROLL|wxLB_NEEDED_SB ); 
	m_installed_sigs->SetToolTip( _("Databases currently usable by ClamAV") );
	
	sbSizer5->Add( m_installed_sigs, 1, wxALL|wxEXPAND, 5 );
	
	m_delete = new wxButton( m_panel_sigman, wxID_ANY, _("&Delete"), wxDefaultPosition, wxDefaultSize, 0 );
	m_delete->SetToolTip( _("Delete an actual signature database from the disk") );
	
	sbSizer5->Add( m_delete, 0, wxALL, 5 );
	
	bSizer7->Add( sbSizer5, 1, wxALL|wxEXPAND, 5 );
	
	m_panel_sigman->SetSizer( bSizer7 );
	m_panel_sigman->Layout();
	bSizer7->Fit( m_panel_sigman );
	tabs->AddPage( m_panel_sigman, _("Local signature management"), false );
	
	bSizer1->Add( tabs, 1, wxEXPAND, 5 );
	
	this->SetSizer( bSizer1 );
	this->Layout();
	
	// Connect Events
	this->Connect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( GUIFrame::OnClose ) );
	this->Connect( wxEVT_IDLE, wxIdleEventHandler( GUIFrame::GUIFrameOnIdle ) );
	tabs->Connect( wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGED, wxNotebookEventHandler( GUIFrame::tabsOnNotebookPageChanged ), NULL, this );
	m_proxy->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( GUIFrame::m_proxyOnCheckBox ), NULL, this );
	m_proxyauth->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( GUIFrame::m_proxyauthOnCheckBox ), NULL, this );
	m_proxy_autodet->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_proxy_autodetOnButtonClick ), NULL, this );
	m_bytecode->Connect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( GUIFrame::m_bytecodeOnCheckBox ), NULL, this );
	m_custom_add->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_custom_addOnButtonClick ), NULL, this );
	m_custom_remove->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_custom_removeOnButtonClick ), NULL, this );
	m_save_settings->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_save_settingsOnButtonClick ), NULL, this );
	m_run_freshclam->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_run_freshclamOnButtonClick ), NULL, this );
	m_local_add->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_local_addOnButtonClick ), NULL, this );
	m_local_remove->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_local_removeOnButtonClick ), NULL, this );
	m_install->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_installOnButtonClick ), NULL, this );
	m_delete->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_deleteOnButtonClick ), NULL, this );
}

GUIFrame::~GUIFrame()
{
	// Disconnect Events
	this->Disconnect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( GUIFrame::OnClose ) );
	this->Disconnect( wxEVT_IDLE, wxIdleEventHandler( GUIFrame::GUIFrameOnIdle ) );
	tabs->Disconnect( wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGED, wxNotebookEventHandler( GUIFrame::tabsOnNotebookPageChanged ), NULL, this );
	m_proxy->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( GUIFrame::m_proxyOnCheckBox ), NULL, this );
	m_proxyauth->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( GUIFrame::m_proxyauthOnCheckBox ), NULL, this );
	m_proxy_autodet->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_proxy_autodetOnButtonClick ), NULL, this );
	m_bytecode->Disconnect( wxEVT_COMMAND_CHECKBOX_CLICKED, wxCommandEventHandler( GUIFrame::m_bytecodeOnCheckBox ), NULL, this );
	m_custom_add->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_custom_addOnButtonClick ), NULL, this );
	m_custom_remove->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_custom_removeOnButtonClick ), NULL, this );
	m_save_settings->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_save_settingsOnButtonClick ), NULL, this );
	m_run_freshclam->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_run_freshclamOnButtonClick ), NULL, this );
	m_local_add->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_local_addOnButtonClick ), NULL, this );
	m_local_remove->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_local_removeOnButtonClick ), NULL, this );
	m_install->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_installOnButtonClick ), NULL, this );
	m_delete->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( GUIFrame::m_deleteOnButtonClick ), NULL, this );
	
}

ProcessOutput::ProcessOutput( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	
	wxBoxSizer* bSizer5;
	bSizer5 = new wxBoxSizer( wxVERTICAL );
	
	m_logoutput = new wxListBox( this, wxID_ANY, wxDefaultPosition, wxSize( 700,300 ), 0, NULL, wxLB_ALWAYS_SB|wxLB_HSCROLL|wxALWAYS_SHOW_SB ); 
	m_logoutput->SetFont( wxFont( wxNORMAL_FONT->GetPointSize(), 76, 90, 90, false, wxEmptyString ) );
	
	bSizer5->Add( m_logoutput, 1, wxALL|wxEXPAND, 5 );
	
	m_cancel_process = new wxButton( this, wxID_ANY, _("&Terminate updater"), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer5->Add( m_cancel_process, 0, wxALL|wxALIGN_CENTER_HORIZONTAL, 5 );
	
	this->SetSizer( bSizer5 );
	this->Layout();
	bSizer5->Fit( this );
	
	this->Centre( wxBOTH );
	
	// Connect Events
	this->Connect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( ProcessOutput::ProcessOutputOnClose ) );
	this->Connect( wxEVT_IDLE, wxIdleEventHandler( ProcessOutput::ProcessOutputOnIdle ) );
	this->Connect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( ProcessOutput::ProcessOutputOnInitDialog ) );
	m_cancel_process->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ProcessOutput::m_cancel_processOnButtonClick ), NULL, this );
}

ProcessOutput::~ProcessOutput()
{
	// Disconnect Events
	this->Disconnect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( ProcessOutput::ProcessOutputOnClose ) );
	this->Disconnect( wxEVT_IDLE, wxIdleEventHandler( ProcessOutput::ProcessOutputOnIdle ) );
	this->Disconnect( wxEVT_INIT_DIALOG, wxInitDialogEventHandler( ProcessOutput::ProcessOutputOnInitDialog ) );
	m_cancel_process->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ProcessOutput::m_cancel_processOnButtonClick ), NULL, this );
	
}
