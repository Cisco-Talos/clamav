// clamav.cpp : Defines the class behaviors for the application.
//

/*
 *  Copyright (C) 2004 Nigel Horne <njh@bandsman.co.uk>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include "stdafx.h"
#include "resource.h"

#include "clamav.h"

#include "clamadoc.h"
#include "clamavw.h"

#include <winsock.h>

#ifdef _DEBUG
#undef THIS_FILE
static char BASED_CODE THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CClamavApp

BEGIN_MESSAGE_MAP(CClamavApp, CWinApp)
	//{{AFX_MSG_MAP(CClamavApp)
	ON_COMMAND(ID_APP_ABOUT, OnAppAbout)
	ON_COMMAND(ID_FILE_NEW, OnFileNew)
	ON_COMMAND(ID_FILE_OPEN, OnFileOpen)
	ON_COMMAND(ID_SET_OPTIONS, OnSetOptions)
	//}}AFX_MSG_MAP
	// Standard file based document commands
	// ON_COMMAND(ID_FILE_NEW, CWinApp::OnFileNew)
	ON_COMMAND(ID_FILE_OPEN, CWinApp::OnFileOpen)
	// Standard print setup command
	ON_COMMAND(ID_FILE_PRINT_SETUP, CWinApp::OnFilePrintSetup)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CClamavApp construction

CClamavApp::CClamavApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

CClamavApp::~CClamavApp()
{
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CClamavApp object

CClamavApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CClamavApp initialization

BOOL CClamavApp::InitInstance()
{
	// Standard initialization
	// If you are not using these features and wish to reduce the size
	//  of your final executable, you should remove from the following
	//  the specific initialization routines you do not need.

	Enable3dControls();

	LoadStdProfileSettings();  // Load standard INI file options (including MRU)

	// Register the application's document templates.  Document templates
	//  serve as the connection between documents, frame windows and views.

	CSingleDocTemplate* pDocTemplate;
	pDocTemplate = new CSingleDocTemplate(
		IDR_MAINFRAME,
		RUNTIME_CLASS(CClamavDoc),
		RUNTIME_CLASS(CMainFrame),       // main SDI frame window
		RUNTIME_CLASS(CClamavView));
	AddDocTemplate(pDocTemplate);
	
	// Start up Winsock
	WSAData wsaData;

    if(WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
		AfxMessageBox("WSAStartup() failed error code");
        return FALSE;
    }
	clamServer = NULL;

	if (m_lpCmdLine[0] != '\0')	{
		// TODO: add command line processing here
		// First argument is the server, second is the file to scan
		// TODO: more rigourous argument checking
		CString args = CString(m_lpCmdLine);

		int index = args.Find(' ');
		if(index == -1)
			exit(1);

		CString server = args.Left(index);
 		const CString fileName = args.Mid(index + 1);
		unsigned short port;

		index = server.Find(':');
		if(index != -1) {
			port = (unsigned short)atoi(server.Mid(index + 1));
			server = server.Left(index);	
		} else
			port = DEFAULT_PORT;

		TRY {
			clamServer = new ClamServer(server, port);
		} CATCH(CException, c) {
			AfxMessageBox("Can't establish a connection to " + server);
			c->Delete();
			exit(1);
		}
		END_CATCH

 		CWinApp::OnFileNew();

		// TODO: set quarantine directory
 		
 		exit(clamServer->Scan(fileName, 0, (CMainFrame *)AfxGetMainWnd(), m_pMainWnd, TRUE, NULL) == TRUE);
	} else {
		// create a new (empty) document
		OnFileNew();
	}

#ifdef _DEBUG
	afxTraceEnabled = TRUE;
#endif

	options = new COptions();
	recursive = TRUE;

	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

// Implementation
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//{{AFX_MSG(CAboutDlg)
		// No message handlers
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

// App command to run the dialog
void CClamavApp::OnAppAbout()
{
	CAboutDlg aboutDlg;
	aboutDlg.DoModal();
}

/////////////////////////////////////////////////////////////////////////////
// CClamavApp commands

int CClamavApp::ExitInstance() 
{
	// TODO: Add your specialized code here and/or call the base class
	if(clamServer) {
		delete clamServer;
		clamServer = NULL;
	}
	if(options) {
		delete options;
		options = NULL;
	}
	WSACleanup();

	return CWinApp::ExitInstance();
}

void CClamavApp::OnFileNew() 
{
	CWinApp::OnFileNew();

	// TODO: Add your command handler code here

	// Open connection to a different server
	if(clamServer) {
		delete clamServer;
		clamServer = NULL;
	}
	TRY {
		clamServer = new ClamServer;
	} CATCH(CException, c) {
		clamServer = NULL;
		c->Delete();
	}
	END_CATCH
}

void CClamavApp::OnFileOpen() 
{
	// TODO: Add your command handler code here

    CString newName;
    if (!DoPromptFileName(newName, AFX_IDS_OPENFILE,
      /*OFN_HIDEREADONLY |*/ OFN_FILEMUSTEXIST, TRUE, NULL))
        return; // open cancelled

    // OpenDocumentFile(newName);
	this->Scan(newName);
}

// TODO: More than one scan happen at once but the progress bar gets confused
// Need a new scanner class. Create a new instance everytime we scan something
// Pass clamServer as a parameter
//	Scanner *s = new Scanner(clamServer, 0, (CMainFrame *)AfxGetMainWnd(), m_pMainWnd, recursive, options->m_quarantineDir);
//	if(s->clean())
//		AfxMessageBox("No virus found in " + filename);
// delete s;
	
void CClamavApp::Scan(const CString& filename)
{
	if(clamServer == NULL)
		AfxMessageBox("You must connect to a clamd server first");
	else if(clamServer->Scan(filename, 0, (CMainFrame *)AfxGetMainWnd(), m_pMainWnd, recursive, options->m_quarantineDir))
		AfxMessageBox("No virus found in " + filename);
}

void CClamavApp::OnSetOptions() 
{
	// TODO: Add your command handler code here
	if(options->DoModal() == IDOK)
		recursive = options->m_recursive;
}
