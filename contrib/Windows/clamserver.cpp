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

#include "mainfrm.h"

#include "clamserver.h"
#include "servername.h"

#include <io.h>
#include <winsock.h>
#include <sys/stat.h>

ClamServer::ClamServer(void)
{
	if(!InitInstance())
		THROW(new CException());	// FIXME: never freed 

	progressBar = NULL;
	stopping = FALSE;
}

ClamServer::ClamServer(CString& serverName, unsigned short p)
{
	LPTSTR hostname = serverName.GetBuffer(64);	
	serverIP = inet_addr(hostname);

	if(serverIP == -1L)
		THROW(CException());

	port = p;

	const int sock = CreateConnection();

	if(sock < 0)
		THROW(CException());

	progressBar = NULL;
	stopping = FALSE;
}

ClamServer::~ClamServer()
{
	if(progressBar) {
		delete progressBar;
		progressBar = NULL;
	}
}

BOOL
ClamServer::InitInstance(void)
{
	ServerName serverName;
	
	if(serverName.DoModal() == IDCANCEL)
		return FALSE;

	const char *hostname = serverName.m_serverName;

	serverIP = inet_addr(hostname);

	if(serverIP == -1L) {
		AfxMessageBox("Unknown host");
		return FALSE;
	}

	port = (unsigned short)serverName.m_port;
	const int sock = CreateConnection();

	if(sock < 0)
		return TRUE;

	return CheckConnection(sock);
}

const BOOL
ClamServer::CheckConnection(int sock)
{
	if(send(sock, "PING\n", 5, 0) < 5) {
		closesocket(sock);
		AfxMessageBox("Can't talk to clamdserver");
		return FALSE;
	}
	char ret[5];
	if(recv(sock, ret, sizeof(ret), 0) <= 4) {
		closesocket(sock);
		AfxMessageBox("Can't receive from clamdserver");
		return FALSE;
	}
	closesocket(sock);
	if(strncmp(ret, "PONG\n", 5) != 0) {
		AfxMessageBox("Is that server running clamd?");
		return FALSE;
	}

	return TRUE;	
}

int
ClamServer::CreateConnection(void)
{
	const int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
		AfxMessageBox("Can't create socket");
		return FALSE;
	}

	struct sockaddr_in server;
	memset(&server, '\0', sizeof(struct sockaddr_in));
	server.sin_family = PF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = serverIP;

	// TODO	display a message about connecting to the server. Include cancel button
	if(connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr)) < 0) {
		AfxMessageBox("Can't connect to clamdserver");
		return FALSE;
	}
	return sock;
}

// TODO: on recursive pop up box with progress bar - to include cancel button
BOOL
ClamServer::Scan(const CString& filename, int level, CMainFrame *mainFrame, CWnd *parent, BOOL recursive, const CString& qDir)
{
	if(level == 0)
		stopping = FALSE;
	else if(stopping) {
		if(progressBar) {
			delete progressBar;
			progressBar = NULL;
		}
		// mainFrame->ChangeStatusText("");
		return TRUE;
	}

	// Don't scan folders "." and ".."
 	if(filename[filename.GetLength() - 1] == '.')
 		return TRUE;

	// I understand newer MFCs have 'PathIsDirectory'

	struct stat statb;

	if(stat(filename, &statb) < 0) {
		// It could be that we've been given a wild card match

		WIN32_FIND_DATA findData;
				
		HANDLE hFind = FindFirstFile(filename, &findData);

		if(hFind == INVALID_HANDLE_VALUE) {
  			// No we haven't...
			AfxMessageBox(CString("Can't stat ") + filename);
			return TRUE;
		}
		return this->ScanWildCard(filename, level, mainFrame, parent, recursive, qDir);
	}

	if(progressBar && !stopping) {
		if(progressBar->IsStopPressed())               
			stopping = TRUE;
		progressBar->SetFilename(filename);
	}

	// mainFrame->ChangeStatusText(filename);	// statusBar.ShowProgress
	// mainFrame->UpdateWindow();

	if(statb.st_mode&S_IFDIR) {
		// Don't recurse unless we've been asked to

		if((!recursive) && (level > 0))
			return TRUE;

		if(progressBar == NULL) {
			// FIXME: not all return paths remove this, possible memory leak
			progressBar = new CProgress(parent);
			progressBar->Create(IDD_PROGRESS, parent);
		}

		// Have been passed a folder.
		return this->ScanFolder(filename, level, mainFrame, parent, recursive, qDir);

	}

	if(progressBar && (level == 0)) {
		delete progressBar;
		progressBar = NULL;
	}

	const int commandSocket = CreateConnection();
	
	if(commandSocket < 0)
		return TRUE;

	if(send(commandSocket, "STREAM\n", 7, 0) < 7) {
		closesocket(commandSocket);
		AfxMessageBox("Send failed to clamd");
		return TRUE;
	}

	char buf[64];
	int nbytes = ClamdRecv(commandSocket, buf, sizeof(buf) - 1);

	if(nbytes < 0) {
		closesocket(commandSocket);
		AfxMessageBox("recv failed from clamd getting PORT");
		return TRUE;
	}
	buf[nbytes] = '\0';

	unsigned short port;

	if(sscanf(buf, "PORT %hu\n", &port) != 1) {
		closesocket(commandSocket);
		AfxMessageBox("Didn't get PORT information from clamd");

		return TRUE;
	}

	const int dataSocket = socket(AF_INET, SOCK_STREAM, 0);

	if(dataSocket < 0) {
		closesocket(commandSocket);
		AfxMessageBox("Can't create dataSocket");
		return TRUE;
	}

	shutdown(dataSocket, 0);

	struct sockaddr_in reply;
	memset(&reply, '\0', sizeof(struct sockaddr_in));
	reply.sin_family = PF_INET;
 	reply.sin_port = htons(port);
	reply.sin_addr.s_addr = serverIP;

	const int rc = connect(dataSocket, (struct sockaddr *)&reply, sizeof(struct sockaddr_in));
	if(rc < 0) {
		closesocket(commandSocket);
		closesocket(dataSocket);
		AfxMessageBox("Failed to connect to port given by clamd");
		return TRUE;
	}

	CFile file;

	if(!file.Open(filename, CFile::modeRead|CFile::typeBinary|CFile::shareDenyNone)) {
		closesocket(commandSocket);
		closesocket(dataSocket);

		AfxMessageBox(CString("Can't open ") + filename + " to scan: ");
		return TRUE;
	}

	if(progressBar)
		progressBar->SetPercent(0);

	char buffer[1500];	// TODO: send in MTU byte chunks
	off_t bytesSent = (off_t)0;

	BOOL error = FALSE;

	while(((nbytes = file.Read(buffer, sizeof(buffer))) > 0) && !stopping) {
		// Every block see if someone wants to do something
		MSG Msg;

		if(::PeekMessage(&Msg, NULL, WM_NULL, WM_USER - 1, PM_NOREMOVE)) {
   			::PeekMessage(&Msg, NULL, WM_NULL, WM_USER - 1, PM_REMOVE);
   			TranslateMessage(&Msg);
   			DispatchMessage(&Msg);

			if((progressBar && progressBar->IsStopPressed()) ||
			   (Msg.message == WM_QUIT)) {
				error = TRUE;
				break;
			}
		}

		char buf[81];
		if(ClamdRecv(commandSocket, buf, sizeof(buf) - 1, 0) > 0) {
			AfxMessageBox(buf);
			error = TRUE;
			break;
		}
			
		if(send(dataSocket, buffer, nbytes, 0) != nbytes) {
			AfxMessageBox("Send error to clamd");
			error = TRUE;
			break;
		}

		if(progressBar) {
			bytesSent += nbytes;

			progressBar->SetPercent((int)(bytesSent * 100 / statb.st_size)); 
		}
	}

	closesocket(dataSocket);
	
	file.Close();

	if(error) {
		closesocket(commandSocket);
		stopping = TRUE;
		if(progressBar && (level == 0)) {
			delete progressBar;
			progressBar = NULL;
		}	
		return TRUE;
	}

	nbytes = ClamdRecv(commandSocket, buffer, sizeof(buffer) - 1);

	closesocket(commandSocket);

	if(nbytes < 0) {
		AfxMessageBox("recv error getting status");
		return TRUE;
	} else if(nbytes == 0)
		return TRUE;

	buffer[nbytes] = '\0';

	if(strstr(buffer, "ERROR") != NULL) {
		AfxMessageBox(filename + " " + buffer);
		return TRUE;
	}

	// TODO: if we're scanning down a directory tree
	// don't display a popup box - update a dialog box
	// which tells us how far we are
	
	if(strstr(buffer, "FOUND") == NULL)
		return TRUE;
	AfxMessageBox(filename + " " + buffer);

	mainFrame->ChangeStatusText(filename + " " + buffer);	// statusBar.ShowProgress

	return FALSE;
}

BOOL
ClamServer::ScanFolder(const CString& string, int level, CMainFrame *mainFrame, CWnd *parent, BOOL recursive, const CString& qDir)
{
	return ScanWildCard(string + "\\*.*", level, mainFrame, parent, recursive, qDir);
}

BOOL
ClamServer::ScanWildCard(const CString& string, int level, CMainFrame *mainFrame, CWnd *parent, BOOL recursive, const CString& qDir)
{
	if(stopping)
		return TRUE;

	WIN32_FIND_DATA findData;
		
	HANDLE hFind = FindFirstFile(string, &findData);

	if(hFind == INVALID_HANDLE_VALUE)
  		// No files in this folder
  		return TRUE;

	// Get to the filename stub - i.e. the file without the trailing \*.*
	const int index = string.Find("\\*.*");

	ASSERT(index >= 0);

	const CString stub = string.Left(index);
 			
  	BOOL rc = TRUE; 

 	do
  		//if(findData.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)
   		// Recurse into this folder/file only if recurse enabled
   			// if(!this->Scan(filename + "\\" + findData.cFileName))
				// break out as soon as one virus is found
				// TODO: optionally report all found
				// return FALSE;
		if(!this->Scan(stub + "\\" + findData.cFileName, level + 1, mainFrame, parent, recursive, qDir))
			rc = FALSE;
	
  	while(FindNextFile(hFind, &findData) && !stopping);

	if(progressBar && (level == 0)) {
		delete progressBar;
		progressBar = NULL;
	}

	return rc;
}

/*
 * Read from clamav - timeout if necessary
 * timeout defaults to 30 seconds, -1 = wait forever, 0 = poll
 * TODO: default time should be read from clamav.conf
 */
int
ClamServer::ClamdRecv(int sock, char *buf, size_t len, int timeout /* = 30 */)
{
	fd_set rfds;
	struct timeval tv;

    if(timeout == -1)
    	return recv(sock, buf, len, 0);

    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    tv.tv_sec = timeout;	   // TODO: from clamav.conf
    tv.tv_usec = 0;

    switch(select(sock + 1, &rfds, NULL, NULL, &tv)) {
    	case -1:
        	AfxMessageBox("select failed");
        	return -1;
        case 0:
			if(timeout != 0)
        		AfxMessageBox("Timeout waiting for data from clamd");
     		return 0;
    }

	return recv(sock, buf, len, 0);
}

// void __cdecl __interrupt __far intFhandler(void) {
// }
