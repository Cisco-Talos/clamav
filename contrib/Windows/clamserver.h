// Maintains connection to the clamd server

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
#ifndef	_CLAMSERVER_H

#include "mainfrm.h"

class ClamServer {

public:
	ClamServer(void);
	ClamServer(CString& serverName, unsigned short port);
	~ClamServer();
	BOOL	Scan(const CString& filename, int level, CMainFrame *mainFrame,
		CWnd *parent, BOOL recursive, const CString& qDir);
		// returns TRUE if the file is clean

private:
	BOOL	InitInstance(void);
	int		CreateConnection(void);
	const	BOOL	CheckConnection(int sock);
	BOOL	ClamServer::ScanFolder(const CString& string, int level, CMainFrame *mainFrame,
		CWnd *parent, BOOL recursive, const CString& qDir);
	BOOL	ClamServer::ScanWildCard(const CString& string, int level, CMainFrame *mainFrame,
		CWnd *parent, BOOL recursive, const CString& qDir);
	int		ClamServer::ClamdRecv(int sock, char *buf, size_t len, int timeout = 30);

	long	serverIP;	// IPv4 address of the clamdserver (only one for now)
	unsigned short	port;	// host order
	BOOL	stopping;	// true if the application has been asked to stop
	CProgress	*progressBar;
};

#define	_CLAMSERVER_H
#endif	_CLAMSERVER_H
