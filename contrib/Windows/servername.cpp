// servername.cpp : implementation file
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
#include "clamav.h"
#include "servername.h"

#ifdef _DEBUG
#undef THIS_FILE
static char BASED_CODE THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// ServerName dialog


ServerName::ServerName(CWnd* pParent /*=NULL*/)
	: CDialog(ServerName::IDD, pParent)
{
	//{{AFX_DATA_INIT(ServerName)
	m_serverName = _T("");
	m_port = DEFAULT_PORT;
	//}}AFX_DATA_INIT
}


void ServerName::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(ServerName)
	DDX_Text(pDX, IDC_SERVERNAME, m_serverName);
	DDV_MaxChars(pDX, m_serverName, 20);
	DDX_Text(pDX, IDC_SERVERPORT, m_port);
	DDV_MinMaxUInt(pDX, m_port, 1, 65535);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(ServerName, CDialog)
	//{{AFX_MSG_MAP(ServerName)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// ServerName message handlers
