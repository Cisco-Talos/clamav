// clamav.h : main header file for the CLAMAV application
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
#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif


#include "resource.h"       // main symbols

#include "mainfrm.h"

#include "options.h"
#include "progress.h"
#include "clamserver.h"

#define	DEFAULT_PORT	3310

/////////////////////////////////////////////////////////////////////////////
// CClamavApp:
// See clamav.cpp for the implementation of this class
//

class CClamavApp : public CWinApp
{
public:
	CClamavApp();
	~CClamavApp();
	void	Scan(const CString& filename);

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CClamavApp)
	public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CClamavApp)
	afx_msg void OnAppAbout();
	afx_msg void OnFileNew();
	afx_msg void OnFileOpen();
	afx_msg void OnSetOptions();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

private:
	ClamServer	*clamServer;
	COptions	*options;
	BOOL		recursive;	// recursively scan folders?
};


/////////////////////////////////////////////////////////////////////////////
