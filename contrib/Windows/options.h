// options.h : header file
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
/////////////////////////////////////////////////////////////////////////////
// COptions dialog

class COptions : public CDialog
{
// Construction
public:
	COptions(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(COptions)
	enum { IDD = IDD_OPTIONS };
	BOOL	m_recursive;
	CString	m_quarantineDir;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(COptions)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(COptions)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
