// progress.cpp : implementation file
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

#include "progress.h"

#ifdef _DEBUG
#undef THIS_FILE
static char BASED_CODE THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CProgress dialog


CProgress::CProgress(CWnd* pParent)
	: CDialog(CProgress::IDD, pParent)
{
	//{{AFX_DATA_INIT(CProgress)
	m_filename = _T("bar");
	m_percent = _T("");
	//}}AFX_DATA_INIT
	stopPressed = FALSE;
}


void CProgress::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CProgress)
	DDX_Text(pDX, IDC_FileName, m_filename);
	DDX_Text(pDX, IDC_Percent, m_percent);
	//}}AFX_DATA_MAP
}

void
CProgress::SetFilename(const CString& filename)
{
	if(stopPressed)
		return;

	m_filename = _T(filename);

	CStatic *text = (CStatic *)GetDlgItem(IDC_FileName);
	if(text) {
		text->SetWindowText(filename);
		// text->UpdateWindow();
		percent = -1;	// force a display when it changes
	} else
		AfxMessageBox("Can't find IDC_FileName");
}

void
CProgress::SetPercent(int p)
{
	if((p < 0) || (p > 100))
		return;

	if(p == percent)
		return;

	char buf[5];
	sprintf(buf, "%d%%", p);

	CStatic *text = (CStatic *)GetDlgItem(IDC_Percent);
	if(text) {
		text->SetWindowText(buf);
		// text->UpdateWindow();
		percent = p;
	} else
		AfxMessageBox("Can't find IDC_Percent");
}	

const BOOL
CProgress::IsStopPressed(void)
{
	return stopPressed;
}

BEGIN_MESSAGE_MAP(CProgress, CDialog)
	//{{AFX_MSG_MAP(CProgress)
	ON_BN_CLICKED(IDSTOP, OnStop)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CProgress message handlers

void CProgress::OnStop() 
{
	// TODO: Add your control notification handler code here
	stopPressed = TRUE;

	CButton *stopButton = (CButton *)GetDlgItem(IDSTOP);
	if(stopButton)
		stopButton->EnableWindow(FALSE);
}
