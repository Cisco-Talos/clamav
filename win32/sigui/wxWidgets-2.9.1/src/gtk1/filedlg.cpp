/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/filedlg.cpp
// Purpose:     native implementation of wxFileDialog
// Author:      Robert Roebling, Zbigniew Zagorski, Mart Raudsepp
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling, 2004 Zbigniew Zagorski, 2005 Mart Raudsepp
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_FILEDLG

#include "wx/filedlg.h"


//-----------------------------------------------------------------------------
// wxFileDialog
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxFileDialog,wxGenericFileDialog)

BEGIN_EVENT_TABLE(wxFileDialog,wxGenericFileDialog)
    EVT_BUTTON(wxID_OK, wxFileDialog::OnFakeOk)
END_EVENT_TABLE()

wxFileDialog::wxFileDialog(wxWindow *parent, const wxString& message,
                           const wxString& defaultDir,
                           const wxString& defaultFileName,
                           const wxString& wildCard,
                           long style, const wxPoint& pos,
                           const wxSize& sz,
                           const wxString& name)
    : wxGenericFileDialog(parent, message, defaultDir, defaultFileName,
                       wildCard, style, pos, sz, name, true )
{
        wxGenericFileDialog::Create( parent, message, defaultDir, defaultFileName, wildCard, style, pos, sz, name );
}

wxFileDialog::~wxFileDialog()
{
}

void wxFileDialog::OnFakeOk( wxCommandEvent &event )
{
    wxGenericFileDialog::OnOk( event );
}

int wxFileDialog::ShowModal()
{
    return wxGenericFileDialog::ShowModal();
}

bool wxFileDialog::Show( bool show )
{
    return wxGenericFileDialog::Show( show );
}

void wxFileDialog::DoSetSize(int x, int y, int width, int height, int sizeFlags )
{
    if (!m_wxwindow)
        return;
    else
        wxGenericFileDialog::DoSetSize( x, y, width, height, sizeFlags );
}

wxString wxFileDialog::GetPath() const
{
    return wxGenericFileDialog::GetPath();
}

void wxFileDialog::GetFilenames(wxArrayString& files) const
{
    wxGenericFileDialog::GetFilenames( files );
}

void wxFileDialog::GetPaths(wxArrayString& paths) const
{
    wxGenericFileDialog::GetPaths( paths );
}

void wxFileDialog::SetMessage(const wxString& message)
{
    wxGenericFileDialog::SetMessage( message );
}

void wxFileDialog::SetPath(const wxString& path)
{
    wxGenericFileDialog::SetPath( path );
}

void wxFileDialog::SetDirectory(const wxString& dir)
{
    wxGenericFileDialog::SetDirectory( dir );
}

wxString wxFileDialog::GetDirectory() const
{
    return wxGenericFileDialog::GetDirectory();
}

void wxFileDialog::SetFilename(const wxString& name)
{

    wxGenericFileDialog::SetFilename( name );
}

wxString wxFileDialog::GetFilename() const
{
    return wxGenericFileDialog::GetFilename();
}

void wxFileDialog::SetWildcard(const wxString& wildCard)
{
    wxGenericFileDialog::SetWildcard( wildCard );
}

void wxFileDialog::SetFilterIndex(int filterIndex)
{
    wxGenericFileDialog::SetFilterIndex( filterIndex );
}

int wxFileDialog::GetFilterIndex() const
{
    return wxGenericFileDialog::GetFilterIndex();
}

#endif // wxUSE_FILEDLG
