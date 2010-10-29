/////////////////////////////////////////////////////////////////////////////
// Name:        screenshot_main.cpp
// Purpose:     Implements the window containing all controls.
// Author:      Utensil Candel (UtensilCandel@@gmail.com)
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

// for all others, include the necessary headers wxWidgets headers)
#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#include "wx/aboutdlg.h"
#include "wx/dir.h"

#include "screenshot_main.h"
#include "autocapture.h"

// ----------------------------------------------------------------------------
// ScreenshotFrame
// ----------------------------------------------------------------------------

ScreenshotFrame::ScreenshotFrame(wxFrame *frame) : GUIFrame(frame)
{
#if wxUSE_STATUSBAR
    statusBar->SetStatusText(_("Welcome to the Automatic Screenshot Generator!"), 0);
#endif

    // set minimum size hints
    GetSizer()->SetSizeHints(this);
}

// ----------------------------------------------------------------------------
// ScreenshotFrame - event handlers
// ----------------------------------------------------------------------------

void ScreenshotFrame::OnClose(wxCloseEvent& WXUNUSED(event))
{
    Destroy();
}

void ScreenshotFrame::OnQuit(wxCommandEvent& WXUNUSED(event))
{
    Destroy();
}

void ScreenshotFrame::OnSeeScreenshots(wxCommandEvent& WXUNUSED(event))
{
    wxString defaultDir = AutoCaptureMechanism::GetDefaultDirectoryAbsPath();

    if (wxFileName::DirExists(defaultDir))
        wxLaunchDefaultBrowser(defaultDir);
    else
        wxMessageBox(_("There isn't any screenshots yet."));
}

void ScreenshotFrame::OnAbout(wxCommandEvent& WXUNUSED(event))
{
    wxAboutDialogInfo info;
    info.SetName(_("Automatic Screenshot Generator"));
    info.SetVersion(_("1.0"));
    info.SetDescription(_("This utility automatically creates screenshots of wxWidgets controls for use in wxWidgets documentation."));
    info.SetCopyright(wxT("(C) 2008 Utensil Candel"));

    wxAboutBox(info);
}

void ScreenshotFrame::OnCaptureFullScreen(wxCommandEvent& WXUNUSED(event))
{
    // Create a DC for the whole screen area
    wxScreenDC dcScreen;

    // Get the size of the screenDC
    wxCoord screenWidth, screenHeight;
    dcScreen.GetSize(&screenWidth, &screenHeight);

    wxBitmap fullscreen(1, 1);
    AutoCaptureMechanism::Capture(&fullscreen, 0, 0, screenWidth, screenHeight);

    AutoCaptureMechanism::Save(&fullscreen, wxT("fullscreen"));

    wxMessageBox(_("A screenshot of the entire screen was saved as:\n\n  ")
                + AutoCaptureMechanism::GetDefaultDirectoryAbsPath() + wxT("fullscreen.png"),
                 _("Full screen capture"), wxICON_INFORMATION|wxOK, this);
}

void ScreenshotFrame::OnCaptureAllControls(wxCommandEvent& WXUNUSED(event))
{
    wxString dir = AutoCaptureMechanism::GetDefaultDirectoryAbsPath();

    // check if there are other screenshots taken before
    if (wxFileName::DirExists(dir))
    {
        int choice = wxMessageBox(_("It seems that you have already generated some screenshots.\n\nClick YES to delete them all (recommended) or NO to preserve them.\nClick CANCEL to cancel this auto-capture operation."),
                            _("Delete existing screenshots?"),
                            wxYES_NO|wxCANCEL|wxICON_QUESTION, this);
        switch(choice)
        {
            case wxYES:
            {
                wxArrayString files;
                wxDir::GetAllFiles(dir, &files, wxT("*.png"), wxDIR_FILES);

                // remove all PNG files from the screenshots folder
                int n = files.GetCount();
                for (int i = 0; i < n; ++i)
                    wxRemoveFile(files[i]);
            }
            break;

            case wxNO: break;
            case wxCANCEL: return;
        }
    }

    // proceed with the automatic screenshot capture

    this->Maximize();

    AutoCaptureMechanism auto_cap(m_notebook1);

    auto_cap.RegisterControl(m_button1);
    auto_cap.RegisterControl(m_staticText1);
    auto_cap.RegisterControl(m_checkBox1, AJ_Union);
    auto_cap.RegisterControl(m_checkBox2, AJ_UnionEnd);
    auto_cap.RegisterControl(m_radioBtn1, AJ_Union);
    auto_cap.RegisterControl(m_radioBtn2, AJ_UnionEnd);
    auto_cap.RegisterControl(m_bpButton1);
    auto_cap.RegisterControl(m_bitmap1);
    auto_cap.RegisterControl(m_gauge1, wxT("wxGauge"));
    auto_cap.RegisterControl(m_slider1);
    auto_cap.RegisterControl(m_toggleBtn1, AJ_Union);
    auto_cap.RegisterControl(m_toggleBtn2, AJ_UnionEnd);
    auto_cap.RegisterControl(m_hyperlink1, wxT("wxHyperlinkCtrl"));
    auto_cap.RegisterControl(m_spinCtrl1, AJ_RegionAdjust);
    auto_cap.RegisterControl(m_spinBtn1);
    auto_cap.RegisterControl(m_scrollBar1);

    auto_cap.RegisterPageTurn();

    auto_cap.RegisterControl(m_checkList1);
    auto_cap.RegisterControl(m_listBox1);
    auto_cap.RegisterControl(m_radioBox1);
    auto_cap.RegisterControl(m_staticBox1);
    auto_cap.RegisterControl(m_treeCtrl1);
    auto_cap.RegisterControl(m_listCtrl1, wxT("wxListCtrl"));

    auto_cap.RegisterControl(m_animationCtrl1);
    auto_cap.RegisterControl(m_collPane1, wxT("wxCollapsiblePane"), AJ_Union);
    auto_cap.RegisterControl(m_collPane2, AJ_UnionEnd);

    auto_cap.RegisterPageTurn();

    auto_cap.RegisterControl(m_textCtrl1, AJ_Union);
    auto_cap.RegisterControl(m_textCtrl2, AJ_UnionEnd);
    auto_cap.RegisterControl(m_richText1);

    auto_cap.RegisterPageTurn();

    auto_cap.RegisterControl(m_colourPicker1, wxT("wxColourPickerCtrl"));
    auto_cap.RegisterControl(m_fontPicker1, wxT("wxFontPickerCtrl"));
    auto_cap.RegisterControl(m_filePicker1, wxT("wxFilePickerCtrl"), AJ_RegionAdjust);
    auto_cap.RegisterControl(m_calendar1, wxT("wxCalendarCtrl"), AJ_RegionAdjust);
    auto_cap.RegisterControl(m_datePicker1, wxT("wxDatePickerCtrl"));
    auto_cap.RegisterControl(m_genericDirCtrl1, wxT("wxGenericDirCtrl"));
    auto_cap.RegisterControl(m_dirPicker1, wxT("wxDirPickerCtrl"), AJ_RegionAdjust);

    auto_cap.RegisterPageTurn();

    auto_cap.RegisterControl(m_choice1, AJ_Dropdown);
    auto_cap.RegisterControl(m_comboBox1, AJ_Dropdown);
    auto_cap.RegisterControl(m_bmpComboBox1, AJ_Dropdown);
    auto_cap.RegisterControl(m_ownerDrawnComboBox1, AJ_Dropdown);
    auto_cap.RegisterControl(m_comboCtrl1, AJ_Dropdown|AJ_Union);
    auto_cap.RegisterControl(m_comboCtrl2, AJ_Dropdown|AJ_UnionEnd);

    auto_cap.CaptureAll();

    wxMessageBox(_("All screenshots were generated successfully in the folder:\n  ") + dir,
                 _("Success"), wxOK|wxICON_INFORMATION, this);
}
