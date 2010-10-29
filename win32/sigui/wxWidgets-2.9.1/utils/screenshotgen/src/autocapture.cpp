/////////////////////////////////////////////////////////////////////////////
// Name:        autocapture.cpp
// Purpose:     Implement wxCtrlMaskOut class
// Author:      Utensil Candel (UtensilCandel@@gmail.com)
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#include "autocapture.h"

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

#include "wx/bitmap.h"
#include "wx/filename.h"
#include "wx/notebook.h"

#include <ctime>

#ifdef __WXMAC__
#include <cstring>
#endif


// ----------------------------------------------------------------------------
// AutoCaptureMechanism
// ----------------------------------------------------------------------------

AutoCaptureMechanism::AutoCaptureMechanism(wxNotebook *notebook,
                                           int flag, int margin)
: m_notebook(notebook),
  m_flag(flag),
  m_margin(margin),
  m_grid(NULL)
{
}

/* static */
wxString AutoCaptureMechanism::default_dir = wxT("screenshots");

/* static */
wxString AutoCaptureMechanism::GetDefaultDirectoryAbsPath()
{
    wxFileName output = wxFileName::DirName(GetDefaultDirectory());
    output.MakeAbsolute();
    return output.GetFullPath();
}

/* static */
void AutoCaptureMechanism::Delay(int seconds)
{
    // TODO: Switch this to use wxTimer.

    // Wait for 3 seconds
    clock_t start = clock();
    while ( clock() - start < (clock_t)CLOCKS_PER_SEC * seconds)
        wxYieldIfNeeded();
}

/* static */
bool AutoCaptureMechanism::Capture(wxBitmap* bitmap, int x, int y,
                                   int width, int height, int delay)
{
    // Somehow wxScreenDC.Blit() doesn't work under Mac for now. Here is a trick.
#ifdef __WXMAC__

    // wxExecute(wxT("screencapture -x ") + tempfile, wxEXEC_SYNC);

    char captureCommand[80] =""; // a reasonable max size is 80
    sprintf(captureCommand, "sleep %d;%s", delay, "screencapture -x /tmp/wx_screen_capture.png");
    system(captureCommand);

    if(delay) Delay(delay);

    wxBitmap fullscreen;
    do
    {
        fullscreen = wxBitmap(wxT("/tmp/wx_screen_capture.png"), wxBITMAP_TYPE_PNG);
    }
    while(!fullscreen.IsOk());

    *bitmap = fullscreen.GetSubBitmap(wxRect(x, y, width, height));

    // to prevent loading the old screenshot next time
    system("rm /tmp/wx_screen_capture.png");

    return true;

#else // Under other paltforms, take a real screenshot

    if(delay) Delay(delay);

    // Create a DC for the whole screen area
    wxScreenDC dcScreen;

    bitmap->Create(width, height);

    // Create a memory DC that will be used for actually taking the screenshot
    wxMemoryDC memDC;
    memDC.SelectObject((*bitmap));
    memDC.Clear();

    // Blit (in this case copy) the actual screen on the memory DC
    // and thus the Bitmap
    memDC.Blit( 0, // Copy to this X coordinate
                0, // Copy to this Y coordinate
                width, // Copy this width
                height, // Copy this height
                &dcScreen, // From where do we copy?
                x, // What's the X offset in the original DC?
                y  // What's the Y offset in the original DC?
              );

    // Select the Bitmap out of the memory DC by selecting a new
    // uninitialized Bitmap
    memDC.SelectObject(wxNullBitmap);
#endif // #ifdef __WXMAC__

    return true;
}

/* static */
bool AutoCaptureMechanism::Capture(wxBitmap* bitmap, wxRect rect, int delay)
{
    wxPoint origin = rect.GetPosition();
    return Capture(bitmap, origin.x, origin.y, rect.GetWidth(), rect.GetHeight(), delay);
}

/* static */
void AutoCaptureMechanism::Save(wxBitmap* screenshot, const wxString& fileName)
{
    // make sure default_dir exists
    if (!wxDirExists(default_dir))
        wxMkdir(default_dir);

    wxFileName fullFileName(default_dir, fileName + ".png");

    // do not overwrite already existing files with this name
    while (fullFileName.FileExists())
        fullFileName.SetName(fullFileName.GetName() + "_");

    // save the screenshot as a PNG
    screenshot->SaveFile(fullFileName.GetFullPath(), wxBITMAP_TYPE_PNG);
}

void AutoCaptureMechanism::CaptureAll()
{
    // start from the first page
    m_notebook->SetSelection(0);
    wxYield();

    for (ControlList::iterator it = m_controlList.begin();
         it != m_controlList.end();
         ++it)
    {
        Control &ctrl = *it;

        if (ctrl.flag == AJ_TurnPage)    // Turn to next page
        {
            m_notebook->SetSelection(m_notebook->GetSelection() + 1);
            wxYield();
            continue;
        }

        // create the screenshot
        wxBitmap screenshot(1, 1);
        Capture(&screenshot, ctrl);

        if(ctrl.flag & AJ_Union)
        {
            // union screenshots until AJ_UnionEnd
            do
            {
                ++it;
                it->name = ctrl.name; //preserving the name
                wxBitmap screenshot2(1, 1);
                Capture(&screenshot2, *it);
                wxBitmap combined(1, 1);
                Union(&screenshot, &screenshot2, &combined);
                screenshot = combined;
            }
            while(!(it->flag & AJ_UnionEnd));
        }

        // and save it
        Save(&screenshot, ctrl.name);
    }
}

bool AutoCaptureMechanism::Capture(wxBitmap* bitmap, Control& ctrl)
{
    // no manual specification for the control name
    // or name adjustment is disabled globally
    if (ctrl.name == wxT("") || m_flag & AJ_DisableNameAdjust)
    {
        // Get its name from wxRTTI
        ctrl.name = ctrl.ctrl->GetClassInfo()->GetClassName();
    }

    int choice = wxNO;

    wxRect rect = GetRect(ctrl.ctrl, ctrl.flag);

    if (ctrl.flag & AJ_Dropdown && !(m_flag & AJ_DisableDropdown))
    {
        // for drop-down controls we need the help of the user
        wxString caption = _("Drop-down screenshot...");
        wxString msg =
            wxString::Format(_("Do you wish to capture the drop-down list of '%s' ?\n\n If YES, please drop down the list of '%s' in 5 seconds after closing this message box.\n If NO, the screenshot for this control won't contain its drop-down list."),
                             ctrl.name, ctrl.name);

        choice = wxMessageBox(msg, caption, wxYES_NO, m_notebook);

        if (choice == wxYES)
        {
            //A little hint
            ctrl.ctrl->SetCursor(wxCursor(wxCURSOR_HAND));

            // Do some rect adjust so it can include the dropdown list
            // This adjust isn't pretty, but it works fine on all three paltforms.
            // Looking forward to a better solution
            int h = rect.GetHeight();
            rect.SetHeight(h * 4);
        }
    }

    // cut off "wx" and change the name into lowercase.
    // e.g. wxButton will have a name of "button" at the end
    ctrl.name.StartsWith(wxT("wx"), &(ctrl.name));
    ctrl.name.MakeLower();

    // take the screenshot
    Capture(bitmap, rect, (choice == wxYES)?5:0);

    if (choice == wxYES) ctrl.ctrl->SetCursor(wxNullCursor);

    if (ctrl.flag & AJ_RegionAdjust)
        PutBack(ctrl.ctrl);

    return true;
}

/* static */
bool AutoCaptureMechanism::Union(wxBitmap* top, wxBitmap* bottom, wxBitmap* result)
{
    int w1, w2, h1, h2, w, h;
    w1 = top->GetWidth();
    w2 = bottom->GetWidth();
    h1 = top->GetHeight();
    h2 = bottom->GetHeight();

    const int gap_between = 20;

    w = (w1 >= w2) ? w1 : w2;
    h = h1 + h2 + gap_between;

    result->Create(w, h);

    wxMemoryDC dstDC;
    dstDC.SelectObject((*result));

    dstDC.SetBrush(*wxWHITE_BRUSH);
    dstDC.Clear();
    dstDC.DrawBitmap((*top), 0, 0);
    dstDC.DrawBitmap((*bottom), 0, h1 + gap_between);

    dstDC.SelectObject(wxNullBitmap);

    return true;
}

wxRect AutoCaptureMechanism::GetRect(wxWindow* ctrl, int flag)
{
    if( (!(m_flag & AJ_DisableRegionAdjust) && (flag & AJ_RegionAdjust))
        || (m_flag & AJ_AlwaysRegionAdjust) )
    {
        wxWindow * parent = ctrl->GetParent();
        wxSizer * sizer = parent->GetSizer();

        //The assertion won't fail if controls are still managed by wxSizer, and it's unlikely to
        //change in the future.
        wxASSERT_MSG(sizer,
        "The GUI that AutoCaptureMechanism working with doesn't manage controls with wxSizer");

        sizer->Detach(ctrl);

        /*
        +---------+-----------+---------+
        |    0    |   label   |    1    |
        +---------+-----------+---------+
        |  label  |    ctrl   |  label  |
        +---------+-----------+---------+
        |    2    |   label   |    3    |
        +---------+-----------+---------+
       */

        m_grid = new wxFlexGridSizer(3, 3, m_margin, m_margin);

        wxStaticText* l[4];

        for (int i = 0; i < 4; ++i)
            l[i] = new wxStaticText(parent, wxID_ANY, wxT(" "));

        m_grid->Add(l[0]);
        m_grid->Add(new wxStaticText(parent, wxID_ANY, wxT(" ")));
        m_grid->Add(l[1]);
        m_grid->Add(new wxStaticText(parent, wxID_ANY, wxT(" ")));
        m_grid->Add(ctrl, 1, wxEXPAND);
        m_grid->Add(new wxStaticText(parent, wxID_ANY, wxT(" ")));
        m_grid->Add(l[2]);
        m_grid->Add(new wxStaticText(parent, wxID_ANY, wxT(" ")));
        m_grid->Add(l[3]);

        sizer->Add(m_grid);
        parent->SetSizer(sizer);
        parent->Layout();

        parent->Refresh();
        wxYield();

        return wxRect(l[0]->GetScreenRect().GetBottomRight(),
                l[3]->GetScreenRect().GetTopLeft());
    }
    else
    {
       return ctrl->GetScreenRect().Inflate(m_margin);
    }
}

void AutoCaptureMechanism::PutBack(wxWindow * ctrl)
{
    if(!m_grid) return;

    m_grid->Detach(ctrl);

    wxSizerItemList children = m_grid->GetChildren();

    for (wxSizerItemList::iterator it = children.begin(); it != children.end(); ++it)
    {
        wxSizerItem* item = *it;
        if (item->IsWindow()) delete (*it)->GetWindow();
    }

    wxSizer * sizer = ctrl->GetParent()->GetSizer();

    //The assertion won't fail if controls are still managed by wxSizer, and it's unlikely to
    //change in the future.
    wxASSERT_MSG(sizer,
    "The GUI that AutoCaptureMechanism working with doesn't manage controls with wxSizer");

    sizer->Detach(m_grid);
    delete m_grid;
    m_grid = NULL;

    sizer->Add(ctrl);
}

