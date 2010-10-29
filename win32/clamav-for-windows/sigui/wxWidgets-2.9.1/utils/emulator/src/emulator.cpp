/////////////////////////////////////////////////////////////////////////////
// Name:        emulator.cpp
// Purpose:     Emulator wxWidgets sample
// Author:      Julian Smart
// Modified by:
// Created:     04/01/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

// for all others, include the necessary headers (this file is usually all you
// need because it includes almost all "standard" wxWidgets headers)
#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#include "wx/confbase.h"
#include "wx/fileconf.h"
#include "wx/cmdline.h"
#include "wx/image.h"
#include "wx/file.h"
#include "wx/filename.h"

#ifdef __WXX11__
#include "wx/x11/reparent.h"
#endif

#include "emulator.h"

// ----------------------------------------------------------------------------
// resources
// ----------------------------------------------------------------------------

// the application icon (under Windows and OS/2 it is in resources)
#if defined(__WXGTK__) || defined(__WXMOTIF__) || defined(__WXMAC__) || defined(__WXMGL__) || defined(__WXX11__)
    #include "emulator.xpm"
#endif

// ----------------------------------------------------------------------------
// event tables and other macros for wxWidgets
// ----------------------------------------------------------------------------

// the event tables connect the wxWidgets events with the functions (event
// handlers) which process them. It can be also done at run-time, but for the
// simple menu events like this the static method is much simpler.
BEGIN_EVENT_TABLE(wxEmulatorFrame, wxFrame)
    EVT_MENU(Emulator_Quit,  wxEmulatorFrame::OnQuit)
    EVT_MENU(Emulator_About, wxEmulatorFrame::OnAbout)
    EVT_CLOSE(wxEmulatorFrame::OnCloseWindow)
END_EVENT_TABLE()

// Create a new application object: this macro will allow wxWidgets to create
// the application object during program execution (it's better than using a
// static object for many reasons) and also declares the accessor function
// wxGetApp() which will return the reference of the right type (i.e. wxEmulatorApp and
// not wxApp)
IMPLEMENT_APP(wxEmulatorApp)

static const wxCmdLineEntryDesc sg_cmdLineDesc[] =
{
    { wxCMD_LINE_OPTION, "u", "use-display", "display number to use (default 100)" },

    { wxCMD_LINE_SWITCH, "h", "help", "displays help on the command line parameters" },
    { wxCMD_LINE_SWITCH, "v", "version", "print version" },

    { wxCMD_LINE_PARAM,  NULL, NULL, "config file 1", wxCMD_LINE_VAL_STRING, wxCMD_LINE_PARAM_OPTIONAL },

    wxCMD_LINE_DESC_END
};


// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// the application class
// ----------------------------------------------------------------------------

wxEmulatorApp::wxEmulatorApp()
{
    m_xnestWindow = NULL;
    m_containerWindow = NULL;
    m_displayNumber = wxT("100");
    m_xnestPID = 0;

}

// 'Main program' equivalent: the program execution "starts" here
bool wxEmulatorApp::OnInit()
{
#if wxUSE_LOG
    wxLog::DisableTimestamp();
#endif // wxUSE_LOG
    wxInitAllImageHandlers();

    wxString currentDir = wxGetCwd();

    // Use argv to get current app directory
    m_appDir = wxFindAppPath(argv[0], currentDir, wxT("WXEMUDIR"));

    // If the development version, go up a directory.
#ifdef __WXMSW__
    if ((m_appDir.Right(5).CmpNoCase(wxT("DEBUG")) == 0) ||
        (m_appDir.Right(11).CmpNoCase(wxT("DEBUGSTABLE")) == 0) ||
        (m_appDir.Right(7).CmpNoCase(wxT("RELEASE")) == 0) ||
        (m_appDir.Right(13).CmpNoCase(wxT("RELEASESTABLE")) == 0)
        )
        m_appDir = wxPathOnly(m_appDir);
#endif

    // Parse the command-line parameters and options
    wxCmdLineParser parser(sg_cmdLineDesc, argc, argv);
    int res;
    {
        wxLogNull log;
        res = parser.Parse();
    }
    if (res == -1 || res > 0 || parser.Found(wxT("h")))
    {
#ifdef __X__
        wxLog::SetActiveTarget(new wxLogStderr);
#endif
        parser.Usage();
        return false;
    }
    if (parser.Found(wxT("v")))
    {
#ifdef __X__
        wxLog::SetActiveTarget(new wxLogStderr);
#endif
        wxString msg;
        msg.Printf(wxT("wxWidgets PDA Emulator (c) Julian Smart, 2002 Version %.2f, %s"), wxEMULATOR_VERSION, __DATE__);
        wxLogMessage(msg);
        return false;
    }
    if (parser.Found(wxT("u"), & m_displayNumber))
    {
        // Should only be number, so strip out anything before
        // and including a : character
        if (m_displayNumber.Find(wxT(':')) != -1)
        {
            m_displayNumber = m_displayNumber.AfterFirst(wxT(':'));
        }
    }
    if (parser.GetParamCount() == 0)
    {
        m_emulatorInfo.m_emulatorFilename = wxT("default.wxe");
    }
    else if (parser.GetParamCount() > 0)
    {
        m_emulatorInfo.m_emulatorFilename = parser.GetParam(0);
    }

    // Load the emulation info
    if (!LoadEmulator(m_appDir))
    {
        //wxMessageBox(wxT("Sorry, could not load this emulator. Please check bitmaps are valid."));
        return false;
    }

    // create the main application window
    wxEmulatorFrame *frame = new wxEmulatorFrame(wxT("wxEmulator"),
                                 wxPoint(50, 50), wxSize(450, 340));

#if wxUSE_STATUSBAR
    frame->SetStatusText(m_emulatorInfo.m_emulatorTitle, 0);

    wxString sizeStr;
    sizeStr.Printf(wxT("Screen: %dx%d"), (int) m_emulatorInfo.m_emulatorScreenSize.x,
            (int) m_emulatorInfo.m_emulatorScreenSize.y);
    frame->SetStatusText(sizeStr, 1);
#endif // wxUSE_STATUSBAR

    m_containerWindow = new wxEmulatorContainer(frame, wxID_ANY);

    frame->SetClientSize(m_emulatorInfo.m_emulatorDeviceSize.x,
                         m_emulatorInfo.m_emulatorDeviceSize.y);

    // and show it (the frames, unlike simple controls, are not shown when
    // created initially)
    frame->Show(true);

#ifdef __WXX11__
    m_xnestWindow = new wxAdoptedWindow;

    wxString cmd;
    cmd.Printf(wxT("Xnest :%s -geometry %dx%d"),
        m_displayNumber.c_str(),
        (int) m_emulatorInfo.m_emulatorScreenSize.x,
        (int) m_emulatorInfo.m_emulatorScreenSize.y);

    // Asynchronously executes Xnest
    m_xnestPID = wxExecute(cmd);
    if (0 == m_xnestPID)
    {
        frame->Destroy();
        wxMessageBox(wxT("Sorry, could not run Xnest. Please check your PATH."));
        return false;
    }

    wxReparenter reparenter;
    if (!reparenter.WaitAndReparent(m_containerWindow, m_xnestWindow, wxT("Xnest")))
    {
        wxMessageBox(wxT("Sorry, could not reparent Xnest.."));
        frame->Destroy();
        return false;
    }

#endif
    m_containerWindow->DoResize();

    // success: wxApp::OnRun() will be called which will enter the main message
    // loop and the application will run. If we returned false here, the
    // application would exit immediately.
    return true;
}

// Prepend the current program directory to the name
wxString wxEmulatorApp::GetFullAppPath(const wxString& filename) const
{
    wxString path(m_appDir);
    if (path.Last() != '\\' && path.Last() != '/' && filename[0] != '\\' && filename[0] != '/')
#ifdef __X__
        path += '/';
#else
        path += '\\';
#endif
    path += filename;

    return path;
}


// Load the specified emulator.
// For now, hard-wired. TODO: make this configurable
bool wxEmulatorApp::LoadEmulator(const wxString& appDir)
{
    // Load config file and bitmaps
    return m_emulatorInfo.Load(appDir);
}

// ----------------------------------------------------------------------------
// main frame
// ----------------------------------------------------------------------------

// frame constructor
wxEmulatorFrame::wxEmulatorFrame(const wxString& title,
    const wxPoint& pos, const wxSize& size)
    : wxFrame(NULL, wxID_ANY, title, pos, size)
{
    // set the frame icon
    SetIcon(wxICON(emulator));

#if wxUSE_MENUS
    // create a menu bar
    wxMenu *menuFile = new wxMenu;

    // the "About" item should be in the help menu
    wxMenu *helpMenu = new wxMenu;
    helpMenu->Append(Emulator_About, wxT("&About...\tF1"), wxT("Show about dialog"));

    menuFile->Append(Emulator_Quit, wxT("E&xit\tAlt-X"), wxT("Quit this program"));

    // now append the freshly created menu to the menu bar...
    wxMenuBar *menuBar = new wxMenuBar();
    menuBar->Append(menuFile, wxT("&File"));
    menuBar->Append(helpMenu, wxT("&Help"));

    // ... and attach this menu bar to the frame
    SetMenuBar(menuBar);
#endif // wxUSE_MENUS

#if wxUSE_STATUSBAR
    // create a status bar just for fun (by default with 1 pane only)
    CreateStatusBar(2);
#endif // wxUSE_STATUSBAR
}


// event handlers

void wxEmulatorFrame::OnQuit(wxCommandEvent& WXUNUSED(event))
{
    // true is to force the frame to close
    Close(true);
}

void wxEmulatorFrame::OnAbout(wxCommandEvent& WXUNUSED(event))
{
    wxString msg;
    msg.Printf( wxT("wxEmulator is an environment for testing embedded X11 apps.\n"));

    wxMessageBox(msg, wxT("About wxEmulator"), wxOK | wxICON_INFORMATION, this);
}

void wxEmulatorFrame::OnCloseWindow(wxCloseEvent& WXUNUSED(event))
{
#ifdef __WXX11__
    if (wxGetApp().m_xnestWindow)
    {
        wxGetApp().m_xnestWindow->SetHandle((WXWindow) NULL);
    }
#endif
    this->Destroy();
    if (wxGetApp().m_xnestPID > 0)
    {
        wxKill(wxGetApp().m_xnestPID);
        wxGetApp().m_xnestPID = 0;
    }
}

IMPLEMENT_CLASS(wxEmulatorContainer, wxWindow)

BEGIN_EVENT_TABLE(wxEmulatorContainer, wxWindow)
    EVT_SIZE(wxEmulatorContainer::OnSize)
    EVT_PAINT(wxEmulatorContainer::OnPaint)
    EVT_ERASE_BACKGROUND(wxEmulatorContainer::OnEraseBackground)
END_EVENT_TABLE()

wxEmulatorContainer::wxEmulatorContainer(wxWindow* parent, wxWindowID id):
    wxWindow(parent, id, wxDefaultPosition, wxDefaultSize)
{
}

void wxEmulatorContainer::OnSize(wxSizeEvent& WXUNUSED(event))
{
    DoResize();
}

void wxEmulatorContainer::DoResize()
{
    wxSize sz = GetClientSize();
    if (wxGetApp().m_xnestWindow
#ifdef __WXX11__
        && wxGetApp().m_xnestWindow->X11GetMainWindow()
#endif
        )
    {
        int deviceWidth = wxGetApp().m_emulatorInfo.m_emulatorDeviceSize.x;
        int deviceHeight = wxGetApp().m_emulatorInfo.m_emulatorDeviceSize.y;

        int x = wxMax(0, (int) ((sz.x - deviceWidth)/2.0));
        int y = wxMax(0, (int) ((sz.y - deviceHeight)/2.0));

        x += wxGetApp().m_emulatorInfo.m_emulatorScreenPosition.x;
        y += wxGetApp().m_emulatorInfo.m_emulatorScreenPosition.y;

        wxGetApp().m_xnestWindow->Move(x, y);
    }
    Refresh();
}

void wxEmulatorContainer::OnPaint(wxPaintEvent& WXUNUSED(event))
{
    wxPaintDC dc(this);

    wxSize sz = GetClientSize();
    if (wxGetApp().m_emulatorInfo.m_emulatorBackgroundBitmap.Ok())
    {
        int deviceWidth = wxGetApp().m_emulatorInfo.m_emulatorDeviceSize.x;
        int deviceHeight = wxGetApp().m_emulatorInfo.m_emulatorDeviceSize.y;

        int x = wxMax(0, (int) ((sz.x - deviceWidth)/2.0));
        int y = wxMax(0, (int) ((sz.y - deviceHeight)/2.0));

        dc.DrawBitmap(wxGetApp().m_emulatorInfo.m_emulatorBackgroundBitmap, x, y);
    }
}

void wxEmulatorContainer::OnEraseBackground(wxEraseEvent& event)
{
    wxDC* dc wxDUMMY_INITIALIZE(NULL);

    if (event.GetDC())
    {
        dc = event.GetDC();
    }
    else
    {
        dc = new wxClientDC(this);
    }

    dc->SetBackground(wxBrush(wxGetApp().m_emulatorInfo.m_emulatorBackgroundColour, wxSOLID));
    dc->Clear();

    if (!event.GetDC())
        delete dc;
}

// Information about the emulator decorations

void wxEmulatorInfo::Copy(const wxEmulatorInfo& info)
{
    m_emulatorFilename = info.m_emulatorFilename;
    m_emulatorTitle = info.m_emulatorTitle;
    m_emulatorDescription = info.m_emulatorDescription;
    m_emulatorScreenPosition = info.m_emulatorScreenPosition;
    m_emulatorScreenSize = info.m_emulatorScreenSize;
    m_emulatorBackgroundBitmap = info.m_emulatorBackgroundBitmap;
    m_emulatorBackgroundBitmapName = info.m_emulatorBackgroundBitmapName;
    m_emulatorBackgroundColour = info.m_emulatorBackgroundColour;
    m_emulatorDeviceSize = info.m_emulatorDeviceSize;
}

// Initialisation
void wxEmulatorInfo::Init()
{
    m_emulatorDeviceSize = wxSize(260, 340);
    m_emulatorScreenSize = wxSize(240, 320);
}

// Loads bitmaps
bool wxEmulatorInfo::Load(const wxString& appDir)
{
    // Try to find absolute path
    wxString absoluteConfigPath = m_emulatorFilename;
    if ( !::wxIsAbsolutePath(absoluteConfigPath) )
    {
        wxString currDir = wxGetCwd();
        absoluteConfigPath = currDir + wxString(wxFILE_SEP_PATH) + m_emulatorFilename;
        if ( !wxFile::Exists(absoluteConfigPath) )
        {
            absoluteConfigPath = appDir + wxString(wxFILE_SEP_PATH)
                + m_emulatorFilename;
        }
    }

    if ( !wxFile::Exists(absoluteConfigPath) )
    {
        wxString str;
        str.Printf( wxT("Could not find config file %s"),
            absoluteConfigPath.c_str() );

        wxMessageBox(str);
        return false;
    }

    wxString rootPath = wxPathOnly(absoluteConfigPath);

    {
        wxFileConfig config(wxT("wxEmulator"), wxT("wxWidgets"),
            absoluteConfigPath, wxEmptyString, wxCONFIG_USE_LOCAL_FILE);

        config.Read(wxT("/General/title"), & m_emulatorTitle);
        config.Read(wxT("/General/description"), & m_emulatorDescription);
        config.Read(wxT("/General/backgroundBitmap"), & m_emulatorBackgroundBitmapName);

        wxString colString;
        if (config.Read(wxT("/General/backgroundColour"), & colString) ||
            config.Read(wxT("/General/backgroundColor"), & colString)
           )
        {
            m_emulatorBackgroundColour = wxHexStringToColour(colString);
        }

        int x = 0, y = 0, w = 0, h = 0, dw = 0, dh = 0;
        config.Read(wxT("/General/screenX"), & x);
        config.Read(wxT("/General/screenY"), & y);
        config.Read(wxT("/General/screenWidth"), & w);
        config.Read(wxT("/General/screenHeight"), & h);
        if (config.Read(wxT("/General/deviceWidth"), & dw) && config.Read(wxT("/General/deviceHeight"), & dh))
        {
            m_emulatorDeviceSize = wxSize(dw, dh);
        }

        m_emulatorScreenPosition = wxPoint(x, y);
        m_emulatorScreenSize = wxSize(w, h);
    }

    if (!m_emulatorBackgroundBitmapName.empty())
    {
        wxString absoluteBackgroundBitmapName = rootPath + wxString(wxFILE_SEP_PATH) + m_emulatorBackgroundBitmapName;
        if ( !wxFile::Exists(absoluteBackgroundBitmapName) )
        {
            wxString str;
            str.Printf( wxT("Could not find bitmap %s"),
                absoluteBackgroundBitmapName.c_str() );
            wxMessageBox(str);
            return false;
        }

        wxBitmapType type = wxDetermineImageType(m_emulatorBackgroundBitmapName);
        if (type == wxBITMAP_TYPE_INVALID)
            return false;

        if (!m_emulatorBackgroundBitmap.LoadFile(m_emulatorBackgroundBitmapName, type))
        {
            wxString str;
            str.Printf( wxT("Could not load bitmap file %s"),
                m_emulatorBackgroundBitmapName.c_str() );
            wxMessageBox(str);
            return false;
        }

        m_emulatorDeviceSize = wxSize(m_emulatorBackgroundBitmap.GetWidth(),
            m_emulatorBackgroundBitmap.GetHeight());
    }
    return true;
}

// Returns the image type, or -1, determined from the extension.
wxBitmapType wxDetermineImageType(const wxString& filename)
{
    wxString path, name, ext;

    wxFileName::SplitPath(filename, & path, & name, & ext);

    ext.MakeLower();
    if (ext == wxT("jpg") || ext == wxT("jpeg"))
        return wxBITMAP_TYPE_JPEG;
    if (ext == wxT("gif"))
        return wxBITMAP_TYPE_GIF;
    if (ext == wxT("bmp"))
        return wxBITMAP_TYPE_BMP;
    if (ext == wxT("png"))
        return wxBITMAP_TYPE_PNG;
    if (ext == wxT("pcx"))
        return wxBITMAP_TYPE_PCX;
    if (ext == wxT("tif") || ext == wxT("tiff"))
        return wxBITMAP_TYPE_TIF;

    return wxBITMAP_TYPE_INVALID;
}

// Convert a colour to a 6-digit hex string
wxString wxColourToHexString(const wxColour& col)
{
    wxString hex;

    hex += wxDecToHex(col.Red());
    hex += wxDecToHex(col.Green());
    hex += wxDecToHex(col.Blue());

    return hex;
}

// Convert 6-digit hex string to a colour
wxColour wxHexStringToColour(const wxString& hex)
{
    unsigned char r = (unsigned char)wxHexToDec(hex.Mid(0, 2));
    unsigned char g = (unsigned char)wxHexToDec(hex.Mid(2, 2));
    unsigned char b = (unsigned char)wxHexToDec(hex.Mid(4, 2));

    return wxColour(r, g, b);
}

// Find the absolute path where this application has been run from.
// argv0 is wxTheApp->argv[0]
// cwd is the current working directory (at startup)
// appVariableName is the name of a variable containing the directory for this app, e.g.
// MYAPPDIR. This is checked first.

wxString wxFindAppPath(const wxString& argv0, const wxString& cwd, const wxString& appVariableName)
{
    wxString str;

    // Try appVariableName
    if (!appVariableName.empty())
    {
        str = wxGetenv(appVariableName);
        if (!str.empty())
            return str;
    }

    if (wxIsAbsolutePath(argv0))
        return wxPathOnly(argv0);
    else
    {
        // Is it a relative path?
        wxString currentDir(cwd);
        if (!wxEndsWithPathSeparator(currentDir))
            currentDir += wxFILE_SEP_PATH;

        str = currentDir + argv0;
        if ( wxFile::Exists(str) )
            return wxPathOnly(str);
    }

    // OK, it's neither an absolute path nor a relative path.
    // Search PATH.

    wxPathList pathList;
    pathList.AddEnvList(wxT("PATH"));
    str = pathList.FindAbsoluteValidPath(argv0);
    if (!str.empty())
        return wxPathOnly(str);

    // Failed
    return wxEmptyString;
}

