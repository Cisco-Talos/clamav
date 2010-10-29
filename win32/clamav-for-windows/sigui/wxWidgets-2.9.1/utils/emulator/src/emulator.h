///////////////////////////////////////////////////////////////////////////////
// Name:        emulator.h
// Purpose:     wxX11-based PDA emulator classes
// Author:      Julian Smart
// Modified by:
// Created:     2002-03-10
// RCS-ID:      $Id$
// Copyright:   (c) wxWidgets team
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_EMULATOR_H_
#define _WX_EMULATOR_H_

#define wxEMULATOR_VERSION 0.1

// Information about the emulator decorations
class wxEmulatorInfo: public wxObject
{
public:

    wxEmulatorInfo() { Init(); }
    wxEmulatorInfo(const wxEmulatorInfo& info) : wxObject() { Init(); Copy(info); }

    void operator= (const wxEmulatorInfo& info) { Copy(info); }
    void Copy(const wxEmulatorInfo& info);

    // Initialisation
    void Init();

    // Loads bitmaps
    bool Load(const wxString& appDir);

    // Emulator config filename
    wxString m_emulatorFilename;

    // Emulator title
    wxString m_emulatorTitle;

    // Emulator description
    wxString m_emulatorDescription;

    // The offset from the top-left of the main emulator
    // bitmap and the virtual screen (where Xnest is
    // positioned)
    wxPoint m_emulatorScreenPosition;

    // The emulated screen size, e.g. 320x240
    wxSize m_emulatorScreenSize;

    // The emulated device size. This is ignored
    // if there is a background bitmap
    wxSize m_emulatorDeviceSize;

    // The bitmap used for drawing the main emulator
    // decorations
    wxBitmap m_emulatorBackgroundBitmap;
    wxString m_emulatorBackgroundBitmapName;

    // The intended background colour (for filling in
    // areas of the window not covered by the bitmap)
    wxColour m_emulatorBackgroundColour;

    // TODO: an array of bitmaps and ids for custom buttons
};

// Emulator app class
class wxEmulatorContainer;
class wxEmulatorApp : public wxApp
{
public:
    wxEmulatorApp();
    virtual bool OnInit();

    // Load the specified emulator
    bool LoadEmulator(const wxString& appDir);

    // Get app dir
    wxString GetAppDir() const { return m_appDir; }

    // Prepend the current app program directory to the name
    wxString GetFullAppPath(const wxString& filename) const;

public:

    wxEmulatorInfo          m_emulatorInfo;
#ifdef __WXX11__
    wxAdoptedWindow*        m_xnestWindow;
#else
    wxWindow*               m_xnestWindow;
#endif
    wxEmulatorContainer*    m_containerWindow;
    wxString                m_appDir;
    wxString                m_displayNumber;
    long                    m_xnestPID;
};

// The container for the Xnest window. The decorations
// will be drawn on this window.
class wxEmulatorContainer: public wxWindow
{
public:

    wxEmulatorContainer(wxWindow* parent, wxWindowID id);

    void DoResize();

    void OnSize(wxSizeEvent& event);
    void OnPaint(wxPaintEvent& event);
    void OnEraseBackground(wxEraseEvent& event);

DECLARE_CLASS(wxEmulatorContainer)
DECLARE_EVENT_TABLE()

};

// Frame class
class wxEmulatorFrame : public wxFrame
{
public:
    // ctor(s)
    wxEmulatorFrame(const wxString& title, const wxPoint& pos, const wxSize& size);

    // event handlers
    void OnQuit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);
    void OnCloseWindow(wxCloseEvent& event);

private:
    // any class wishing to process wxWidgets events must use this macro
    DECLARE_EVENT_TABLE()
};

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// IDs for the controls and the menu commands
enum
{
    // menu items
    Emulator_Quit = 1,

    // it is important for the id corresponding to the "About" command to have
    // this standard value as otherwise it won't be handled properly under Mac
    // (where it is special and put into the "Apple" menu)
    Emulator_About = wxID_ABOUT
};

// Returns the image type, or -1, determined from the extension.
wxBitmapType wxDetermineImageType(const wxString& filename);

// Convert a colour to a 6-digit hex string
wxString wxColourToHexString(const wxColour& col);

// Convert 6-digit hex string to a colour
wxColour wxHexStringToColour(const wxString& hex);

// Find the absolute path where this application has been run from.
wxString wxFindAppPath(const wxString& argv0, const wxString& cwd, const wxString& appVariableName);

#endif
    // _WX_EMULATOR_H_

