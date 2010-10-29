/////////////////////////////////////////////////////////////////////////////
// Name:        autocapture.h
// Purpose:     Defines the AutoCaptureMechanism class
// Author:      Utensil Candel (UtensilCandel@@gmail.com)
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _AUTOCAPTURE_H_
#define _AUTOCAPTURE_H_

#include "wx/beforestd.h"
#include <vector>
#include "wx/afterstd.h"

#include "wx/gdicmn.h"

class wxBitmap;
class wxFlexGridSizer;
class wxWindow;
class wxNotebook;

/**
    GlobalAdjustFlags works with AutoCaptureMechanism's constructor, to disbale/enable
    some auto-adjustment for all controls.

    They are used to make AutoCaptureMechanism more configurable and provide a fallback
    to detect the bugs that the adjustments intended to avoid.

    @see AdjustFlags
*/
enum GlobalAdjustFlags
{
    /**
        This is the default. All adjustments instructed in
        AutoCaptureMechanism::RegisterControl() will be performed.
    */
    AJ_NormalAll = 0,

    /**
        Disable region adjustment for all controls.
    */
    AJ_DisableRegionAdjust =  1 << 0,

    /**
        Enable region adjustment for all controls.

        If AJ_DisableRegionAdjust and AJ_AlwaysRegionAdjust are both specified, current
        implemetation will ignore AJ_DisableRegionAdjust.
    */
    AJ_AlwaysRegionAdjust =  1 << 1,

    /**
        Disable name adjustment for all controls.
    */
    AJ_DisableNameAdjust = 1 << 2,

    /**
        For all the "Drop-down Controls", e.g. wxChoice, do not prompt the user about whether
        to capture their drop-down state, and always capture only its non-drop-down state.
    */
    AJ_DisableDropdown = 1 << 3
};

/**
    AdjustFlags works with AutoCaptureMechanism::RegisterControl() to specify how to
    adjust the screenshot of the current control.

    They are used to avoid bugs, look better or interact with user etc.

    @see GlobalAdjustFlags
*/
enum AdjustFlags
{
    /**
        This is the default. Perform no adjustment for this control.
    */
    AJ_Normal = 0,

    /**
        Perform region adjustment for this control.

        On some platforms and for some controls, wxWindow::GetScreenRect() will return
        a smaller or deflected region. In these cases, the screenshots we get are incomplete.
        It's recommended for everyone to fix the controls' code, yet this flag provides a
        workaround to get a guaranteed correct region without using wxWindow::GetScreenRect().

        This workaround("label trick") is inspired by (or say stolen from) Auria's work.
    */
    AJ_RegionAdjust = 1 << 0,

    /**
        This flag provides a way to capture the drop-down state of "Drop-down Controls",
        e.g. wxChoice.

        For all the "Drop-down Controls", prompt the user about whether to capture their
        drop-down state, if the user chooses YES, he should drop down the control in about
        3 seconds and wait util it's captured in that state.
    */
    AJ_Dropdown = 1 << 1,

    /**
        This flag is used internally by RegisterPageTurn(). Don't use it directly unless you
        know what you are doing.
    */
    AJ_TurnPage = 1 << 2,

    /**
        This flag provides a functionality to union screenshots of different modes/states of
        a control into one image. e.g. the single-line/multi-line modes of a wxTextCtrl.

        For a series of controls to be unioned, you should specify AJ_Union for the first,
        and AJ_UnionEnd for the last. For the controls between them, you can either specify
        AJ_Union or not.

        The filename of the generated screenshot is the name of the first control in the series.
    */
    AJ_Union = 1 << 3,

    /**
        @see AJ_Union.
    */
    AJ_UnionEnd = 1 << 4
};

/**
    @class AutoCaptureMechanism

    AutoCaptureMechanism provides an easy-to-use and adjustable facility to take the screenshots
    for all controls fully automaticly and correctly. It also provides an advanced feature to
    union screenshots of different states/modes of a control.

    @section tag_filename_convention Screenshot File Name Convention

    All screenshots are generated as PNG files. For a control named wxName, its screenshot file
    name would be "name.png", e.g. "button.png" for wxButton. This is the protocol with the
    doxygen document of wxWidgets.

    By default, screenshots are generated under the subdirectory "screenshots" of current working
    directory. During updating or adding new screenshots, first make sure screenshots are generated
    correctly, and then copy them to the following subdirectory of docs/doxygen/images:

    "wxmsw" for MS Windows, "wxgtk" for Linux and "wxmac" for Mac OS.

    @section tag_gui_assumption The Assumption of GUI

    Unfortunately, this class have an assumption about the structure of GUI:
    It must have the follwoing top-down structure:

    wxNotebook->wxPanel->wxSizer->wxControl

    That means, in the wxNotebook associated with this class, controls that needs to be
    taken screenshots are placed on different panels(for grouping) and layed out by wxSizers.

    @section tag_tutorial Tutorial

    In the contruction, you should associate a wxNotebook with this class, in that wxNotebook,
    controls that needs to be captured are placed on different panels(for grouping).

    When you register controls, you should do it in order: Register the controls on the first
    panel(using RegisterControl()), and then register a page turn(using RegisterPageTurn()),
    so this class can turn a page of the wxNotebook to present the second page. And then
    you register the controls on the second panel, then a page turn, and so on.

    When you are done, simply call CaptureAll(), then screenshots of all controls will be
    automaticly generated.

    @section tag_autoadjust Make Use of Auto Adjustments

    First take a look at the document of RegisterControl(), enum AdjustFlags and
    GlobalAdjustFlags.

    And then, ScreenshotFrame::OnCaptureAllControls() is a good example of making use of
    auto adjustment. Taking a look at it will get you started.

    @section tag_developer_note Notes for Developers

    @subsection tag_cnc CaptureAll() and Capture()

    The implementation of Auto Adjustments is in CaptureAll() and Capture(), the code is
    short, quite readable and well commented, please read the codes before any modification.

    If you need the class to do something sepcial for you, consider introducing a new flag
    and implement it in them. For an operation performed on multiple controls, implemente
    its logic in CaptureAll(), otherwise in the private member Capture().

    @subsection tag_yield_issue wxYield Issues

    Not quite a good habit, but this class made a lot of use of wxYield()/wxYieldIfNeeded().
    They are used to ensure the update of GUI(e.g. the page turn of wxNotebook) is done
    before any further screenshot-taking, or to do the timing(in Delay()). Without their use,
    there would be subtle bugs.

    I've read documents about wxYield() and understand the down side of it before using it.
    But I didn't find a better approach to do those things, and I used them carefully. So
    please DO NOT remove any of these wxYield()s unless you're sure that it won't cause problems
    on all of MS Windows XP/Vista, Linux(Ubuntu/Fedora), Mac OS Tiger/Leopard. And please
    help me to find a better approach, thank you :)
*/
class AutoCaptureMechanism
{
public:
    /**
        Constructor.

        @param notebook
        The wxNotebook associated with this class.Please see @ref tag_gui_assumption
        and @ref tag_tutorial.

        @param flag
        It's one of or a combination of GlobalAdjustFlags, to disbale/enable some auto-adjustment
        for all controls.

        @param margin
        It's the margin around every control in the sreenshots.
    */
    AutoCaptureMechanism(wxNotebook *notebook,
                         int flag = AJ_NormalAll,
                         int margin = 5);

    ~AutoCaptureMechanism() { }

    /**
        Register a control and perform specifid auto adjustments.

        @param ctrl
        The pointer to the control to be taken a screenshot.

        @param name
        If you find out that the screenshot for this control was generated under an incorrect
        file name, specify @a name. e.g. for wxButton, "wxButton" or "button" are both OK.

        @param flag

        If you end up with an a smaller or deflected screenshot, use AJ_RegionAdjust.

        If you want to caputure the "drop-down" state of a "drop-down" control, use AJ_Dropdown.

        If you want to present different states of a control in one screenshot, use AJ_Union
        and AJ_UnionEnd.

        Please read the document of enum AdjustFlags, and notice that this flag could be enabled/
        disabled by global flag GlobalAdjustFlags.
    */
    void RegisterControl(wxWindow * ctrl, wxString name = wxT(""), int flag = AJ_Normal)
    {
        m_controlList.push_back(Control(ctrl, name, flag));
    }

    /**
        Register a control and perform specifid auto adjustments.

        This is the same as RegisterControl(wxWindow * ctrl, wxString name, int flag),
        But with it, you won't have to specify the name if you only want to auto-adjust something
        other than name adjustment.
    */
    void RegisterControl(wxWindow * ctrl, int flag)
    {
        RegisterControl(ctrl, wxT(""), flag);
    }

    /**
        Register a page turn.

        When you finished registering the controls on a panel, remember to call it to turn the
        wxNotebook to the next panel.
    */
    void RegisterPageTurn()
    {
        m_controlList.push_back(Control(0, wxT(""), AJ_TurnPage));
    }

    /**
        Capture all registered controls of the associated wxNotebook.
    */
    void CaptureAll();

    /*
        Static Members
    */
    /**
        Take a screenshot for the given region.

        @param bitmap
            Bitmap to save the screenshot to.
        @param rect
            Given rectangular region.
        @param delay
            Only useful for Mac, for fixing a delay bug. It seems that it
            didn't fix the bug, so it might be removed soon.
    */
    static bool Capture(wxBitmap* bitmap, wxRect rect, int delay = 0);

    /**
        Take a screenshot for the given region.

        @see Capture(wxBitmap*,wxRect,int)
    */
    static bool Capture(wxBitmap* bitmap, int x, int y, int width, int height, int delay = 0);

    /**
        Save the screenshot as the name of @a fileName in the default directory.

        @a fileName should be without ".png".
    */
    static void Save(wxBitmap* screenshot, const wxString& fileName);

    /**
        Set the default directory where the screenshots will be generated.
    */
    static void SetDefaultDirectory(const wxString& dir) { default_dir = dir; }

    /**
        Get the default directory where the screenshots will be generated.
    */
    static wxString GetDefaultDirectory() { return default_dir; }

    /**
        Get the absolute path of the default directory where the screenshots will be generated.
    */
    static wxString GetDefaultDirectoryAbsPath();

private:

    /*
        Internal Data Structures

        They might go public in future to provide reuse of ControlList.
    */
    struct Control
    {
        Control() {}

        Control(wxWindow * _ctrl, wxString _name, int _flag)
            : ctrl(_ctrl), name(_name), flag(_flag) {}

        wxWindow * ctrl;
        wxString name;
        int flag;
    };

    typedef std::vector<Control> ControlList;

    /*
        Internal Functions

        They are only used to clearify the logic of some public functions and it's nonsense
        to call them elsewhere.
    */

    /*
        Capture and auto adjust the control. Used by CaptureAll().
    */
    bool Capture(wxBitmap* bitmap, Control& ctrl);

    /*
        Get the correct rectangular region that the control occupies. Used by
        Capture(Control & ctrl).

        If AJ_RegionAdjust is specified, it will use the "label trick" to perform
        region auto adjustment.

        The "label trick" is to reattach the control to a wxFlexGridSizer m_grid,
        surround the control with labels and get the control's region by label's positions.
        Just like this:

        +---------+-----------+---------+
        |    0    |   label   |    1    |
        +---------+-----------+---------+
        |  label  |    ctrl   |  label  |
        +---------+-----------+---------+
        |    2    |   label   |    3    |
        +---------+-----------+---------+

        So, there will be a side effect: the control is moved to a new position. So after taking the
        screenshot, Capture(Control & ctrl) should call PutBack(wxWindow * ctrl) to put it back.

        If AJ_RegionAdjust isn't specified, it will simply call wxWindow::GetScreenRect().
    */
    wxRect GetRect(wxWindow* ctrl, int flag);

    /*
        Put the control back after the label trick used in GetRect(). Used by
        Capture(Control & ctrl).
    */
    void PutBack(wxWindow * ctrl);

    /*
        Union two screenshots in the vertical direction, and leave a gap between the
        screenshots. Used by CaptureAll().

        The gap is 20 pixels by default. Currently it isn't configurable.
    */
    static bool Union(wxBitmap* top, wxBitmap* bottom, wxBitmap* result);

    /*
        Delay a few seconds without blocking GUI.
    */
    static void Delay(int seconds);

    /*
        Data Members
    */
    ControlList m_controlList;

    wxNotebook* m_notebook;

    int m_flag;

    int m_margin;

    wxFlexGridSizer* m_grid;

    static wxString default_dir;
};

#endif // _AUTOCAPTURE_H_


