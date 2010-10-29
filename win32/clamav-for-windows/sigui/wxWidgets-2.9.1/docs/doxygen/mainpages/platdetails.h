/////////////////////////////////////////////////////////////////////////////
// Name:        platdetails.h
// Purpose:     Platform details page of the Doxygen manual
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**

@page page_port Platform Details

wxWidgets defines a common API across platforms, but uses the native graphical
user interface (GUI) on each platform, so your program will take on the native
look and feel that users are familiar with. Unfortunately native toolkits and
hardware do not always support the functionality that the wxWidgets API
requires. This chapter collects notes about differences among supported platforms
and ports.

@li @ref page_port_wxgtk
@li @ref page_port_wxosx
@li @ref page_port_wxos2
@li @ref page_port_wxmgl
@li @ref page_port_wxx11
@li @ref page_port_wxmotif
@li @ref page_port_wxmsw
@li @ref page_port_nativedocs


<hr>



@section page_port_wxgtk wxGTK

@htmlonly
<img src="logo_gtk.png" alt="GTK logo" title="GTK logo" class="logo">
@endhtmlonly

wxGTK is a port of wxWidgets using the GTK+ library.
It makes use of GTK+'s native widgets wherever possible and uses
wxWidgets' generic controls when needed. GTK+ itself has been
ported to a number of systems, but so far only the original X11
version is supported. Support for other GTK+ backends is planned,
such as the new DirectFB backend.

All work is being done on GTK+ version 2.0 and above. Support for
GTK+ 1.2 will be deprecated in a later release.

You will need GTK+ 2.6 or higher which is available from:

http://www.gtk.org

The newer version of GTK+ you use, the more native widgets and
features will be utilized. We have gone to great lengths to
allow compiling wxWidgets applications with the latest version of
GTK+, with the resulting binary working on systems even with a
much earlier version of GTK+. You will have to ensure that the
application is launched with lazy symbol binding for that.

In order to configure wxWidgets to compile wxGTK you will
need use the @c --with-gtk argument to the @c configure script.
This is the default for many systems.

GTK+ 1.2 can still be used, albeit discouraged. For that you can
pass @c --with-gtk=1 to the @c configure script.

For further information, please see the files in @c docs/gtk
in the distribution.


@section page_port_wxosx wxOSX

@htmlonly
<img src="logo_osxleopard.png" alt="Mac OS X (Leopard) logo"
    title="Mac OS X (Leopard) logo" class="logo">
@endhtmlonly

@subsection page_port_wxosx_carbon wxOSX/Carbon

wxOSX/Carbon is a port of wxWidgets for the Macintosh OS platform.
Currently MacOS X 10.4 or higher are supported. wxOSX/Carbon can
be compiled both using Apple's command line developer tools
as well as Apple's Xcode IDE. wxOSX/Carbon supports both the Intel
and PowerPC architectures and can be used to produce
"universal binaries" in order create application which can run
both architecture. Unfortunately, wxOSX/Carbon does not support any
64-bit architecture since Apple decided not to port its Carbon
API entirely to 64-bit.

@note Carbon has been deprecated by Apple as of OS X 10.5 and will likely
be removed entirely in a future OS version. It's recommended you look into
switching your app over to wxOSX/Cocoa as soon as possible.

For further information, please see the files in @c docs/osx
in the distribution.



@subsection page_port_wxosx_cocoa wxOSX/Cocoa

wxOSX/Cocoa is another port of wxWidgets for the Macintosh OS
platform. In contrast to wxOSX/Carbon, it uses the Cocoa API 
in place of Carbon. Much work has gone into this port and many 
controls are functional, but the port has not reached the maturity
of the wxOSX/Carbon port yet. It is possible to use wxOSX/Cocoa
on 64-bit architectures.

In order to configure wxWidgets to compile wxOSX/Cocoa you will
need to type:

@verbatim configure --with-osx_cocoa @endverbatim

For further information, please see the files in @c docs/osx
in the distribution.

@note There was a previous effort towards a Cocoa port called 
wxCocoa, which was implemented totally with Cocoa API unlike the OSX/Cocoa port
which uses OS X C APIs to share code, and while it is no longer being actively 
developed, docs for it are available in @c docs/cocoa in the distribution.



@section page_port_wxmgl wxMGL

wxMGL is a port of wxWidgets using the MGL library available
from SciTech as the underlying graphics backend. wxMGL draws
its widgets using the wxUniversal widget set which is part
of wxWidgets. MGL itself runs on a variety of platforms
including DOS, Linux hardware (similar to the Linux framebuffer)
and various graphics systems such as Win32, X11 and OS/2.
Note that currently MGL for Linux runs only on x86-based systems.

You will MGL 5.0 or higher which is available from

http://www.scitechsoft.com/products/product_download.html

In order to configure wxWidgets to compile wxMGL you will
need to type:

@verbatim configure --with-mgl --with-universal @endverbatim

Under DOS, wxMGL uses a dmake based make system.

For further information, please see the files in @c docs/mgl
in the distribution.



@section page_port_wxos2 wxOS2

wxOS2 is a port of wxWidgets for the IBM OS/2 Warp3 and Warp4 platforms.
This port is currently under construction and in beta phase.

For further information, please see the files in @c docs/os2
in the distribution.



@section page_port_wxx11 wxX11

@htmlonly
<img src="logo_x11.png" alt="X.org logo" title="X.org logo" class="logo">
@endhtmlonly

wxX11 is a port of wxWidgets using X11 (The X Window System)
as the underlying graphics backend. wxX11 draws its widgets
using the wxUniversal widget set which is now part of wxWidgets.
wxX11 is well-suited for a number of special applications such
as those running on systems with few resources (PDAs) or for
applications which need to use a special themed look.

In order to configure wxWidgets to compile wxX11 you will
need to type:

@verbatim configure --with-x11 --with-universal @endverbatim

For further information, please see the files in @c docs/x11
in the distribution. There is also a page on the use of
wxWidgets for embedded applications on the wxWidgets web site.



@section page_port_wxmotif wxMotif

@htmlonly
<img src="logo_motif.png" alt="Motif logo" title="Motif logo" class="logo">
@endhtmlonly

wxMotif is a port of wxWidgets for X11 systems using Motif libraries.
Motif libraries provide a clean and fast user interface at the expense
of the beauty and candy of newer interfaces like GTK.

For further information, please see the files in @c docs/motif
in the distribution.




@section page_port_wxmsw wxMSW

@htmlonly
<img src="logo_win.png" alt="Windows logo" title="Windows logo" class="logo">
@endhtmlonly

wxMSW is a port of wxWidgets for the Windows platforms including Windows 95,
98, ME, 2000, NT, XP and Vista in ANSI and Unicode modes (for Windows 9x and
ME through the MSLU extension library). wxMSW ensures native look and feel for
XP when using wxWidgets version 2.3.3 or higher.wxMSW can be compiled with a
great variety of compilers including Microsoft Studio VC++, Borland 5.5,
MinGW32, Cygwin and Watcom as well as cross-compilation with a Linux-hosted
MinGW32 tool chain.

For further information, please see the files in docs/msw
in the distribution.

@subsection page_port_wxmsw_themedborders Themed borders on Windows

Starting with wxWidgets 2.8.5, you can specify the @c wxBORDER_THEME style to have wxWidgets
use a themed border. Using the default XP theme, this is a thin 1-pixel blue border,
with an extra 1-pixel border in the window client background colour (usually white) to
separate the client area's scrollbars from the border.

If you don't specify a border style for a wxTextCtrl in rich edit mode, wxWidgets now gives
the control themed borders automatically, where previously they would take the Windows 95-style
sunken border. Other native controls such as wxTextCtrl in non-rich edit mode, and wxComboBox
already paint themed borders where appropriate. To use themed borders on other windows, such
as wxPanel, pass the @c wxBORDER_THEME style, or (apart from wxPanel) pass no border style.

In general, specifying @c wxBORDER_THEME will cause a border of some kind to be used, chosen by the platform
and control class. To leave the border decision entirely to wxWidgets, pass @c wxBORDER_DEFAULT.
This is not to be confused with specifying @c wxBORDER_NONE, which says that there should
definitely be @e no border.

@subsubsection page_port_wxmsw_themedborders_details More detail on border implementation

The way that wxMSW decides whether to apply a themed border is as follows.
The theming code calls wxWindow::GetBorder() to obtain a border. If no border style has been
passed to the window constructor, GetBorder() calls GetDefaultBorder() for this window.
If wxBORDER_THEME was passed to the window constructor, GetBorder() calls GetDefaultBorderForControl().

The implementation of wxWindow::GetDefaultBorder() on wxMSW calls wxWindow::CanApplyThemeBorder()
which is a virtual function that tells wxWidgets whether a control can have a theme
applied explicitly (some native controls already paint a theme in which case we should not
apply it ourselves). Note that wxPanel is an exception to this rule because in many cases
we wish to create a window with no border (for example, notebook pages). So wxPanel
overrides GetDefaultBorder() in order to call the generic wxWindowBase::GetDefaultBorder(),
returning wxBORDER_NONE.

@subsection page_port_wxmsw_wince wxWinCE

wxWinCE is the name given to wxMSW when compiled on Windows CE devices;
most of wxMSW is common to Win32 and Windows CE but there are
some simplifications, enhancements, and differences in
behaviour.

For building instructions, see docs/msw/wince in the
distribution, also the section about Visual Studio 2005 project
files below. The rest of this section documents issues you
need to be aware of when programming for Windows CE devices.

@subsubsection page_port_wxmsw_wince_ General issues for wxWinCE programming

Mobile applications generally have fewer features and
simpler user interfaces. Simply omit whole sizers, static
lines and controls in your dialogs, and use comboboxes instead
of listboxes where appropriate. You also need to reduce
the amount of spacing used by sizers, for which you can
use a macro such as this:

@code
#if defined(__WXWINCE__)
    #define wxLARGESMALL(large,small) small
#else
    #define wxLARGESMALL(large,small) large
#endif

// Usage
topsizer->Add( CreateTextSizer( message ), 0, wxALL, wxLARGESMALL(10,0) );
@endcode

There is only ever one instance of a Windows CE application running,
and wxWidgets will take care of showing the current instance and
shutting down the second instance if necessary.

You can test the return value of wxSystemSettings::GetScreenType()
for a qualitative assessment of what kind of display is available,
or use wxGetDisplaySize() if you need more information.

You can also use wxGetOsVersion to test for a version of Windows CE at
run-time (see the next section). However, because different builds
are currently required to target different kinds of device, these
values are hard-wired according to the build, and you cannot
dynamically adapt the same executable for different major Windows CE
platforms. This would require a different approach to the way
wxWidgets adapts its behaviour (such as for menubars) to suit the
style of device.

See the "Life!" example (demos/life) for an example of
an application that has been tailored for PocketPC and Smartphone use.

@note don't forget to have this line in your .rc file, as for
    desktop Windows applications:

@verbatim #include "wx/msw/wx.rc" @endverbatim

@subsubsection page_port_wxmsw_wince_sdk Testing for WinCE SDKs

Use these preprocessor symbols to test for the different types of device or SDK:

@li @b __SMARTPHONE__ Generic mobile devices with phone buttons and a small display
@li @b __PDA__ Generic mobile devices with no phone
@li @b __HANDHELDPC__ Generic mobile device with a keyboard
@li @b __WXWINCE__ Microsoft-powered Windows CE devices, whether PocketPC, Smartphone or Standard SDK
@li @b WIN32_PLATFORM_WFSP Microsoft-powered smartphone
@li @b __POCKETPC__ Microsoft-powered PocketPC devices with touch-screen
@li @b __WINCE_STANDARDSDK__ Microsoft-powered Windows CE devices, for generic Windows CE applications
@li @b __WINCE_NET__ Microsoft-powered Windows CE .NET devices (_WIN32_WCE is 400 or greater)

wxGetOsVersion will return these values:

@li @b wxWINDOWS_POCKETPC The application is running under PocketPC.
@li @b wxWINDOWS_SMARTPHONE The application is running under Smartphone.
@li @b wxWINDOWS_CE The application is running under Windows CE (built with the Standard SDK).


@subsubsection page_port_wxmsw_wince_sizing Window sizing in wxWinCE

Top level windows (dialogs, frames) are created always full-screen. Fit() of sizers will not rescale top
level windows but instead will scale window content.

If the screen orientation changes, the windows will automatically be resized
so no further action needs to be taken (unless you want to change the layout
according to the orientation, which you could detect in idle time, for example).
When input panel (SIP) is shown, top level windows (frames and dialogs) resize
accordingly (see wxTopLevelWindow::HandleSettingChange()).

@subsubsection page_port_wxmsw_wince_toplevel Closing top-level windows in wxWinCE

You won't get a wxCloseEvent when the user clicks on the X in the titlebar
on Smartphone and PocketPC; the window is simply hidden instead. However the system may send the
event to force the application to close down.

@subsubsection page_port_wxmsw_wince_hibernation Hibernation in wxWinCE

Smartphone and PocketPC will send a @c wxEVT_HIBERNATE to the application object in low
memory conditions. Your application should release memory and close dialogs,
and wake up again when the next @c wxEVT_ACTIVATE or @c wxEVT_ACTIVATE_APP message is received.
(@c wxEVT_ACTIVATE_APP is generated whenever a @c wxEVT_ACTIVATE event is received
in Smartphone and PocketPC, since these platforms do not support @c WM_ACTIVATEAPP.)

@subsubsection page_port_wxmsw_wince_hwbutt Hardware buttons in wxWinCE

Special hardware buttons are sent to a window via the @c wxEVT_HOTKEY event
under Smartphone and PocketPC. You should first register each required button with
wxWindow::RegisterHotKey(), and unregister the button when you're done with it. For example:

@code
win->RegisterHotKey(0, wxMOD_WIN, WXK_SPECIAL1);
win->UnregisterHotKey(0);
@endcode

You may have to register the buttons in a @c wxEVT_ACTIVATE event handler
since other applications will grab the buttons.

There is currently no method of finding out the names of the special
buttons or how many there are.

@subsubsection page_port_wxmsw_wince_dialogs Dialogs in wxWinCE

PocketPC dialogs have an OK button on the caption, and so you should generally
not repeat an OK button on the dialog. You can add a Cancel button if necessary, but some dialogs
simply don't offer you the choice (the guidelines recommend you offer an Undo facility
to make up for it). When the user clicks on the OK button, your dialog will receive
a @c wxID_OK event by default. If you wish to change this, call wxDialog::SetAffirmativeId()
with the required identifier to be used. Or, override wxDialog::DoOK() (return @false to
have wxWidgets simply call Close to dismiss the dialog).

Smartphone dialogs do @e not have an OK button on the caption, and are closed
using one of the two menu buttons. You need to assign these using wxTopLevelWindow::SetLeftMenu
and wxTopLevelWindow::SetRightMenu(), for example:

@code
#ifdef __SMARTPHONE__
    SetLeftMenu(wxID_OK);
    SetRightMenu(wxID_CANCEL, _("Cancel"));
#elif defined(__POCKETPC__)
    // No OK/Cancel buttons on PocketPC, OK on caption will close
#else
    topsizer->Add( CreateButtonSizer( wxOK|wxCANCEL ), 0, wxEXPAND | wxALL, 10 );
#endif
@endcode

For implementing property sheets (flat tabs), use a wxNotebook with @c wxNB_FLAT|wxNB_BOTTOM
and have the notebook left, top and right sides overlap the dialog by about 3 pixels
to eliminate spurious borders. You can do this by using a negative spacing in your
sizer Add() call. The cross-platform property sheet dialog wxPropertySheetDialog is
provided, to show settings in the correct style on PocketPC and on other platforms.

Notifications (bubble HTML text with optional buttons and links) will also be
implemented in the future for PocketPC.

Modeless dialogs probably don't make sense for PocketPC and Smartphone, since
frames and dialogs are normally full-screen, and a modeless dialog is normally
intended to co-exist with the main application frame.

@subsubsection page_port_wxmsw_wince_ppc Menubars and toolbars in PocketPC

On PocketPC, a frame must always have a menubar, even if it's empty.
An empty menubar/toolbar is automatically provided for dialogs, to hide
any existing menubar for the duration of the dialog.

Menubars and toolbars are implemented using a combined control,
but you can use essentially the usual wxWidgets API; wxWidgets will combine the menubar
and toolbar. However, there are some restrictions:

@li You must create the frame's primary toolbar with wxFrame::CreateToolBar(),
because this uses the special wxToolMenuBar class (derived from wxToolBar)
to implement the combined toolbar and menubar. Otherwise, you can create and manage toolbars
using the wxToolBar class as usual, for example to implement an optional
formatting toolbar above the menubar as Pocket Word does. But don't assign
a wxToolBar to a frame using SetToolBar - you should always use CreateToolBar
for the main frame toolbar.
@li Deleting and adding tools to wxToolMenuBar after Realize is called is not supported.
@li For speed, colours are not remapped to the system colours as they are
in wxMSW. Provide the tool bitmaps either with the correct system button background,
or with transparency (for example, using XPMs).
@li Adding controls to wxToolMenuBar is not supported. However, wxToolBar supports
controls.

Unlike in all other ports, a wxDialog has a wxToolBar automatically created
for you. You may either leave it blank, or access it with wxDialog::GetToolBar()
and add buttons, then calling wxToolBar::Realize(). You cannot set or recreate
the toolbar.

@subsubsection page_port_wxmsw_wince_smart Menubars and toolbars in Smartphone

On Smartphone, there are only two menu buttons, so a menubar is simulated
using a nested menu on the right menu button. Any toolbars are simply ignored on
Smartphone.

@subsubsection page_port_wxmsw_wince_closing Closing windows in wxWinCE

The guidelines state that applications should not have a Quit menu item,
since the user should not have to know whether an application is in memory
or not. The close button on a window does not call the window's
close handler; it simply hides the window. However, the guidelines say that
the Ctrl+Q accelerator can be used to quit the application, so wxWidgets
defines this accelerator by default and if your application handles
wxID_EXIT, it will do the right thing.

@subsubsection page_port_wxmsw_wince_ctx Context menus in wxWinCE

To enable context menus in PocketPC, you currently need to call wxWindow::EnableContextMenu(),
a wxWinCE-only function. Otherwise the context menu event (wxContextMenuEvent) will
never be sent. This API is subject to change.

Context menus are not supported in Smartphone.

@subsubsection page_port_wxmsw_wince_ctrl Control differences on wxWinCE

These controls and styles are specific to wxWinCE:

@li wxTextCtrl The @c wxTE_CAPITALIZE style causes a CAPEDIT control to
be created, which capitalizes the first letter.

These controls are missing from wxWinCE:

@li MDI classes MDI is not supported under Windows CE.
@li wxMiniFrame Not supported under Windows CE.

Tooltips are not currently supported for controls, since on PocketPC controls with
tooltips are distinct controls, and it will be hard to add dynamic
tooltip support.

Control borders on PocketPC and Smartphone should normally be specified with
@c wxBORDER_SIMPLE instead of @c wxBORDER_SUNKEN. Controls will usually adapt
appropriately by virtue of their GetDefaultBorder() function, but if you
wish to specify a style explicitly you can use @c wxDEFAULT_CONTROL_BORDER
which will give a simple border on PocketPC and Smartphone, and the sunken border on
other platforms.

@subsubsection page_port_wxmsw_wince_help Online help in wxWinCE

You can use the help controller wxWinceHelpController which controls
simple @c .htm files, usually installed in the Windows directory.
See the Windows CE reference for how to format the HTML files.

@subsubsection page_port_wxmsw_wince_install Installing your PocketPC and Smartphone applications

To install your application, you need to build a CAB file using
the parameters defined in a special .inf file. The CabWiz program
in your SDK will compile the CAB file from the .inf file and
files that it specifies.

For delivery, you can simply ask the user to copy the CAB file to the
device and execute the CAB file using File Explorer. Or, you can
write a program for the desktop PC that will find the ActiveSync
Application Manager and install the CAB file on the device,
which is obviously much easier for the user.

Here are some links that may help.

@li A setup builder that takes CABs and builds a setup program is at
    http://www.eskimo.com/~scottlu/win/index.html.
@li Sample installation files can be found in
    <tt>Windows CE Tools/wce420/POCKET PC 2003/Samples/Win32/AppInst</tt>.
@li An installer generator using wxPython can be found at
    http://ppcquicksoft.iespana.es/ppcquicksoft/myinstall.html.
@li Miscellaneous Windows CE resources can be found at
    http://www.orbworks.com/pcce/resources.html.
@li Installer creation instructions with a setup.exe for installing to PPC can be found at
    http://www.pocketpcdn.com/articles/creatingsetup.html.
@li Microsoft instructions are at
    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dnce30/html/appinstall30.asp?frame=true
@li Troubleshooting WinCE application installations:
    http://support.microsoft.com/default.aspx?scid=KB;en-us;q181007

You may also check out <tt>demos/life/setup/wince</tt> which contains
scripts to create a PocketPC installation for ARM-based
devices. In particular, @c build.bat builds the distribution and
copies it to a directory called @c Deliver.

@subsubsection page_port_wxmsw_wince_filedlg wxFileDialog in PocketPC

Allowing the user to access files on memory cards, or on arbitrary
parts of the filesystem, is a pain; the standard file dialog only
shows folders under My Documents or folders on memory cards
(not the system or card root directory, for example). This is
a known problem for PocketPC developers.

If you need a file dialog that allows access to all folders,
you can use wxGenericFileDialog instead. You will need to include
@c wx/generic/filedlgg.h.

@subsubsection page_port_wxmsw_wince_evc Embedded Visual C++ Issues

<b>Run-time type information</b>

If you wish to use runtime type information (RTTI) with eVC++ 4, you need to download
an extra library, @c ccrtrtti.lib, and link with it. At the time of
writing you can get it from here:

@verbatim
http://support.microsoft.com/kb/830482/en-us
@endverbatim

Otherwise you will get linker errors similar to this:

@verbatim
wxwince26d.lib(control.obj) : error LNK2001: unresolved external symbol "const type_info::`vftable'" (??_7type_info@@6B@)
@endverbatim

<b>Windows Mobile 5.0 emulator</b>

Note that there is no separate emulator configuration for Windows Mobile 5.0: the
emulator runs the ARM code directly.

<b>Visual Studio 2005 project files</b>

Unfortunately, Visual Studio 2005, required to build Windows Mobile 5.0 applications,
doesn't do a perfect job of converting the project files from eVC++ format.

When you have converted the wxWidgets workspace, edit the configuration properties
for each configuration and in the Librarian, add a relative path ..\\..\\lib to
each library path. For example:
<tt>..\\$(PlatformName)\\$(ConfigurationName)\\wx_mono.lib</tt>.

Then, for a sample you want to compile, edit the configuration properties
and make sure
<tt>..\\..\\lib\\$(PlatformName)\\$(ConfigurationName)</tt>
is in the Linker/General/Additional Library Directories property.
Also change the Linker/Input/Additional Dependencies property to something like
<tt>coredll.lib wx_mono.lib wx_wxjpeg.lib wx_wxpng.lib wx_wxzlib.lib wx_wxexpat.lib
    commctrl.lib winsock.lib wininet.lib</tt>
(since the library names in the wxWidgets workspace were changed by VS 2005).

Alternately, you could edit all the names to be identical to the original eVC++
names, but this will probably be more fiddly.

@subsubsection page_port_wxmsw_wince_issues Remaining issues

These are some of the remaining problems to be sorted out, and features
to be supported.

@li <b>Windows Mobile 5 issues.</b> It is not possible to get the HMENU for
the command bar on Mobile 5, so the menubar functions need to be rewritten
to get the individual menus without use of a menubar handle. Also the
new Mobile 5 convention of using only two menus (and no bitmap buttons) needs to be
considered.
@li <b>Sizer speed.</b> Particularly for dialogs containing notebooks,
layout seems slow. Some analysis is required.
@li <b>Notification boxes.</b> The balloon-like notification messages, and their
icons, should be implemented. This will be quite straightforward.
@li <b>SIP size.</b> We need to be able to get the area taken up by the SIP (input panel),
and the remaining area, by calling SHSipInfo. We also may need to be able to show and hide
the SIP programmatically, with SHSipPreference. See also the <em>Input Dialogs</em> topic in
the <em>Programming Windows CE</em> guide for more on this, and how to have dialogs
show the SIP automatically using the @c WC_SIPREF control.
@li <b>wxStaticBitmap.</b> The About box in the "Life!" demo shows a bitmap that is
the correct size on the emulator, but too small on a VGA Pocket Loox device.
@li <b>wxStaticLine.</b> Lines don't show up, and the documentation suggests that
missing styles are implemented with @c WM_PAINT.
@li <b>HTML control.</b> PocketPC has its own HTML control which can be used for showing
local pages or navigating the web. We should create a version of wxHtmlWindow that uses this
control, or have a separately-named control (wxHtmlCtrl), with a syntax as close as possible
to wxHtmlWindow.
@li <b>Tooltip control.</b> PocketPC uses special TTBUTTON and TTSTATIC controls for adding
tooltips, with the tooltip separated from the label with a double tilde. We need to support
this using SetToolTip.(Unfortunately it does not seem possible to dynamically remove the tooltip,
so an extra style may be required.)
@li <b>Focus.</b> In the wxPropertySheetDialog demo on Smartphone, it's not possible to navigate
between controls. The focus handling in wxWidgets needs investigation. See in particular
src/common/containr.cpp, and note that the default OnActivate handler in src/msw/toplevel.cpp
sets the focus to the first child of the dialog.
@li <b>OK button.</b> We should allow the OK button on a dialog to be optional, perhaps
by using @c wxCLOSE_BOX to indicate when the OK button should be displayed.
@li <b>Dynamic adaptation.</b> We should probably be using run-time tests more
than preprocessor tests, so that the same WinCE application can run on different
versions of the operating system.
@li <b>Modeless dialogs.</b> When a modeless dialog is hidden with the OK button, it doesn't restore the
frame's menubar. See for example the find dialog in the dialogs sample. However, the menubar is restored
if pressing Cancel (the window is closed). This reflects the fact that modeless dialogs are
not very useful on Windows CE; however, we could perhaps destroy/restore a modeless dialog's menubar
on deactivation and activation.
@li <b>Home screen plugins.</b> Figure out how to make home screen plugins for use with wxWidgets
applications (see http://www.codeproject.com/ce/CTodayWindow.asp for inspiration).
Although we can't use wxWidgets to create the plugin (too large), we could perhaps write
a generic plugin that takes registry information from a given application, with
options to display information in a particular way using icons and text from
a specified location.
@li <b>Further abstraction.</b> We should be able to abstract away more of the differences
between desktop and mobile applications, in particular for sizer layout.
@li <b>Dialog captions.</b> The blue, bold captions on dialogs - with optional help button -
should be catered for, either by hard-wiring the capability into all dialogs and panels,
or by providing a standard component and sizer.


@section page_port_nativedocs Documentation for the native toolkits

It's sometimes useful to interface directly with the underlying toolkit
used by wxWidgets to e.g. use toolkit-specific features.
In such case (or when you want to e.g. write a port-specific patch) it can be
necessary to use the underlying toolkit API directly:

- wxMSW port uses win32 API: see MSDN docs at http://msdn2.microsoft.com/en-us/library/ms649779.aspx
- wxGTK port uses GTK+ and other lower-level libraries; see 
  - GTK+ docs at http://library.gnome.org/devel/gtk/unstable/
  - GDK docs at http://library.gnome.org/devel/gdk/unstable/
  - GLib docs at http://library.gnome.org/devel/glib/unstable/
  - GObject docs at http://library.gnome.org/devel/gobject/unstable/
  - Pango docs at http://library.gnome.org/devel/pango/unstable/
- wxMac port uses the Carbon API: see Carbon docs at http://developer.apple.com/carbon
- wxCocoa port uses the Cocoa API: see Cocoa docs at http://developer.apple.com/cocoa

*/
