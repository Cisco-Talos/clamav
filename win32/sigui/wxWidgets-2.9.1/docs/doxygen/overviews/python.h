/////////////////////////////////////////////////////////////////////////////
// Name:        python.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_python wxPython Overview

This topic was written by Robin Dunn, author of the
<a href="http://www.python.org/">wxPython</a> wrapper.

@li @ref overview_python_what
@li @ref overview_python_why
@li @ref overview_python_othergui
@li @ref overview_python_using
@li @ref overview_python_classes
@li @ref overview_python_help


<hr>


@section overview_python_what What is wxPython?

wxPython is a blending of the wxWidgets GUI classes and the Python programming
language.

@subsection overview_python_what_py Python

So what is Python?  Go to http://www.python.org to learn more, but in a
nutshell Python is an interpreted, interactive, object-oriented programming
language. It is often compared to Tcl, Perl, Scheme or Java.

Python combines remarkable power with very clear syntax. It has modules,
classes, exceptions, very high level dynamic data types, and dynamic typing.
There are interfaces to many system calls and libraries, and new built-in
modules are easily written in C or C++. Python is also usable as an extension
language for applications that need a programmable interface.

Python is copyrighted but freely usable and distributable, even for commercial
use.

@subsection overview_python_what_wxpy wxPython

wxPython is a Python package that can be imported at runtime that includes a
collection of Python modules and an extension module (native code). It provides
a series of Python classes that mirror (or shadow) many of the wxWidgets GUI
classes. This extension module attempts to mirror the class hierarchy of
wxWidgets as closely as possible. This means that there is a wxFrame class in
wxPython that looks, smells, tastes and acts almost the same as the wxFrame
class in the C++ version.

wxPython is very versatile. It can be used to create standalone GUI
applications, or in situations where Python is embedded in a C++ application as
an internal scripting or macro language.

Currently wxPython is available for Win32 platforms and the GTK toolkit (wxGTK)
on most Unix/X-windows platforms. See the wxPython website http://wxPython.org/
for details about getting wxPython working for you.


@section overview_python_why Why Use wxPython?

So why would you want to use wxPython over just C++ and wxWidgets? Personally I
prefer using Python for everything. I only use C++ when I absolutely have to
eke more performance out of an algorithm, and even then I usually code it as an
extension module and leave the majority of the program in Python.

Another good thing to use wxPython for is quick prototyping of your wxWidgets
apps. With C++ you have to continuously go though the edit-compile-link-run
cycle, which can be quite time consuming. With Python it is only an edit-run
cycle. You can easily build an application in a few hours with Python that
would normally take a few days or longer with C++. Converting a wxPython app to
a C++/wxWidgets app should be a straight forward task.


@section overview_python_othergui Other Python GUIs

There are other GUI solutions out there for Python.

@subsection overview_python_othergui_tkinter Tkinter

Tkinter is the de facto standard GUI for Python. It is available on nearly
every platform that Python and Tcl/TK are. Why Tcl/Tk? Well because Tkinter is
just a wrapper around Tcl's GUI toolkit, Tk. This has it's upsides and it's
downsides...

The upside is that Tk is a pretty versatile toolkit. It can be made to do a lot
of things in a lot of different environments. It is fairly easy to create new
widgets and use them interchangeably in your programs.

The downside is Tcl. When using Tkinter you actually have two separate language
interpreters running, the Python interpreter and the Tcl interpreter for the
GUI. Since the guts of Tcl is mostly about string processing, it is fairly slow
as well. (Not too bad on a fast Pentium II, but you really notice the
difference on slower machines.)

It wasn't until the latest version of Tcl/Tk that native Look and Feel was
possible on non-Motif platforms. This is because Tk usually implements its own
widgets (controls) even when there are native controls available.

Tkinter is a pretty low-level toolkit. You have to do a lot of work (verbose
program code) to do things that would be much simpler with a higher level of
abstraction.

@subsection overview_python_othergui_pythonwin PythonWin

PythonWin is an add-on package for Python for the Win32 platform. It includes
wrappers for MFC as well as much of the Win32 API. Because of its foundation,
it is very familiar for programmers who have experience with MFC and the Win32
API. It is obviously not compatible with other platforms and toolkits.
PythonWin is organized as separate packages and modules so you can use the
pieces you need without having to use the GUI portions.

@subsection overview_python_othergui_others Others

There are quite a few other GUI modules available for Python, some in active
use, some that haven't been updated for ages. Most are simple wrappers around
some C or C++ toolkit or another, and most are not cross-platform compatible.
See <a href="http://pypi.python.org/pypi?:action=browse&show=all&c=433">this link</a>
for a listing of a few of them.


@section overview_python_using Using wxPython

I'm not going to try and teach the Python language here. You can do that at the
<a href="http://www.python.org/doc/tut/tut.html">Python Tutorial</a>. I'm also
going to assume that you know a bit about wxWidgets already, enough to notice
the similarities in the classes used.

Take a look at the following wxPython program. You can find a similar program
in the @c wxPython/demo directory, named @c DialogUnits.py. If your Python and
wxPython are properly installed, you should be able to run it by issuing this
command:

@code
python DialogUnits.py
@endcode

@code
01: ## import all of the wxPython GUI package
02: from wxPython.wx import *
03:
04: ## Create a new frame class, derived from the wxPython Frame.
05: class MyFrame(wxFrame):
06:
07:     def __init__(self, parent, id, title):
08:         # First, call the base class' __init__ method to create the frame
09:         wxFrame.__init__(self, parent, id, title,
10:                          wxPoint(100, 100), wxSize(160, 100))
11:
12:         # Associate some events with methods of this class
13:         EVT_SIZE(self, self.OnSize)
14:         EVT_MOVE(self, self.OnMove)
15:
16:         # Add a panel and some controls to display the size and position
17:         panel = wxPanel(self, -1)
18:         wxStaticText(panel, -1, "Size:",
19:                      wxDLG_PNT(panel, wxPoint(4, 4)),  wxDefaultSize)
20:         wxStaticText(panel, -1, "Pos:",
21:                      wxDLG_PNT(panel, wxPoint(4, 14)), wxDefaultSize)
22:         self.sizeCtrl = wxTextCtrl(panel, -1, "",
23:                                    wxDLG_PNT(panel, wxPoint(24, 4)),
24:                                    wxDLG_SZE(panel, wxSize(36, -1)),
25:                                    wxTE_READONLY)
26:         self.posCtrl = wxTextCtrl(panel, -1, "",
27:                                   wxDLG_PNT(panel, wxPoint(24, 14)),
28:                                   wxDLG_SZE(panel, wxSize(36, -1)),
29:                                   wxTE_READONLY)
30:
31:
32:     # This method is called automatically when the CLOSE event is
33:     # sent to this window
34:     def OnCloseWindow(self, event):
35:         # tell the window to kill itself
36:         self.Destroy()
37:
38:     # This method is called by the system when the window is resized,
39:     # because of the association above.
40:     def OnSize(self, event):
41:         size = event.GetSize()
42:         self.sizeCtrl.SetValue("%s, %s" % (size.width, size.height))
43:
44:         # tell the event system to continue looking for an event handler,
45:         # so the default handler will get called.
46:         event.Skip()
47:
48:     # This method is called by the system when the window is moved,
49:     # because of the association above.
50:     def OnMove(self, event):
51:         pos = event.GetPosition()
52:         self.posCtrl.SetValue("%s, %s" % (pos.x, pos.y))
53:
54:
55: # Every wxWidgets application must have a class derived from wxApp
56: class MyApp(wxApp):
57:
58:     # wxWidgets calls this method to initialize the application
59:     def OnInit(self):
60:
61:         # Create an instance of our customized Frame class
62:         frame = MyFrame(NULL, -1, "This is a test")
63:         frame.Show(true)
64:
65:         # Tell wxWidgets that this is our main window
66:         self.SetTopWindow(frame)
67:
68:         # Return a success flag
69:         return true
70:
71:
72: app = MyApp(0)     # Create an instance of the application class
73: app.MainLoop()     # Tell it to start processing events
74:
@endcode

@subsection overview_python_using_notice Things to Notice

At line 2 the wxPython classes, constants, and etc. are imported into the
current module's namespace. If you prefer to reduce namespace pollution you can
use @c "from wxPython import wx" and then access all the wxPython identifiers
through the wx module, for example, @c "wx.wxFrame".

At line 13 the frame's sizing and moving events are connected to methods of the
class. These helper functions are intended to be like the event table macros
that wxWidgets employs. But since static event tables are impossible with
wxPython, we use helpers that are named the same to dynamically build the
table. The only real difference is that the first argument to the event helpers
is always the window that the event table entry should be added to.

Notice the use of @c wxDLG_PNT and @c wxDLG_SZE in lines 19-29 to convert from
dialog units to pixels. These helpers are unique to wxPython since Python can't
do method overloading like C++.

There is an @c OnCloseWindow method at line 34 but no call to @c EVT_CLOSE to
attach the event to the method. Does it really get called?  The answer is, yes
it does. This is because many of the standard events are attached to windows
that have the associated standard method names. I have tried to follow the lead
of the C++ classes in this area to determine what is standard but since that
changes from time to time I can make no guarantees, nor will it be fully
documented. When in doubt, use an @c EVT_*** function.

At lines 17 to 21 notice that there are no saved references to the panel or the
static text items that are created. Those of you who know Python might be
wondering what happens when Python deletes these objects when they go out of
scope. Do they disappear from the GUI?  They don't. Remember that in wxPython
the Python objects are just shadows of the corresponding C++ objects. Once the
C++ windows and controls are attached to their parents, the parents manage them
and delete them when necessary. For this reason, most wxPython objects do not
need to have a @c __del__ method that explicitly causes the C++ object to be
deleted. If you ever have the need to forcibly delete a window, use the
Destroy() method as shown on line 36.

Just like wxWidgets in C++, wxPython apps need to create a class derived from
@c wxApp (line 56) that implements a method named @c OnInit, (line 59.) This
method should create the application's main window (line 62) and use
wxApp.SetTopWindow() (line 66) to inform wxWidgets about it.

And finally, at line 72 an instance of the application class is created. At
this point wxPython finishes initializing itself, and calls the @c OnInit
method to get things started. (The zero parameter here is a flag for
functionality that isn't quite implemented yet. Just ignore it for now.) The
call to @c MainLoop at line 73 starts the event loop which continues until the
application terminates or all the top level windows are closed.


@section overview_python_classes Classes Implemented in wxPython

The following classes are supported in wxPython. Most provide nearly full
implementations of the public interfaces specified in the C++ documentation,
others are less so. They will all be brought as close as possible to the C++
spec over time.

@li wxAcceleratorEntry
@li wxAcceleratorTable
@li wxActivateEvent
@li wxBitmap
@li wxBitmapButton
@li wxBitmapDataObject
@li wxBMPHandler
@li wxBoxSizer
@li wxBrush
@li wxBusyInfo
@li wxBusyCursor
@li wxButton
@li wxCalculateLayoutEvent
@li wxCalendarCtrl
@li wxCaret
@li wxCheckBox
@li wxCheckListBox
@li wxChoice
@li wxClientDC
@li wxClipboard
@li wxCloseEvent
@li wxColourData
@li wxColourDialog
@li wxColour
@li wxComboBox
@li wxCommandEvent
@li wxConfigBase
@li wxControl
@li wxCursor
@li wxCustomDataObject
@li wxDataFormat
@li wxDataObject
@li wxDataObjectComposite
@li wxDataObjectSimple
@li wxDateTime
@li wxDateSpan
@li wxDC
@li wxDialog
@li wxDirDialog
@li wxDragImage
@li wxDropFilesEvent
@li wxDropSource
@li wxDropTarget
@li wxEraseEvent
@li wxEvent
@li wxEvtHandler
@li wxFileConfig
@li wxFileDataObject
@li wxFileDialog
@li wxFileDropTarget
@li wxFileSystem
@li wxFileSystemHandler
@li wxFocusEvent
@li wxFontData
@li wxFontDialog
@li wxFont
@li wxFrame
@li wxFSFile
@li wxGauge
@li wxGIFHandler
@li wxGLCanvas
@li wxHtmlCell
@li wxHtmlContainerCell
@li wxHtmlDCRenderer
@li wxHtmlEasyPrinting
@li wxHtmlParser
@li wxHtmlTagHandler
@li wxHtmlTag
@li wxHtmlWinParser
@li wxHtmlPrintout
@li wxHtmlWinTagHandler
@li wxHtmlWindow
@li wxIconizeEvent
@li wxIcon
@li wxIdleEvent
@li wxImage
@li wxImageHandler
@li wxImageList
@li wxIndividualLayoutConstraint
@li wxInitDialogEvent
@li wxInputStream
@li @ref wxFileSystem "wxInternetFSHandler"
@li wxJoystickEvent
@li wxJPEGHandler
@li wxKeyEvent
@li wxLayoutAlgorithm
@li wxLayoutConstraints
@li wxListBox
@li wxListCtrl
@li wxListEvent
@li wxListItem
@li wxMask
@li wxMaximizeEvent
@li wxMDIChildFrame
@li wxMDIClientWindow
@li wxMDIParentFrame
@li wxMemoryDC
@li wxMemoryFSHandler
@li wxMenuBar
@li wxMenuEvent
@li wxMenuItem
@li wxMenu
@li wxMessageDialog
@li wxMetafileDC
@li wxMiniFrame
@li wxMouseEvent
@li wxMoveEvent
@li wxNotebookEvent
@li wxNotebook
@li wxPageSetupDialogData
@li wxPageSetupDialog
@li wxPaintDC
@li wxPaintEvent
@li wxPalette
@li wxPanel
@li wxPen
@li wxPNGHandler
@li wxPoint
@li wxPostScriptDC
@li wxPreviewFrame
@li wxPrintData
@li wxPrintDialogData
@li wxPrintDialog
@li wxPrinter
@li wxPrintPreview
@li wxPrinterDC
@li wxPrintout
@li wxProcess
@li wxQueryLayoutInfoEvent
@li wxRadioBox
@li wxRadioButton
@li wxRealPoint
@li wxRect
@li wxRegionIterator
@li wxRegion
@li wxSashEvent
@li wxSashLayoutWindow
@li wxSashWindow
@li wxScreenDC
@li wxScrollBar
@li wxScrollEvent
@li ::wxScrolledWindow
@li wxScrollWinEvent
@li wxShowEvent
@li wxSingleChoiceDialog
@li wxSizeEvent
@li wxSize
@li wxSizer
@li wxSizerItem
@li wxSlider
@li wxSpinButton
@li wxSpinEvent
@li wxSplitterWindow
@li wxStaticBitmap
@li wxStaticBox
@li wxStaticBoxSizer
@li wxStaticLine
@li wxStaticText
@li wxStatusBar
@li wxSysColourChangedEvent
@li wxTaskBarIcon
@li wxTextCtrl
@li wxTextDataObject
@li wxTextDropTarget
@li wxTextEntryDialog
@li wxTimer
@li wxTimerEvent
@li wxTimeSpan
@li wxTipProvider
@li wxToolBarTool
@li wxToolBar
@li wxToolTip
@li wxTreeCtrl
@li wxTreeEvent
@li wxTreeItemData
@li wxTreeItemId
@li wxUpdateUIEvent
@li wxValidator
@li wxWindowDC
@li wxWindow
@li @ref wxFileSystem "wxZipFSHandler"


@section overview_python_help Where to Go for Help

Since wxPython is a blending of multiple technologies, help comes from multiple
sources. See http://wxpython.org/ for details on various sources of help, but
probably the best source is the wxPython-users mail list. You can view the
archive or subscribe by going to http://wxpython.org/maillist.php

Or you can send mail directly to the list using this address:
wxpython-users@lists.wxwidgets.org

*/

