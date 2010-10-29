/////////////////////////////////////////////////////////////////////////////
// Name:        cat_classes.h
// Purpose:     Classes-by-category page of the Doxygen manual
// Author:      wxWidgets team
// RCS-ID:      $Id: cat_classes.h 52468 2008-03-13 16:30:38Z FM $
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page page_class_cat Summarized Class List by Category

This page contains a summarized listing of classes, please see the
@ref group_class page for a full listing.

@beginInvisibleTable
<tr><td>
@li @ref page_class_cat_basicwnd
@li @ref page_class_cat_winlayout
@li @ref page_class_cat_managedwnd
@li @ref page_class_cat_menus
@li @ref page_class_cat_ctrl
@li @ref page_class_cat_validator
@li @ref page_class_cat_pickers
@li @ref page_class_cat_aui
@li @ref page_class_cat_cmndlg
@li @ref page_class_cat_html
@li @ref page_class_cat_miscwnd
</td><td>
@li @ref page_class_cat_dc
@li @ref page_class_cat_gdi
@li @ref page_class_cat_gc
@li @ref page_class_cat_image
@li @ref page_class_cat_events
@li @ref page_class_cat_appmanagement
@li @ref page_class_cat_printing
@li @ref page_class_cat_dvf
@li @ref page_class_cat_dnd
@li @ref page_class_cat_vfs
@li @ref page_class_cat_threading
</td><td>
@li @ref page_class_cat_rtti
@li @ref page_class_cat_debugging
@li @ref page_class_cat_logging
@li @ref page_class_cat_data
@li @ref page_class_cat_conv
@li @ref page_class_cat_containers
@li @ref page_class_cat_smartpointers
@li @ref page_class_cat_file
@li @ref page_class_cat_streams
@li @ref page_class_cat_xml
@li @ref page_class_cat_xrc
</td><td>
@li @ref page_class_cat_net
@li @ref page_class_cat_archive
@li @ref page_class_cat_ipc
@li @ref page_class_cat_help
@li @ref page_class_cat_media
@li @ref page_class_cat_gl
@li @ref page_class_cat_misc
</td></tr>
@endTable


<hr>


@section page_class_cat_basicwnd Basic Windows

The following are the most important window classes

@li wxWindow: base class for all windows and controls
@li wxControl: base class (mostly) for native controls/widgets
@li wxPanel: window which can smartly manage child windows
@li ::wxScrolledWindow: Window with automatically managed scrollbars (see
    wxScrolled)
@li wxTopLevelWindow: Any top level window, dialog or frame



@section page_class_cat_winlayout Window Layout

There are two different systems for laying out windows (and dialogs in
particular). One is based upon so-called sizers and it requires less typing,
thinking and calculating and will in almost all cases produce dialogs looking
equally well on all platforms, the other is based on so-called constraints and
is deprecated, though still available.

Related Overviews: @ref overview_sizer

These are the classes relevant to sizer-based layout:

@li wxSizer: Abstract base class
@li wxBoxSizer: A sizer for laying out windows in a row or column
@li wxGridSizer: A sizer for laying out windows in a grid with all fields
    having the same size
@li wxFlexGridSizer: A sizer for laying out windows in a flexible grid
@li wxGridBagSizer: Another grid sizer that lets you specify the cell an item
    is in, and items can span rows and/or columns.
@li wxStaticBoxSizer: Same as wxBoxSizer, but with a surrounding static box
@li wxWrapSizer: A sizer which wraps its child controls as size permits

Other layout classes:

@li wxLayoutAlgorithm: An alternative window layout facility



@section page_class_cat_managedwnd Managed Windows

There are several types of window that are directly controlled by the window
manager (such as MS Windows, or the Motif Window Manager). Frames and dialogs
are similar in wxWidgets, but only dialogs may be modal.

Related Overviews: @ref overview_cmndlg

@li wxDialog: Dialog box
@li wxFrame: Normal frame
@li wxMDIChildFrame: MDI child frame
@li wxMDIParentFrame: MDI parent frame
@li wxMiniFrame: A frame with a small title bar
@li wxPopupWindow: A toplevel window without decorations, e.g. for a combobox pop-up
@li wxPropertySheetDialog: Property sheet dialog
@li wxSplashScreen: Splash screen class
@li wxTipWindow: Shows text in a small window
@li wxWizard: A wizard dialog



@section page_class_cat_menus Menus

@li wxMenu: Displays a series of menu items for selection
@li wxMenuBar: Contains a series of menus for use with a frame
@li wxMenuItem: Represents a single menu item



@section page_class_cat_ctrl Controls

Typically, these are small windows which provide interaction with the user.
Controls that are not static can have wxValidator associated with them.

@li wxAnimationCtrl: A control to display an animation
@li wxControl: The base class for controls
@li wxBitmapButton: Push button control, displaying a bitmap
@li wxBitmapComboBox: A combobox with bitmaps next to text items
@li wxBitmapToggleButton: A toggle button with bitmaps.
@li wxButton: Push button control, displaying text
@li wxCalendarCtrl: Control showing an entire calendar month
@li wxCheckBox: Checkbox control
@li wxCheckListBox: A listbox with a checkbox to the left of each item
@li wxChoice: Choice control (a combobox without the editable area)
@li wxCollapsiblePane: A panel which can be shown/hidden by the user
@li wxComboBox: A choice with an editable area
@li wxComboCtrl: A combobox with application defined popup
@li wxDataViewCtrl: A control to display tabular or tree like data
@li wxDataViewTreeCtrl: A specialized wxDataViewCtrl with a wxTreeCtrl-like API
@li wxDataViewListCtrl: A specialized wxDataViewCtrl for displaying and editing simple tables.
@li wxEditableListBox: A listbox with editable items.
@li wxFileCtrl: A control for selecting a file. Useful for custom file dialogs.
@li wxGauge: A control to represent a varying quantity, such as time remaining
@li wxGenericDirCtrl: A control for displaying a directory tree
@li wxGrid: A control to display spread-sheet like data in tabular form
@li wxHeaderCtrl: a small control to display the top header of tabular data
@li wxHtmlListBox: An abstract class for creating listboxes showing HTML
    content
@li wxHyperlinkCtrl: A static text which opens an URL when clicked
@li wxListBox: A list of strings for single or multiple selection
@li wxListCtrl: A control for displaying lists of strings and/or icons, plus a
    multicolumn report view
@li wxListView: A simpler interface (fa&ccedil;ade) for wxListCtrl in report
    mode
@li wxNotebook: A notebook class
@li wxOwnerDrawnComboBox: A combobox with owner-drawn list items
@li wxPropertyGrid: A complex control to display hierachical, editable information
@li wxRadioBox: A group of radio buttons
@li wxRadioButton: A round button to be used with others in a mutually
    exclusive way
@li wxRearrangeCtrl: A control allowing the user to rearrange a list of items.
@li wxRichTextCtrl: Generic rich text editing control
@li wxSimpleHtmlListBox: A listbox showing HTML content
@li wxStaticBox: A static, or group box for visually grouping related controls
@li wxScrollBar: Scrollbar control
@li wxSearchCtrl: A text input control used to initiate a search
@li wxSpinButton: A spin or `up-down' control
@li wxSpinCtrl: A spin control - i.e. spin button and text control displaying
    an integer
@li wxSpinCtrlDouble: A spin control - i.e. spin button and text control displaying
    a real number
@li wxStaticText: One or more lines of non-editable text
@li wxTextCtrl: Single or multiline text editing control
@li wxToggleButton: A button which stays pressed when clicked by user.
@li wxTreeCtrl: Tree (hierarchy) control
@li wxStaticBitmap: A control to display a bitmap
@li wxStyledTextCtrl: A wxWidgets implementation of the Scintilla source code
    editing component for plain text editing.
@li wxSlider: A slider that can be dragged by the user
@li wxVListBox: A listbox supporting variable height rows



@section page_class_cat_validator Validators

These are the window validators, used for filtering and validating user input.

Related Overviews: @ref overview_validator

@li wxValidator: Base validator class
@li wxTextValidator: Text control validator class
@li wxGenericValidator: Generic control validator class



@section page_class_cat_pickers Picker Controls

A picker control is a control whose appearance and behaviour is highly
platform-dependent.

@li wxColourPickerCtrl: A control which allows the user to choose a colour
@li wxDirPickerCtrl: A control which allows the user to choose a directory
@li wxFilePickerCtrl: A control which allows the user to choose a file
@li wxFontPickerCtrl: A control which allows the user to choose a font
@li wxDatePickerCtrl: Small date picker control



@section page_class_cat_miscwnd Miscellaneous Windows

The following are a variety of classes that are derived from wxWindow.

@li wxCollapsiblePane: A panel which can be shown/hidden by the user
@li wxPanel: A window whose colour changes according to current user settings
@li ::wxScrolledWindow: Window with automatically managed scrollbars (see
    wxScrolled)
@li wxHScrolledWindow: As ::wxScrolledWindow but supports columns of variable
    widths
@li wxVScrolledWindow: As ::wxScrolledWindow but supports rows of variable
    heights
@li wxHVScrolledWindow: As ::wxScrolledWindow but supports scroll units of
    variable sizes.
@li wxGrid: A grid (table) window
@li wxInfoBar: An information bar usually shown on top of the main window.
@li wxSplitterWindow: Window which can be split vertically or horizontally
@li wxStatusBar: Implements the status bar on a frame
@li wxToolBar: Toolbar class
@li wxNotebook: Notebook class
@li wxListbook: Similar to notebook but using list control
@li wxChoicebook: Similar to notebook but using choice control
@li wxTreebook: Similar to notebook but using tree control
@li wxSashWindow: Window with four optional sashes that can be dragged
@li wxSashLayoutWindow: Window that can be involved in an IDE-like layout
    arrangement
@li wxWizardPage: A base class for the page in wizard dialog.
@li wxWizardPageSimple: A page in wizard dialog.



@section page_class_cat_aui Window Docking (wxAUI)

wxAUI is a set classes for writing a customizable application interface
with built-in docking, floatable panes and a flexible MDI-like interface.

Related Overviews: @ref overview_aui

@li wxAuiManager: The central class for managing the interface
@li wxAuiNotebook: A replacement notebook class with extra features
@li wxAuiPaneInfo: Describes a single pane
@li wxAuiDockArt: Art and metrics provider for customizing the docking user
    interface
@li wxAuiTabArt: Art and metrics provider for customizing the notebook user
    interface



@section page_class_cat_cmndlg Common Dialogs

Common dialogs are ready-made dialog classes which are frequently used in an
application.

Related Overviews: @ref overview_cmndlg

@li wxDialog: Base class for common dialogs
@li wxColourDialog: Colour chooser dialog
@li wxDirDialog: Directory selector dialog
@li wxFileDialog: File selector dialog
@li wxFindReplaceDialog: Text search/replace dialog
@li wxFontDialog: Font chooser dialog
@li wxMessageDialog: Simple message box dialog
@li wxMultiChoiceDialog: Dialog to get one or more selections from a list
@li wxPageSetupDialog: Standard page setup dialog
@li wxPasswordEntryDialog: Dialog to get a password from the user
@li wxPrintDialog: Standard print dialog
@li wxProgressDialog: Progress indication dialog
@li wxRearrangeDialog: Dialog allowing the user to rearrange a list of items.
@li wxRichTextFormattingDialog: A dialog for formatting the content of a
    wxRichTextCtrl
@li wxSingleChoiceDialog: Dialog to get a single selection from a list and
    return the string
@li wxSymbolPickerDialog: Symbol selector dialog
@li wxTextEntryDialog: Dialog to get a single line of text from the user
@li wxWizard: A wizard dialog.



@section page_class_cat_html HTML

wxWidgets provides a set of classes to display text in HTML format. These
classes include a help system based on the HTML widget.

@li wxHtmlHelpController: HTML help controller class
@li wxHtmlWindow: HTML window class
@li wxHtmlEasyPrinting: Simple class for printing HTML
@li wxHtmlPrintout: Generic HTML wxPrintout class
@li wxHtmlParser: Generic HTML parser class
@li wxHtmlTagHandler: HTML tag handler, pluginable into wxHtmlParser
@li wxHtmlWinParser: HTML parser class for wxHtmlWindow
@li wxHtmlWinTagHandler: HTML tag handler, pluginable into wxHtmlWinParser


@section page_class_cat_dc Device Contexts

Device contexts are surfaces that may be drawn on, and provide an abstraction
that allows parameterisation of your drawing code by passing different device
contexts.

Related Overviews: @ref overview_dc

@li wxAutoBufferedPaintDC: A helper device context for double buffered drawing
    inside @b OnPaint().
@li wxBufferedDC: A helper device context for double buffered drawing.
@li wxBufferedPaintDC: A helper device context for double buffered drawing
    inside @b OnPaint().
@li wxClientDC: A device context to access the client area outside
    @b OnPaint() events
@li wxPaintDC: A device context to access the client area inside @b OnPaint()
    events
@li wxWindowDC: A device context to access the non-client area
@li wxScreenDC: A device context to access the entire screen
@li wxDC: The device context base class
@li wxMemoryDC: A device context for drawing into bitmaps
@li wxMetafileDC: A device context for drawing into metafiles
@li wxMirrorDC: A proxy device context allowing for simple mirroring.
@li wxPostScriptDC: A device context for drawing into PostScript files
@li wxPrinterDC: A device context for drawing to printers



@section page_class_cat_gc Graphics Context classes

These classes are related to drawing using a new vector based drawing API and
are based on the modern drawing backend GDI+, CoreGraphics and Cairo.

@li wxGraphicsRenderer: Represents a drawing engine.
@li wxGraphicsContext: Represents a graphics context currently being drawn on.
@li wxGraphicsBrush: Brush for drawing into a wxGraphicsContext
@li wxGraphicsPen: Pen for drawing into a wxGraphicsContext
@li wxGraphicsFont: Font for drawing text on a wxGraphicsContext
@li wxGraphicsMatrix: Represents an affine matrix for drawing transformation
@li wxGraphicsPath: Represents a path for drawing



@section page_class_cat_gdi Graphics Device Interface

These classes are related to drawing on device contexts and windows.

@li wxColour: Represents the red, blue and green elements of a colour
@li wxDCClipper: Wraps the operations of setting and destroying the clipping
    region
@li wxBrush: Used for filling areas on a device context
@li wxBrushList: The list of previously-created brushes
@li wxFont: Represents fonts
@li wxFontList: The list of previously-created fonts
@li wxPen: Used for drawing lines on a device context
@li wxPenList: The list of previously-created pens
@li wxPalette: Represents a table of indices into RGB values
@li wxRegion: Represents a simple or complex region on a window or device
    context
@li wxRendererNative: Abstracts high-level drawing primitives



@section page_class_cat_image Image and bitmap classes

These classes represent images and bitmap in various formats and ways
to access and create them.

Related Overviews: @ref overview_bitmap

@li wxAnimation: Represents an animation
@li wxBitmap: Represents a platform dependent bitmap
@li wxBitmapHandler: Class for loading a saving a wxBitmap in a specific format
@li wxCursor: A small, transparent bitmap representing the cursor
@li wxIcon: A small, transparent bitmap for assigning to frames and drawing on
    device contexts
@li wxImage: A platform-independent image class
@li wxImageHandler: Class for loading a saving a wxImage in a specific format
@li wxImageList: A list of images, used with some controls
@li wxMask: Represents a mask to be used with a bitmap for transparent drawing
@li wxMemoryDC: A device context for drawing into bitmaps
@li wxPixelData: Class template for direct access to wxBitmap's and wxImage's internal data



@section page_class_cat_events Events

An event object contains information about a specific event. Event handlers
(usually member functions) have a single, event argument.

Related Overviews: @ref overview_events

@li wxActivateEvent: A window or application activation event
@li wxCalendarEvent: Used with wxCalendarCtrl
@li wxCalculateLayoutEvent: Used to calculate window layout
@li wxChildFocusEvent: A child window focus event
@li wxClipboardTextEvent: A clipboard copy/cut/paste treebook event event
@li wxCloseEvent: A close window or end session event
@li wxCommandEvent: An event from a variety of standard controls
@li wxContextMenuEvent: An event generated when the user issues a context menu
    command
@li wxDateEvent: Used with wxDatePickerCtrl
@li wxDialUpEvent: Event send by wxDialUpManager
@li wxDropFilesEvent: A drop files event
@li wxEraseEvent: An erase background event
@li wxEvent: The event base class
@li wxFindDialogEvent: Event sent by wxFindReplaceDialog
@li wxFocusEvent: A window focus event
@li wxKeyEvent: A keypress event
@li wxIconizeEvent: An iconize/restore event
@li wxIdleEvent: An idle event
@li wxInitDialogEvent: A dialog initialisation event
@li wxJoystickEvent: A joystick event
@li wxKeyboardState: State of the keyboard modifiers.
@li wxListEvent: A list control event
@li wxMaximizeEvent: A maximize event
@li wxMenuEvent: A menu event
@li wxMouseCaptureChangedEvent: A mouse capture changed event
@li wxMouseCaptureLostEvent: A mouse capture lost event
@li wxMouseEvent: A mouse event
@li wxMouseState: State of the mouse
@li wxMoveEvent: A move event
@li wxNavigationKeyEvent: An event set by navigation keys such as tab
@li wxNotebookEvent: A notebook control event
@li wxNotifyEvent: A notification event, which can be vetoed
@li wxPaintEvent: A paint event
@li wxProcessEvent: A process ending event
@li wxQueryLayoutInfoEvent: Used to query layout information
@li wxRichTextEvent: A rich text editing event
@li wxScrollEvent: A scroll event from sliders, stand-alone scrollbars and spin
    buttons
@li wxScrollWinEvent: A scroll event from scrolled windows
@li wxSizeEvent: A size event
@li wxSocketEvent: A socket event
@li wxSpinEvent: An event from wxSpinButton
@li wxSplitterEvent: An event from wxSplitterWindow
@li wxSysColourChangedEvent: A system colour change event
@li wxTimerEvent: A timer expiration event
@li wxTreebookEvent: A treebook control event
@li wxTreeEvent: A tree control event
@li wxUpdateUIEvent: A user interface update event
@li wxWindowCreateEvent: A window creation event
@li wxWindowDestroyEvent: A window destruction event
@li wxWizardEvent: A wizard event



@section page_class_cat_appmanagement Application and Process Management

@li wxApp: Application class
@li wxCmdLineParser: Command line parser class
@li wxDynamicLibrary: Class to work with shared libraries.
@li wxProcess: Process class



@section page_class_cat_printing Printing Framework

A printing and previewing framework is implemented to make it relatively
straightforward to provide document printing facilities.

Related Overviews: @ref overview_printing

@li wxPreviewFrame: Frame for displaying a print preview
@li wxPreviewCanvas: Canvas for displaying a print preview
@li wxPreviewControlBar: Standard control bar for a print preview
@li wxPrintDialog: Standard print dialog
@li wxPageSetupDialog: Standard page setup dialog
@li wxPrinter: Class representing the printer
@li wxPrinterDC: Printer device context
@li wxPrintout: Class representing a particular printout
@li wxPrintPreview: Class representing a print preview
@li wxPrintData: Represents information about the document being printed
@li wxPrintDialogData: Represents information about the print dialog
@li wxPageSetupDialogData: Represents information about the page setup dialog



@section page_class_cat_dvf Document/View Framework

wxWidgets supports a document/view framework which provides housekeeping for a
document-centric application.

Related Overviews: @ref overview_docview

@li wxCommand: Base class for undo/redo actions
@li wxCommandProcessor: Maintains the undo/redo stack
@li wxDocument: Represents a document
@li wxView: Represents a view
@li wxDocTemplate: Manages the relationship between a document class and a
    view class
@li wxDocManager: Manages the documents and views in an application
@li wxDocChildFrame: A child frame for showing a document view
@li wxDocParentFrame: A parent frame to contain views
@li wxDocMDIChildFrame: An MDI child frame for showing a document view
@li wxDocMDIParentFrame: An MDI parent frame to contain views
@li wxFileHistory: Maintains a list of the most recently visited files



@section page_class_cat_dnd Clipboard and Drag & Drop

Related Overviews: @ref overview_dnd

@li wxDataObject: Data object class
@li wxDataFormat: Represents a data format
@li wxTextDataObject: Text data object class
@li wxFileDataObject: File data object class
@li wxBitmapDataObject: Bitmap data object class
@li wxURLDataObject: URL data object class
@li wxCustomDataObject: Custom data object class
@li wxClipboard: Clipboard class
@li wxDropTarget: Drop target class
@li wxFileDropTarget: File drop target class
@li wxTextDropTarget: Text drop target class
@li wxDropSource: Drop source class



@section page_class_cat_vfs Virtual File System

wxWidgets provides a set of classes that implement an extensible virtual file
system, used internally by the HTML classes.

@li wxFSFile: Represents a file in the virtual file system
@li wxFileSystem: Main interface for the virtual file system
@li wxFileSystemHandler: Class used to announce file system type



@section page_class_cat_threading Threading

wxWidgets provides a set of classes to make use of the native thread
capabilities of the various platforms.

Related Overviews: @ref overview_thread

@li wxThread: Thread class
@li wxThreadHelper: Manages background threads easily
@li wxMutex: Mutex class
@li wxMutexLocker: Mutex locker utility class
@li wxCriticalSection: Critical section class
@li wxCriticalSectionLocker: Critical section locker utility class
@li wxCondition: Condition class
@li wxSemaphore: Semaphore class



@section page_class_cat_rtti Runtime Type Information (RTTI)

wxWidgets supports runtime manipulation of class information, and dynamic
creation of objects given class names.

Related Overviews: @ref overview_rtti

@see @ref group_funcmacro_rtti "RTTI Functions and Macros"

@li wxClassInfo: Holds runtime class information
@li wxObject: Root class for classes with runtime information



@section page_class_cat_debugging Debugging

wxWidgets supports some aspects of debugging an application through classes,
functions and macros.

Related Overviews: @ref overview_debugging

@see @ref group_funcmacro_debug "Debugging Functions and Macros"

@li wxDebugContext: Provides memory-checking facilities
@li wxDebugReport: Base class for creating debug reports in case of a program
    crash.
@li wxDebugReportCompress: Class for creating compressed debug reports.
@li wxDebugReportUpload: Class for uploading compressed debug reports via HTTP.
@li wxDebugReportPreview: Abstract base class for previewing the contents of a
    debug report.
@li wxDebugReportPreviewStd: Standard implementation of wxDebugReportPreview.



@section page_class_cat_logging Logging

wxWidgets provides several classes and functions for message logging.

Related overview: @ref overview_log

@see @ref group_funcmacro_log "Logging Functions and Macros"

@li wxLog: The base log class
@li wxLogStderr: Log messages to a C STDIO stream
@li wxLogStream: Log messages to a C++ iostream
@li wxLogTextCtrl: Log messages to a wxTextCtrl
@li wxLogWindow: Log messages to a log frame
@li wxLogGui: Default log target for GUI programs
@li wxLogNull: Temporarily suppress message logging
@li wxLogChain: Allows to chain two log targets
@li wxLogInterposer: Allows to filter the log messages
@li wxLogInterposerTemp: Allows to filter the log messages
@li wxStreamToTextRedirector: Allows to redirect output sent to @c cout to a wxTextCtrl



@section page_class_cat_data Data Structures

These are the data structure classes supported by wxWidgets.

@li wxAny: A class for storing arbitrary types that may change at run-time
@li wxCmdLineParser: Command line parser class
@li wxDateSpan: A logical time interval.
@li wxDateTime: A class for date/time manipulations
@li wxLongLong: A portable 64 bit integer type
@li wxObject: The root class for most wxWidgets classes
@li wxPathList: A class to help search multiple paths
@li wxPoint: Representation of a point
@li wxRect: A class representing a rectangle
@li wxRegEx: Regular expression support
@li wxRegion: A class representing a region
@li wxString: A string class
@li wxStringTokenizer: A class for interpreting a string as a list of tokens or
    words
@li wxRealPoint: Representation of a point using floating point numbers
@li wxSize: Representation of a size
@li wxTimeSpan: A time interval.
@li wxURI: Represents a Uniform Resource Identifier
@li wxVariant: A class for storing arbitrary types that may change at run-time



@section page_class_cat_conv Text Conversion

These classes define objects for performing conversions between different
multibyte and Unicode encodings and wide character strings.

@li wxMBConv: Base class for all convertors, defines the API implemented by all
    the other convertor classes.
@li wxMBConvUTF7: Convertor for UTF-7
@li wxMBConvUTF8: Convertor for UTF-8
@li wxMBConvUTF16: Convertor for UTF-16
@li wxMBConvUTF32: Convertor for UTF-32
@li wxCSConv: Convertor for any system-supported encoding which can be
    specified by name.

Related Overviews: @ref overview_mbconv


@section page_class_cat_containers Containers

These are classes, templates and class macros are used by wxWidgets. Most of
these classes provide a subset or almost complete STL API.

Related Overviews: @ref overview_container

@li wxArray<T>: A type-safe dynamic array implementation (macro based)
@li wxArrayString: An efficient container for storing wxString objects
@li wxHashMap<T>: A type-safe hash map implementation (macro based)
@li wxHashSet<T>: A type-safe hash set implementation(macro based)
@li wxHashTable: A simple hash table implementation (deprecated, use wxHashMap)
@li wxList<T>: A type-safe linked list implementation (macro based)
@li wxVector<T>: Template base vector implementation identical to std::vector



@section page_class_cat_smartpointers Smart Pointers

wxWidgets provides a few smart pointer class templates.

@li wxObjectDataPtr<T>: A shared pointer (using intrusive reference counting)
@li wxScopedPtr<T>: A scoped pointer
@li wxSharedPtr<T>: A shared pointer (using non-intrusive reference counting)
@li wxWeakRef<T>: A weak reference



@section page_class_cat_file File Handling

wxWidgets has several small classes to work with disk files and directories.

Related overview: @ref overview_file

@li wxFileName: Operations with the file name and attributes
@li wxDir: Class for enumerating files/subdirectories.
@li wxDirTraverser: Class used together with wxDir for recursively enumerating
    the files/subdirectories
@li wxFile: Low-level file input/output class.
@li wxFFile: Another low-level file input/output class.
@li wxTempFile: Class to safely replace an existing file
@li wxTextFile: Class for working with text files as with arrays of lines
@li wxStandardPaths: Paths for standard directories
@li wxPathList: A class to help search multiple paths
@li wxFileSystemWatcher: Class providing notifications of file system changes



@section page_class_cat_streams Streams

wxWidgets has its own set of stream classes as an alternative to the
standard stream libraries and to provide enhanced functionality.

Related overview: @ref overview_stream

@li wxStreamBase: Stream base class
@li wxStreamBuffer: Stream buffer class
@li wxInputStream: Input stream class
@li wxOutputStream: Output stream class
@li wxCountingOutputStream: Stream class for querying what size a stream would
    have.
@li wxFilterInputStream: Filtered input stream class
@li wxFilterOutputStream: Filtered output stream class
@li wxBufferedInputStream: Buffered input stream class
@li wxBufferedOutputStream: Buffered output stream class
@li wxMemoryInputStream: Memory input stream class
@li wxMemoryOutputStream: Memory output stream class
@li wxDataInputStream: Platform-independent binary data input stream class
@li wxDataOutputStream: Platform-independent binary data output stream class
@li wxTextInputStream: Platform-independent text data input stream class
@li wxTextOutputStream: Platform-independent text data output stream class
@li wxFileInputStream: File input stream class
@li wxFileOutputStream: File output stream class
@li wxFFileInputStream: Another file input stream class
@li wxFFileOutputStream: Another file output stream class
@li wxTempFileOutputStream: Stream to safely replace an existing file
@li wxStringInputStream: String input stream class
@li wxStringOutputStream: String output stream class
@li wxZlibInputStream: Zlib and gzip (compression) input stream class
@li wxZlibOutputStream: Zlib and gzip (compression) output stream class
@li wxZipInputStream: Input stream for reading from ZIP archives
@li wxZipOutputStream: Output stream for writing from ZIP archives
@li wxTarInputStream: Input stream for reading from tar archives
@li wxTarOutputStream: Output stream for writing from tar archives
@li wxSocketInputStream: Socket input stream class
@li wxSocketOutputStream: Socket output stream class



@section page_class_cat_xml XML

@li wxXmlDocument: A class to parse XML files
@li wxXmlNode: A class which represents XML nodes
@li wxXmlAttribute: A class which represent an XML attribute



@section page_class_cat_archive Archive

@li wxArchiveInputStream
@li wxArchiveOutputStream
@li wxArchiveEntry



@section page_class_cat_xrc XML Based Resource System (XRC)

Resources allow your application to create controls and other user interface
elements from specifications stored in an XML format.

Related overview: @ref overview_xrc

@li wxXmlResource: The main class for working with resources
@li wxXmlResourceHandler: The base class for XML resource handlers



@section page_class_cat_net Networking

wxWidgets provides its own classes for socket based networking.

@li wxDialUpManager: Provides functions to check the status of network
    connection and to establish one
@li wxIPV4address: Represents an Internet address
@li wxIPaddress: Represents an Internet address
@li wxSocketBase: Represents a socket base object
@li wxSocketClient: Represents a socket client
@li wxSocketServer: Represents a socket server
@li wxSocketEvent: A socket event
@li wxFTP: FTP protocol class
@li wxHTTP: HTTP protocol class
@li wxURL: Represents a Universal Resource Locator



@section page_class_cat_ipc Interprocess Communication

wxWidgets provides simple interprocess communications facilities based on
Windows DDE, but available on most platforms using TCP.

Related overview: @ref overview_ipc

@li wxClient, wxDDEClient: Represents a client
@li wxConnection, wxDDEConnection: Represents the connection between a client
    and a server
@li wxServer, wxDDEServer: Represents a server



@section page_class_cat_help Help

@li wxHelpController: Family of classes for controlling help windows
@li wxHtmlHelpController: HTML help controller class
@li wxContextHelp: Class to put application into context-sensitive help mode
@li wxContextHelpButton: Button class for putting application into
    context-sensitive help mode
@li wxHelpProvider: Abstract class for context-sensitive help provision
@li wxSimpleHelpProvider: Class for simple context-sensitive help provision
@li wxHelpControllerHelpProvider: Class for context-sensitive help provision
    via a help controller
@li wxToolTip: Class implementing tooltips



@section page_class_cat_media Multimedia

@li wxMediaCtrl: Display multimedia contents.



@section page_class_cat_gl OpenGL

@li wxGLCanvas: Canvas that you can render OpenGL calls to.
@li wxGLContext: Class to ease sharing of OpenGL data resources.



@section page_class_cat_misc Miscellaneous

@li wxCaret: A caret (cursor) object
@li wxConfigBase: Classes for reading/writing the configuration settings
@li wxTimer: Timer class
@li wxStopWatch: Stop watch class
@li wxMimeTypesManager: MIME-types manager class
@li wxSystemSettings: System settings class for obtaining various global
    parameters
@li wxSystemOptions: System options class for run-time configuration
@li wxAcceleratorTable: Accelerator table
@li wxAutomationObject: OLE automation class
@li wxFontMapper: Font mapping, finding suitable font for given encoding
@li wxEncodingConverter: Encoding conversions
@li wxCalendarDateAttr: Used with wxCalendarCtrl
@li wxQuantize: Class to perform quantization, or colour reduction
@li wxSingleInstanceChecker: Check that only single program instance is running

*/

