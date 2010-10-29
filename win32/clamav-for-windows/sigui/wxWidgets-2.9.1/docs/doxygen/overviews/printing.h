/////////////////////////////////////////////////////////////////////////////
// Name:        printing.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_printing Printing Framework Overview

Classes:
@li wxPrintout
@li wxPrinter
@li wxPrintPreview
@li wxPrinterDC
@li wxPostScriptDC
@li wxPrintDialog
@li wxPrintData
@li wxPrintDialogData
@li wxPageSetupDialog
@li wxPageSetupDialogData


@li @ref overview_printing_printout
@li @ref overview_printing_printer
@li @ref overview_printing_printpreview
@li @ref overview_printing_printerdc
@li @ref overview_printing_postscriptdc
@li @ref overview_printing_printdialog
@li @ref overview_printing_printdata
@li @ref overview_printing_printdialogdata
@li @ref overview_printing_pagesetupdialog
@li @ref overview_printing_pagesetupdialogdata


<hr>


The printing framework relies on the application to provide classes whose
member functions can respond to particular requests, such as 'print this page'
or 'does this page exist in the document?'. This method allows wxWidgets to
take over the housekeeping duties of turning preview pages, calling the print
dialog box, creating the printer device context, and so on: the application can
concentrate on the rendering of the information onto a device context.

In most cases, the only class you will need to derive from is wxPrintout; all
others will be used as-is.

A brief description of each class's role and how they work together follows.

For the special case of printing under Unix, where various different printing
backends have to be offered, please have a look at @ref overview_unixprinting.


@section overview_printing_printout wxPrintout

A document's printing ability is represented in an application by a derived
wxPrintout class. This class prints a page on request, and can be passed to the
Print function of a wxPrinter object to actually print the document, or can be
passed to a wxPrintPreview object to initiate previewing. The following code
(from the printing sample) shows how easy it is to initiate printing,
previewing and the print setup dialog, once the wxPrintout functionality has
been defined. Notice the use of MyPrintout for both printing and previewing.
All the preview user interface functionality is taken care of by wxWidgets. For
more details on how MyPrintout is defined, please look at the printout sample
code.

@code
case WXPRINT_PRINT:
{
    wxPrinter printer;
    MyPrintout printout("My printout");
    printer.Print(this, &printout, true);
    break;
}
case WXPRINT_PREVIEW:
{
    // Pass two printout objects: for preview, and possible printing.
    wxPrintPreview *preview = new wxPrintPreview(new MyPrintout, new MyPrintout);
    wxPreviewFrame *frame = new wxPreviewFrame(preview, this,
                                               "Demo Print Preview",
                                               wxPoint(100, 100),
                                               wxSize(600, 650));
    frame->Centre(wxBOTH);
    frame->Initialize();
    frame->Show(true);
    break;
}
@endcode

wxPrintout assembles the printed page and (using your subclass's overrides)
writes requested pages to a wxDC that is passed to it. This wxDC could be a
wxMemoryDC (for displaying the preview image on-screen), a wxPrinterDC (for
printing under MSW and Mac), or a wxPostScriptDC (for printing under GTK or
generating PostScript output).

The @ref overview_docview "document/view framework" creates a default
wxPrintout object for every view, calling wxView::OnDraw() to achieve a
prepackaged print/preview facility.

If your window classes have a Draw(wxDC *dc) routine to do screen rendering,
your wxPrintout subclass will typically call those routines to create portions
of the image on your printout. Your wxPrintout subclass can also make its own
calls to its wxDC to draw headers, footers, page numbers, etc.

The scaling of the drawn image typically differs from the screen to the preview
and printed images. This class provides a set of routines named
FitThisSizeToXXX(), MapScreenSizeToXXX(), and GetLogicalXXXRect, which can be
used to set the user scale and origin of the wxPrintout's DC so that your class
can easily map your image to the printout withough getting into the details of
screen and printer PPI and scaling. See the printing sample for examples of how
these routines are used.


@section overview_printing_printer wxPrinter

Class wxPrinter encapsulates the platform-dependent print function with a common
interface. In most cases, you will not need to derive a class from wxPrinter;
simply create a wxPrinter object in your Print function as in the example above.


@section overview_printing_printpreview wxPrintPreview

Class wxPrintPreview manages the print preview process. Among other things, it
constructs the wxDCs that get passed to your wxPrintout subclass for printing
and manages the display of multiple pages, a zoomable preview image, and so
forth. In most cases you will use this class as-is, but you can create your own
subclass, for example, to change the layout or contents of the preview window.


@section overview_printing_printerdc wxPrinterDC

Class wxPrinterDC is the wxDC that represents the actual printed page under MSW
and Mac. During printing, an object of this class will be passed to your derived
wxPrintout object to draw upon. The size of the wxPrinterDC will depend on the
paper orientation and the resolution of the printer.

There are two important rectangles in printing: the <em>page rectangle</em>
defines the printable area seen by the application, and under MSW and Mac, it
is the printable area specified by the printer. (For PostScript printing, the
page rectangle is the entire page.) The inherited function
wxDC::GetSize() returns the page size in device pixels. The
point (0,0) on the wxPrinterDC represents the top left corner of the page
rectangle; that is, the page rect is given by wxRect(0, 0, w, h), where (w,h)
are the values returned by GetSize.

The <em>paper rectangle</em>, on the other hand, represents the entire paper
area including the non-printable border. Thus, the coordinates of the top left
corner of the paper rectangle will have small negative values, while the width
and height will be somewhat larger than that of the page rectangle. The
wxPrinterDC-specific function wxPrinterDC::GetPaperRect() returns the paper
rectangle of the given wxPrinterDC.


@section overview_printing_postscriptdc wxPostScriptDC

Class wxPostScriptDC is the wxDC that represents the actual printed page under
GTK and other PostScript printing. During printing, an object of this class
will be passed to your derived wxPrintout object to draw upon. The size of the
wxPostScriptDC will depend upon the wxPrintData used to construct it.

Unlike a wxPrinterDC, there is no distinction between the page rectangle and
the paper rectangle in a wxPostScriptDC; both rectangles are taken to represent
the entire sheet of paper.


@section overview_printing_printdialog wxPrintDialog

Class wxPrintDialog puts up the standard print dialog, which allows you to
select the page range for printing (as well as many other print settings, which
may vary from platform to platform). You provide an object of type
wxPrintDialogData to the wxPrintDialog at construction, which is used to
populate the dialog.


@section overview_printing_printdata wxPrintData

Class wxPrintData is a subset of wxPrintDialogData that is used (internally) to
initialize a wxPrinterDC or wxPostScriptDC. (In fact, a wxPrintData is a data
member of a wxPrintDialogData and a wxPageSetupDialogData). Essentially,
wxPrintData contains those bits of information from the two dialogs necessary
to configure the wxPrinterDC or wxPostScriptDC (e.g., size, orientation, etc.).
You might wish to create a global instance of this object to provide
call-to-call persistence to your application's print settings.


@section overview_printing_printdialogdata wxPrintDialogData

Class wxPrintDialogData contains the settings entered by the user in the print
dialog. It contains such things as page range, number of copies, and so forth.
In most cases, you won't need to access this information; the framework takes
care of asking your wxPrintout derived object for the pages requested by the
user.


@section overview_printing_pagesetupdialog wxPageSetupDialog

Class wxPageSetupDialog puts up the standard page setup dialog, which allows
you to specify the orientation, paper size, and related settings. You provide
it with a wxPageSetupDialogData object at intialization, which is used to
populate the dialog; when the dialog is dismissed, this object contains the
settings chosen by the user, including orientation and/or page margins.

Note that on Macintosh, the native page setup dialog does not contain entries
that allow you to change the page margins. You can use the Mac-specific class
wxMacPageMarginsDialog (which, like wxPageSetupDialog, takes a
wxPageSetupDialogData object in its constructor) to provide this capability;
see the printing sample for an example.


@section overview_printing_pagesetupdialogdata wxPageSetupDialogData

Class wxPageSetupDialogData contains settings affecting the page size (paper
size), orientation, margins, and so forth. Note that not all platforms populate
all fields; for example, the MSW page setup dialog lets you set the page
margins while the Mac setup dialog does not.

You will typically create a global instance of each of a wxPrintData and
wxPageSetupDialogData at program initiation, which will contain the default
settings provided by the system. Each time the user calls up either the
wxPrintDialog or the wxPageSetupDialog, you pass these data structures to
initialize the dialog values and to be updated by the dialog. The framework
then queries these data structures to get information like the printed page
range (from the wxPrintDialogData) or the paper size and/or page orientation
(from the wxPageSetupDialogData).

*/

