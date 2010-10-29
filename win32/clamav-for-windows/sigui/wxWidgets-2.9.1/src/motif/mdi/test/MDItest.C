/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   MDItest.c

   History
      03-Mar-96 1.0; Scott W. Sadler (sws@iti-oh.com)
                     Created         
*/

// Includes

#include <assert.h>
#include <Xm/MainW.h>
#include <Xm/RowColumn.h>
#include <Xm/CascadeBG.h>
#include <Xm/Text.h>
#include <Xm/PushBG.h>
#include <Xm/AtomMgr.h>
#include <Xm/Protocols.h>
#include "XsMDICanvas.h"
#include "XsMotifWindow.h"

// Fallback resources

static char *fallbacks[] = {
   "*MDItest.height:                500",
   "*MDItest.width:                 500",
   "*MDIinner.width:                300",
   "*MDIinner.height:               300",

   "*fileMenu.labelString:          File",
   "*fileMenu.mnemonic:             F",
   "*openMenuItem.labelString:      Open...",
   "*openMenuItem.mnemonic:         O",
   "*newMenuItem.labelString:       New...",
   "*newMenuItem.mnemonic:          N",
   "*editMenu.labelString:          Edit",
   "*editMenu.mnemonic:             E",
   "*cutMenuItem.labelString:       Cut",
   "*cutMenuItem.mnemonic:          t",
   "*copyMenuItem.labelString:      Copy",
   "*copyMenuItem.mnemonic:         C",
   "*pasteMenuItem.labelString:     Paste",
   "*pasteMenuItem.mnemonic:        P",
   "*helpMenu.labelString:          Help",
   "*helpMenu.mnemonic:             H",
   "*aboutMenuItem.labelString:     About",
   "*aboutMenuItem.mnemonic:        A",
   "*scrolledText.rows:             10",
   "*scrolledText.columns:          30",

   "*background:              grey",
   "*fontList:                -*-helvetica-medium-r-normal-*-14-*-*-*-*-*-iso8859-1",

   NULL
};
      
/*
   ----------------------------------------------------------------------------
   MyDocument class
*/

class MyDocument : public XsMotifWindow {

   public:

// Constructor/Destructor

      MyDocument (const char *name, XsMDICanvas *canvas);
      virtual ~MyDocument ( );
      
   protected:

// This member function is called to create the document contents

      virtual void _buildClientArea (Widget);

// Implementation

      XsMDICanvas   *_canvas;

// Callbacks

      void  _newWindow ( );
      void  _doNothing ( );
      
   private:
   
// Callbacks

      static void _newWindowCallback (Widget, XtPointer, XtPointer);
      static void _doNothingCallback (Widget, XtPointer, XtPointer);
};
      
// Constructor

MyDocument::MyDocument (const char *name, XsMDICanvas *canvas) :
   XsMotifWindow (name)
{
   assert (canvas != 0);

// Initialize

   _canvas = canvas;
}

// Destructor

MyDocument::~MyDocument ( )
{
   // Empty
}

// _buildClientArea (called to create document contents)

void MyDocument::_buildClientArea (Widget parent)
{
   assert (parent != 0);
   
   Widget   pulldown;
   Widget   cascade;
   Widget   button;
   
// Create a main window with some dummy menus

   Widget mainW = XtVaCreateWidget ("mainWin", xmMainWindowWidgetClass, parent,
      XmNtopAttachment, XmATTACH_FORM, XmNbottomAttachment, XmATTACH_FORM,
      XmNleftAttachment, XmATTACH_FORM, XmNrightAttachment, XmATTACH_FORM,
      NULL);
      
// Create a menubar

   Widget menuBar = XmCreateMenuBar (mainW, "menuBar", NULL, 0);

// Create the "file" menu

   pulldown = XmCreatePulldownMenu (menuBar, "pulldown", NULL, 0);
   cascade = XtVaCreateManagedWidget ("fileMenu", xmCascadeButtonGadgetClass,
      menuBar, XmNsubMenuId, pulldown, NULL);
   
   button = XtVaCreateManagedWidget ("openMenuItem", xmPushButtonGadgetClass,
      pulldown, NULL);
   XtAddCallback (button, XmNactivateCallback, _doNothingCallback, (XtPointer)this);
      
   button = XtVaCreateManagedWidget ("newMenuItem", xmPushButtonGadgetClass,
      pulldown, NULL);
   XtAddCallback (button, XmNactivateCallback, _newWindowCallback, (XtPointer)this);

// Create the "edit" menu

   pulldown = XmCreatePulldownMenu (menuBar, "pulldown", NULL, 0);
   cascade = XtVaCreateManagedWidget ("editMenu", xmCascadeButtonGadgetClass,
      menuBar, XmNsubMenuId, pulldown, NULL);
   
   button = XtVaCreateManagedWidget ("cutMenuItem", xmPushButtonGadgetClass,
      pulldown, NULL);
   XtAddCallback (button, XmNactivateCallback, _doNothingCallback, (XtPointer)this);
      
   button = XtVaCreateManagedWidget ("copyMenuItem", xmPushButtonGadgetClass,
      pulldown, NULL);
   XtAddCallback (button, XmNactivateCallback, _doNothingCallback, (XtPointer)this);

   button = XtVaCreateManagedWidget ("pasteMenuItem", xmPushButtonGadgetClass,
      pulldown, NULL);
   XtAddCallback (button, XmNactivateCallback, _doNothingCallback, (XtPointer)this);

// Create the help menu

   pulldown = XmCreatePulldownMenu (menuBar, "pulldown", NULL, 0);
   cascade = XtVaCreateManagedWidget ("helpMenu", xmCascadeButtonGadgetClass,
      menuBar, XmNsubMenuId, pulldown, NULL);
   
   button = XtVaCreateManagedWidget ("aboutMenuItem", xmPushButtonGadgetClass,
      pulldown, NULL);
   XtAddCallback (button, XmNactivateCallback, _doNothingCallback, (XtPointer)this);
      
   XtVaSetValues (menuBar, XmNmenuHelpWidget, cascade, NULL);

// Manage the menubar

   XtManageChild (menuBar);
   
// Create the work area

   const int nargs = 8;
   Arg   args[nargs];
   int n;
	    
   n = 0;
   XtSetArg (args[n], XmNscrollingPolicy, XmAUTOMATIC); n++;
   XtSetArg (args[n], XmNhighlightThickness, (Dimension)0);    n++;
   XtSetArg (args[n], XmNeditMode, XmMULTI_LINE_EDIT); n++;
   XtSetArg (args[n], XmNeditable, True); n++;
   XtSetArg (args[n], XmNwordWrap, False); n++;
   XtSetArg (args[n], XmNcursorPositionVisible, True);   n++;
   XtSetArg (args[n], XmNverifyBell, True); n++;
			      
   assert (n <= nargs);
				 
   Widget scrolledText = XmCreateScrolledText (mainW, "scrolledText", args, n);
   XtManageChild (scrolledText);
   
// Set the main window area

   XtVaSetValues (mainW, XmNmenuBar, menuBar, XmNworkWindow,
      XtParent (scrolledText), NULL);
   
   XtManageChild (mainW);
}

// _newWindow

void MyDocument::_newWindow ( )
{
   
// Create a new document (this will leak, but who cares?)

   MyDocument *newDoc = new MyDocument ("Document", _canvas);

// Add it to the canvas

   _canvas->add (newDoc);
}

// _newWindowCallback

void MyDocument::_newWindowCallback (Widget, XtPointer clientData, XtPointer)
{
   MyDocument *obj = (MyDocument*)clientData;
   obj->_newWindow ( );
}   

// _doNothingCallback

void MyDocument::_doNothingCallback (Widget w, XtPointer, XtPointer)
{
   XBell (XtDisplayOfObject (w), 100);
}
   
/*
   ----------------------------------------------------------------------------
   MyDocument2 class
*/

class MyDocument2 : public XsMotifWindow {

   public:

// Constructor/Destructor

      MyDocument2 (const char *name);
      virtual ~MyDocument2 ( );
      
   protected:

// This member function is called to create the document contents

      virtual void _buildClientArea (Widget);

// Implementation

      XsMDICanvas    *_canvas;
      MyDocument     *_win1;
};
      
// Constructor

MyDocument2::MyDocument2 (const char *name) : XsMotifWindow (name)
{
   _canvas = 0;
   _win1 = 0;
}

// Destructor

MyDocument2::~MyDocument2 ( )
{
   delete _canvas;
   delete _win1;
}

// _buildClientArea

void MyDocument2::_buildClientArea (Widget parent)
{
   assert (parent != 0);
   
// Create a nested MDI canvas

   _canvas = new XsMDICanvas ("MDIinner", parent);
      
// Attach it up

   XtVaSetValues (_canvas->base ( ), XmNtopAttachment, XmATTACH_FORM,
      XmNbottomAttachment, XmATTACH_FORM, XmNleftAttachment, XmATTACH_FORM,
      XmNrightAttachment, XmATTACH_FORM, NULL);

// Create a document

   _win1 = new MyDocument ("InnerWin", _canvas);

// Add the document to the canvas

   _canvas->add (_win1);

// Show the canvas

   _canvas->show ( );
}

/*
   ----------------------------------------------------------------------------
   main
*/

static void _destroyCallback (Widget, XtPointer clientData, XtPointer)
{
   Boolean *quit = (Boolean*)clientData;
   *quit = True;
}
   
int main (int argc, char **argv)
{
   XtAppContext   appContext;
   Widget   topLevel;
   Boolean  quit = False;
   
// Initialize toolkit

   topLevel = XtVaAppInitialize (&appContext, "MDI", NULL, 0, &argc, argv,
      fallbacks, XmNdeleteResponse, XmDO_NOTHING, NULL);
      
   Display *dpy = XtDisplay (topLevel);
   
// Add protocols

   Atom WM_DELETE_WINDOW = XmInternAtom (dpy, "WM_DELETE_WINDOW", False);

   XmAddWMProtocolCallback (topLevel, WM_DELETE_WINDOW, _destroyCallback,
      &quit);
   
// Create the MDI canvas

   XsMDICanvas *canvas = new XsMDICanvas ("MDItest", topLevel);
   
// Create the MDI documents

   MyDocument *win1 = new MyDocument ("Document", canvas);
   MyDocument2 *win2 = new MyDocument2 ("Document 2");
   
// Add documents to MDI canvas

   canvas->add (win1);
   canvas->add (win2);
   
// Show the canvas

   canvas->show ( );

// Realize everything

   XtRealizeWidget (topLevel);
   
// Let 'er rip

   XEvent event;

   while (!quit)
   {
      XtAppNextEvent (appContext, &event);
      XtDispatchEvent (&event);
   }      
      
// Cleanup

   delete win1;
   delete win2;
   delete canvas;
   
// Close the X connection

   XtDestroyWidget (topLevel);
   XtCloseDisplay (dpy);
   XtDestroyApplicationContext (appContext);
   
   return (0);
}
