/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsMDIWindow.C

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

// Includes

#include <assert.h>
#include <Xm/Xm.h>
#include "XsMDIWindow.h"

// Constructor

XsMDIWindow::XsMDIWindow (const char *name) : XsComponent (name)
{

// Initialize
   
   _clientArea = 0;
   _parent = 0;

// Initial size and placement

   _initX = (Position)-1;
   _initY = (Position)-1;
   _initH = (Dimension)-1;
   _initW = (Dimension)-1;
   _placed = False;
}

// Destructor

XsMDIWindow::~XsMDIWindow ( )
{
   // Empty
}

// raise

void XsMDIWindow::raise ( )
{
   assert (_base != 0);
   XRaiseWindow (XtDisplay (_base), XtWindow (_base));
}

// lower

void XsMDIWindow::lower ( )
{
   assert (_base != 0);
   XLowerWindow (XtDisplay (_base), XtWindow (_base));
}

// show

void XsMDIWindow::show ( )
{

// Create the window (if necessary)

   if (_base == 0)
   {
      assert (_parent != 0);
      _createWindow (_parent);
   }
   
// Manage the client area

   XtManageChild (_clientArea);
   
// Configure the window position and size

   if (_placed == False)
   {
      const int nargs = 4;
      Arg   args[nargs];
      int   n = 0;
      
      if (_initX != (Position)-1)
      {
         XtSetArg (args[n], XmNx, _initX);   n++;
      }
      if (_initY != (Position)-1)
      {
         XtSetArg (args[n], XmNy, _initY);   n++;
      }
      if (_initW != (Dimension)-1)
      {
         XtSetArg (args[n], XmNwidth, _initW);  n++;
      }
      if (_initH != (Dimension)-1)
      {
         XtSetArg (args[n], XmNheight, _initH); n++;
      }
         
      assert (n <= nargs);
      XtSetValues (_base, args, n);

      _placed = True;
   }
   
// Call the base class

   XsComponent::show ( );
}

// setPosition

void XsMDIWindow::setPosition (Position x, Position y)
{
   if (_base != 0)
      XtVaSetValues (_base, XmNx, x, XmNy, y, NULL);
   else
   {
      _initX = x;
      _initY = y;
   }      
}

// setSize

void XsMDIWindow::setSize (Dimension w, Dimension h)
{
   if (_base != 0)
      XtVaSetValues (_base, XmNwidth, w, XmNheight, h, NULL);
   else
   {
      _initW = w;
      _initH = h;
   }
}

// className

const char* XsMDIWindow::className ( ) const
{
   return ("XsMDIWindow");
}

// _setWindowParent

void XsMDIWindow::_setWindowParent (Widget p)
{
   
// This is called by the canvas to tell us who our parent is

   _parent = p;
}
