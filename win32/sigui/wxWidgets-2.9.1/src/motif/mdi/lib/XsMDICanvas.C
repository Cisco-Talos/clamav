/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsMDICanvas.C

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

// Includes

#include <assert.h>
#include <Xm/ScrolledW.h>
#include <Xm/DrawingA.h>
#include "XsMDICanvas.h"
#include "XsMDIWindow.h"

// Static definitions

String XsMDICanvas::_resources[] = {
   "*canvas.resizePolicy:     XmRESIZE_GROW",
   NULL
};

// Constructor

XsMDICanvas::XsMDICanvas (const char *name, Widget parent) : XsComponent (name)
{
   assert (parent != 0);

// Initialize

   _list = 0;
   _num = 0;
   _max = 0;
   _place = 0;
   
// Install resources

   _setResources (parent, _resources);
   
// Create the scrolled window

   const int nargs = 10;
   Arg   args[nargs];
   int   n = 0;
   
   XtSetArg (args[n], XmNscrollingPolicy, XmAUTOMATIC);   n++;
   XtSetArg (args[n], XmNscrolledWindowMarginHeight, (Dimension)0);  n++;
   XtSetArg (args[n], XmNscrolledWindowMarginWidth, (Dimension)0);   n++;
   XtSetArg (args[n], XmNmarginHeight, (Dimension)5);    n++;
   XtSetArg (args[n], XmNmarginWidth, (Dimension)5);     n++;

   assert (n <= nargs);
			   
   _base = XmCreateScrolledWindow (parent, _name, args, n);
   
// Install the destroy handler
            
   _installDestroyHandler ( );
		
// Create the drawing area (canvas)

   _drawArea = XtVaCreateWidget ("canvas", xmDrawingAreaWidgetClass,
      _base, XmNmarginHeight, (Dimension)0, XmNmarginWidth, (Dimension)0,
      NULL);

// Set resize callback on drawing area

   XtAddCallback (_drawArea, XmNresizeCallback, _canvasResizeCallback, (XtPointer)this);

// Set resize callback on clip window

   XtVaGetValues (_base, XmNclipWindow, &_clipWin, NULL);
   XtAddCallback (_clipWin, XmNresizeCallback, _clipResizeCallback, (XtPointer)this);
}

// Destructor

XsMDICanvas::~XsMDICanvas ( )
{

/*
   Remove callbacks to prevent calls to destroyed class-part of XsMDICanvas
   while children are being destroyed.
*/

   if (_drawArea)
      XtRemoveCallback (_drawArea, XmNresizeCallback, _canvasResizeCallback, (XtPointer)this);

   if (_clipWin)
      XtRemoveCallback (_clipWin, XmNresizeCallback, _clipResizeCallback, (XtPointer)this);

// Remove all windows

   removeAll ( ); 
}
   
// add

void XsMDICanvas::add (XsMDIWindow *win)
{
   assert (win != 0);

   const int increment = 10;

// Check if we need to allocate more space

   if (_num >= _max)
   {
      XsMDIWindow **newList = new XsMDIWindow*[_max + increment];

      for (int loop = 0; loop < _num; loop++)
         newList[loop] = _list[loop];
      _max += increment;

      delete [] _list;
      _list = newList;
   }

// Add the new window

   _list[_num++] = win;

// Install the parent canvas 

   win->_setWindowParent (_drawArea);

// If the canvas is shown, place the window

   if (XtIsManaged (_base))
      _placeWindow (win);
}

// remove

void XsMDICanvas::remove (XsMDIWindow *win)
{
   assert (win != 0);

// Remove the window

   int   i, j;

   for (i = 0; i < _num; i++)
   {
      if (_list[i] == win)
      {
         win->hide ( );
         win->_setWindowParent (0);
         
         for (j = i; j < _num - 1; j++)
            _list[j] = _list[j + 1];
         _num--;

         return;
      }
   }

   assert (0);    // Couldn't find window
}

// removeAll

void XsMDICanvas::removeAll ( )
{

// Delete and reset the list

   delete [] _list;

   _list = 0;
   _num = 0;
   _max = 0;
}
                        
// show

void XsMDICanvas::show ( )
{
   assert (_drawArea != 0);

// Place all of the child windows

   for (int loop = 0; loop < _num; loop++)
      _placeWindow (_list[loop]);
      
// Manage the drawing area and canvas

   XtManageChild (_drawArea);

// Call base class

   XsComponent::show ( );
}

// className

const char* XsMDICanvas::className ( ) const
{
   return ("XsMDICanvas");
}

// _componentDestroyed

void XsMDICanvas::_componentDestroyed ( )
{

// Remove the callbacks

   XtRemoveCallback (_drawArea, XmNresizeCallback, _canvasResizeCallback, (XtPointer)this);
   XtRemoveCallback (_clipWin, XmNresizeCallback, _clipResizeCallback, (XtPointer)this);
   
   _drawArea = 0;
   _clipWin = 0;
}
   
// _placeWindow

void XsMDICanvas::_placeWindow (XsMDIWindow *win)
{
   assert (win != 0);
   
// Compute window placement

   Position x, y;
   
   const int maxWin = 10;
   const Position offset = 20;
   const Position minOffset = 10;
   
   x = (_place * offset) + minOffset;
   y = (_place * offset) + minOffset;
   
   if (++_place == maxWin)
      _place = 0;
      
// Set the window placement

   win->setPosition (x, y);
   
// Show the window

   win->show ( );
}

// _resize

void XsMDICanvas::_resize (XtPointer)
{
   Dimension   clipHeight;
   Dimension   clipWidth;
   Dimension   canvasHeight;
   Dimension   canvasWidth;
	    
// Check if clip window and canvas are managed

   if (!XtIsManaged (_clipWin) || !XtIsManaged (_drawArea))
      return;
   
// Get the clip window size

   XtVaGetValues (_clipWin, XmNwidth, &clipWidth, XmNheight, &clipHeight, NULL);
   
// Get the canvas size

   XtVaGetValues (_drawArea, XmNwidth, &canvasWidth, XmNheight, &canvasHeight, NULL);

// Force the canvas to be at least as big as the clip window

   if (canvasWidth < clipWidth)
      canvasWidth = clipWidth;
   if (canvasHeight < clipHeight)
      canvasHeight = clipHeight;
			   
   XtVaSetValues (_drawArea, XmNwidth, canvasWidth, XmNheight, canvasHeight, NULL);
}

// _clipResizeCallback

void XsMDICanvas::_clipResizeCallback (Widget, XtPointer clientData, XtPointer callData)
{
   XsMDICanvas *obj = (XsMDICanvas*)clientData;
   obj->_resize (callData);
}

// _canvasResizeCallback

void XsMDICanvas::_canvasResizeCallback (Widget, XtPointer clientData, XtPointer callData)
{
   XsMDICanvas *obj = (XsMDICanvas*)clientData;
   obj->_resize (callData);
}

