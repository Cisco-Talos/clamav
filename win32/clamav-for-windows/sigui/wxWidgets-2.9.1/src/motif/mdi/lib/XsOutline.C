/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsOutline.C

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

// Includes

#include <assert.h>
#include <X11/StringDefs.h>
#include "XsOutline.h"

// Constructor

XsOutline::XsOutline (Widget w)
{
   assert (w != 0);
   
// Initialize

   _w = w;
   
// Get window dimensions

   unsigned int moreJunk;
   unsigned int uw, uh;
   Window   junk;
   
   XGetGeometry (XtDisplay (_w), XtWindow (_w), &junk, &_x, &_y, &uw, &uh, &moreJunk, &moreJunk);

   _width = uw;
   _height = uh;
   
// Get initial settings

   _savedX = _x;
   _savedY = _y;
   _savedH = _savedW = 0;
   
// Create the graphics context

   XGCValues   values;
   unsigned long valuemask;

   Display *dpy = XtDisplay (_w);
   
   valuemask = GCFunction | GCLineWidth | GCSubwindowMode;
   values.function = GXinvert;
   values.line_width = 0;
   values.subwindow_mode = IncludeInferiors;
      
   _gc = XCreateGC (dpy, XtWindow (_w), valuemask, &values);
}

// Destructor

XsOutline::~XsOutline ( )
{
   XFreeGC (XtDisplay (_w), _gc);
}

// go

Boolean XsOutline::go (Boolean drawInitial)
{
   XtAppContext appContext = XtWidgetToApplicationContext (_w);
   XEvent event;
   int   done = 0;
   
// Grab the pointer

   if (_grabPointer ( ) == False)
      return (False);      
   
// Draw the initial box (if requested)

   if (drawInitial)
      _drawOutline (False);

// Process the events locally

   while (!done)
   {
      XtAppNextEvent (appContext, &event);

      switch (event.type)
      {
         case ButtonRelease:
         {

// Clear the outline and break

            _drawOutline (True);
            done = 1;
            break;
         }
         case MotionNotify:
         {
            XEvent next;
            
// Process only the last motion event

            while (XPending (XtDisplay (_w)) > 0)
            {
               XPeekEvent (XtDisplay (_w), &next);
               if (next.type != MotionNotify)
                  break;
               XtAppNextEvent (appContext, &event);
            }
               
// Send this event

            _motionHandler (&event);
            
            break;
         }
         default:
         {
            XtDispatchEvent (&event);
            break;
         }
      }
   }

// Ungrab the pointer

   _ungrabPointer ( );
   
   return (True);
}

// _drawOutline

void XsOutline::_drawOutline (Boolean clear)
{

// Clear the current outline

   if (_savedH || _savedW)
      _drawIt (_savedX, _savedY, _savedW, _savedH);
   
// Save current values

   _savedX = _x; _savedY = _y;
   _savedW = _width; _savedH = _height;
   
// Draw the new outline (unless flagged to just clear)

   if (!clear)
      _drawIt (_x, _y, _width, _height);      
}

// _getCursor

Cursor XsOutline::_getCursor ( ) const
{
   return (None);
}
   
// _grabPointer 

Boolean XsOutline::_grabPointer ( )
{
   
// Sync everything up before being grabby

   XSync (XtDisplay (_w), False);   

// Grab the pointer

   if (XGrabPointer (XtDisplay (_w), XtWindow (_w), False, GrabEventMask, 
      GrabModeAsync, GrabModeAsync, XtWindow (XtParent (_w)), _getCursor ( ), 
      CurrentTime) != GrabSuccess)
   {
      XBell (XtDisplay (_w), 100);
      return (False);
   }
      
   return (True);
}

// _ungrabPointer

void XsOutline::_ungrabPointer ( )
{

// Ungrab the pointer

   XUngrabPointer (XtDisplay (_w), CurrentTime);
}
   
// _drawIt

void XsOutline::_drawIt (int x, int y, int w, int h)
{
   const int nsegs = 8;
   XSegment    segs[nsegs];

// Across the top

   segs[0].x1 = x; segs[0].y1 = y;
   segs[0].x2 = x + w - 1; segs[0].y2 = y;
      
   segs[1].x1 = x + BorderSize; segs[1].y1 = y + BorderSize;
   segs[1].x2 = x + w - BorderSize - 1; segs[1].y2 = y + BorderSize;
      
// Down the left

   segs[2].x1 = x + w - 1; segs[2].y1 = y + 1;
   segs[2].x2 = x + w - 1; segs[2].y2 = y + h - 1;
   
   segs[3].x1 = x + w - BorderSize - 1; segs[3].y1 = y + BorderSize + 1;
   segs[3].x2 = x + w - BorderSize - 1; segs[3].y2 = y + h - BorderSize - 1;
   
// Across the bottom

   segs[4].x1 = x + 1; segs[4].y1 = y + h - 1;
   segs[4].x2 = x + w - 2; segs[4].y2 = y + h - 1;
   
   segs[5].x1 = x + BorderSize + 1; segs[5].y1 = y + h - BorderSize - 1;
   segs[5].x2 = x + w - BorderSize - 2; segs[5].y2 = y + h - BorderSize - 1;
   
// Up the left

   segs[6].x1 = x; segs[6].y1 = y + h - 1;
   segs[6].x2 = x; segs[6].y2 = y + 1;
   
   segs[7].x1 = x + BorderSize; segs[7].y1 = y + h - BorderSize - 1;
   segs[7].x2 = x + BorderSize; segs[7].y2 = y + BorderSize + 1;
   
// Draw the segments

   XDrawSegments (XtDisplay (_w), XtWindow (XtParent (_w)), _gc, segs, nsegs);
}
