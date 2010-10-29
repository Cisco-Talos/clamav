/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsResizeOutline.C

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

// Includes

#include <assert.h>
#include <X11/cursorfont.h>
#include "XsResizeOutline.h"

// Static definitions

Cursor XsResizeOutline::_cursors[XsResizeOutline::NumCursors];
int XsResizeOutline::_mutex = 0;

// Constructor

XsResizeOutline::XsResizeOutline (Widget w, int direction) : XsOutline (w)
{
   
// Initialize

   _minWidth = 5;
   _minHeight = 5;
   _direction = direction;
   
// Translate current window location to root coordinates

   Position xpos, ypos;
   
   XtTranslateCoords (XtParent (_w), (Position)_x, (Position)_y, &xpos, &ypos);

   _rootX = (int)xpos;
   _rootY = (int)ypos;

// Save the original window position and size

   _origX = _x;
   _origY = _y;
   _origW = _width;
   _origH = _height;

   _origRootX = _rootX;
   _origRootY = _rootY;

// Create the cursors (if necessary)

   if (_mutex == 0)
   {
      Display *dpy = XtDisplay (_w);
      
// Create cursors

      _cursors[TopCursor] = XCreateFontCursor (dpy, XC_top_side);
      _cursors[BottomCursor] = XCreateFontCursor (dpy, XC_bottom_side);
      _cursors[LeftCursor] = XCreateFontCursor (dpy, XC_left_side);
      _cursors[RightCursor] = XCreateFontCursor (dpy, XC_right_side);
      _cursors[TopLeftCursor] = XCreateFontCursor (dpy, XC_top_left_corner);
      _cursors[TopRightCursor] = XCreateFontCursor (dpy, XC_top_right_corner);
      _cursors[BottomLeftCursor] = XCreateFontCursor (dpy, XC_bottom_left_corner);
      _cursors[BottomRightCursor] = XCreateFontCursor (dpy, XC_bottom_right_corner);
      _cursors[Fleur] = XCreateFontCursor (dpy, XC_fleur);
      _mutex = 1;
   }
}
   
// Destructor

XsResizeOutline::~XsResizeOutline ( )
{
   // Empty
}
   
// setMinSize

void XsResizeOutline::setMinSize (int minWidth, int minHeight)
{
   assert (minWidth > 0);
   assert (minHeight > 0);
   
   _minWidth = minWidth;
   _minHeight = minHeight;
}
   
// _motionHandler

void XsResizeOutline::_motionHandler (XEvent *event)
{
   int   curX, curY;
   int   diff;
   int   x, y, w, h;

// Get current mouse position

   curX = event->xbutton.x_root;
   curY = event->xbutton.y_root;

   if (_direction & Undetermined)
   {

/*
   Just let the mouse roam around until it crosses the outline. 
   When it does so, lock in the direction, change the cursor, and let
   it rip.
*/

      if (((curX <= _origRootX) || (curX >= (_origRootX + _origW)))
         || ((curY <= _origRootY) || (curY >= (_origRootY + _origH))))
      {

         const int CornerOffset = 30;
         
// Crossed box.  Figure out where and set direction

         _direction = 0;
         
         if (curY <= (_origRootY + CornerOffset))
            _direction |= Up;
         else if (curY >= (_origRootY + _origH - CornerOffset))
            _direction |= Down;
            
         if (curX <= (_origRootX + CornerOffset))
            _direction |= Left;
         else if (curX >= (_origRootX + _origW - CornerOffset))
            _direction |= Right;

// Get the new cursor

         XChangeActivePointerGrab (XtDisplay (_w), GrabEventMask,
            _getCursor ( ), CurrentTime);
      }
      else
         return;
   }
            
// Get the current values

   x = _x; y = _y; w = _width; h = _height;
   
// Process the motion

   if (_direction & Up)
   {
      if (curY < (_origRootY + _origH - 1 - _minHeight))
      {
         diff = _rootY - curY;
         _rootY = curY;
         _y -= diff;
         _height = _origRootY + _origH - curY;
      }
      else
      {
         _rootY = _origRootY + _origH - 1 - _minHeight;
         _y = _origY + _origH - 1 - _minHeight;
         _height = _minHeight;
      }         
   }
   else if (_direction & Down)
   {
      if (curY > (_origRootY + _minHeight))
         _height = curY - _origRootY - 1;
      else
         _height = _minHeight;
   }

   if (_direction & Left)
   {
      if (curX < (_origRootX + _origW - 1 - _minWidth))
      {
         diff = _rootX - curX;
         _rootX = curX;
         _x -= diff;      
         _width = _origRootX + _origW - curX;         
      }
      else
      {
         _rootX = _origRootX + _origW - 1 - _minWidth;
         _x = _origX + _origW - 1 - _minWidth;
         _width = _minWidth;
      }         
   }
   else if (_direction & Right)
   {
      if (curX > (_origRootX + _minWidth))
         _width = curX - _origRootX - 1;
      else
         _width = _minWidth;
   }

// Check if the values have "really" changed

   if ((w != _width) || (h != _height) || (x != _x) || (y != _y))
      _drawOutline (False);
}

// _getCursor

Cursor XsResizeOutline::_getCursor ( ) const
{
   if (_direction == Up)
      return (_cursors[TopCursor]);
   if (_direction == Down)
      return (_cursors[BottomCursor]);
   if (_direction == Left)
      return (_cursors[LeftCursor]);
   if (_direction == Right)
      return (_cursors[RightCursor]);
   if (_direction == (Up | Left))
      return (_cursors[TopLeftCursor]);
   if (_direction == (Up | Right))
      return (_cursors[TopRightCursor]);
   if (_direction == (Down | Left))
      return (_cursors[BottomLeftCursor]);
   if (_direction == (Down | Right))
      return (_cursors[BottomRightCursor]);
   if (_direction == Undetermined)
      return (_cursors[Fleur]);
      
   assert (0);
   return (None);
}

