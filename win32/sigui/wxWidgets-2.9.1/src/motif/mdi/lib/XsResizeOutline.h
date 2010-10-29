/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsResizeOutline.h

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

#ifndef XSRESIZEOUTLINE_H
#define XSRESIZEOUTLINE_H

// Includes

#include "XsOutline.h"

class XsResizeOutline : public XsOutline {

   public:
   
// Enumerations

   enum { Up = 0x0001, Right = 0x0002, Down = 0x0004, Left = 0x0008,
      Undetermined = 0x0010 };
   
   enum Cursors {
      TopCursor = 0, BottomCursor, LeftCursor, RightCursor, TopLeftCursor,
      TopRightCursor, BottomLeftCursor, BottomRightCursor, Fleur,
      NumCursors };

// Constructor/Destructor

      XsResizeOutline (Widget w, int direction);
      virtual ~XsResizeOutline ( );
      
      void  setMinSize (int minWidth, int minHeight);

   protected:
      
// Motion handler

      virtual  void _motionHandler (XEvent*);

// Resize cursor

      virtual Cursor _getCursor ( ) const;

   private:
   
// Implementation

      int   _rootX, _rootY;               // Root coordinates
      int   _origRootX, _origRootY;
      
      int   _origX, _origY;               // Window coordinates
      int   _origW, _origH;

      int   _minWidth, _minHeight;

      int   _direction;

      static Cursor  _cursors[NumCursors];
      static int  _mutex;
};

#endif
