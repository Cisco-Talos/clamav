/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsOutline.h

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

#ifndef XSOUTLINE_H
#define XSOUTLINE_H

// Includes

#include <X11/Intrinsic.h>

// XsOutline class

class XsOutline {

   public:

// Constructor/Destructor
      
      XsOutline (Widget w);
      virtual ~XsOutline ( );
      
// Event handler

      Boolean go (Boolean drawInitial = False);
      
// Utilities

      int width ( ) const;
      int height ( ) const;
      int x ( ) const;
      int y ( ) const;
      
   protected:

// Enumerations

      enum { BorderSize = 6 };
      enum { GrabEventMask = (unsigned int)(ButtonPressMask | ButtonReleaseMask | PointerMotionMask) };

// Components

      Widget      _w;
      
// Graphics context

      GC          _gc;

// Current dimensions

      int         _x, _y;
      int         _width;
      int         _height;

// Outline utilities

      virtual  void _motionHandler (XEvent*) = 0;
      virtual  Cursor _getCursor ( ) const;
      void     _drawOutline (Boolean);
      
   private:
   
// Pointer grabs

      Boolean  _grabPointer ( );
      void     _ungrabPointer ( );
      
// Save dimensions

      int   _savedX, _savedY;
      int   _savedW, _savedH;

// Drawing

      void  _drawIt (int, int, int, int);
};
      
// Inline member functions

inline int XsOutline::width ( ) const
{
   return (_width);
}

inline int XsOutline::height ( ) const
{
   return (_height);
}

inline int XsOutline::x ( ) const
{
   return (_x);
}

inline int XsOutline::y ( ) const
{
   return (_y);
}

#endif
