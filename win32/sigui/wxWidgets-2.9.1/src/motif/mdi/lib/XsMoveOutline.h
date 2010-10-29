/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsMoveOutline.h

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

#ifndef XSMOVEOUTLINE_H
#define XSMOVEOUTLINE_H

// Includes

#include "XsOutline.h"

// XsMoveOutline class

class XsMoveOutline : public XsOutline {

   public:
      
// Constructor/Destructor

      XsMoveOutline (Widget w);
      virtual ~XsMoveOutline ( );

   protected:
      
// Motion handler

      virtual  void _motionHandler (XEvent*);

// Moving cursor

      virtual Cursor _getCursor ( ) const;

   private:

// Implementation

      int      _rootX;
      int      _rootY;

      static   Cursor   _fleur;
};

#endif
