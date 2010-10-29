/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsMDIWindow.h

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

#ifndef XSMDIWINDOW_H
#define XSMDIWINDOW_H

// Includes

#include "XsComponent.h"

// XsMDIWindow class

class XsMDIWindow : public XsComponent {

   friend class XsMDICanvas;
   
   public:

// Constructor/Destructor

      XsMDIWindow (const char *name);
      virtual ~XsMDIWindow ( );
      
// Window manipulation

      virtual void raise ( );
      virtual void lower ( );

// Utilities

      Widget   clientArea ( ) const;
      
// Position and size

      virtual void setPosition (Position x, Position y);
      virtual void setSize (Dimension w, Dimension h);

// Class name

      virtual const char *className ( ) const;

   protected:

// Only the friendly canvas can show a window

      virtual void show ( );

// Window creation functions

      virtual void _buildClientArea (Widget parent) = 0;
      virtual void _createWindow (Widget parent) = 0;
      
// Implementation

      Widget      _clientArea;         // Client work area
      
// Initial window size and placement

      Position    _initX, _initY;
      Dimension   _initW, _initH;
      Boolean     _placed;
         
   private:
   
// Window parent installation 

      void     _setWindowParent (Widget);
      Widget   _parent;
};

// Inline member functions

inline Widget XsMDIWindow::clientArea ( ) const
{
   return (_clientArea);
}

#endif

