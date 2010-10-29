/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsMDICanvas.h

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

#ifndef XSMDICANVAS_H
#define XSMDICANVAS_H

// Includes

#include "XsComponent.h"

// Forward declarations

class XsMDIWindow;

// XsMDICanvas class

class XsMDICanvas : public XsComponent {

   public:
   
// Constructor/Destructor

      XsMDICanvas (const char *name, Widget parent);
      virtual ~XsMDICanvas ( );
      
// MDI Window manipulation

      virtual void add (XsMDIWindow *win);      // Add an MDI window
      virtual void remove (XsMDIWindow *win);   // Remove an MDI window
      void removeAll ( );                       // Remove all MDI windows
      
// Utilities

      int   numWindows ( ) const;            // Number of MDI windows
      Widget GetDrawingArea() const { return _drawArea; }

// Component methods

      virtual void show ( );
      
// Class name

      virtual const char *className ( ) const;

   protected:

// Component life-cycle

      virtual void _componentDestroyed ( );

// Geometry management

      virtual  void _placeWindow (XsMDIWindow *win);

// Canvas resize handler

      virtual void   _resize (XtPointer);

// Implementation

      Widget         _clipWin;
      Widget         _drawArea;

      XsMDIWindow  **_list;
      int            _num;
      int            _max;
      int            _place;
      
   private:
   
// Callbacks

      static void _clipResizeCallback (Widget, XtPointer, XtPointer);
      static void _canvasResizeCallback (Widget, XtPointer, XtPointer);
      
// Resources

      static String  _resources[];
};

// Inline member functions

inline XsMDICanvas::numWindows ( ) const
{
   return (_num);
}

#endif
