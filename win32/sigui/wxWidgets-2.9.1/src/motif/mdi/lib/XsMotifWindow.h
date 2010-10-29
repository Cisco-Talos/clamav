/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsMotifWindow.h

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

#ifndef XSMOTIFWINDOW_H
#define XSMOTIFWINDOW_H

// Includes

#include <Xm/Xm.h>
#include "XsMDIWindow.h"

// Forward declarations

class XsMotifWindow;

/*
   ----------------------------------------------------------------------------
   _XsMotifBase class
*/

class _XsMotifBase : public XsComponent {

   public:
   
// Destructor

      virtual ~_XsMotifBase ( );

// Window actions

      virtual void show ( );
      
// Class name

      virtual const char *className ( ) const;
      
   protected:
   
// Protected constructor

      _XsMotifBase (const char *name, XsMotifWindow *win);

// Component life-cycle

      virtual void _componentDestroyed ( );

// Utilities

      void _drawShadows (Position x, Position y, Dimension width,
         Dimension height, Dimension thick, Boolean reverse = False);

      void _drawLine (Position x1, Position y1, Position x2, Position y2, GC &gc);

// Implementation

      XsMotifWindow  *_win;

      GC    _topShadowGC;
      GC    _bottomShadowGC;

// Event handlers

      virtual void _map ( );

// Internal Event handlers      

      static void _mapEventHandler (Widget, XtPointer, XEvent*, Boolean*);
};      

/*
   ----------------------------------------------------------------------------
   _XsMotifComponent class
*/

class _XsMotifComponent : public _XsMotifBase {

   public:

// Destructor

      virtual ~_XsMotifComponent ( );
   
// Enumerations

      enum Cursors {
         TopCursor = 0, BottomCursor, LeftCursor, RightCursor,
         TopLeftCursor, TopRightCursor, BottomLeftCursor,
         BottomRightCursor, NumCursors };

// Class name

      virtual const char *className ( ) const;
      
   protected:
   
// Protected constructor

      _XsMotifComponent (const char *name, XsMotifWindow *win, Widget parent = 0);

// Cursors

      static Cursor  _cursors[NumCursors];
      
// Component parameters

      Dimension   _borderSize;
      Dimension   _buttonSize;
      Dimension   _cornerSize;
      
// Event handlers

      virtual void _expose (XEvent*) = 0;
      virtual void _input (XEvent*);
      
   private:
   
// Internal Event handlers      

      static void _exposeEventHandler (Widget, XtPointer, XEvent*, Boolean*);
      static void _inputEventHandler (Widget, XtPointer, XEvent*, Boolean*);

// Resources

      static XtResource _resourceList[];
      
      static int  _mutex;
};

/*
   ----------------------------------------------------------------------------
   _XsMotifCorner class
*/

class _XsMotifCorner : public _XsMotifComponent {

   public:
   
// Enumerations

      enum Corner { TopLeft = 0, TopRight, BottomLeft, BottomRight, Max };
      
// Constructor/Destructor

      _XsMotifCorner (const char *name, XsMotifWindow *win, Corner corner);
      virtual ~_XsMotifCorner ( );

// Class name

      virtual const char *className ( ) const;
      
   protected:
   
// Implementation

      Corner      _corner;
      
// Event handlers

      virtual void _expose (XEvent*);
      virtual void _input (XEvent*);
      virtual void _map ( );
};

/*
   ----------------------------------------------------------------------------
   _XsMotifSide class
*/

class _XsMotifSide : public _XsMotifComponent {

   public:
   
// Enumerations

      enum Side { Top = 0, Bottom, Left, Right, Max };

// Constructor/Destructor

      _XsMotifSide (const char *name, XsMotifWindow *win, Side side);
      virtual ~_XsMotifSide ( );
      
// Class name

      virtual const char *className ( ) const;
      
   protected:
   
// Implementation

      Side     _side;
      
      int         _lastW;
      int         _lastH;

// Event handlers

      virtual void _expose (XEvent*);
      virtual void _input (XEvent*);
      virtual void _map ( );
      virtual void _configure (XEvent *);
      
   private:
   
// Callbacks

      static void _configureEventHandler (Widget, XtPointer, XEvent*, Boolean*);
};

/*
   ----------------------------------------------------------------------------
   _XsMotifButton class
*/

class _XsMotifButton : public _XsMotifComponent {

   public:
   
// Enumerations

      enum Button { Menu = 0, Minimize, Maximize, Max };

// Constructor/Destructor

      _XsMotifButton (const char *name, XsMotifWindow *win, Button button);
      virtual ~_XsMotifButton ( );
      
// Utilities

      virtual void redraw ( );

// Class name

      virtual const char *className ( ) const;
      
   protected:
   
// Implementation

      Boolean     _pressed;
      Button      _button;
      
// Event handlers

      virtual void _expose (XEvent*);
      virtual void _input (XEvent*);
      virtual void _map ( );
};

/*
   ----------------------------------------------------------------------------
   _XsMotifTitle class
*/

class _XsMotifTitle : public _XsMotifComponent {

   public:
   
// Constructor/Destructor

      _XsMotifTitle (const char *name, XsMotifWindow *win);
      virtual ~_XsMotifTitle ( );
      
// Title string

      void  setTitle (const char *name);
      const char *title ( ) const;
      
// Class name

      virtual const char *className ( ) const;
      
   protected:
   
// Implementation

      Boolean     _pressed;
      String      _titleString;
      GC          _fontGC;
      
      XFontStruct   *_titleFont;

      int         _lastW;
      int         _lastH;
      
// Component life-cycle

      virtual void _componentDestroyed ( );

// Utilities

      virtual void _redraw ( );
      
// Event handlers

      virtual void _expose (XEvent*);
      virtual void _input (XEvent*);
      virtual void _map ( );
      virtual void _configure (XEvent*);
      
   private:
   
// Callbacks

      static void _configureEventHandler (Widget, XtPointer, XEvent*, Boolean*);
      
// Resources

      static XtResource _resourceList[];
};

// Inline member functions

inline const char *_XsMotifTitle::title ( ) const
{
   return (_titleString);
}

/*
   ----------------------------------------------------------------------------
   _XsMotifIcon class
*/

class _XsMotifIcon : public _XsMotifComponent {

   public:
   
// Constructor/Destructor

      _XsMotifIcon (const char *name, XsMotifWindow *win, Widget parent);
      virtual ~_XsMotifIcon ( );
      
// Window operations

      virtual void show ( );
      
// Icon name/pixmap

      void  setIconName (const char *name);
      const char *iconName ( ) const;
      
      void  setPixmap (Pixmap pm);
      Pixmap pixmap ( ) const;
      
// Class name

      virtual const char *className ( ) const;
      
   protected:
   
// Implementation

      GC    _fontGC;
      GC    _pixmapGC;
      
      Dimension      _iconSize;
      String         _iconName;
      XFontStruct   *_iconFont;
      Pixmap         _pixmap;
      Boolean        _freePixmap;
      
      Dimension      _width, _height;
      Position       _iconX, _iconY;
      Boolean        _placed;
      
// Component life-cycle

      virtual void _componentDestroyed ( );

// Event handlers

      virtual void _expose (XEvent*);
      virtual void _input (XEvent*);
      virtual void _map ( );
      
   private:
   
// Resources

      static XtResource _resourceList[];
};

// Inline member-functions

inline const char *_XsMotifIcon::iconName ( ) const
{
   return (_iconName);
}

inline Pixmap _XsMotifIcon::pixmap ( ) const
{
   return (_pixmap);
}

/*
   ----------------------------------------------------------------------------
   _XsMotifMenu class
*/

class _XsMotifMenu : public _XsMotifBase {

   public:
   
// Constructor/Destructor

      _XsMotifMenu (const char *name, XsMotifWindow *win);
      virtual ~_XsMotifMenu ( );
      
// Utilities

      virtual void popup (Boolean atPointer = True);
      
// Enumerations

      enum Item {
         NoItem = -1, Restore, Move, Size, Minimize,
         Maximize, Raise, Lower, Close, Num
      };
      
// Class name

      virtual const char *className ( ) const;

   protected:

// Dimensions

      enum { ShadowThickness = 1 };
      enum { VertTextOffset = 3 };
      enum { HorizTextOffset = 10 };
            
// Implementation

      static Cursor  _cursor;
      static Pixmap  _stipple;
      static Display *_dpy;

      Boolean        _saveUnder;
      
      String         _strings[Num];
      XFontStruct   *_menuFont;

      GC             _fontGC;
      GC             _grayGC;
      GC             _backgroundGC;

      Item           _curItem;
      
// Component life-cycle

      virtual void _componentDestroyed ( );

// Menu event processing

      virtual void _processEvents ( );
      
// Utilities

      virtual void _processItem (Item item);
      virtual void _redrawMenu ( );

      void _redrawItem (Item);
      void _toggleItem (Item, Boolean active = False);
      Item _trackPointer (XMotionEvent *event);
      
// Pointer grabs

      Boolean  _grabPointer ( );
      void     _ungrabPointer ( );
      
// Event handlers

      virtual void _map ( );

   private:
   
// Work procedure

      static Boolean _workProc (XtPointer);
      
// Resources

      static XtResource _resourceList[];
      static int  _count;
};


/*
   ----------------------------------------------------------------------------
   XsMotifWindow class
*/

class XsMotifWindow : public XsMDIWindow {

   public:

// Constructor/Destructor

      XsMotifWindow (const char *name);
      virtual ~XsMotifWindow ( );
   
// Window manipulation

      virtual void raise ( );
      virtual void lower ( );

      virtual void minimize ( );
      virtual void maximize ( );
      virtual void restore ( );

      virtual void close ( );
      
// Window and icon strings

      void  setTitle (const char *name);
      const char *title ( ) const;
      
      void  setIconName (const char *name);
      const char *iconName ( ) const;
      
      void  setPixmap (Pixmap pm);
      Pixmap pixmap ( ) const;
      
// Window icon handle

      Widget   icon ( ) const;
      
// Menu settings

      void  popupMenu (Boolean atPointer = True);
      
// Utilities

      Boolean  maximized ( ) const;
      Boolean  minimized ( ) const;
      
// Position and size

      virtual void setPosition (Position, Position);
      virtual void setSize (Dimension, Dimension);

      Dimension minWidth ( ) const;
      Dimension minHeight ( ) const;
      
// Class name

      virtual const char *className ( ) const;

   protected:

// Window creation functions

      virtual void _buildClientArea (Widget parent) = 0;
      virtual void _createWindow (Widget parent);

// Window components

      _XsMotifCorner   *_corners[_XsMotifCorner::Max];
      _XsMotifSide     *_sides[_XsMotifSide::Max];
      _XsMotifButton   *_buttons[_XsMotifButton::Max];
      _XsMotifTitle    *_title;            
      _XsMotifIcon     *_icon;
      _XsMotifMenu     *_menu;
      
// Window dimensions

      Dimension   _savedWidth, _savedHeight;
      Position    _savedX, _savedY;
      Dimension   _minW, _maxW;
      Dimension   _minH, _maxH;
      
// Window parameters

      Boolean     _showBorder;
      Boolean     _showResize;
      Boolean     _showTitle;
      Boolean     _showMenu;
      Boolean     _showMinimize;
      Boolean     _showMaximize;
      Boolean     _lowerOnIconify;
      
// Window state

      Boolean     _maximized;
      Boolean     _minimized;
      
// Callbacks

      virtual void _mapEvent ( );
      
   private:
   
// Internal event handlers

      static void _mapEventHandler (Widget, XtPointer, XEvent*, Boolean*);

// Resources

      static XtResource _resourceList[];
};

// Inline member functions

inline Boolean XsMotifWindow::maximized ( ) const
{
   return (_maximized);
}

inline Boolean XsMotifWindow::minimized ( ) const
{
   return (_minimized);
}

inline const char *XsMotifWindow::title ( ) const
{
   if (_title != 0)
      return (_title->title ( ));
   else
      return (0);
}
      
inline const char *XsMotifWindow::iconName ( ) const
{
   if (_icon != 0)
      return (_icon->iconName ( ));
   else
      return (0);
}
      
inline Pixmap XsMotifWindow::pixmap ( ) const
{
   if (_icon != 0)
      return (_icon->pixmap ( ));
   else
      return (None);
}
      
inline Widget XsMotifWindow::icon ( ) const
{
   if (_icon != 0)
      return (_icon->base ( ));
   else
      return (0);
}
      
inline Dimension XsMotifWindow::minWidth ( ) const
{
   return (_minW);
}
   
inline Dimension XsMotifWindow::minHeight ( ) const
{
   return (_minH);
}
   
#endif
