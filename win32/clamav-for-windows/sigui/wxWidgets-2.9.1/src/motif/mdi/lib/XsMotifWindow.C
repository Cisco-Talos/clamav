/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsMotifWindow.C

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

// Includes

#include <assert.h>
#include <Xm/Form.h>
#include <Xm/RowColumn.h>
#include <Xm/SeparatoG.h>
#include <Xm/PushBG.h>
#include <X11/Shell.h>
#include <X11/cursorfont.h>
#include "XsMotifWindow.h"
#include "XsResizeOutline.h"
#include "XsMoveOutline.h"
#include "xs_motif_icon.xbm"

// Constants

const int BorderSize_   = 6;
const int ButtonSize_   = 23;
const int IconSize_     = 70;

/*
   ----------------------------------------------------------------------------
   _XsMotifBase
*/
   
// Constructor

_XsMotifBase::_XsMotifBase (const char *name, XsMotifWindow *win) :
   XsComponent (name)
{
   assert (win != 0);
   
// Initialize

   _win = win;
   _topShadowGC = 0;
   _bottomShadowGC = 0;
}
   
// Destructor

_XsMotifBase::~_XsMotifBase ( )
{
   if (_topShadowGC)
      XtReleaseGC (_base, _topShadowGC);

   if (_bottomShadowGC)
      XtReleaseGC (_base, _bottomShadowGC);
}

// show

void _XsMotifBase::show ( )
{
   assert (_base != 0);
   
// Install event handler

   XtAddEventHandler (_base, StructureNotifyMask, False, _mapEventHandler, (XtPointer)this);

// Call the base-class

   XsComponent::show ( );
}
   
// className

const char* _XsMotifBase::className ( ) const
{
   return ("_XsMotifBase");
}

// _componentDestroyed ( )

void _XsMotifBase::_componentDestroyed ( )
{

// Clean up the GCs

   if (_topShadowGC)
      XtReleaseGC (_base, _topShadowGC);

   if (_bottomShadowGC)
      XtReleaseGC (_base, _bottomShadowGC);

   _topShadowGC = 0;
   _bottomShadowGC = 0;
   
// Call the base-class

   XsComponent::_componentDestroyed ( );
}

// _drawShadows

void _XsMotifBase::_drawShadows (Position x, Position y, Dimension width,
   Dimension height, Dimension thick, Boolean reverse)
{
   assert (_base != 0);
   assert (thick > 0);
   
   const int nsegs = 2;
   XSegment segs[nsegs];
   GC    topShadowGC;
   GC    bottomShadowGC;
   
// Work out the graphics contexts

   topShadowGC = (reverse == False) ? _topShadowGC : _bottomShadowGC;
   bottomShadowGC = (reverse == False) ? _bottomShadowGC : _topShadowGC;
   
   for (int loop = 0; loop < thick; loop++)
   {

/*
   TOP SHADOW DRAWING
*/

// Across the top

      segs[0].x1 = x + loop;
      segs[0].y1 = y + loop;
      segs[0].x2 = x + width - loop - 2; 
      segs[0].y2 = y + loop;
      
// Down the left side

      segs[1].x1 = x + loop;
      segs[1].y1 = y + loop + 1;
      segs[1].x2 = x + loop;
      segs[1].y2 = y + height - loop - 2;
      
      XDrawSegments (XtDisplay (_base), XtWindow (_base), topShadowGC, segs, nsegs);

/*
   BOTTOM SHADOW DRAWING
*/
      
// Across the bottom

      segs[0].x1 = x + loop;
      segs[0].y1 = y + height - loop - 1;
      segs[0].x2 = x + width - loop - 1;
      segs[0].y2 = y + height - loop - 1;
      
// Down the right side

      segs[1].x1 = x + width - loop - 1;
      segs[1].y1 = y + loop;
      segs[1].x2 = x + width - loop - 1;
      segs[1].y2 = y + height - loop - 1;

      XDrawSegments (XtDisplay (_base), XtWindow (_base), bottomShadowGC, segs, nsegs);
   }   
}

// _drawLine

void _XsMotifBase::_drawLine (Position x1, Position y1, Position x2, Position y2, GC &gc)
{
   assert (_base != 0);
   XDrawLine (XtDisplay (_base), XtWindow (_base), gc, x1, y1, x2, y2);
}
   
// _map

void _XsMotifBase::_map ( )
{

// Create the graphics contexts

   unsigned long valuemask;
   XGCValues   values;
   Pixel topShadow;
   Pixel bottomShadow;

   XtVaGetValues (_win->base ( ), XmNtopShadowColor, &topShadow, XmNbottomShadowColor, 
      &bottomShadow, NULL);

// Create the graphics contexts

   valuemask = GCForeground | GCLineWidth | GCGraphicsExposures;
   values.line_width = 0;
   values.graphics_exposures = False;
   
   values.foreground = topShadow;
   _topShadowGC = XtGetGC (_base, valuemask, &values);

   values.foreground = bottomShadow;
   _bottomShadowGC = XtGetGC (_base, valuemask, &values);
}

// _mapEventHandler

void _XsMotifBase::_mapEventHandler (Widget, XtPointer clientData, XEvent *event, Boolean*)
{
   if (event->type == MapNotify)
   {
      _XsMotifBase *obj = (_XsMotifBase*)clientData;
      obj->_map ( );

// Remove the event handler

      XtRemoveEventHandler (obj->_base, StructureNotifyMask, False, obj->_mapEventHandler, clientData);
   }
}

/*
   ----------------------------------------------------------------------------
   _XsMotifComponent
*/
   
Cursor _XsMotifComponent::_cursors[_XsMotifComponent::NumCursors];

int _XsMotifComponent::_mutex = 0;

XtResource _XsMotifComponent::_resourceList[] = {
   {
      "borderSize",
      "BorderSize",
      XmRDimension,
      sizeof (Dimension),
      XtOffset (_XsMotifComponent*, _borderSize),
      XmRImmediate,
      (XtPointer)BorderSize_
   },
   {
      "buttonSize",
      "ButtonSize",
      XmRDimension,
      sizeof (Dimension),
      XtOffset (_XsMotifComponent*, _buttonSize),
      XmRImmediate,
      (XtPointer)ButtonSize_
   }
};

// Constructor

_XsMotifComponent::_XsMotifComponent (const char *name, XsMotifWindow *win,
   Widget parent) : _XsMotifBase (name, win)
{
   
// Create cursors (if necessary)

   if (_mutex == 0)
   {

      Display *dpy = XtDisplay (win->base ( ));

      _cursors[TopCursor] = XCreateFontCursor (dpy, XC_top_side);
      _cursors[BottomCursor] = XCreateFontCursor (dpy, XC_bottom_side);
      _cursors[LeftCursor] = XCreateFontCursor (dpy, XC_left_side);
      _cursors[RightCursor] = XCreateFontCursor (dpy, XC_right_side);
      _cursors[TopLeftCursor] = XCreateFontCursor (dpy, XC_top_left_corner);
      _cursors[TopRightCursor] = XCreateFontCursor (dpy, XC_top_right_corner);
      _cursors[BottomLeftCursor] = XCreateFontCursor (dpy, XC_bottom_left_corner);
      _cursors[BottomRightCursor] = XCreateFontCursor (dpy, XC_bottom_right_corner);

      _mutex = 1;
   }

// Create the component

   _base = XtVaCreateWidget (name, widgetClass, (parent != 0) ? parent : _win->base ( ), NULL);

// Install destroy handler

   _installDestroyHandler ( );
   
// Get resources
   
   _getResources (_resourceList, XtNumber (_resourceList));

// Compute the corner size

   _cornerSize = _buttonSize + _borderSize;

// Install event handlers

   XtAddEventHandler (_base, ExposureMask, False, _exposeEventHandler, (XtPointer)this);
   XtAddEventHandler (_base, ButtonPressMask | ButtonReleaseMask | Button1MotionMask | Button2MotionMask, False, _inputEventHandler, (XtPointer)this);
}

// Destructor

_XsMotifComponent::~_XsMotifComponent ( )
{
   // Empty
}

// className

const char* _XsMotifComponent::className ( ) const
{
   return ("_XsMotifComponent");
}

// _input

void _XsMotifComponent::_input (XEvent*)
{
   // Empty
}

// _exposeEventHandler

void _XsMotifComponent::_exposeEventHandler (Widget, XtPointer clientData, XEvent *event, Boolean*)
{
   _XsMotifComponent *obj = (_XsMotifComponent*)clientData;

   if (event->xexpose.count == 0)
      obj->_expose (event);
}

// _inputEventHandler

void _XsMotifComponent::_inputEventHandler (Widget, XtPointer clientData, XEvent *event, Boolean*)
{
   _XsMotifComponent *obj = (_XsMotifComponent*)clientData;
   obj->_input (event);
}

/*
   ----------------------------------------------------------------------------
   _XsMotifCorner
*/

// Constructor

_XsMotifCorner::_XsMotifCorner (const char *name, XsMotifWindow *win, Corner corner)
   : _XsMotifComponent (name, win)
{
   
// Initialize

   _corner = corner;

// Configure component

   XtVaSetValues (_base, XmNwidth, _cornerSize, XmNheight, _cornerSize,
      XmNborderWidth, (Dimension)0, NULL);
}

// Destructor

_XsMotifCorner::~_XsMotifCorner ( )
{
   // Empty
}

// className

const char *_XsMotifCorner::className ( ) const
{
   return ("_XsMotifCorner");
}

// _expose

void _XsMotifCorner::_expose (XEvent*)
{
   Dimension   w, h;

   if (_topShadowGC == 0) // JACS
     return;

// Get the size of the corner

   XtVaGetValues (_base, XmNwidth, &w, XmNheight, &h, NULL);
   
// Draw the shadow

   _drawShadows (0, 0, w, h, 1);

// Draw the extra lines and relief

   switch (_corner)
   {
      case TopLeft:
      {
         _drawLine (1, 1, w - 2, 1, _topShadowGC);
         _drawLine (1, 1, 1, h - 2, _topShadowGC);

// Relief

         _drawLine (_borderSize - 1, _borderSize - 1, _borderSize +
            _buttonSize - 2, _borderSize - 1, _bottomShadowGC);

         _drawLine (_borderSize - 1, _borderSize - 1, _borderSize - 1,
            _borderSize + _buttonSize - 2, _bottomShadowGC);
         
         break;
      }
      case TopRight:
      {
         _drawLine (1, 1, w - 2, 1, _topShadowGC);
         _drawLine (w - 2, 1, w - 2, h - 2, _bottomShadowGC);

// Relief

         _drawLine (0, _borderSize - 1, _buttonSize - 1, _borderSize - 1,
            _bottomShadowGC);

         _drawLine (w - _borderSize, _borderSize - 1, w - _borderSize,
            _borderSize + _buttonSize - 2, _topShadowGC);            

         break;
      }
      case BottomLeft:
      {
         _drawLine (1, 1, 1, h - 2, _topShadowGC);
         _drawLine (1, h - 2, w - 2, h - 2, _bottomShadowGC);

// Relief

         _drawLine (_borderSize - 1, h - _borderSize, _borderSize +
            _buttonSize - 2, h - _borderSize, _topShadowGC);

         _drawLine (_borderSize - 1, 1, _borderSize - 1,
            _buttonSize - 1, _bottomShadowGC);

         break;
      }
      case BottomRight:
      {
         _drawLine (1, h - 2, w - 2, h - 2, _bottomShadowGC);
         _drawLine (w - 2, 1, w - 2, h - 2, _bottomShadowGC);

// Relief

         _drawLine (1, h - _borderSize, _buttonSize, h - _borderSize,
            _topShadowGC);

         _drawLine (w - _borderSize, 1, w - _borderSize,
            _buttonSize - 1, _topShadowGC);

         break;
      }
      default:
         assert (0);
   }         
}

// _input

void _XsMotifCorner::_input (XEvent *event)
{
   switch (event->type)
   {
      case ButtonPress:
      {
         if (event->xbutton.button == 2)
         {
            XsMoveOutline move (_win->base ( ));

// Start the move

            if (move.go ( ) != False)
            {

// Relocate the window      
   
               _win->setPosition (move.x ( ), move.y ( ));
            }
         }
         else if (event->xbutton.button == 3)
            _win->popupMenu ( );

         break;
      }
      case ButtonRelease:
      {
         switch (event->xbutton.button)
         {
            case 1:
            case 2:
            {
               _win->raise ( );     // Raise the window
               break;
            }
         }
         break;
      }
      case MotionNotify:
      {

// Figure kind of resize we are doing

         int   dir;
            
         if (_corner == TopLeft)
            dir = XsResizeOutline::Up | XsResizeOutline::Left;
         else if (_corner == TopRight)
            dir = XsResizeOutline::Up | XsResizeOutline::Right;
         else if (_corner == BottomLeft)
            dir = XsResizeOutline::Down | XsResizeOutline::Left;
         else if (_corner == BottomRight)
            dir = XsResizeOutline::Down | XsResizeOutline::Right;
         else
            assert (0);

         XsResizeOutline resize (_win->base ( ), dir);
         resize.setMinSize (_win->minWidth ( ), _win->minHeight ( ));
         
// Start the resize

         if (resize.go ( ) != False)
         {

// Relocate the window      
   
            _win->setPosition (resize.x ( ), resize.y ( ));
            _win->setSize (resize.width ( ), resize.height ( ));
         }
         break;
      }
   }
}

// _map

void _XsMotifCorner::_map ( )
{

// Call the base-class

   _XsMotifComponent::_map ( );

// Install the cursor

   if (_corner == TopLeft)
      XDefineCursor (XtDisplay (_base), XtWindow (_base), _cursors[TopLeftCursor]);
   else if (_corner == TopRight)
      XDefineCursor (XtDisplay (_base), XtWindow (_base), _cursors[TopRightCursor]);
   else if (_corner == BottomLeft)
      XDefineCursor (XtDisplay (_base), XtWindow (_base), _cursors[BottomLeftCursor]);
   else if (_corner == BottomRight)
      XDefineCursor (XtDisplay (_base), XtWindow (_base), _cursors[BottomRightCursor]);
   else
      assert (0);
}

/*
   ----------------------------------------------------------------------------
   _XsMotifSide
*/

// Constructor

_XsMotifSide::_XsMotifSide (const char *name, XsMotifWindow *win, Side side) :
   _XsMotifComponent (name, win)
{
   
// Initialize

   _side = side;
   _lastW = _lastH = -1;

// Configure component

   switch (_side)
   {
      case Top:
      case Bottom:
      {
         XtVaSetValues (_base, XmNheight, _borderSize, XmNborderWidth,
            (Dimension)0, NULL);
         break;
      }
      case Left:
      case Right:
      {
         XtVaSetValues (_base, XmNwidth, _borderSize, XmNborderWidth,
            (Dimension)0, NULL);
         break;
      }
      default:
         assert (0);      
   }

// Install event handler

   XtAddEventHandler (_base, StructureNotifyMask, False, _configureEventHandler, (XtPointer)this);
}

// Destructor

_XsMotifSide::~_XsMotifSide ( )
{
   // Empty
}

// className

const char *_XsMotifSide::className ( ) const
{
   return ("_XsMotifSide");
}

// _expose

void _XsMotifSide::_expose (XEvent *event)
{
   if (_topShadowGC == 0) // JACS
     return;

// Clear out the window first

   if (event != 0)
      XClearWindow (XtDisplay (_base), XtWindow (_base));
   
   Dimension   w, h;

// Get the size of the side

   XtVaGetValues (_base, XmNwidth, &w, XmNheight, &h, NULL);
   
// Draw the shadow

   _drawShadows (0, 0, w, h, 1);

// Draw the extra lines

   switch (_side)
   {
      case Top:
      {
         _drawLine (1, 1, w - 2, 1, _topShadowGC);
         break;
      }
      case Bottom:
      {
         _drawLine (1, h - 2, w - 2, h - 2, _bottomShadowGC);
         break;
      }
      case Left:
      {
         _drawLine (1, 1, 1, h - 2, _topShadowGC);
         break;
      }
      case Right:
      {
         _drawLine (w - 2, 1, w - 2, h - 2, _bottomShadowGC);
         break;
      }
      default:
         assert (0);
   }
}
         
// _input

void _XsMotifSide::_input (XEvent *event)
{
   switch (event->type)
   {
      case ButtonPress:
      {
         if (event->xbutton.button == 2)
         {
            XsMoveOutline move (_win->base ( ));

// Start the move

            if (move.go ( ) != False)
            {

// Relocate the window      
   
               _win->setPosition (move.x ( ), move.y ( ));
            }
         }
         else if (event->xbutton.button == 3)
            _win->popupMenu ( );

         break;
      }
      case ButtonRelease:
      {
         switch (event->xbutton.button)
         {
            case 1:
            case 2:
            {
               _win->raise ( );     // Raise the window
               break;
            }
         }
         break;
      }
      case MotionNotify:
      {

// Figure kind of resize we are doing

         int   dir;
         
         if (_side == Top)
            dir = XsResizeOutline::Up;
         else if (_side == Bottom)
            dir = XsResizeOutline::Down;
         else if (_side == Left)
            dir = XsResizeOutline::Left;
         else if (_side == Right)
            dir = XsResizeOutline::Right;
         else
            assert (0);

         XsResizeOutline resize (_win->base ( ), dir);
         resize.setMinSize (_win->minWidth ( ), _win->minHeight ( ));

// Start the resize

         if (resize.go ( ) != False)
         {

// Relocate the window      
   
            _win->setPosition (resize.x ( ), resize.y ( ));
            _win->setSize (resize.width ( ), resize.height ( ));
         }
         break;
      }
   }
}

// _map

void _XsMotifSide::_map ( )
{

// Call the base-class

   _XsMotifComponent::_map ( );

// Install the cursor

   if (_side == Top)
      XDefineCursor (XtDisplay (_base), XtWindow (_base), _cursors[TopCursor]);
   else if (_side == Bottom)
      XDefineCursor (XtDisplay (_base), XtWindow (_base), _cursors[BottomCursor]);
   else if (_side == Left)
      XDefineCursor (XtDisplay (_base), XtWindow (_base), _cursors[LeftCursor]);
   else if (_side == Right)
      XDefineCursor (XtDisplay (_base), XtWindow (_base), _cursors[RightCursor]);
   else
      assert (0);
}

// _configure

void _XsMotifSide::_configure (XEvent *event)
{
   XConfigureEvent *ce = (XConfigureEvent*)event;
   
/*
   Check if window has been resized.  If so, generate an expose event
   to redraw its contents.
*/

   if ((_lastW != ce->width) || (_lastH != ce->height))
   {
      if ((_base != 0) && XtIsManaged (_base))
         XClearArea (XtDisplay (_base), XtWindow (_base), 0, 0, 0, 0, True);

      _lastW = ce->width;
      _lastH = ce->height;
   }
}

// _configureEventHandler

void _XsMotifSide::_configureEventHandler (Widget, XtPointer clientData, XEvent *event, Boolean*)
{
   if (event->type == ConfigureNotify)
   {
      _XsMotifSide *obj = (_XsMotifSide*)clientData;
      obj->_configure (event);
   }
}

/*
   ----------------------------------------------------------------------------
   _XsMotifButton
*/

// Constructor

_XsMotifButton::_XsMotifButton (const char *name, XsMotifWindow *win, Button button) :
   _XsMotifComponent (name, win)
{
   
// Initialize

   _pressed = False;
   _button = button;

// Configure the component

   XtVaSetValues (_base, XmNheight, _buttonSize, XmNwidth, _buttonSize,
      XmNborderWidth, (Dimension)0, NULL);
}

// Destructor

_XsMotifButton::~_XsMotifButton ( )
{
   // Empty
}

// redraw

void _XsMotifButton::redraw ( )
{

// Make sure component is viewable

   if (!XtIsRealized (_base))
      return;
      
// Check if window is viewable

   XWindowAttributes attrs;
   XGetWindowAttributes (XtDisplay (_base), XtWindow (_base), &attrs);
   
   if (attrs.map_state == IsViewable)
      _expose (0);      // Just pretend we got an expose event
}
   
// className

const char *_XsMotifButton::className ( ) const
{
   return ("_XsMotifButton");
}

// _expose

void _XsMotifButton::_expose (XEvent *event)
{
   if (_topShadowGC == 0) // JACS
     return;

   Dimension   w, h;

// Get the size of the button

   XtVaGetValues (_base, XmNwidth, &w, XmNheight, &h, NULL);
   
// Draw the shadow

   _drawShadows (0, 0, w, h, 1, _pressed);

// Draw the extra line

   _drawLine (1, h - 2, w - 2, h - 2, (_pressed) ? _topShadowGC : _bottomShadowGC);

// Check if we need to draw the decal

   if ((_button != Maximize) && (event == 0))
      return;
      
// Compute the decal size

   Dimension dw, dh;
   Boolean  reverse = False;
   
   switch (_button)
   {
      case Menu:
      {
         dw = _buttonSize - 6;
	 dh = 4;
         break;            
      }
      case Minimize:
      {
         dw = dh = 4;
         break;
      }
      case Maximize:
      {
         dw = _buttonSize - 6;
         dh = dw - 1;

         if (_win->maximized ( ))
            reverse = True;
            
         break;
      }
      default:
         assert (0);
   }

// Draw the decal

   _drawShadows ((w / 2) - (dw / 2), (h / 2) - (dh / 2), dw, dh, 1, reverse);
}

// _input

void _XsMotifButton::_input (XEvent *event)
{
   static Time lastTime = (Time)0;
   
   switch (event->type)
   {
      case ButtonPress:
      {
         if (event->xbutton.button == 1)
         {
            _pressed = True;
         
            if (_button == Menu)
            {

// Get double-click time

               int multiClick = XtGetMultiClickTime (XtDisplay (_base));

// Check for double-click

               if ((event->xbutton.time - lastTime) <= multiClick)
               {
                  _win->close ( );
                  return;
               }                  
               else
                  lastTime = event->xbutton.time;                  

// Redraw the button (pushed-in)

               redraw ( );

// Popup the menu

               _win->popupMenu (False);

// The menu will consume the ButtonRelease, so fake one

               _pressed = False;
               redraw ( );

            }
            else if ((_button == Minimize) || (_button == Maximize))
            {
               redraw ( );
            }
         }
         else if (event->xbutton.button == 2)            
         {
            XsMoveOutline move (_win->base ( ));

// Start the move

            if (move.go ( ) != False)
            {

// Relocate the window      
   
               _win->setPosition (move.x ( ), move.y ( ));
            }
         }
         else if (event->xbutton.button == 3)
            _win->popupMenu ( );

         break;
      }
      case ButtonRelease:
      {
         if (event->xbutton.button == 1)
         {
            _pressed = False;

// Check if pointer is really in the window

            XButtonEvent *b = &event->xbutton;
            Dimension width, height;
            Boolean  inWindow = False;

            XtVaGetValues (_base, XmNwidth, &width, XmNheight, &height, NULL);
            if ((b->x >= 0) && (b->y >= 0) && (b->x < width) && (b->y < height))
               inWindow = True;

            if (_button == Minimize)
            {
               if (inWindow)
               {
                  if (_win->minimized ( ))
                     _win->restore ( );
                  else
                     _win->minimize ( );
               }
               else
                  redraw ( );
            }
            else if (_button == Maximize)
            {
               if (inWindow)
               {
                  if (_win->maximized ( ))
                     _win->restore ( );
                  else
                     _win->maximize ( );
               }
               else                  
                  redraw ( );
            }
         }
         break;
      }
   }
}

// _map

void _XsMotifButton::_map ( )
{
   
// Call the base-class
      
   _XsMotifComponent::_map ( );
	 
// Raise ourself

   XRaiseWindow (XtDisplay (_base), XtWindow (_base));
}
   
/*
   ----------------------------------------------------------------------------
   _XsMotifTitle
*/

XtResource _XsMotifTitle::_resourceList[] = {
   {
      "title",
      "Title",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifTitle*, _titleString),
      XmRImmediate,
      NULL
   },
   {
      "titleFont",
      "TitleFont",
      XmRFontStruct,
      sizeof (XFontStruct*),
      XtOffset (_XsMotifTitle*, _titleFont),
      XmRString,
      "-*-helvetica-bold-o-normal-*-14-*-*-*-*-*-iso8859-1"
   }
};

// Constructor

_XsMotifTitle::_XsMotifTitle (const char *name, XsMotifWindow *win) :
   _XsMotifComponent (name, win)
{
   
// Initialize

   _pressed = False;
   _titleString = 0;
   _titleFont = 0;
   _fontGC = 0;
   _lastW = _lastH = -1;
   
// Get resources
   
   _getResources (_resourceList, XtNumber (_resourceList));

// Copy title string to local memory

   if (_titleString != 0)
   {
      char *tmp = new char[strlen (_titleString) + 1];
      strcpy (tmp, _titleString);
      _titleString = tmp;
   }
         
// Configure the title

   XtVaSetValues (_base,  XmNheight, _buttonSize, XmNborderWidth,
      (Dimension)0, NULL);

// Install event handler

   XtAddEventHandler (_base, StructureNotifyMask, False, _configureEventHandler, (XtPointer)this);
}

// Destructor

_XsMotifTitle::~_XsMotifTitle ( )
{
   if (_fontGC)
      XtReleaseGC (_base, _fontGC);

   delete [] _titleString;
}

// setTitle

void _XsMotifTitle::setTitle (const char *title)
{
   assert (title != 0);
      
   delete [] _titleString;
   
   _titleString = new char[strlen (title) + 1];
   strcpy (_titleString, title);
}   

// className

const char *_XsMotifTitle::className ( ) const
{
   return ("_XsMotifTitle");
}

// _componentDestroyed

void _XsMotifTitle::_componentDestroyed ( )
{
   
// Clean up the GCs

   if (_fontGC)
      XtReleaseGC (_base, _fontGC);

   _fontGC = 0;
   
// Call base-class

   _XsMotifComponent::_componentDestroyed ( );
}
   
// _redraw

void _XsMotifTitle::_redraw ( )
{
   _expose (0);      // Just pretend we got an expose event
}

// _expose

void _XsMotifTitle::_expose (XEvent *event)
{
   if (_topShadowGC == 0) // JACS
     return;

// Clear out the window first

   if (event != 0)
      XClearWindow (XtDisplay (_base), XtWindow (_base));
   
   Dimension   w, h;

// Get the size of the button

   XtVaGetValues (_base, XmNwidth, &w, XmNheight, &h, NULL);
   
// Draw the shadow

   _drawShadows (0, 0, w, h, 1, _pressed);

// Draw the extra line

   _drawLine (1, h - 2, w - 2, h - 2, (_pressed) ? _topShadowGC : _bottomShadowGC);

// If this is an artificial event, no need continuing

   if (event == 0)
      return;
      
// Draw the text string

   const int LeftOffset = 5;
   const int TopOffset = 2;

// Figure out the title

   const char *title = (_titleString != 0) ? _titleString : _win->name ( );
         
   if ((title != 0) && (title[0] != '\0'))
   {
      int len = strlen (title);

      XDrawString (XtDisplay (_base), XtWindow (_base), _fontGC,
         LeftOffset, TopOffset + _titleFont->ascent, title, len);
   }
}

// _input

void _XsMotifTitle::_input (XEvent *event)
{
   switch (event->type)
   {
      case ButtonPress:
      {
         switch (event->xbutton.button)
         {
            case 1:
            {
               _pressed = True;
               _redraw ( );
               break;
            }
            case 2:
            {
               XsMoveOutline move (_win->base ( ));

// Start the move

               if (move.go ( ) != False)
               {

// Relocate the window      
   
                  _win->setPosition (move.x ( ), move.y ( ));
               }
               break;
            }
            case 3:
            {
               _win->popupMenu ( );
               break;
            }
         }
         break;
      }         
      case ButtonRelease:
      {
         switch (event->xbutton.button)
         {
            case 1:
            case 2:
            {
               _pressed = False;
               _redraw ( );

               _win->raise ( );
               break;
            }
         }
         break;
      }
      case MotionNotify:
      {
         XsMoveOutline move (_win->base ( ));

// Start the move

         if (move.go ( ) != False)
         {

// Relocate the window      
   
            _win->setPosition (move.x ( ), move.y ( ));

// Redraw the title bar

            _pressed = False;
            _redraw ( );
         }
         break;
      }
   }
}

// _map

void _XsMotifTitle::_map ( )
{
   
// Call the base-class

   _XsMotifComponent::_map ( );

// Raise ourself
   
   XRaiseWindow (XtDisplay (_base), XtWindow (_base));
   
   unsigned long valuemask;
   XGCValues   values;
   Pixel foreground;
   Pixel background;

// Get the pixels

   XtVaGetValues (_win->base ( ), XmNforeground, &foreground, XmNbackground, &background, NULL);

// Create the font graphics context

   valuemask = GCForeground | GCBackground | GCGraphicsExposures | GCFont;

   values.foreground = foreground;
   values.background = background;
   values.font = _titleFont->fid;
   values.graphics_exposures = False;

   _fontGC = XtGetGC (_base, valuemask, &values);
}

// _configure

void _XsMotifTitle::_configure (XEvent *event)
{
   XConfigureEvent *ce = (XConfigureEvent*)event;
   
/*
   Check if window has been resized.  If so, generate an expose event
   to redraw its contents.
*/

   if ((_lastW != ce->width) || (_lastH != ce->height))
   {
      if ((_base != 0) && XtIsManaged (_base))
         XClearArea (XtDisplay (_base), XtWindow (_base), 0, 0, 0, 0, True);

      _lastW = ce->width;
      _lastH = ce->height;
   }
}

// _configureEventHandler

void _XsMotifTitle::_configureEventHandler (Widget, XtPointer clientData, XEvent *event, Boolean*)
{
   if (event->type == ConfigureNotify)
   {
      _XsMotifTitle *obj = (_XsMotifTitle*)clientData;
      obj->_configure (event);
   }
}

/*
   ----------------------------------------------------------------------------
   _XsMotifIcon
*/

XtResource _XsMotifIcon::_resourceList[] = {
   {
      "iconSize",
      "IconSize",
      XmRDimension,
      sizeof (Dimension),
      XtOffset (_XsMotifIcon*, _iconSize),
      XmRImmediate,
      (XtPointer)IconSize_
   },
   {
      "iconName",
      "IconName",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifIcon*, _iconName),
      XmRImmediate,
      NULL
   },
   {
      "iconFont",
      "IconFont",
      XmRFontStruct,
      sizeof (XFontStruct*),
      XtOffset (_XsMotifIcon*, _iconFont),
      XmRString,
      "-*-helvetica-bold-r-normal-*-12-*-*-*-*-*-iso8859-1"
   },
   {
      XmNiconX,
      XmCIconX,
      XmRPosition,
      sizeof (Position),
      XtOffset (_XsMotifIcon*, _iconX),
      XmRImmediate,
      (XtPointer)-1
   },      
   {
      XmNiconY,
      XmCIconY,
      XmRPosition,
      sizeof (Position),
      XtOffset (_XsMotifIcon*, _iconY),
      XmRImmediate,
      (XtPointer)-1
   }
};

// Constructor

_XsMotifIcon::_XsMotifIcon (const char *name, XsMotifWindow *win, Widget parent) :
   _XsMotifComponent (name, win, parent)
{
   
// Initialize

   _pixmapGC = 0;
   _fontGC = 0;

   _iconName = 0;
   _pixmap = 0;
   _freePixmap = False;
   
   _width = _height = 0;
   _placed = 0;
   
// Get resources
   
   _getResources (_resourceList, XtNumber (_resourceList));

// Copy icon name to local memory

   if (_iconName != 0)
   {
      char *tmp = new char[strlen (_iconName) + 1];
      strcpy (tmp, _iconName);
      _iconName = tmp;
   }

// Configure the icon

   XtVaSetValues (_base, XmNwidth, _iconSize, XmNheight, _iconSize, NULL);
}

// Destructor

_XsMotifIcon::~_XsMotifIcon ( )
{
   if (_fontGC)
      XtReleaseGC (_base, _fontGC);
      
   if (_pixmapGC)
      XtReleaseGC (_base, _pixmapGC);
      
   if (_freePixmap)
      XFreePixmap (XtDisplay (_base), _pixmap);

   delete [] _iconName;
}

// show

void _XsMotifIcon::show ( )
{

/*
   Configure the icon position.  Either use the position specified
   in the resource, or place the icon at the top-left corner of the
   window.
*/

   if (_placed == False)
   {
      Position x, y;
   
      if (_iconX == -1)
      {
         XtVaGetValues (_win->base ( ), XmNx, &x, NULL);
         if (x < 0)  x = 0;
         _iconX = x;
      }
      else
         x = _iconX;
      
      if (_iconY == -1)
      {
         XtVaGetValues (_win->base ( ), XmNy, &y, NULL);
         if (y < 0)  y = 0;
         _iconY = y;
      }
      else
         y = _iconY;
      
      XtVaSetValues (_base, XmNx, x, XmNy, y, NULL);

      _placed = True;
   }
   
// Call the base class

   _XsMotifComponent::show ( );
}

// setIconName

void _XsMotifIcon::setIconName (const char *iconName)
{
   assert (iconName != 0);

   delete [] _iconName;
   
   _iconName = new char[strlen (iconName) + 1];
   strcpy (_iconName, iconName);
}

// setPixmap

void _XsMotifIcon::setPixmap (Pixmap pixmap)
{
   assert (pixmap != 0);
   
// Free the existing pixmap (if necessary)

   if (_freePixmap)
   {
      XFreePixmap (XtDisplay (_base), _pixmap);
      _freePixmap = False;
   }
   
// Save the new pixmap

   _pixmap = pixmap;

// Get the pixmap width and height

   Window   dummy;
   int      xd, yd;
   unsigned int   uw, uh, ub, ud;
   
   XGetGeometry (XtDisplay (_base), _pixmap, &dummy, &xd, &yd, &uw, &uh, &ub, &ud);

   _width = uw;
   _height = uh;
}
   
// className

const char *_XsMotifIcon::className ( ) const
{
   return ("_XsMotifIcon");
}

// _componentDestroyed

void _XsMotifIcon::_componentDestroyed ( )
{
   
// Clear up the GCs

   if (_fontGC)
      XtReleaseGC (_base, _fontGC);

   if (_pixmapGC)
      XtReleaseGC (_base, _pixmapGC);

   if (_freePixmap)
      XFreePixmap (XtDisplay (_base), _pixmap);

   _fontGC = 0;
   _pixmapGC = 0;
   _freePixmap = 0;
   
// Call the base-class

   _XsMotifComponent::_componentDestroyed ( );
}
   
// _input

void _XsMotifIcon::_input (XEvent *event)
{
   static Time lastTime = (Time)0;
   
   switch (event->type)
   {
      case ButtonPress:
      {
         switch (event->xbutton.button)
         {
            case 1:
               break;

            case 2:
            {
               XsMoveOutline move (_base);

// Start the move

               if (move.go ( ) != False)
               {

// Relocate the window      
   
                  _win->setPosition (move.x ( ), move.y ( ));
               }
               break;
            }
            case 3:
            {
               _win->popupMenu ( );
               break;
            }               
         }
         break;
      }         
      case ButtonRelease:
      {
         switch (event->xbutton.button)
         {
            case 1:
            {

// Get double-click time

               int multiClick = XtGetMultiClickTime (XtDisplay (_base));

// Check for double-click

               if ((event->xbutton.time - lastTime) <= multiClick)
                  _win->restore ( );
               else
               {
                  lastTime = event->xbutton.time;
                  _win->raise ( );
               }
               break;
            }
         }
         break;
      }
      case MotionNotify:
      {
         XsMoveOutline  move (_base);

// Start the move

         if (move.go ( ) != False)
         {

// Relocate the icon
   
            _win->setPosition (move.x ( ), move.y ( ));
         }
         break;
      }
   }
}

// _expose

void _XsMotifIcon::_expose (XEvent *)
{
   if (_topShadowGC == 0) // JACS
     return;

   Dimension   iconHeight;
   Dimension   iconWidth;

// Compute icon size

   XtVaGetValues (_base, XmNwidth, &iconWidth, XmNheight, &iconHeight, NULL);
         
// Draw the shadow

   _drawShadows (0, 0, iconWidth, iconHeight, 2);

// Figure out the icon string

   const char *iconName = (_iconName != 0) ? _iconName : (_win->title ( ) != 0) ?
      _win->title ( ) : _win->name ( );
         
   const int fontX = 3;
   const int fontY = 3;
   
   if ((iconName != 0) && (iconName[0] != '\0'))
   {
      int   textWidth;
      int   len = strlen (iconName);
         
// Compute the text size

      textWidth = XTextWidth (_iconFont, iconName, len);

// Center the text in the bottom of the icon (or left-justify it)
      
      int   x, y;

      if (textWidth <= (iconWidth - (fontX * 2)))
         x = (iconWidth - (int)textWidth) / 2;
      else
         x = fontX;
           
      y = (int)iconHeight - _iconFont->descent - fontY;

// Draw the string

      XDrawString (XtDisplay (_base), XtWindow (_base), _fontGC,
         x, y, iconName, len);
   }

// Compute label size

   int labelHeight = _iconFont->descent + _iconFont->ascent + (fontY * 2);
   
   if (labelHeight >= (iconHeight - 6))
      return;
      
// Draw the separator

   int sepY = (iconHeight) - labelHeight;

   _drawLine (1, sepY, iconWidth - 2, sepY, _bottomShadowGC);
   _drawLine (1, sepY + 1, iconWidth - 2, sepY + 1, _topShadowGC);

// Draw the pixmap frame

   const int frameX = 4;
   const int frameY = 4;
   
   if ((frameX + 6) >= sepY)
      return;
      
   int   frameWidth = iconWidth - (frameX * 2);
   int   frameHeight = sepY - frameY - 2;
   
   _drawShadows (frameX, frameY, frameWidth, frameHeight, 1, True);

   frameWidth -= 2;
   frameHeight -= 2;
   
   _drawShadows (frameX + 1, frameY + 1, frameWidth, frameHeight, 1);
   
   frameWidth -= 2;
   frameHeight -= 2;

// Blit the pixmap

   if (_pixmap != 0)
   {
      if ((frameWidth > 0) && (frameHeight > 0))
      {
         int   origX, origY;
         int   drawW, drawH;
         
// Center the pixmap or top-left orient it

         if (frameWidth > _width)
         {
            origX = (frameWidth - _width) / 2;
            origX += frameX + 2;
            drawW = _width;
         }
         else
         {
            origX = frameX + 2;
            drawW = frameWidth;
         }
            
         if (frameHeight > _height)
         {
            origY = (frameHeight - _height) / 2;
            origY += frameY + 2;
            drawH = _height;
         }
         else
         {
            origY = frameY + 2;
            drawH = frameHeight;
         }
      
         XCopyArea (XtDisplay (_base), _pixmap, XtWindow (_base), _pixmapGC,
            0, 0, drawW, drawH, origX, origY);
      }
   }
}
   
// _map

void _XsMotifIcon::_map ( )
{
   unsigned long valuemask;
   XGCValues   values;
   Pixel fg;
   Pixel bg;
   int   depth;
   
// Call the base-class
      
   _XsMotifComponent::_map ( );
	 
// Get the icon pixels

   XtVaGetValues (_win->base ( ), XmNdepth, &depth, XmNbackground, &bg,
      XmNforeground, &fg, NULL);
      
// Create the default icon pixmap

   if (_pixmap == 0)
   {
      _pixmap = XCreatePixmapFromBitmapData (XtDisplay (_base), XtWindow (_base),
         xs_motif_icon_bits, xs_motif_icon_width, xs_motif_icon_height,
         fg, bg, depth);

// Set this pixmap

      setPixmap (_pixmap);
      
      _freePixmap = True;
      
// Create the icon pixmap graphics context

      valuemask = GCGraphicsExposures | GCForeground | GCBackground;
      
      values.graphics_exposures = False;
      values.foreground = fg;
      values.background = bg;

      _pixmapGC = XtGetGC (_base, valuemask, &values);
   }

// Create the font graphics context

   valuemask = GCForeground | GCBackground | GCGraphicsExposures | GCFont;

   values.foreground = fg;
   values.background = bg;
   values.font = _iconFont->fid;
   values.graphics_exposures = False;

   _fontGC = XtGetGC (_base, valuemask, &values);
}
   
/*
   ----------------------------------------------------------------------------
   _XsMotifMenu
*/

// Static definitions

int _XsMotifMenu::_count = 0;
Cursor _XsMotifMenu::_cursor = None;
Pixmap _XsMotifMenu::_stipple = None;
Display *_XsMotifMenu::_dpy = 0;

// Resources

XtResource _XsMotifMenu::_resourceList[] = {
   {
      "saveUnder",
      "SaveUnder",
      XmRBoolean,
      sizeof (Boolean),
      XtOffset (_XsMotifMenu*, _saveUnder),
      XmRImmediate,
      (XtPointer)True
   },
   {
      "restoreString",
      "RestoreString",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifMenu*, _strings[Restore]),
      XmRString,
      "Restore"
   },
   {
      "moveString",
      "MoveString",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifMenu*, _strings[Move]),
      XmRString,
      "Move"
   },
   {
      "sizeString",
      "SizeString",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifMenu*, _strings[Size]),
      XmRString,
      "Size"
   },
   {
      "minimizeString",
      "MinimizeString",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifMenu*, _strings[Minimize]),
      XmRString,
      "Minimize"
   },
   {
      "maximizeString",
      "MaximizeString",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifMenu*, _strings[Maximize]),
      XmRString,
      "Maximize"
   },
   {
      "raiseString",
      "RaiseString",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifMenu*, _strings[Raise]),
      XmRString,
      "Raise"
   },
   {
      "lowerString",
      "LowerString",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifMenu*, _strings[Lower]),
      XmRString,
      "Lower"
   },
   {
      "closeString",
      "CloseString",
      XmRString,
      sizeof (String),
      XtOffset (_XsMotifMenu*, _strings[Close]),
      XmRString,
      "Close"
   },
   {
      "menuFont",
      "menuFont",
      XmRFontStruct,
      sizeof (XFontStruct*),
      XtOffset (_XsMotifMenu*, _menuFont),
      XmRString,
      "-*-helvetica-bold-o-normal-*-14-*-*-*-*-*-iso8859-1"
   }
};

// Constructor

_XsMotifMenu::_XsMotifMenu (const char *name, XsMotifWindow *win) :
   _XsMotifBase (name, win)
{

// Create the cursor (if necessary)

   if (_count++ == 0)
   {

// Create the menu cursor

      _cursor = XCreateFontCursor (XtDisplay (win->base ( )), XC_arrow);

// Create a stippled pixmap

      Widget   parent = _win->base ( );
      Pixel    foreground;
      Pixel    background;
      int      depth;
      
      XtVaGetValues (parent, XmNforeground, &foreground, XmNbackground,
         &background, XmNdepth, &depth, NULL);
      
      const int pixmapWidth = 2;
      const int pixmapHeight = 2;
      static unsigned char pixmapBits[] = { 0x02, 0x01 };

      _dpy = XtDisplay (parent);
      _stipple = XCreatePixmapFromBitmapData (_dpy, DefaultRootWindow (_dpy),
         (char*)pixmapBits, pixmapWidth, pixmapHeight, foreground, background,
         depth);
   }      

// Initialize

   _fontGC = 0;
   _grayGC = 0;
   _backgroundGC = 0;
   
// Create the component (why doesn't overrideShell work?)

   _base = XtVaCreatePopupShell (_name, topLevelShellWidgetClass,
      XtParent (_win->base ( )), XmNoverrideRedirect, True,
      XmNborderWidth, 1, NULL);

// Install destroy handler

   _installDestroyHandler ( );
   
// Install event handler ('cause we never call _XsMotifBase::show)

   XtAddEventHandler (_base, StructureNotifyMask, False, _mapEventHandler, (XtPointer)this);

// Get resources
   
   _getResources (_resourceList, XtNumber (_resourceList));

// Get the background color

   Pixel bg;

   XtVaGetValues (_win->base ( ), XmNbackground, &bg, NULL);
      
// Compute the size of the (largest) menu item

   int   textHeight = _menuFont->ascent + _menuFont->descent;
   int   textWidth = 0;
   int   tmp;
   
   for (int loop = 0; loop < Num; loop++)
   {
      tmp = XTextWidth (_menuFont, _strings[loop], strlen (_strings[loop]));

      if (tmp > textWidth)
         textWidth = tmp;
   }
      
// Put a border around the buttons

   textWidth += (2 * HorizTextOffset);
   textHeight += (2 * VertTextOffset);
   
/*
   The menu height is the menu-shadow (1 pixel on top and bottom) + the
   items themselves.
*/

   int   menuHeight = (2 * ShadowThickness) +   // Top and bottom shadow
                      (textHeight * Num);       // The menu items
   
/*
   The menu width is the menu-shadow (1 pixel on the left and right) +
   the largest menu text (calculated above)
*/

   int   menuWidth = (2 * ShadowThickness) +    // Left and right shadow   
                     textWidth;                 // Largest text item

// Configure the popup
      
   XtVaSetValues (_base, XmNsaveUnder, _saveUnder, XmNwidth, menuWidth,
      XmNheight, menuHeight, NULL);
}

// Destructor

_XsMotifMenu::~_XsMotifMenu ( )
{
   if (_fontGC)
      XtReleaseGC (_base, _fontGC);

   if (_grayGC)
      XtReleaseGC (_base, _grayGC);
      
   if (_backgroundGC)
      XtReleaseGC (_base, _backgroundGC);

// Free the pixmap (if necessary)

   if (--_count == 0)
      XFreePixmap (_dpy, _stipple);
}

// popup

void _XsMotifMenu::popup (Boolean atPointer)
{
   assert (_base != 0);
   
   Position x, y;

// Compute the location of the menu.

   if (atPointer)
   {
      unsigned int mask;
      Window   win;
      int      winX, winY;
      int      rootX, rootY;
            
// Menu at pointer location

      XQueryPointer (XtDisplay (_base), XtWindow (XtParent (_base)),
         &win, &win, &rootX, &rootY, &winX, &winY, &mask);
         
      x = (Position)rootX;
      y = (Position)rootY;
   }
   else
   {
      
// Menu at top-left corner of client area

      XtTranslateCoords (_win->clientArea ( ), 0, 0, &x, &y);
   }      

// Move the menu

   XtVaSetValues (_base, XmNx, x, XmNy, y, NULL);
   
// Initialize the item

   _curItem = NoItem;
   
// Pop it up

   XtPopup (_base, XtGrabNone);
   
// Grab the pointer

   if (_grabPointer ( ) == FALSE)
      return;
   
// Update the menu

   _processEvents ( );
   
// Pop the menu down

   XtPopdown (_base);

// Ungrab the pointer

   _ungrabPointer ( );

   if (_curItem != NoItem)
   {
      
/*
   Post a work-proc to process this item.  This will allow everything
   to get caught up before we process the menu item
*/

      XtAppContext appContext = XtWidgetToApplicationContext (_base);
      XtAppAddWorkProc (appContext, _workProc, (XtPointer)this);
   }
}   

// className

const char *_XsMotifMenu::className ( ) const
{
   return ("_XsMotifMenu");
}

// _componentDestroyed

void _XsMotifMenu::_componentDestroyed ( )
{

// Clean up the GCs

   if (_fontGC)
      XtReleaseGC (_base, _fontGC);

   if (_grayGC)
      XtReleaseGC (_base, _grayGC);
      
   if (_backgroundGC)
      XtReleaseGC (_base, _backgroundGC);

   _fontGC = 0;
   _grayGC = 0;
   _backgroundGC = 0;
   
// Call the base-class

   _XsMotifBase::_componentDestroyed ( );
}
   
// _processEvents

void _XsMotifMenu::_processEvents ( )
{
   assert (_base != 0);
   
   XtAppContext appContext = XtWidgetToApplicationContext (_base);
   XEvent event;
   Display *dpy = XtDisplay (_base);
   int   done = 0;
      
   while (!done)
   {
      XtAppNextEvent (appContext, &event);

// Process this event

      switch (event.type)
      {
         case ButtonRelease:
         {
            done = 1;
            break;
         }
         case Expose:
         {
            _redrawMenu ( );
            break;
         }
         case MotionNotify:
         {
            XEvent next;

// Process only the last motion event

            while (XPending (dpy) > 0)
            {
               XPeekEvent (dpy, &next);
               if (next.type != MotionNotify)
                  break;
               XtAppNextEvent (appContext, &event);
            }

// Track the mouse and toggle the menu items

            Item item = _trackPointer ((XMotionEvent*)&event);

// Unselect the current item (if the item is different)
               
            if (item != _curItem)
            {
               _toggleItem (_curItem, False);
               
// Select the new item
   
               _toggleItem ((_curItem = item), True);
            }
                        
            break;
         }
         default:
         {
            XtDispatchEvent (&event);
            break;
         }
      }
   }
}

// _processItem

void _XsMotifMenu::_processItem (Item item)
{
   if (item == NoItem)
      return;

   switch (item)
   {
      case Restore:
      {
         _win->restore ( );
         break;
      }         
      case Move:
      {
         Widget base = (_win->minimized ( )) ? _win->icon ( ) : _win->base ( );

// Warp the pointer to the center of the window

         Dimension width, height;
         XtVaGetValues (base, XmNwidth, &width, XmNheight, &height, NULL);
         
         XWarpPointer (XtDisplay (_base), None, XtWindow (base), 0, 0, 0, 0,
            (width / 2), (height / 2));
            
// Move the window

         XsMoveOutline move (base);

// Start the move

         if (move.go (True) != False)
         {

// Relocate the window      
   
            _win->setPosition (move.x ( ), move.y ( ));
         }
         break;
      }         
      case Size:
      {
         Widget base = (_win->minimized ( )) ? _win->icon ( ) : _win->base ( );

// Warp the pointer to the center of the window

         Dimension width, height;
         XtVaGetValues (base, XmNwidth, &width, XmNheight, &height, NULL);
         
         XWarpPointer (XtDisplay (_base), None, XtWindow (base), 0, 0, 0, 0,
            (width / 2), (height / 2));
            
// Resize the window

         XsResizeOutline resize (_win->base ( ), XsResizeOutline::Undetermined);
         resize.setMinSize (_win->minWidth ( ), _win->minHeight ( ));

// Start the resize

         if (resize.go (True) != False)
         {

// Relocate the window      
   
            _win->setPosition (resize.x ( ), resize.y ( ));
            _win->setSize (resize.width ( ), resize.height ( ));
         }
         break;
      }
      case Minimize:
      {
         _win->minimize ( );
         break;
      }
      case Maximize:
      {
         _win->maximize ( );
         break;
      }         
      case Raise:
      {
         _win->raise ( );
         break;
      }
      case Lower:
      {
         _win->lower ( );
         break;
      }
      case Close:
      {
         _win->close ( );
         break;
      }
      default:
         assert (0);
   }
}

// _redrawMenu

void _XsMotifMenu::_redrawMenu ( )
{
   Dimension   w, h;
   
// Get the size of the menu

   XtVaGetValues (_base, XmNwidth, &w, XmNheight, &h, NULL);
   
// Draw a shadow around the menu

   _drawShadows (0, 0, w, h, ShadowThickness);

// Cycle and draw all of the elements

   for (int loop = 0; loop < Num; loop++)
      _redrawItem ((Item)loop);
}

// _redrawItem

void _XsMotifMenu::_redrawItem (Item item)
{
   if (item == NoItem)
      return;
   
   int   x = ShadowThickness + HorizTextOffset;
   int   y;
      
/*
   Compute the y-position of the element.  This will be the size of the
   top-shadow + the items before it + the offset of the item itself
*/

   y = ShadowThickness +                           // Top shadow
       (item * ((VertTextOffset * 2) + (_menuFont->descent + _menuFont->ascent))) +
       (VertTextOffset + _menuFont->ascent);       // The item iteself

// Figure out the graphics-context

   GC gc;
   
   if (_win->minimized ( ))
      gc = ((item == Size) || (item == Minimize)) ? _grayGC : _fontGC;
   else if (_win->maximized ( ))
      gc = (item == Maximize) ? _grayGC : _fontGC;
   else
      gc = (item == Restore) ? _grayGC : _fontGC;      
   
// Draw the string

   XDrawString (XtDisplay (_base), XtWindow (_base), gc, x, y,
      _strings[item], strlen (_strings[item]));
}

// _toggleItem

void _XsMotifMenu::_toggleItem (Item item, Boolean active)
{
   if (item == NoItem)
      return;
   
/*
   Either draw the background of the specified item in the active color
   or the standard background color
*/

   GC gc = (active) ? _topShadowGC : _backgroundGC;
   
// Get the width of the menu

   Dimension menuWidth;
   XtVaGetValues (_base, XmNwidth, &menuWidth, NULL);

// Compute the location and size of the rectangle

   int   x, y;
   unsigned int width, height;

   x = ShadowThickness;
   height = ((VertTextOffset * 2) + (_menuFont->descent + _menuFont->ascent));
   y = ShadowThickness + (item * height);
   width = menuWidth - (2 * ShadowThickness);
   
// Draw the filled rectangle

   XFillRectangle (XtDisplay (_base), XtWindow (_base), gc, x, y, width, height);

// Redraw the text

   _redrawItem (item);
}
   
// _trackPointer

_XsMotifMenu::Item _XsMotifMenu::_trackPointer (XMotionEvent *event)
{
   assert (_base != 0);
   
   Dimension   menuWidth;
   Dimension   menuHeight;
   Position    x, y;   

// Get the menu size and position

   XtVaGetValues (_base, XmNwidth, &menuWidth, XmNheight, &menuHeight,
      XmNx, &x, XmNy, &y, NULL);
   
// Make sure the pointer is in the menu

   if ((event->x_root < x) || (event->x_root > (x + menuWidth)))
      return (NoItem);
      
   if ((event->y_root < y) || (event->y_root > (y + menuHeight)))
      return (NoItem);
      
// Make sure the pointer is on the confines of the shadow

   if ((event->x < ShadowThickness) || (event->x > (menuWidth - (2 * ShadowThickness))))
      return (NoItem);
      
   if ((event->y < ShadowThickness) || (event->y > (menuHeight - (2 * ShadowThickness))))
      return (NoItem);
      
/*
   Now we are just concerned with the y-position.  Subtract off the
   shadow thickness to normalize the location
*/

   int   yPos = event->y - ShadowThickness;
   
// Compute which item the mouse is in

   int itemHeight = (VertTextOffset * 2) + (_menuFont->descent + _menuFont->ascent);

   Item item = (Item)(yPos / itemHeight);
   
// Validate that the item is not grayed-out

   if (_win->minimized ( ))
   {
      if ((item == Size) || (item == Minimize))
         item = NoItem;
   }
   else if (_win->maximized ( ))
   {
      if (item == Maximize)
         item = NoItem;
   }
   else if (item == Restore)
      item = NoItem;

   return (item);
}

// _grabPointer 

Boolean _XsMotifMenu::_grabPointer ( )
{
   
// Sync everything up before being grabby

   XSync (XtDisplay (_base), False);

// Grab the pointer

   if (XGrabPointer (XtDisplay (_base), XtWindow (_base), False,
      (unsigned int)(ButtonPressMask | ButtonReleaseMask | PointerMotionMask |
      EnterWindowMask | LeaveWindowMask), GrabModeAsync,
      GrabModeAsync, None, _cursor, CurrentTime) != GrabSuccess)
   {
      XBell (XtDisplay (_base), 100);
      return (False);
   }
      
   return (True);
}

// _ungrabPointer

void _XsMotifMenu::_ungrabPointer ( )
{

// Ungrab the pointer

   XUngrabPointer (XtDisplay (_base), CurrentTime);

// Sync everything back up

   XSync (XtDisplay (_base), False);
}

// _map

void _XsMotifMenu::_map ( )
{
   
// Call the base-class

   _XsMotifBase::_map ( );

   unsigned long valuemask;
   XGCValues   values;
   Pixel foreground;
   Pixel background;
   
// Get the pixels

   XtVaGetValues (XtParent (_base), XmNforeground, &foreground, NULL);
   XtVaGetValues (_base, XmNbackground, &background, NULL);

// Create the font graphics context

   valuemask = GCForeground | GCBackground | GCGraphicsExposures | GCFont;

   values.foreground = foreground;
   values.background = background;
   values.font = _menuFont->fid;
   values.graphics_exposures = False;

   _fontGC = XtGetGC (_base, valuemask, &values);

// Create the insensitive font graphics context

   valuemask |= (GCFillStyle | GCTile);

   values.fill_style = FillTiled;
   values.tile = _stipple;

   _grayGC = XtGetGC (_base, valuemask, &values);

// Create the background contexts

   valuemask = GCForeground | GCLineWidth | GCGraphicsExposures;
   values.line_width = 0;
   values.graphics_exposures = False;
   values.foreground = background;

   _backgroundGC = XtGetGC (_base, valuemask, &values);
}

// _workProc

Boolean _XsMotifMenu::_workProc (XtPointer clientData)
{
   _XsMotifMenu *obj = (_XsMotifMenu*)clientData;
   if (obj->_curItem != NoItem)
      obj->_processItem (obj->_curItem);

   return (True);
}

/*
   ----------------------------------------------------------------------------
   XsMotifWindow
*/

// Static definitions

XtResource XsMotifWindow::_resourceList[] = {
   {
      "showBorder",
      "ShowBorder",
      XmRBoolean,
      sizeof (Boolean),
      XtOffset (XsMotifWindow*, _showBorder),
      XmRImmediate,
      (XtPointer)True
   },
   {
      "showResize",
      "ShowResize",
      XmRBoolean,
      sizeof (Boolean),
      XtOffset (XsMotifWindow*, _showResize),
      XmRImmediate,
      (XtPointer)True
   },
   {
      "showTitle",
      "ShowTitle",
      XmRBoolean,
      sizeof (Boolean),
      XtOffset (XsMotifWindow*, _showTitle),
      XmRImmediate,
      (XtPointer)True
   },
   {
      "showMenu",
      "ShowMenu",
      XmRBoolean,
      sizeof (Boolean),
      XtOffset (XsMotifWindow*, _showMenu),
      XmRImmediate,
      (XtPointer)True
   },
   {
      "showMinimize",
      "ShowMinimize",
      XmRBoolean,
      sizeof (Boolean),
      XtOffset (XsMotifWindow*, _showMinimize),
      XmRImmediate,
      (XtPointer)True
   },
   {
      "showMaximize",
      "ShowMaximize",
      XmRBoolean,
      sizeof (Boolean),
      XtOffset (XsMotifWindow*, _showMaximize),
      XmRImmediate,
      (XtPointer)True
   },
   {
      "lowerOnIconify",
      "LowerOnIconify",
      XmRBoolean,
      sizeof (Boolean),
      XtOffset (XsMotifWindow*, _lowerOnIconify),
      XmRImmediate,
      (XtPointer)False
   },
   {
      XmNminWidth,
      XmCMinWidth,
      XmRDimension,
      sizeof (Dimension),
      XtOffset (XsMotifWindow*, _minW),
      XmRImmediate,
      (XtPointer)((BorderSize_ + ButtonSize_) * 3)
   },
   {
      XmNmaxWidth,
      XmCMaxWidth,
      XmRDimension,
      sizeof (Dimension),
      XtOffset (XsMotifWindow*, _maxW),
      XmRImmediate,
      (XtPointer)-1
   },
   {
      XmNminHeight,
      XmCMinHeight,
      XmRDimension,
      sizeof (Dimension),
      XtOffset (XsMotifWindow*, _minH),
      XmRImmediate,
      (XtPointer)((BorderSize_ + ButtonSize_) * 3)
   },
   {
      XmNmaxHeight,
      XmCMaxHeight,
      XmRDimension,
      sizeof (Dimension),
      XtOffset (XsMotifWindow*, _maxH),
      XmRImmediate,
      (XtPointer)-1
   }
};    

// Constructor

XsMotifWindow::XsMotifWindow (const char *name) : XsMDIWindow (name)
{
   int   loop;
   
// Initialize

   for (loop = 0; loop < _XsMotifSide::Max; loop++)
   {
      _corners[loop] = 0;
      _sides[loop] = 0;
   }

   for (loop = 0; loop < _XsMotifButton::Max; loop++)
      _buttons[loop] = 0;

   _title = 0;
   _icon = 0;
   _menu = 0;
      
   _maximized = False;
   _minimized = False;
}
   
// Destructor

XsMotifWindow::~XsMotifWindow ( )
{
   int   loop;
   
   for (loop = 0; loop < _XsMotifSide::Max; loop++)
   {
      delete _corners[loop];
      delete _sides[loop];
   }

   for (loop = 0; loop < _XsMotifButton::Max; loop++)
      delete _buttons[loop];

   delete _title;
   delete _icon;
   delete _menu;
}

// raise

void XsMotifWindow::raise ( )
{
   Widget w = (_minimized == True) ? _icon->base ( ) : _base;
   assert (w != 0);
   XRaiseWindow (XtDisplay (w), XtWindow (w));
}

// lower

void XsMotifWindow::lower ( )
{
   Widget w = (_minimized == True) ? _icon->base ( ) : _base;
   assert (w != 0);
   XLowerWindow (XtDisplay (w), XtWindow (w));
}

// minimize

void XsMotifWindow::minimize ( )
{
   assert (_base != 0);
   
// Check if we are already minimized

   if (_minimized == True)
      return;

// Minimize the window

   hide ( );

   _minimized = True;

// Lower (if necessary)

   if (_lowerOnIconify)
      lower ( );

   _icon->show ( );
}
   
// maximize

void XsMotifWindow::maximize ( )
{
   assert (_base != 0);
   
// Check if we are already in this state

   if (_maximized == True)
      return;

// Restore (if necessary)

   if (_minimized)
      restore ( );
      
// Save current dimensions

   XtVaGetValues (_base, XmNx, &_savedX, XmNy, &_savedY, XmNwidth,
      &_savedWidth, XmNheight, &_savedHeight, NULL);

/*
   Constrain the new window size.  The size of the maximized window
   is equal to the size of the current clip-window of the canvas.
*/

   const Dimension offset = 5;      // Border around max'd window
   
   Widget clipWindow = XtParent (XtParent (_base));
   assert (clipWindow != 0);
   Dimension   clipW, clipH;   
   Window      child;
   int         newX, newY;
   
   XtVaGetValues (clipWindow, XmNheight, &clipH, XmNwidth, &clipW, NULL);
   
// Add in offset

   if (clipW > (offset * 2))
      clipW -= (offset * 2);
      
   if (clipH > (offset * 2))
      clipH -= (offset * 2);
      
// Compute the new window position (map clip-window to work-area)

   XTranslateCoordinates (XtDisplay (_base), XtWindow (clipWindow),
      XtWindow (XtParent (_base)), (int)offset, (int)offset,
      &newX, &newY, &child);
   
// Set new maximum dimensions

   setPosition ((Position)newX, (Position)newY);
   setSize (clipW, clipH);

   _maximized = True;

// Redraw the maximize button

   _buttons[_XsMotifButton::Maximize]->redraw ( );
}
   
// restore

void XsMotifWindow::restore ( )
{
   assert (_base != 0);
   
// Check if we are already restored

   if ((_maximized == False) && (_minimized == False))
      return;

// Either un-minimize or un-maximize

   if (_minimized)
   {

// Restore the window

      _icon->hide ( );
      _minimized = False;

// If maximized, restore again

      if (_maximized)
         restore ( );
         
// Show the window

      show ( );
   }
   else
   {
   
// Restore saved dimensions

      setPosition (_savedX, _savedY);
      setSize (_savedWidth, _savedHeight);
   }
}
   
// close

void XsMotifWindow::close ( )
{

/*
   Don't delete the window (because its not ours to delete).
   Just hide it.
*/
   
   if (_minimized)
      _icon->hide ( );
   else
      hide ( );
}

// setTitle

void XsMotifWindow::setTitle (const char *title)
{
   if (_title != 0)
      _title->setTitle (title);
}   

// setIconName

void XsMotifWindow::setIconName (const char *iconName)
{
   if (_icon != 0)
      _icon->setIconName (iconName);
}

// setPixmap

void XsMotifWindow::setPixmap (Pixmap pixmap)
{
   if (_icon != 0)
      _icon->setPixmap (pixmap);
}
   
// popupMenu

void XsMotifWindow::popupMenu (Boolean b)
{
   if (_menu != 0)
      _menu->popup (b);
}
   
// setPosition

void XsMotifWindow::setPosition (Position x, Position y)
{
   if (_base != 0)
   {
      Widget w = (_minimized == True) ? _icon->base ( ) : _base;
      assert (w != 0);
      XtVaSetValues (w, XmNx, x, XmNy, y, NULL);
   }
   else
      XsMDIWindow::setPosition (x, y);    // Cache the points
}
      
// setSize

void XsMotifWindow::setSize (Dimension w, Dimension h)
{

// Set the window size

   if (_base != 0)
   {
      if (w < _minW)
         w = _minW;
      else if ((_maxW != (Dimension)-1) && (w > _maxW))
         w = _maxW;
      
      if (h < _minH)
         h = _minH;
      else if ((_maxH != (Dimension)-1) && (h > _maxH))
         h = _maxH;
      
      if (_minimized == False)
         XtVaSetValues (_base, XmNwidth, w, XmNheight, h, NULL);

// If window was maximized, change the window state back to normal

      if (_maximized == True)
      {
         _maximized = False;

// Redraw the maximize button

         _buttons[_XsMotifButton::Maximize]->redraw ( );
      }
   }
   else
      XsMDIWindow::setSize (w, h);     // Cache the points
}
      
// className

const char* XsMotifWindow::className ( ) const
{
   return ("XsMotifWindow");
}

// _createWindow

void XsMotifWindow::_createWindow (Widget parent)
{
   assert (parent != 0);
   
// Create the window frame

   _base = XtVaCreateWidget (_name, xmFormWidgetClass, parent,
      XmNborderWidth, (Dimension)1, NULL);
      
// Install destroy handler

   _installDestroyHandler ( );
   
// Get resources
   
   _getResources (_resourceList, XtNumber (_resourceList));

/*
   Fix configuration inter-dependencies.  Here are the rules:

   1) If there is no border, then there are no resize handles
   2) If there is no title, then there are no buttons (would look stupid)
*/

   if (_showBorder == False)
      _showResize = False;
      
   if (_showTitle == False)
   {
      _showMenu = False;
      _showMinimize = False;
      _showMaximize = False;
   }      

/*
   Corners
*/

   if (_showResize)
   {

// Top-Left

      _corners[_XsMotifCorner::TopLeft] = new _XsMotifCorner ("topLeft", this, _XsMotifCorner::TopLeft);

      XtVaSetValues (_corners[_XsMotifCorner::TopLeft]->base ( ), XmNtopAttachment,
         XmATTACH_FORM, XmNbottomAttachment, XmATTACH_NONE, XmNleftAttachment,
         XmATTACH_FORM, XmNrightAttachment, XmATTACH_NONE, NULL);

// Top-Right

      _corners[_XsMotifCorner::TopRight] = new _XsMotifCorner ("topRight", this, _XsMotifCorner::TopRight);

      XtVaSetValues (_corners[_XsMotifCorner::TopRight]->base ( ), XmNtopAttachment,
         XmATTACH_FORM, XmNbottomAttachment, XmATTACH_NONE, XmNleftAttachment,
         XmATTACH_NONE, XmNrightAttachment, XmATTACH_FORM, NULL);
         
// Bottom-Left

      _corners[_XsMotifCorner::BottomLeft] = new _XsMotifCorner ("bottomLeft", this, _XsMotifCorner::BottomLeft);
      
      XtVaSetValues (_corners[_XsMotifCorner::BottomLeft]->base ( ), XmNtopAttachment,
         XmATTACH_NONE, XmNbottomAttachment, XmATTACH_FORM, XmNleftAttachment,
         XmATTACH_FORM, XmNrightAttachment, XmATTACH_NONE, NULL);

// Bottom-Right

      _corners[_XsMotifCorner::BottomRight] = new _XsMotifCorner ("bottomRight", this, _XsMotifCorner::BottomRight);

      XtVaSetValues (_corners[_XsMotifCorner::BottomRight]->base ( ), XmNtopAttachment,
         XmATTACH_NONE, XmNbottomAttachment, XmATTACH_FORM, XmNleftAttachment,
         XmATTACH_NONE, XmNrightAttachment, XmATTACH_FORM, NULL);
   }
         
/*
   Sides
*/

   if (_showBorder)
   {

// Top   

      _sides[_XsMotifSide::Top] = new _XsMotifSide ("top", this, _XsMotifSide::Top);

      XtVaSetValues (_sides[_XsMotifSide::Top]->base ( ),  XmNtopAttachment,
         XmATTACH_FORM, XmNbottomAttachment, XmATTACH_NONE, NULL);

      if (_showResize)
      {
         XtVaSetValues (_sides[_XsMotifSide::Top]->base ( ), XmNleftAttachment,
            XmATTACH_WIDGET, XmNleftWidget, _corners[_XsMotifCorner::TopLeft]->base ( ),
            XmNrightAttachment, XmATTACH_WIDGET, XmNrightWidget,
            _corners[_XsMotifCorner::TopRight]->base ( ), NULL);
      }
      else
      {
         XtVaSetValues (_sides[_XsMotifSide::Top]->base ( ), XmNleftAttachment,
            XmATTACH_FORM, XmNrightAttachment, XmATTACH_FORM, NULL);
      }
      
// Bottom

      _sides[_XsMotifSide::Bottom] = new _XsMotifSide ("bottom", this, _XsMotifSide::Bottom);

      XtVaSetValues (_sides[_XsMotifSide::Bottom]->base ( ), XmNtopAttachment,
         XmATTACH_NONE, XmNbottomAttachment, XmATTACH_FORM, NULL);

      if (_showResize)
      {
         XtVaSetValues (_sides[_XsMotifSide::Bottom]->base ( ), XmNleftAttachment,
            XmATTACH_WIDGET, XmNleftWidget, _corners[_XsMotifCorner::BottomLeft]->base ( ),
            XmNrightAttachment, XmATTACH_WIDGET, XmNrightWidget,
            _corners[_XsMotifCorner::BottomRight]->base ( ), NULL);
      }
      else
      {
         XtVaSetValues (_sides[_XsMotifSide::Bottom]->base ( ), XmNleftAttachment,
            XmATTACH_FORM, XmNrightAttachment, XmATTACH_FORM, NULL);
      }

// Left side

      _sides[_XsMotifSide::Left] = new _XsMotifSide ("left", this, _XsMotifSide::Left);

      XtVaSetValues (_sides[_XsMotifSide::Left]->base ( ), XmNleftAttachment,
         XmATTACH_FORM, XmNrightAttachment, XmATTACH_NONE, NULL);

      if (_showResize)
      {
         XtVaSetValues (_sides[_XsMotifSide::Left]->base ( ), XmNtopAttachment,
            XmATTACH_WIDGET, XmNtopWidget, _corners[_XsMotifCorner::TopLeft]->base ( ),
            XmNbottomAttachment, XmATTACH_WIDGET, XmNbottomWidget,
            _corners[_XsMotifCorner::BottomLeft]->base ( ), NULL);
      }
      else
      {
         XtVaSetValues (_sides[_XsMotifSide::Left]->base ( ), XmNtopAttachment,
            XmATTACH_FORM, XmNbottomAttachment, XmATTACH_FORM, NULL);
      }

// Right side

      _sides[_XsMotifSide::Right] = new _XsMotifSide ("right", this, _XsMotifSide::Right);

      XtVaSetValues (_sides[_XsMotifSide::Right]->base ( ), XmNleftAttachment,
         XmATTACH_NONE, XmNrightAttachment, XmATTACH_FORM, NULL);

      if (_showResize)
      {
         XtVaSetValues (_sides[_XsMotifSide::Right]->base ( ), XmNtopAttachment,
            XmATTACH_WIDGET, XmNtopWidget, _corners[_XsMotifCorner::TopRight]->base ( ),
            XmNbottomAttachment, XmATTACH_WIDGET, XmNbottomWidget,
            _corners[_XsMotifCorner::BottomRight]->base ( ), NULL);
      }
      else
      {
         XtVaSetValues (_sides[_XsMotifSide::Right]->base ( ), XmNtopAttachment,
            XmATTACH_FORM, XmNbottomAttachment, XmATTACH_FORM, NULL);
      }
   }
         
// Menu button

   if (_showMenu)
   {
      _buttons[_XsMotifButton::Menu] = new _XsMotifButton ("menu", this, _XsMotifButton::Menu);

      XtVaSetValues (_buttons[_XsMotifButton::Menu]->base ( ), XmNbottomAttachment,
         XmATTACH_NONE, XmNrightAttachment, XmATTACH_NONE, NULL);

      if (_showBorder)
      {
         XtVaSetValues (_buttons[_XsMotifButton::Menu]->base ( ), XmNleftAttachment,
            XmATTACH_WIDGET, XmNleftWidget, _sides[_XsMotifSide::Left]->base ( ),
            XmNtopAttachment, XmATTACH_WIDGET, XmNtopWidget, _sides[_XsMotifSide::Top]->base ( ),
            NULL);
      }
      else
      {
         XtVaSetValues (_buttons[_XsMotifButton::Menu]->base ( ), XmNleftAttachment,
            XmATTACH_FORM, XmNtopAttachment, XmATTACH_FORM, NULL);
      }
   }
   
// Maximize button

   if (_showMaximize)
   {
      _buttons[_XsMotifButton::Maximize] = new _XsMotifButton ("maximize", this, _XsMotifButton::Maximize);
      
      XtVaSetValues (_buttons[_XsMotifButton::Maximize]->base ( ), XmNbottomAttachment,
         XmATTACH_NONE, XmNleftAttachment, XmATTACH_NONE, NULL);
         
      if (_showBorder)
      {
         XtVaSetValues (_buttons[_XsMotifButton::Maximize]->base ( ), XmNtopAttachment,
            XmATTACH_WIDGET, XmNtopWidget, _sides[_XsMotifSide::Top]->base ( ),
            XmNrightAttachment, XmATTACH_WIDGET, XmNrightWidget, _sides[_XsMotifSide::Right]->base ( ),
            NULL);
      }
      else
      {
         XtVaSetValues (_buttons[_XsMotifButton::Maximize]->base ( ), XmNtopAttachment,
            XmATTACH_FORM, XmNrightAttachment, XmATTACH_FORM, NULL);
      }
   }
      
// Minimize button

   if (_showMinimize)
   {
      _buttons[_XsMotifButton::Minimize] = new _XsMotifButton ("minimize", this, _XsMotifButton::Minimize);

      XtVaSetValues (_buttons[_XsMotifButton::Minimize]->base ( ),
         XmNbottomAttachment, XmATTACH_NONE, XmNleftAttachment, XmATTACH_NONE,
         NULL);
         
      if (_showBorder)
      {
         XtVaSetValues (_buttons[_XsMotifButton::Minimize]->base ( ), XmNtopAttachment,
            XmATTACH_WIDGET, XmNtopWidget, _sides[_XsMotifSide::Top]->base ( ),
            XmNrightAttachment, XmATTACH_WIDGET, XmNrightWidget,
            _sides[_XsMotifSide::Right]->base ( ), NULL);
      }
      else
      {
         XtVaSetValues (_buttons[_XsMotifButton::Minimize]->base ( ),
            XmNtopAttachment, XmATTACH_FORM, XmNrightAttachment, XmATTACH_FORM,
            NULL);
      }

      if (_showMaximize)
      {
         XtVaSetValues (_buttons[_XsMotifButton::Minimize]->base ( ),
            XmNrightAttachment, XmATTACH_WIDGET, XmNrightWidget,
            _buttons[_XsMotifButton::Maximize]->base ( ), NULL);
      }
   }
      
/*
   Titlebar
*/

   if (_showTitle)
   {
      _title = new _XsMotifTitle ("title", this);

      XtVaSetValues (_title->base ( ), XmNbottomAttachment, XmATTACH_NONE,
         NULL);

      if (_showBorder)
      {
         XtVaSetValues (_title->base ( ), XmNtopAttachment, XmATTACH_WIDGET,
            XmNtopWidget, _sides[_XsMotifSide::Top]->base ( ),
            XmNleftAttachment, XmATTACH_WIDGET, XmNleftWidget,
            _sides[_XsMotifSide::Left]->base ( ), XmNrightAttachment,
            XmATTACH_WIDGET, XmNrightWidget, _sides[_XsMotifSide::Right]->base ( ),
            NULL);
      }
      else
      {
         XtVaSetValues (_title->base ( ), XmNtopAttachment, XmATTACH_FORM,
            XmNleftAttachment, XmATTACH_FORM, XmNrightAttachment, XmATTACH_FORM,
            NULL);
      }      

      if (_showMenu)
      {
         XtVaSetValues (_title->base ( ), XmNleftAttachment, XmATTACH_WIDGET,
            XmNleftWidget, _buttons[_XsMotifButton::Menu]->base ( ), NULL);
      }

      Widget ba = (_buttons[_XsMotifButton::Minimize] != 0) ?
         _buttons[_XsMotifButton::Minimize]->base ( ) :
         (_buttons[_XsMotifButton::Maximize] != 0) ?
         _buttons[_XsMotifButton::Maximize]->base ( ) : 0;
         
      if (ba)
      {
         XtVaSetValues (_title->base ( ), XmNrightAttachment, XmATTACH_WIDGET,
            XmNrightWidget, ba, NULL);
      }
   }
      
/*
   Icon
*/

   _icon = new _XsMotifIcon ("icon", this, parent);

/*
   Menu
*/

   _menu = new _XsMotifMenu ("menu", this);
   
/*
   Client Area
*/

   _clientArea = XtVaCreateWidget ("clientArea", xmFormWidgetClass, _base, NULL);

   if (_showBorder)
   {
      XtVaSetValues (_clientArea, XmNleftAttachment, XmATTACH_WIDGET,
         XmNleftWidget, _sides[_XsMotifSide::Left]->base ( ), XmNrightAttachment,
         XmATTACH_WIDGET, XmNrightWidget, _sides[_XsMotifSide::Right]->base ( ),
         XmNbottomAttachment, XmATTACH_WIDGET, XmNbottomWidget,
         _sides[_XsMotifSide::Bottom]->base ( ), NULL);
   }
   else
   {
      XtVaSetValues (_clientArea, XmNleftAttachment, XmATTACH_FORM,
         XmNrightAttachment, XmATTACH_FORM, XmNbottomAttachment, XmATTACH_FORM,
         NULL);
   }
   
   Widget topW = (_showTitle) ? _title->base ( ) :
                 (_showBorder) ? _sides[_XsMotifSide::Top]->base ( ) : 0;
                 
   if (topW)
   {
      XtVaSetValues (_clientArea, XmNtopAttachment, XmATTACH_WIDGET,
         XmNtopWidget, topW, NULL);
   }
   else
      XtVaSetValues (_clientArea, XmNtopAttachment, XmATTACH_FORM, NULL);

// Call the class function to create the contents of the window

   _buildClientArea (_clientArea);
   
// Add an event handler to be called when this window is mapped

   XtAddEventHandler (_base, StructureNotifyMask, False, _mapEventHandler, (XtPointer)this);

// Show everything

   int   loop;

   for (loop = 0; loop < _XsMotifSide::Max; loop++)
   {
      if (_corners[loop] != 0)
         _corners[loop]->show ( );
      if (_sides[loop] != 0)
         _sides[loop]->show ( );
   }

   for (loop = 0; loop < _XsMotifButton::Max; loop++)
   {
      if (_buttons[loop] != 0)
         _buttons[loop]->show ( );
   }

   if (_title != 0)
      _title->show ( );
}
   
// _mapEvent

void XsMotifWindow::_mapEvent ( )
{
      
// Raise the client-area

   XRaiseWindow (XtDisplay (_clientArea), XtWindow (_clientArea));
}

// _mapEventHandler

void XsMotifWindow::_mapEventHandler (Widget, XtPointer clientData, XEvent *event, Boolean*)
{
   if (event->type == MapNotify)
   {
      XsMotifWindow *obj = (XsMotifWindow*)clientData;
      obj->_mapEvent ( );
      XtRemoveEventHandler (obj->_base, StructureNotifyMask, False, obj->_mapEventHandler, clientData);
   }
}
