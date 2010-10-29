/*
   Copyright (C) 1996 Scott W. Sadler
   All rights reserved.
*/

/*
   XsComponent.C

   History
      03-Mar-96 1.0; Scott W. Sadler (ssadler@cisco.com)
                     Created         
*/

// Includes

#ifndef NDEBUG
#include <iostream.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <Xm/Xm.h>
#include "XsComponent.h"

// Constructor

XsComponent::XsComponent (const char *name)
{
   assert (name != 0);
   
// Initialize

   _base = 0;
   
// Copy component name

   int len = strlen (name);
   _name = new char [len + 1];
   strcpy (_name, name);
}

// Destructor  

XsComponent::~XsComponent ( )
{

// Destroy the widget

   if (_base != 0)
   {
      _removeDestroyHandler ( );
      XtDestroyWidget (_base);
   }
      
   delete [] _name;
}
   
// show

void XsComponent::show ( )
{

#ifndef NDEBUG
  //   if (XtIsManaged (_base))
  //      cout << "Re-managing a widget:" << _name << endl;
#endif

// Make sure the _destroyHandler was installed

   assert (XtHasCallbacks (_base, XmNdestroyCallback) == XtCallbackHasSome);

   assert (_base != 0);
   XtManageChild (_base);
}

// hide

void XsComponent::hide ( )
{

#ifndef NDEBUG
  //   if (!XtIsManaged (_base)) 
  //      cout << "Re-unmanaging a widget:" << _name << endl;
#endif

   assert (_base != 0);
   XtUnmanageChild (_base);
}

// Conversion operator

XsComponent::operator Widget ( ) const
{
   assert (_base != 0);
   return (_base);
}

// operator ==
   
Boolean XsComponent::operator == (const XsComponent& rval)
{
   return (_base == rval._base);
}
   
// className

const char* XsComponent::className ( ) const
{
   return ("XsComponent");
}

// _installDestroyHandler

void XsComponent::_installDestroyHandler ( )
{
   assert (_base != 0);
   
// Install the destroy handler

   XtAddCallback (_base, XmNdestroyCallback, _componentDestroyedCallback, (XtPointer)this);
}

// _removeDestroyHandler

void XsComponent::_removeDestroyHandler ( )
{
   assert (_base != 0);

// Remove the destroy handler

   XtRemoveCallback (_base, XmNdestroyCallback, _componentDestroyedCallback, (XtPointer)this);
}

// _componentDestroyed

void XsComponent::_componentDestroyed ( )
{
   _base = 0;
}

// _componentDestroyedCallback

void XsComponent::_componentDestroyedCallback (Widget, XtPointer clientData, XtPointer)
{
   XsComponent *obj = (XsComponent*)clientData;
   obj->_componentDestroyed ( );
}

// _setResources

void XsComponent::_setResources (Widget w, const String *resources)
{
   assert (w != 0);
   
   XrmDatabase rdb = 0;
   const int bufSize = 200;
   char  buffer[bufSize];
   int   loop;

// Create an empty resource database

   rdb = XrmGetStringDatabase ("");

// Add the component resources

   loop = 0;
   while (resources[loop] != 0)
   {
      sprintf (buffer, "*%s%s\n", _name, resources[loop++]);
      assert (strlen (buffer) < bufSize);
      XrmPutLineResource (&rdb, buffer);
   }
   
// Merge these resources into the database

   if (rdb != 0)
   {
      XrmDatabase db = XtDatabase (XtDisplay (w));
      XrmCombineDatabase (rdb, &db, FALSE);
   }
}

// _getResources

void XsComponent::_getResources (const XtResourceList resources, int num)
{
   assert (_base != 0);
   assert (resources != 0);
         
// Validate input

   if (num <= 0)
      return;
      
// Get the subresources

   XtGetSubresources (XtParent (_base), (XtPointer)this, _name,
      className ( ), resources, num, 0, 0);
}   

