/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/data.cpp
// Purpose:     wxMGL-specific global data
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/cursor.h"
#endif

/* Current cursor, in order to hang on to
 * cursor handle when setting the cursor globally */
wxCursor g_globalCursor;

/* Don't allow event propagation during drag */
bool g_blockEventsOnDrag = false;

/* Don't allow mouse event propagation during scroll */
bool g_blockEventsOnScroll = false;

/* Don't allow window closing if there are open dialogs */
int g_openDialogs = 0;

/* true when the message queue is empty. this gets set to
   false by all event callbacks before anything else is done */
bool g_isIdle = false;
