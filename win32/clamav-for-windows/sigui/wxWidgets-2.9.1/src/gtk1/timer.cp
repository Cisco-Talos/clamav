/////////////////////////////////////////////////////////////////////////////
// Name:        gtk/timer.cpp
// Purpose:     wxTimer implementation
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_TIMER

#include "wx/gtk1/private/timer.h"

#include "gtk/gtk.h"

// ----------------------------------------------------------------------------
// wxTimer
// ----------------------------------------------------------------------------

extern "C" {
static gint timeout_callback(void *data)
{
    wxTimerImpl * const timer = (wxTimerImpl *)data;

    const bool keepGoing = !timer->IsOneShot();
    if ( !keepGoing )
        timer->Stop();

    // When getting called from GDK's timer handler we
    // are no longer within GDK's grab on the GUI
    // thread so we must lock it here ourselves.
    gdk_threads_enter();

    timer->Notify();

    // Release lock again.
    gdk_threads_leave();

    return keepGoing;
}
}

bool wxGTKTimerImpl::Start(int millisecs, bool oneShot)
{
    if ( !wxTimerImpl::Start(millisecs, oneShot) )
        return false;

    wxASSERT_MSG( m_tag == -1, wxT("shouldn't be still running") );

    m_tag = gtk_timeout_add( m_milli, timeout_callback, this );

    return true;
}

void wxGTKTimerImpl::Stop()
{
    wxASSERT_MSG( m_tag != -1, wxT("should be running") );

    gtk_timeout_remove( m_tag );
    m_tag = -1;
}

#endif // wxUSE_TIMER

