/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/evtloop.cpp
// Purpose:     wxEventLoop implementation
// Author:      Vaclav Slavik
// Created:     2006-08-16
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/evtloop.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/log.h"
#endif

#include "wx/thread.h"
#include "wx/private/fdiodispatcher.h"
#include "wx/dfb/private.h"
#include "wx/nonownedwnd.h"
#include "wx/buffer.h"

#include <errno.h>

#define TRACE_EVENTS "events"

// ===========================================================================
// implementation
// ===========================================================================

//-----------------------------------------------------------------------------
// wxDFBEventsHandler
//-----------------------------------------------------------------------------

// This handler is installed to process input on DirectFB's events socket (
// obtained using CreateFileDescriptor()). When IDirectFBEventBuffer is used
// in this mode, events are written to the file descriptor and we read them
// in OnReadWaiting() below.
class wxDFBEventsHandler : public wxFDIOHandler
{
public:
    wxDFBEventsHandler()
        : m_fd(-1), m_offset(0)
    {}

    void SetFD(int fd) { m_fd = fd; }

    void Reset()
    {
        m_fd = -1;
        m_offset = 0;
    }

    // implement wxFDIOHandler pure virtual methods
    virtual void OnReadWaiting();
    virtual void OnWriteWaiting()
        { wxFAIL_MSG("OnWriteWaiting shouldn't be called"); }
    virtual void OnExceptionWaiting()
        { wxFAIL_MSG("OnExceptionWaiting shouldn't be called"); }

private:
    // DirectFB -> wxWidgets events translation
    void HandleDFBEvent(const wxDFBEvent& event);

    int m_fd;
    size_t m_offset;
    DFBEvent m_event;
};

void wxDFBEventsHandler::OnReadWaiting()
{
    for ( ;; )
    {
        int size = read(m_fd,
                        ((char*)&m_event) + m_offset,
                        sizeof(m_event) - m_offset);

        if ( size == 0 || (size == -1 && (errno == EAGAIN || errno == EINTR)) )
        {
            // nothing left in the pipe (EAGAIN is expected for an FD with
            // O_NONBLOCK)
            break;
        }

        if ( size == -1 )
        {
            wxLogSysError(_("Failed to read event from DirectFB pipe"));
            break;
        }

        size += m_offset;
        m_offset = 0;

        if ( size != sizeof(m_event) )
        {
            m_offset = size;
            break;
        }

        HandleDFBEvent(m_event);
    }
}

void wxDFBEventsHandler::HandleDFBEvent(const wxDFBEvent& event)
{
    switch ( event.GetClass() )
    {
        case DFEC_WINDOW:
        {
            wxDFBWindowEvent winevent(((const DFBEvent&)event).window);
            wxNonOwnedWindow::HandleDFBWindowEvent(winevent);
            break;
        }

        case DFEC_NONE:
        case DFEC_INPUT:
        case DFEC_USER:
#if wxCHECK_DFB_VERSION(0,9,23)
        case DFEC_UNIVERSAL:
#endif
        {
            wxLogTrace(TRACE_EVENTS,
                       "ignoring event of unsupported class %i",
                       (int)event.GetClass());
        }
    }
}

//-----------------------------------------------------------------------------
// wxEventLoop initialization
//-----------------------------------------------------------------------------

wxIDirectFBEventBufferPtr wxGUIEventLoop::ms_buffer;
int wxGUIEventLoop::ms_bufferFd;
static wxDFBEventsHandler gs_DFBEventsHandler;

wxGUIEventLoop::wxGUIEventLoop()
{
    // Note that this has to be done here so that the buffer is ready when
    // an event loop runs; GetDirectFBEventBuffer(), which also calls
    // InitBuffer(), may be called before or after the first wxGUIEventLoop
    // instance is created.
    if ( !ms_buffer )
        InitBuffer();
}

/* static */
void wxGUIEventLoop::InitBuffer()
{
    // create DirectFB events buffer:
    ms_buffer = wxIDirectFB::Get()->CreateEventBuffer();

    // and setup a file descriptor that we can watch for new events:

    ms_buffer->CreateFileDescriptor(&ms_bufferFd);
    int flags = fcntl(ms_bufferFd, F_GETFL, 0);
    if ( flags == -1 || fcntl(ms_bufferFd, F_SETFL, flags | O_NONBLOCK) == -1 )
    {
        wxLogSysError(_("Failed to switch DirectFB pipe to non-blocking mode"));
        return;
    }

    wxFDIODispatcher *dispatcher = wxFDIODispatcher::Get();
    wxCHECK_RET( dispatcher, "wxDFB requires wxFDIODispatcher" );

    gs_DFBEventsHandler.SetFD(ms_bufferFd);
    dispatcher->RegisterFD(ms_bufferFd, &gs_DFBEventsHandler, wxFDIO_INPUT);
}

/* static */
void wxGUIEventLoop::CleanUp()
{
    wxFDIODispatcher *dispatcher = wxFDIODispatcher::Get();
    wxCHECK_RET( dispatcher, "wxDFB requires wxFDIODispatcher" );
    dispatcher->UnregisterFD(ms_bufferFd);

    ms_buffer.Reset();
    gs_DFBEventsHandler.Reset();
}

/* static */
wxIDirectFBEventBufferPtr wxGUIEventLoop::GetDirectFBEventBuffer()
{
    if ( !ms_buffer )
        InitBuffer();

    return ms_buffer;
}

//-----------------------------------------------------------------------------
// events dispatch and loop handling
//-----------------------------------------------------------------------------

bool wxGUIEventLoop::YieldFor(long eventsToProcess)
{
#if wxUSE_THREADS
    if ( !wxThread::IsMain() )
        return true; // can't process events from other threads
#endif // wxUSE_THREADS

    m_isInsideYield = true;
    m_eventsToProcessInsideYield = eventsToProcess;

#if wxUSE_LOG
    wxLog::Suspend();
#endif // wxUSE_LOG

    // TODO: implement event filtering using the eventsToProcess mask

    // process all pending events:
    while ( Pending() )
        Dispatch();

    // handle timers, sockets etc.
    OnNextIteration();

    // it's necessary to call ProcessIdle() to update the frames sizes which
    // might have been changed (it also will update other things set from
    // OnUpdateUI() which is a nice (and desired) side effect)
    while ( ProcessIdle() ) {}

#if wxUSE_LOG
    wxLog::Resume();
#endif // wxUSE_LOG

    m_isInsideYield = false;

    return true;
}
