/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/thread.cpp
// Purpose:     wxThread Implementation
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if defined(__BORLANDC__)
    #pragma hdrstop
#endif

#if wxUSE_THREADS

#include "wx/thread.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/app.h"
    #include "wx/module.h"
#endif

#include "wx/apptrait.h"

#include "wx/palmos/private.h"
#include "wx/palmos/missing.h"

// must have this symbol defined to get _beginthread/_endthread declarations
#ifndef _MT
    #define _MT
#endif

#if defined(__BORLANDC__)
    #if !defined(__MT__)
        // I can't set -tWM in the IDE (anyone?) so have to do this
        #define __MT__
    #endif

    #if !defined(__MFC_COMPAT__)
        // Needed to know about _beginthreadex etc..
        #define __MFC_COMPAT__
    #endif
#endif // BC++

// define wxUSE_BEGIN_THREAD if the compiler has _beginthreadex() function
// which should be used instead of Win32 ::CreateThread() if possible
#if defined(__VISUALC__) || \
    (defined(__BORLANDC__) && (__BORLANDC__ >= 0x500)) || \
    (defined(__GNUG__) && defined(__MSVCRT__)) || \
    defined(__WATCOMC__) || defined(__MWERKS__)

#ifndef __WXWINCE__
    #undef wxUSE_BEGIN_THREAD
    #define wxUSE_BEGIN_THREAD
#endif

#endif

#ifdef wxUSE_BEGIN_THREAD
    // the return type of the thread function entry point
    typedef unsigned THREAD_RETVAL;

    // the calling convention of the thread function entry point
    #define THREAD_CALLCONV __stdcall
#else
    // the settings for CreateThread()
    typedef DWORD THREAD_RETVAL;
    #define THREAD_CALLCONV WINAPI
#endif

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// the possible states of the thread ("=>" shows all possible transitions from
// this state)
enum wxThreadState
{
    STATE_NEW,          // didn't start execution yet (=> RUNNING)
    STATE_RUNNING,      // thread is running (=> PAUSED, CANCELED)
    STATE_PAUSED,       // thread is temporarily suspended (=> RUNNING)
    STATE_CANCELED,     // thread should terminate a.s.a.p. (=> EXITED)
    STATE_EXITED        // thread is terminating
};

// ----------------------------------------------------------------------------
// this module globals
// ----------------------------------------------------------------------------

// TLS index of the slot where we store the pointer to the current thread
static DWORD gs_tlsThisThread = 0xFFFFFFFF;

// id of the main thread - the one which can call GUI functions without first
// calling wxMutexGuiEnter()
static DWORD gs_idMainThread = 0;

// if it's false, some secondary thread is holding the GUI lock
static bool gs_bGuiOwnedByMainThread = true;

// critical section which controls access to all GUI functions: any secondary
// thread (i.e. except the main one) must enter this crit section before doing
// any GUI calls
static wxCriticalSection *gs_critsectGui = NULL;

// critical section which protects gs_nWaitingForGui variable
static wxCriticalSection *gs_critsectWaitingForGui = NULL;

// critical section which serializes WinThreadStart() and WaitForTerminate()
// (this is a potential bottleneck, we use a single crit sect for all threads
// in the system, but normally time spent inside it should be quite short)
static wxCriticalSection *gs_critsectThreadDelete = NULL;

// number of threads waiting for GUI in wxMutexGuiEnter()
static size_t gs_nWaitingForGui = 0;

// are we waiting for a thread termination?
static bool gs_waitingForThread = false;

// ============================================================================
// Windows implementation of thread and related classes
// ============================================================================

// ----------------------------------------------------------------------------
// wxCriticalSection
// ----------------------------------------------------------------------------

wxCriticalSection::wxCriticalSection()
{
}

wxCriticalSection::~wxCriticalSection()
{
}

void wxCriticalSection::Enter()
{
}

void wxCriticalSection::Leave()
{
}

// ----------------------------------------------------------------------------
// wxMutex
// ----------------------------------------------------------------------------

class wxMutexInternal
{
public:
    wxMutexInternal(wxMutexType mutexType);
    ~wxMutexInternal();

    bool IsOk() const { return m_mutex != NULL; }

    wxMutexError Lock() { return LockTimeout(INFINITE); }
    wxMutexError TryLock() { return LockTimeout(0); }
    wxMutexError Unlock();

private:
    wxMutexError LockTimeout(DWORD milliseconds);

    HANDLE m_mutex;

    wxDECLARE_NO_COPY_CLASS(wxMutexInternal);
};

// all mutexes are recursive under Win32 so we don't use mutexType
wxMutexInternal::wxMutexInternal(wxMutexType WXUNUSED(mutexType))
{
}

wxMutexInternal::~wxMutexInternal()
{
}

wxMutexError wxMutexInternal::LockTimeout(DWORD milliseconds)
{
    return wxMUTEX_NO_ERROR;
}

wxMutexError wxMutexInternal::Unlock()
{
    return wxMUTEX_NO_ERROR;
}

// --------------------------------------------------------------------------
// wxSemaphore
// --------------------------------------------------------------------------

// a trivial wrapper around Win32 semaphore
class wxSemaphoreInternal
{
public:
    wxSemaphoreInternal(int initialcount, int maxcount);
    ~wxSemaphoreInternal();

    bool IsOk() const { return m_semaphore != NULL; }

    wxSemaError Wait() { return WaitTimeout(INFINITE); }

    wxSemaError TryWait()
    {
        wxSemaError rc = WaitTimeout(0);
        if ( rc == wxSEMA_TIMEOUT )
            rc = wxSEMA_BUSY;

        return rc;
    }

    wxSemaError WaitTimeout(unsigned long milliseconds);

    wxSemaError Post();

private:
    HANDLE m_semaphore;

    wxDECLARE_NO_COPY_CLASS(wxSemaphoreInternal);
};

wxSemaphoreInternal::wxSemaphoreInternal(int initialcount, int maxcount)
{
}

wxSemaphoreInternal::~wxSemaphoreInternal()
{
}

wxSemaError wxSemaphoreInternal::WaitTimeout(unsigned long milliseconds)
{
    return wxSEMA_NO_ERROR;
}

wxSemaError wxSemaphoreInternal::Post()
{
    return wxSEMA_NO_ERROR;
}

// ----------------------------------------------------------------------------
// wxThread implementation
// ----------------------------------------------------------------------------

// wxThreadInternal class
// ----------------------

class wxThreadInternal
{
public:
    wxThreadInternal(wxThread *thread)
    {
        m_thread = thread;
        m_hThread = 0;
        m_state = STATE_NEW;
        m_priority = WXTHREAD_DEFAULT_PRIORITY;
        m_nRef = 1;
    }

    ~wxThreadInternal()
    {
        Free();
    }

    void Free()
    {
        if ( m_hThread )
        {
            if ( !::CloseHandle(m_hThread) )
            {
                wxLogLastError(wxT("CloseHandle(thread)"));
            }

            m_hThread = 0;
        }
    }

    // create a new (suspended) thread (for the given thread object)
    bool Create(wxThread *thread, unsigned int stackSize);

    // wait for the thread to terminate, either by itself, or by asking it
    // (politely, this is not Kill()!) to do it
    wxThreadError WaitForTerminate(wxCriticalSection& cs,
                                   wxThread::ExitCode *pRc,
                                   wxThread *threadToDelete = NULL);

    // kill the thread unconditionally
    wxThreadError Kill();

    // suspend/resume/terminate
    bool Suspend();
    bool Resume();
    void Cancel() { m_state = STATE_CANCELED; }

    // thread state
    void SetState(wxThreadState state) { m_state = state; }
    wxThreadState GetState() const { return m_state; }

    // thread priority
    void SetPriority(unsigned int priority);
    unsigned int GetPriority() const { return m_priority; }

    // thread handle and id
    HANDLE GetHandle() const { return m_hThread; }
    DWORD  GetId() const { return m_tid; }

    // thread function
    static THREAD_RETVAL THREAD_CALLCONV WinThreadStart(void *thread);

    void KeepAlive()
    {
        if ( m_thread->IsDetached() )
            ::InterlockedIncrement(&m_nRef);
    }

    void LetDie()
    {
        if ( m_thread->IsDetached() && !::InterlockedDecrement(&m_nRef) )
            delete m_thread;
    }

private:
    // the thread we're associated with
    wxThread *m_thread;

    HANDLE        m_hThread;    // handle of the thread
    wxThreadState m_state;      // state, see wxThreadState enum
    unsigned int  m_priority;   // thread priority in "wx" units
    DWORD         m_tid;        // thread id

    // number of threads which need this thread to remain alive, when the count
    // reaches 0 we kill the owning wxThread -- and die ourselves with it
    LONG m_nRef;

    wxDECLARE_NO_COPY_CLASS(wxThreadInternal);
};

// small class which keeps a thread alive during its lifetime
class wxThreadKeepAlive
{
public:
    wxThreadKeepAlive(wxThreadInternal& thrImpl) : m_thrImpl(thrImpl)
        { m_thrImpl.KeepAlive(); }
    ~wxThreadKeepAlive()
        { m_thrImpl.LetDie(); }

private:
    wxThreadInternal& m_thrImpl;
};


THREAD_RETVAL THREAD_CALLCONV wxThreadInternal::WinThreadStart(void *param)
{
    THREAD_RETVAL rc;

    return rc;
}

void wxThreadInternal::SetPriority(unsigned int priority)
{
}

bool wxThreadInternal::Create(wxThread *thread, unsigned int stackSize)
{
    return false;
}

wxThreadError wxThreadInternal::Kill()
{
    return wxTHREAD_NO_ERROR;
}

wxThreadError
wxThreadInternal::WaitForTerminate(wxCriticalSection& cs,
                                   wxThread::ExitCode *pRc,
                                   wxThread *threadToDelete)
{
    return wxTHREAD_NO_ERROR;
}

bool wxThreadInternal::Suspend()
{
    return true;
}

bool wxThreadInternal::Resume()
{
    return true;
}

// static functions
// ----------------

wxThread *wxThread::This()
{
    return NULL;
}

bool wxThread::IsMain()
{
    return true;
}

void wxThread::Yield()
{
}

int wxThread::GetCPUCount()
{
    return 1;
}

unsigned long wxThread::GetCurrentId()
{
    return 0;
}

bool wxThread::SetConcurrency(size_t level)
{
    return true;
}

// ctor and dtor
// -------------

wxThread::wxThread(wxThreadKind kind)
{
}

wxThread::~wxThread()
{
}

// create/start thread
// -------------------

wxThreadError wxThread::Create(unsigned int stackSize)
{
    return wxTHREAD_NO_ERROR;
}

wxThreadError wxThread::Run()
{
    return wxTHREAD_RUNNING;
}

// suspend/resume thread
// ---------------------

wxThreadError wxThread::Pause()
{
    return wxTHREAD_NO_ERROR;
}

wxThreadError wxThread::Resume()
{
    return wxTHREAD_NO_ERROR;
}

// stopping thread
// ---------------

wxThread::ExitCode wxThread::Wait()
{
    return 0;
}

wxThreadError wxThread::Delete(ExitCode *pRc)
{
    return wxTHREAD_NO_ERROR;
}

wxThreadError wxThread::Kill()
{
    return wxTHREAD_NO_ERROR;
}

void wxThread::Exit(ExitCode status)
{
}

// priority setting
// ----------------

void wxThread::SetPriority(unsigned int prio)
{
}

unsigned int wxThread::GetPriority() const
{
    return 1;
}

unsigned long wxThread::GetId() const
{
    return 0;
}

bool wxThread::IsRunning() const
{
    return true;
}

bool wxThread::IsAlive() const
{
    return true;
}

bool wxThread::IsPaused() const
{
    return false;
}

bool wxThread::TestDestroy()
{
    return true;
}

// ----------------------------------------------------------------------------
// Automatic initialization for thread module
// ----------------------------------------------------------------------------

class wxThreadModule : public wxModule
{
public:
    virtual bool OnInit();
    virtual void OnExit();

private:
    DECLARE_DYNAMIC_CLASS(wxThreadModule)
};

IMPLEMENT_DYNAMIC_CLASS(wxThreadModule, wxModule)

bool wxThreadModule::OnInit()
{
    return true;
}

void wxThreadModule::OnExit()
{
}

// ----------------------------------------------------------------------------
// under Windows, these functions are implemented using a critical section and
// not a mutex, so the names are a bit confusing
// ----------------------------------------------------------------------------

void wxMutexGuiEnterImpl()
{
}

void wxMutexGuiLeaveImpl()
{
}

void WXDLLIMPEXP_BASE wxMutexGuiLeaveOrEnter()
{
}

bool WXDLLIMPEXP_BASE wxGuiOwnedByMainThread()
{
    return true;
}

// wake up the main thread if it's in ::GetMessage()
void WXDLLIMPEXP_BASE wxWakeUpMainThread()
{
}

bool WXDLLIMPEXP_BASE wxIsWaitingForThread()
{
    return false;
}

// ----------------------------------------------------------------------------
// include common implementation code
// ----------------------------------------------------------------------------

#include "wx/thrimpl.cpp"

#endif // wxUSE_THREADS
