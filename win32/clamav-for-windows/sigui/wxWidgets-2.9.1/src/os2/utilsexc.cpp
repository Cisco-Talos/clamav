/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/utilsexec.cpp
// Purpose:     Various utilities
// Author:      David Webster
// Modified by:
// Created:     10/17/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#include "wx/process.h"

#include "wx/os2/private.h"

#define PURE_32
#ifndef __EMX__
    #include <upm.h>
    #ifndef __WATCOMC__
        #include <netcons.h>
        #include <netbios.h>
    #endif
#endif

#include <ctype.h>
#ifdef __EMX__
#include <dirent.h>
#endif

#include <sys/stat.h>
#include <io.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>


// this message is sent when the process we're waiting for terminates
#define wxWM_PROC_TERMINATED (WM_USER + 10000)

#ifndef NO_ERROR
#  define NO_ERROR  0
#endif

// structure describing the process we're being waiting for
struct wxExecuteData
{
public:
    ~wxExecuteData()
    {
//         cout << "Closing thread: " << endl;
        DosExit(EXIT_PROCESS, 0);
    }

    HWND         hWnd;          // window to send wxWM_PROC_TERMINATED to [not used]
    RESULTCODES  vResultCodes;
    wxProcess*   pHandler;
    ULONG        ulExitCode;    // the exit code of the process
    bool         bState;        // set to false when the process finishes
};

static ULONG wxExecuteThread(wxExecuteData* pData)
{
    ULONG ulRc;
    PID   vPidChild;

//     cout << "Executing thread: " << endl;

    ulRc = ::DosWaitChild( DCWA_PROCESSTREE
                          ,DCWW_NOWAIT
                          ,&pData->vResultCodes
                          ,&vPidChild
                          ,pData->vResultCodes.codeTerminate // process PID to look at
                         );
    if (ulRc != NO_ERROR)
    {
        wxLogLastError(wxT("DosWaitChild"));
    }
    delete pData;
    return 0;
}

// window procedure of a hidden window which is created just to receive
// the notification message when a process exits
MRESULT APIENTRY wxExecuteWindowCbk( HWND   hWnd,
                                     ULONG  ulMessage,
                                     MPARAM WXUNUSED(wParam),
                                     MPARAM lParam)
{
    if (ulMessage == wxWM_PROC_TERMINATED)
    {
        wxExecuteData*              pData = (wxExecuteData *)lParam;

        if (pData->pHandler)
        {
            pData->pHandler->OnTerminate( (int)pData->vResultCodes.codeTerminate
                                         ,(int)pData->vResultCodes.codeResult
                                        );
        }

        if (pData->bState)
        {
            // we're executing synchronously, tell the waiting thread
            // that the process finished
            pData->bState = 0;
        }
        else
        {
            // asynchronous execution - we should do the clean up
            delete pData;
        }
        ::WinDestroyWindow(hWnd);    // we don't need it any more
    }
    return 0;
}

long wxExecute( const wxString& rCommand,
                int flags,
                wxProcess* pHandler)
{
    if (rCommand.empty())
    {
//         cout << "empty command in wxExecute." << endl;
        return 0;
    }

    // create the process
    UCHAR                           vLoadError[CCHMAXPATH] = {0};
    RESULTCODES                     vResultCodes = {0};
    ULONG                           ulExecFlag;
    PSZ                             zArgs = NULL;
    PSZ                             zEnvs = NULL;
    APIRET                          rc;
    TID                             vTID;

    if (flags & wxEXEC_SYNC)
        ulExecFlag = EXEC_SYNC;
    else
        ulExecFlag = EXEC_ASYNCRESULT;

    rc = ::DosExecPgm( (PCHAR)vLoadError
                      ,sizeof(vLoadError)
                      ,ulExecFlag
                      ,zArgs
                      ,zEnvs
                      ,&vResultCodes
                      ,rCommand.c_str()
                     );
    if (rc != NO_ERROR)
    {
        wxLogSysError(_("Execution of command '%s' failed with error: %ul"), rCommand.c_str(), rc);
        return 0;
    }
//     cout << "Executing: " << rCommand.c_str() << endl;
    // Alloc data
    wxExecuteData*                  pData = new wxExecuteData;

    pData->vResultCodes = vResultCodes;
    pData->hWnd         = NULLHANDLE;
    pData->bState       = (flags & wxEXEC_SYNC) != 0;
    if (flags & wxEXEC_SYNC)
    {
        wxASSERT_MSG(!pHandler, wxT("wxProcess param ignored for sync execution"));
        pData->pHandler = NULL;
    }
    else
    {
        // may be NULL or not
        pData->pHandler = pHandler;
    }

    rc = ::DosCreateThread( &vTID
                           ,(PFNTHREAD)&wxExecuteThread
                           ,(ULONG)pData
                           ,CREATE_READY|STACK_SPARSE
                           ,8192
                          );
    if (rc != NO_ERROR)
    {
        wxLogLastError(wxT("CreateThread in wxExecute"));
        delete pData;

        // the process still started up successfully...
        return vResultCodes.codeTerminate;
    }
    if (!(flags & wxEXEC_SYNC))
    {
        // return the pid
        // warning: don't exit your app unless you actively
        // kill and cleanup you child processes
        // Maybe detach the process here???
        // If cmd.exe need to pass DETACH to detach the process here
        return vResultCodes.codeTerminate;
    }

    // waiting until command executed
    ::DosWaitThread(&vTID, DCWW_WAIT);

    ULONG ulExitCode = pData->vResultCodes.codeResult;
    delete pData;

    // return the exit code
    return (long)ulExitCode;
}

long wxExecute(
  char**                            ppArgv
, int                               flags
, wxProcess*                        pHandler
)
{
    wxString                        sCommand;

    while (*ppArgv != NULL)
    {
        wxString                    sArg((wxChar*)(*ppArgv++));


        sCommand << sArg.c_str() << ' ';
    }
    sCommand.RemoveLast();
    return wxExecute( sCommand
                     ,flags
                     ,pHandler
                    );
}

bool wxGetFullHostName( wxChar* zBuf, int nMaxSize)
{
    return wxGetHostName( zBuf, nMaxSize );
}
