/*
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2010 Gianluigi Tiesi <sherpya@netfarm.it>
 *
 *  Authors: Gianluigi Tiesi
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#include <platform.h>
#include <winsvc.h>

#include "service.h"
#include "output.h"

static SERVICE_STATUS svc;
static SERVICE_STATUS_HANDLE svc_handle;
static SERVICE_TABLE_ENTRYA DT[] = {{"Service", ServiceMain}, {NULL, NULL}};

static HANDLE evStart;
static HANDLE DispatcherThread;
static int checkpoint_every = 5000;

int svc_uninstall(const char *name, int verbose)
{
    SC_HANDLE sm, svc;
    int ret = 1;

    if (!(sm = OpenSCManagerA(NULL, NULL, DELETE))) {
        if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
            fprintf(stderr, "Windows Services are not supported on this Platform\n");
        else
            fprintf(stderr, "Unable to Open SCManager (%d)\n", GetLastError());
        return 0;
    }

    if ((svc = OpenServiceA(sm, name, DELETE))) {
        if (DeleteService(svc)) {
            if (verbose) printf("Service %s successfully removed\n", name);
        } else {
            fprintf(stderr, "Unable to Open Service %s (%d)\n", name, GetLastError());
            ret = 0;
        }
    } else {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            if (verbose) printf("Service %s does not exist\n", name);
        } else {
            fprintf(stderr, "Unable to Open Service %s (%d)\n", name, GetLastError());
            ret = 0;
        }
    }

    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(sm);
    return ret;
}

int svc_install(const char *name, const char *dname, const char *desc)
{
    SC_HANDLE sm, svc;
    char modulepath[MAX_PATH];
    char binpath[MAX_PATH];
    SERVICE_DESCRIPTIONA sdesc = {(char *)desc};

    if (!GetModuleFileName(NULL, modulepath, MAX_PATH - 1)) {
        fprintf(stderr, "Unable to get the executable name (%d)\n", GetLastError());
        return 0;
    }

    if (!svc_uninstall(name, 0)) return 0;

    if (!(sm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE | DELETE))) {
        if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
            fprintf(stderr, "Windows Services are not supported on this Platform\n");
        else
            fprintf(stderr, "Unable to Open SCManager (%d)\n", GetLastError());
        return 0;
    }

    if (strchr(modulepath, ' '))
        snprintf(binpath, MAX_PATH - 1, "\"%s\" --daemon --service-mode", modulepath);
    else
        snprintf(binpath, MAX_PATH - 1, "%s --daemon --service-mode", modulepath);

    svc = CreateServiceA(sm, name, dname, SERVICE_CHANGE_CONFIG,
                         SERVICE_WIN32_OWN_PROCESS,
                         SERVICE_DEMAND_START,
                         SERVICE_ERROR_NORMAL,
                         binpath,
                         NULL, /* Load group order */
                         NULL, /* Tag Id */
                         NULL, /* Dependencies */
                         NULL, /* User -> Local System */
                         "");

    if (!svc) {
        fprintf(stderr, "Unable to Create Service %s (%d)\n", name, GetLastError());
        CloseServiceHandle(sm);
        return 0;
    }

    /* ChangeServiceConfig2A() */
    if (!ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &sdesc))
        fprintf(stderr, "Unable to set description for Service %s (%d)\n", name, GetLastError());

    CloseServiceHandle(svc);
    CloseServiceHandle(sm);

    printf("Service %s successfully created.\n", name);
    printf("Use 'net start %s' and 'net stop %s' to start/stop the service.\n", name, name);
    return 1;
}

static void svc_getcpvalue(const char *name)
{
    HKEY hKey;
    DWORD dwType;
    DWORD value, vlen = sizeof(DWORD);
    char subkey[MAX_PATH];

    snprintf(subkey, MAX_PATH - 1, "SYSTEM\\CurrentControlSet\\Services\\%s", name);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return;

    if ((RegQueryValueExA(hKey, "Checkpoint", NULL, &dwType, (LPBYTE)&value, &vlen) == ERROR_SUCCESS) &&
        (vlen == sizeof(DWORD) && (dwType == REG_DWORD)))
        checkpoint_every = value;

    RegCloseKey(hKey);
}

void svc_register(const char *name)
{
    DWORD tid;
    DT->lpServiceName = (char *)name;
    svc_getcpvalue(name);

    evStart          = CreateEvent(NULL, TRUE, FALSE, NULL);
    DispatcherThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartServiceCtrlDispatcherA, (LPVOID)DT, 0, &tid);
}

void svc_ready(void)
{
    WaitForSingleObject(evStart, INFINITE);

    svc.dwCurrentState = SERVICE_RUNNING;
    svc.dwControlsAccepted |= SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    svc.dwCheckPoint = 0;

    if (!SetServiceStatus(svc_handle, &svc)) {
        logg(LOGG_INFO, "[service] SetServiceStatus() failed with %d\n", GetLastError());
        exit(1);
    }
}

int svc_checkpoint(const char *type, const char *name, unsigned int custom, void *context)
{
    if (svc.dwCurrentState == SERVICE_START_PENDING) {
        svc.dwCheckPoint++;
        if ((svc.dwCheckPoint % checkpoint_every) == 0)
            SetServiceStatus(svc_handle, &svc);
    }
    return 0;
}

void WINAPI ServiceCtrlHandler(DWORD code)
{
    switch (code) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            svc.dwCurrentState = SERVICE_STOPPED;
            svc.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
            SetServiceStatus(svc_handle, &svc);
            return;
        case SERVICE_CONTROL_INTERROGATE:
            break;
    }

    SetServiceStatus(svc_handle, &svc);
}

BOOL WINAPI cw_stop_ctrl_handler(DWORD CtrlType)
{
    if (CtrlType == CTRL_C_EVENT) {
        SetConsoleCtrlHandler(cw_stop_ctrl_handler, FALSE);
        fprintf(stderr, "Control+C pressed, aborting...\n");
        exit(0);
    }
    return TRUE;
}

void WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv)
{
    svc.dwServiceType             = SERVICE_WIN32;
    svc.dwCurrentState            = SERVICE_START_PENDING;
    svc.dwControlsAccepted        = 0;
    svc.dwWin32ExitCode           = NO_ERROR;
    svc.dwServiceSpecificExitCode = 0;
    svc.dwCheckPoint              = 0;
    svc.dwWaitHint                = 0;

    if (!(svc_handle = RegisterServiceCtrlHandlerA(DT->lpServiceName, ServiceCtrlHandler))) {
        logg(LOGG_INFO, "[service] RegisterServiceCtrlHandler() failed with %d\n", GetLastError());
        exit(1);
    }

    if (!SetServiceStatus(svc_handle, &svc)) {
        logg(LOGG_INFO, "[service] SetServiceStatus() failed with %d\n", GetLastError());
        exit(1);
    }

    SetEvent(evStart);
    WaitForSingleObject(DispatcherThread, INFINITE);
    cw_stop_ctrl_handler(CTRL_C_EVENT);
}