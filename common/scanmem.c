/*
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2005-2010 Gianluigi Tiesi <sherpya@netfarm.it>
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

#include <windows.h>
#include <tlhelp32.h>

#include <psapi.h>
#include <windns.h>

#include <clamav.h>
#include <others.h>

#include "actions.h"
#include "output.h"
#include "clamdcom.h"
#include "exescanner.h"
#include "scanmem.h"

typedef int (*proc_callback)(PROCESSENTRY32 ProcStruct, MODULEENTRY32 me32, void *data, struct mem_info *info);
int sock;
struct optstruct *clamdopts;

static inline bool lookup_cache(filelist_t **list, const char *filename, cl_error_t *result)
{
    filelist_t *current = *list;
    while (current) {
        /* Cache hit */
        if (!_stricmp(filename, current->filename)) {
            if (NULL != result) {
                *result = current->res;
            }
            return true;
        }
        current = current->next;
    }

    return false;
}

static inline void insert_cache(filelist_t **list, const char *filename,
                                cl_error_t res)
{
    filelist_t *current = *list, *prev = NULL;

    if (!current) /* New */
        *list = current = malloc(sizeof(filelist_t));
    else {
        while (current->next)
            current = current->next;
        prev       = current;
        prev->next = current = malloc(sizeof(filelist_t));
    }

    current->next        = NULL;
    current->res         = res;
    current->filename[0] = 0;
    strncat(current->filename, filename,
            MAX_PATH - 1 - strlen(current->filename));
    current->filename[MAX_PATH - 1] = 0;
}

static inline void free_cache(filelist_t **list)
{
    filelist_t *current, *prev;
    current = prev = *list;

    if (!current)
        return;

    do {
        prev    = current;
        current = prev->next;
        free(prev);
    } while (current);
}

/**
 * @brief Resolve a memory module path using the same sharing policy as action
 *        source opens.
 *
 * @param path           Path to resolve.
 * @param resolved_path  Resolved path on success. Caller must free it.
 * @return cl_error_t    CL_SUCCESS if the path was resolved.
 */
static cl_error_t scanmem_resolve_action_path(const char *path, char **resolved_path)
{
    HANDLE handle     = INVALID_HANDLE_VALUE;
    cl_error_t status = CL_EARG;

    if ((NULL == path) || (NULL == resolved_path)) {
        return CL_EARG;
    }

    *resolved_path = NULL;

    handle = CreateFileA(
        path,
        FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE == handle) {
        status = CL_EOPEN;
        goto done;
    }

    status = cli_get_filepath_from_handle(handle, resolved_path);

done:
    if (INVALID_HANDLE_VALUE != handle) {
        CloseHandle(handle);
    }
    return status;
}

static inline char *wc2mb(const wchar_t *wc, DWORD flags)
{
    BOOL invalid = FALSE;
    DWORD len = 0, res = 0;
    char *mb = NULL;

    len = WideCharToMultiByte(CP_ACP, flags, wc, -1, NULL, 0, NULL, &invalid);
    if (!len && (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
        fprintf(stderr, "WideCharToMultiByte() failed with %d\n", GetLastError());
        return NULL;
    }

    mb = malloc(len + 1);
    if (!mb) return NULL;

    res = WideCharToMultiByte(CP_ACP, flags, wc, -1, mb, len, NULL, &invalid);
    if (res && ((!invalid || (flags != WC_NO_BEST_FIT_CHARS)))) return mb;
    free(mb);
    return NULL;
}

/* Needed to Scan System Processes */
int EnablePrivilege(LPCSTR PrivilegeName, DWORD yesno)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LoadLibraryA("advapi32.dll")) {
        logg(LOGG_WARNING, "EnablePrivilege functions are missing\n");
        return 0;
    }

    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken))
        return 0;

    if (!LookupPrivilegeValue(NULL, PrivilegeName, &luid))
        return 0;

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = yesno;

    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);

    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS) ? 1 : 0;
}

static char *getaltpath(const wchar_t *filename)
{
    WIN32_FIND_DATAW wfdw;
    HANDLE hf                     = INVALID_HANDLE_VALUE;
    wchar_t *part                 = _wcsdup(filename);
    wchar_t comprev[MAX_PATH + 1] = L"", compose[MAX_PATH + 1];
    wchar_t *rev = comprev, *slash = part, *c = NULL;
    size_t l, la;
    size_t i;

    do {
        if (slash != part)
            *slash = 0;

        /* c: d: etc */
        if ((wcslen(part) == 2) && (part[1] == L':')) {
            *rev++ = L':';
            *rev++ = part[0];
            break;
        }

        hf = FindFirstFileW(part, &wfdw);
        if (hf == INVALID_HANDLE_VALUE) /* Network path */
        {
            for (i = wcslen(part); i > 0; i--)
                *rev++ = part[i - 1];
            break;
        }
        FindClose(hf);
        l  = wcslen(wfdw.cFileName);
        la = wcslen(wfdw.cAlternateFileName);

        if (la)
            for (i = la; i > 0; i--)
                *rev++ = *(wfdw.cAlternateFileName + i - 1);
        else
            for (i = l; i > 0; i--)
                *rev++ = *(wfdw.cFileName + i - 1);
        *rev++ = '\\';

    } while ((slash = wcsrchr(part, L'\\')));

    rev = comprev;
    c   = compose;
    for (i = wcslen(rev); i > 0; i--)
        *c++ = *(rev + i - 1);
    *c = 0;

    free(part);
    return wc2mb(compose, WC_NO_BEST_FIT_CHARS);
}

int walkmodules_th(proc_callback callback, void *data, struct mem_info *info)
{
    HANDLE hSnap = INVALID_HANDLE_VALUE, hModuleSnap = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 ps;
    MODULEENTRY32 me32;

    logg(LOGG_INFO, " *** Memory Scan: using ToolHelp ***\n\n");

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return -1;

    ps.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &ps)) {
        CloseHandle(hSnap);
        return -1;
    }

    do {
        /* system process */
        if (!ps.th32ProcessID)
            continue;
        hModuleSnap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ps.th32ProcessID);
        if (hModuleSnap == INVALID_HANDLE_VALUE)
            continue;

        me32.dwSize = sizeof(MODULEENTRY32);
        if (!Module32First(hModuleSnap, &me32)) {
            CloseHandle(hModuleSnap);
            continue;
        }

        /* Check and transform non ANSI filenames to ANSI using altnames */
        HANDLE hFile = CreateFileA(
            me32.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            wchar_t nameW[MAX_PATH + 1];
            char *converted = NULL;
            HANDLE p;

            if (err == ERROR_BAD_NETPATH) {
                logg(LOGG_WARNING, "Warning scanning files on non-ansi network paths is not "
                                   "supported\n");
                logg(LOGG_WARNING, "File: %s\n", me32.szExePath);
                continue;
            }

            if ((err != ERROR_INVALID_NAME) && (err != ERROR_PATH_NOT_FOUND)) {
                logg(LOGG_WARNING, "Expected ERROR_INVALID_NAME/ERROR_PATH_NOT_FOUND but got %d\n",
                     err);
                continue;
            }

            p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                            ps.th32ProcessID);

            if (!GetModuleFileNameExW(p, NULL, nameW, MAX_PATH)) {
                logg(LOGG_WARNING, "GetModuleFileNameExW() failed %d\n", GetLastError());
                CloseHandle(p);
                continue;
            }
            CloseHandle(p);

            if (!(converted = getaltpath(nameW))) {
                logg(LOGG_WARNING, "Cannot map filename to ANSI codepage\n");
                continue;
            }
            strcpy(me32.szExePath, converted);
            free(converted);
        } else {
            CloseHandle(hFile);
        }

        do
            if (callback(ps, me32, data, info))
                break;
        while (Module32Next(hModuleSnap, &me32));

        CloseHandle(hModuleSnap);
    } while (Process32Next(hSnap, &ps));
    CloseHandle(hSnap);
    return 0;
}

int walkmodules_psapi(proc_callback callback, void *data, struct mem_info *info)
{
    DWORD procs[1024], needed, nprocs, mneeded;
    HANDLE hProc;
    HMODULE mods[1024];
    PROCESSENTRY32 ps;
    MODULEENTRY32 me32;
    MODULEINFO mi;
    int i, j;

    logg(LOGG_INFO, " *** Memory Scan: using PsApi ***\n\n");

    if (!EnumProcesses(procs, sizeof(procs), &needed))
        return -1;

    nprocs = needed / sizeof(DWORD);

    memset(&ps, 0, sizeof(PROCESSENTRY32));
    memset(&me32, 0, sizeof(MODULEENTRY32));
    ps.dwSize   = sizeof(PROCESSENTRY32);
    me32.dwSize = sizeof(MODULEENTRY32);

    for (i = 0; i < nprocs; i++) {
        if (!procs[i])
            continue; /* System process */

        hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                            procs[i]);

        if (!hProc)
            continue;

        if (!EnumProcessModules(hProc, mods, sizeof(mods),
                                &mneeded)) {
            CloseHandle(hProc);
            continue;
        }

        if (!GetModuleBaseNameA(hProc, mods[0], ps.szExeFile,
                                MAX_PATH - 1)) {
            CloseHandle(hProc);
            continue;
        }

        ps.th32ProcessID = procs[i];

        for (j = 0; j < (mneeded / sizeof(HMODULE)); j++) {
            if (!GetModuleBaseNameA(hProc, mods[j], me32.szModule,
                                    MAX_PATH - 1))
                continue;

            if (!GetModuleFileNameExA(hProc, mods[j], me32.szExePath,
                                      MAX_PATH - 1))
                continue;

            if (!GetModuleInformation(hProc, mods[j], &mi,
                                      sizeof(mi)))
                continue;

            me32.hModule       = mods[j];
            me32.th32ProcessID = procs[i];
            me32.modBaseAddr   = mi.lpBaseOfDll;
            me32.modBaseSize   = mi.SizeOfImage;
            if (callback(ps, me32, data, info))
                break;
        }
        CloseHandle(hProc);
    }
    return 0;
}

int kill_process(DWORD pid)
{
    HANDLE hProc;
    if (GetCurrentProcessId() == pid) {
        logg(LOGG_WARNING, "Don't want to kill myself\n");
        return 1;
    }

    if ((hProc = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid))) {
        TerminateProcess(hProc, 0);
        if (WaitForSingleObject(hProc, TIMEOUT_MODULE) != WAIT_OBJECT_0)
            logg(LOGG_WARNING, "Unable to unload process from memory\n");
        CloseHandle(hProc);
    } else
        logg(LOGG_WARNING, "OpenProcess() failed %lu\n", GetLastError());
    return 1; /* Skip to next process anyway */
}

/* Not so safe ;) */
int unload_module(DWORD pid, HANDLE hModule)
{
    DWORD rc = 1;
    HANDLE ht;
    HANDLE hProc;

    if (GetCurrentProcessId() == pid) {
        logg(LOGG_WARNING, "Don't want to unload modules from myself\n");
        return 1;
    }

    hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                            PROCESS_VM_WRITE | PROCESS_VM_READ,
                        FALSE, pid);

    if (!hProc) {
        logg(LOGG_WARNING, "OpenProcess() failed %lu\n", GetLastError());
        return 1; /* Skip to next process */
    }

    if ((ht = CreateRemoteThread(
             hProc, 0, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, hModule, 0,
             &rc))) {
        if (WaitForSingleObject(ht, TIMEOUT_MODULE) == WAIT_TIMEOUT) {
            CloseHandle(ht);
            CloseHandle(hProc);
            logg(LOGG_INFO, "The module may trying to trick us, killing the process, please "
                            "rescan\n");
            return kill_process(pid);
        }
        CloseHandle(ht);
        rc = 0; /* Continue scanning this process */
    } else {
        DWORD res = GetLastError();
        if (res == ERROR_CALL_NOT_IMPLEMENTED) {
            logg(LOGG_WARNING, "Module unloading is not supported on this OS\n");
            rc = -1; /* Don't complain about removing/moving the file */
        } else {
            logg(LOGG_ERROR, "CreateRemoteThread() failed %lu\n", res);
            rc = 1; /* Skip to next process */
        }
    }

    CloseHandle(hProc);
    return rc;
}

#define FILLBYTES(dst)                                       \
    if (IsBadReadPtr(seek, sizeof(dst))) {                   \
        logg(LOGG_ERROR, "ScanMem Align: Bad pointer!!!\n"); \
        return 1;                                            \
    }                                                        \
    memcpy(&dst, seek, sizeof(dst))

/* PE Realignment - FIXME: a lot of code is copy/paste from exeScanner.c */
int align_pe(unsigned char *buffer, size_t size)
{
    int i = 0;
    uint16_t e_mz;
    uint32_t e_lfanew, e_magic;
    unsigned char *seek = buffer;
    PIMAGE_FILE_HEADER pehdr;
    PIMAGE_OPTIONAL_HEADER32 opthdr;
    PIMAGE_SECTION_HEADER sechdr;

    FILLBYTES(e_mz);
    if (e_mz != IMAGE_DOS_SIGNATURE) {
        /* cli_dbgmsg("ScanMem Align: DOS Signature not found\n"); */
        return 0;
    }

    seek += 0x3c;

    FILLBYTES(e_lfanew);
    if (!e_lfanew) {
        /* cli_dbgmsg("ScanMem Align: Invalid PE offset\n"); */
        return 0;
    }
    seek = buffer + e_lfanew;

    /* PE Signature 'PE' */
    FILLBYTES(e_magic);
    if (e_magic != IMAGE_NT_SIGNATURE) {
        /* cli_dbgmsg("ScanMem Align: PE Signature not found\n"); */
        return 0;
    }
    seek += sizeof(e_magic);

    if (IsBadReadPtr(seek, sizeof(IMAGE_FILE_HEADER)))
        return 0;
    pehdr = (PIMAGE_FILE_HEADER)seek;
    seek += sizeof(IMAGE_FILE_HEADER);

    if (IsBadReadPtr(seek, sizeof(IMAGE_OPTIONAL_HEADER32)))
        return 0;
    opthdr = (PIMAGE_OPTIONAL_HEADER32)seek;
    seek += sizeof(IMAGE_OPTIONAL_HEADER32);

    /* Invalid sections number */
    if ((pehdr->NumberOfSections < 1) || (pehdr->NumberOfSections > 32)) {
        /* cli_dbgmsg("ScanMem Align: Invalid sections number\n"); */
        return 0;
    }

    for (i = 0; i < pehdr->NumberOfSections; i++) {
        if (IsBadWritePtr(seek, sizeof(IMAGE_SECTION_HEADER)))
            return 0;
        sechdr = (PIMAGE_SECTION_HEADER)seek;
        seek += sizeof(IMAGE_SECTION_HEADER);
        sechdr->PointerToRawData = sechdr->VirtualAddress;
        sechdr->SizeOfRawData    = sechdr->Misc.VirtualSize;
    }
    return 1;
}

int dump_pe(const char *filename, PROCESSENTRY32 ProcStruct,
            MODULEENTRY32 me32)
{
#ifdef _WIN64 /* MinGW has a broken header for ReadProcessMemory() */
    size_t bytesread = 0;
#else
    DWORD bytesread = 0;
#endif
    DWORD byteswrite = 0;
    int ret          = -1;
    HANDLE hFile = INVALID_HANDLE_VALUE, hProc = NULL;
    unsigned char *buffer = NULL;

    if (!(hProc = OpenProcess(PROCESS_VM_READ, FALSE, ProcStruct.th32ProcessID)))
        return -1;

    buffer = malloc((size_t)me32.modBaseSize);
    if (!ReadProcessMemory(hProc, me32.modBaseAddr, buffer,
                           (size_t)me32.modBaseSize, &bytesread)) {
        free(buffer);
        CloseHandle(hProc);
        return ret;
    }

    CloseHandle(hProc);

    /* PE Realignment */
    align_pe(buffer, me32.modBaseSize);

    hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        logg(LOGG_INFO, "Error creating %s\n", filename);
        free(buffer);
        return ret;
    }

    if (WriteFile(hFile, buffer, (DWORD)bytesread, &byteswrite, NULL))
        ret = _open_osfhandle((intptr_t)hFile, O_RDONLY | O_BINARY);
    free(buffer);
    return ret;
}

/*
 * filename is the display name for scan output. scan_open_path is the path to
 * submit or open for scanning. action_target is the original on-disk module to
 * quarantine when scanning a temporary dump of a packed module finds the
 * infection. action_open_path is an optional resolved path to open for
 * quarantine action; when action_open_path_required is true, action setup fails
 * closed instead of opening action_target by its unresolved name.
 */
cl_error_t scanfile(
    const char *filename,
    const char *scan_open_path,
    const char *action_target,
    const char *action_open_path,
    bool action_open_path_required,
    scanmem_data *scan_data,
    struct mem_info *info,
    action_source_t *infected_action_source)
{
    int fd = -1;
    int scantype;
    cl_error_t status = CL_CLEAN;
    int infected = 0;
    const char *scan_path = (NULL != scan_open_path) ? scan_open_path : filename;
    const char *action_display_filename = (NULL != action_target) ? action_target : filename;
    bool action_target_is_scan_target =
        ((NULL == action_target) || (0 == strcmp(action_target, filename))) &&
        ((NULL == action_open_path) || (0 == strcmp(action_open_path, scan_path)));
    action_source_t action_source;
    bool have_action_source = false;
    bool action_source_open_failed = false;
    bool scan_uses_action_source = false;
    cl_error_t action_source_status = CL_SUCCESS;
    int scan_errors_before = 0;
    int scan_result        = 0;

    cl_verdict_t verdict   = CL_VERDICT_NOTHING_FOUND;
    const char *alert_name = NULL;

    action_source_init(&action_source);

    logg(LOGG_DEBUG, "Scanning %s\n", filename);

    if (action) {
        if (NULL != action_open_path) {
            action_source_status = action_source_open_path(
                action_display_filename,
                action_open_path,
                &action_source);
        } else if (action_open_path_required) {
            action_source_status = CL_EOPEN;
        } else {
            action_source_status = action_source_open(action_display_filename, &action_source);
        }
        if (CL_SUCCESS != action_source_status) {
            logg(LOGG_WARNING, "Can't open file %s for safe quarantine action: %s\n", action_display_filename, cl_strerror(action_source_status));
            action_source_open_failed = true;
        } else {
            have_action_source = true;
        }
    }

    if (have_action_source && action_target_is_scan_target) {
        fd                      = action_source.scan_fd;
        scan_uses_action_source = true;
    } else if ((fd = safe_open(scan_path, O_RDONLY | O_BINARY)) == -1) {
        logg(LOGG_WARNING, "Can't open file %s, %s\n", scan_path, strerror(errno));
        if (have_action_source) {
            action_source_close(&action_source);
        }
        return CL_EOPEN;
    }

    if (info->d) { // clamdscan
        if (scan_uses_action_source) {
#ifdef HAVE_FD_PASSING
            if (optget(clamdopts, "LocalSocket")->enabled) {
                scantype = FILDES;
            } else
#endif
            {
                scantype = STREAM;
            }
        } else if (optget(info->opts, "stream")->enabled)
            scantype = STREAM;
        else if (optget(info->opts, "multiscan")->enabled)
            scantype = MULTI;
        else if (optget(info->opts, "allmatch")->enabled)
            scantype = ALLMATCH;
        else
            scantype = CONT;

        if ((sock = dconnect(clamdopts)) < 0) {
            info->errors++;
            if (!scan_uses_action_source) {
                close(fd);
            }
            if (have_action_source) {
                action_source_close(&action_source);
            }
            return CL_EOPEN;
        }
        scan_errors_before = info->errors;
        scan_result        = dsresult(sock, scantype, scan_path, scan_uses_action_source ? &action_source : NULL, false, NULL, &info->errors, clamdopts);
        if (scan_result > 0) {
            info->ifiles++;
            status = CL_VIRUS;
            infected = 1;
        } else if ((scan_result < 0) || (info->errors > scan_errors_before)) {
            status = CL_EOPEN;
        }
    } else { // clamscan
        status = cl_scandesc_ex(
            fd,
            filename,
            &verdict,
            &alert_name,
            &info->bytes_scanned,
            info->engine,
            info->options,
            NULL,  // void *context,
            NULL,  // const char *hash_hint,
            NULL,  // char **hash_out,
            NULL,  // const char *hash_alg,
            NULL,  // const char *file_type_hint,
            NULL); // char **file_type_out);

        switch (verdict) {
            case CL_VERDICT_NOTHING_FOUND: {
                logg(LOGG_INFO, "%s: OK    \n", filename);
                status = CL_CLEAN;
            } break;
            case CL_VERDICT_TRUSTED: {
                // TODO: Option to print "TRUSTED" verdict instead of "OK"?
                logg(LOGG_INFO, "%s: OK    \n", filename);
                status = CL_CLEAN;
            } break;
            case CL_VERDICT_STRONG_INDICATOR:
            case CL_VERDICT_POTENTIALLY_UNWANTED: {
                logg(LOGG_INFO, "%s: %s FOUND\n", filename, alert_name);
                info->ifiles++;
                status = CL_VIRUS;
                infected = 1;
            } break;
        }
    }

    if (!scan_uses_action_source) {
        close(fd);
    }
    fd = -1;

    if (infected && action) {
        if (have_action_source) {
            if (NULL != infected_action_source) {
                *infected_action_source = action_source;
                action_source_init(&action_source);
                have_action_source = false;
            } else {
                action(&action_source);
            }
        } else if (action_source_open_failed) {
            if (optget(info->opts, "remove")->enabled) {
                notremoved++;
            } else {
                notmoved++;
            }
            logg(LOGG_ERROR, "Can't apply quarantine action for scan target '%s': safe source '%s' is unavailable: %s\n",
                 filename,
                 action_display_filename,
                 cl_strerror(action_source_status));
        }
    }

    if (have_action_source) {
        action_source_close(&action_source);
    }

    return status;
}

int scanmem_cb(PROCESSENTRY32 ProcStruct, MODULEENTRY32 me32, void *data, struct mem_info *info)
{
    scanmem_data *scan_data     = data;
    int rc                      = 0;
    int isprocess               = 0;
    char modulename[MAX_PATH]   = "";
    char expandmodule[MAX_PATH] = "";
    char *resolved_modulename           = NULL;
    const char *module_scan_path        = modulename;
    const char *module_action_open_path = NULL;
    action_source_t deferred_action_source;
    cl_error_t cached_result        = CL_CLEAN;
    cl_error_t resolve_status       = CL_CLEAN;
    bool cache_hit                  = false;
    bool module_filter_enabled      = false;
    bool module_excluded            = false;

    if (!scan_data)
        return 0;
    scan_data->res = CL_CLEAN;
    action_source_init(&deferred_action_source);

    modulename[0] = 0;
    /* Special case, btw why I get \SystemRoot\ in process szExePath?
     There are also other cases? */
    if ((strlen(me32.szExePath) > 12) &&
        !strncmp(me32.szExePath, "\\SystemRoot\\", 12)) {
        expandmodule[0] = 0;
        strncat(expandmodule, me32.szExePath, MAX_PATH - 1 - strlen(expandmodule));
        expandmodule[MAX_PATH - 1] = 0;
        snprintf(expandmodule, MAX_PATH - 1, "%%SystemRoot%%\\%s",
                 &me32.szExePath[12]);
        expandmodule[MAX_PATH - 1] = 0;
        ExpandEnvironmentStringsA(expandmodule, modulename, MAX_PATH - 1);
        modulename[MAX_PATH - 1] = 0;
    }

    if (!modulename[0]) {
        strncpy(modulename, me32.szExePath, MAX_PATH - 1);
        modulename[MAX_PATH - 1] = 0;
    }

    cache_hit = lookup_cache(&scan_data->files, modulename, &cached_result);
    if (cache_hit) {
        scan_data->res = cached_result;
    }
    isprocess      = !_stricmp(ProcStruct.szExeFile, modulename) ||
                !_stricmp(ProcStruct.szExeFile, me32.szModule);

    if (!cache_hit) {
        if (isprocess)
            scan_data->processes++;
        else
            scan_data->modules++;

        info->files++;

        /* check for module exclusion */
        scan_data->res = CL_CLEAN;
        module_filter_enabled = info->d || scan_data->exclude;
        module_excluded       = module_filter_enabled && chkpath(modulename, clamdopts);

        if (action && !module_excluded) {
            resolve_status = scanmem_resolve_action_path(modulename, &resolved_modulename);
            if ((CL_SUCCESS == resolve_status) && (NULL != resolved_modulename)) {
                module_scan_path        = resolved_modulename;
                module_action_open_path = resolved_modulename;
                if (module_filter_enabled) {
                    module_excluded = chkpath(resolved_modulename, clamdopts);
                }
            } else {
                logg(LOGG_WARNING, "Can't resolve module path %s for safe quarantine action: %s\n",
                     modulename,
                     cl_strerror(resolve_status));
            }
        }

        if (!module_excluded)
            scan_data->res = scanfile(
                modulename,
                module_scan_path,
                modulename,
                module_action_open_path,
                NULL != action,
                scan_data,
                info,
                &deferred_action_source);

        if (!module_excluded && (CL_CLEAN == scan_data->res) && is_packed(module_scan_path)) {
            char *dumped = cli_gentemp(NULL);
            int fd       = -1;
            if ((fd = dump_pe(dumped, ProcStruct, me32)) > 0) {
                close(fd);
                scan_data->res = scanfile(
                    dumped,
                    dumped,
                    modulename,
                    module_action_open_path,
                    NULL != action,
                    scan_data,
                    info,
                    &deferred_action_source);
                DeleteFileA(dumped);
            }
            free(dumped);
        }
        /*
         * Keep caching clean results. Do not cache infected module results
         * while a quarantine action is enabled: move/remove may need to retry
         * after kill/unload or after an action failure, and action() does not
         * report whether a copy/move/remove succeeded. This can duplicate
         * --copy output for a module mapped into multiple processes, but it
         * avoids suppressing later move/remove opportunities.
         */
        if ((CL_CLEAN == scan_data->res) ||
            ((CL_VIRUS == scan_data->res) && (NULL == action))) {
            insert_cache(&scan_data->files, modulename, scan_data->res);
        }
    }

    if (scan_data->res == CL_VIRUS) {
        if (isprocess && scan_data->kill) {
            logg(LOGG_INFO, "Unloading program %s from memory\n", modulename);
            rc = kill_process(ProcStruct.th32ProcessID);
        } else if (scan_data->unload) {
            logg(LOGG_INFO, "Unloading module %s from %s\n", me32.szModule, modulename);
            if ((rc = unload_module(ProcStruct.th32ProcessID, me32.hModule)) == -1)
                /* CreateProcessThread() is not implemented */
                goto done;
        }

        if (action && !cache_hit) {
            if (-1 != deferred_action_source.scan_fd) {
                action(&deferred_action_source);
            }
        }
    }

done:
    if (-1 != deferred_action_source.scan_fd) {
        action_source_close(&deferred_action_source);
    }
    if (NULL != resolved_modulename) {
        free(resolved_modulename);
    }
    return rc;
}

int scanmem(struct mem_info *info)
{
    scanmem_data data;
    data.files      = NULL;
    data.printclean = 1;
    data.kill       = 0;
    data.unload     = 0;
    data.exclude    = 0;
    data.res        = CL_CLEAN;
    data.processes  = 0;
    data.modules    = 0;

    HMODULE psapi_ok = LoadLibraryA("psapi.dll");
    HMODULE k32_ok   = LoadLibraryA("kernel32.dll");

    if (!(psapi_ok || k32_ok)) {
        logg(LOGG_INFO, " *** Memory Scanning is not supported on this OS ***\n\n");
        return -1;
    }

    if (optget(info->opts, "infected")->enabled)
        data.printclean = 0;
    if (optget(info->opts, "kill")->enabled)
        data.kill = 1;
    if (optget(info->opts, "unload")->enabled)
        data.unload = 1;
    if (optget(info->opts, "exclude")->enabled)
        data.exclude = 1;

    if (info->d) {
        if ((sock = dconnect(clamdopts)) < 0) {
            info->errors++;
            return -1;
        }
    }

    logg(LOGG_INFO, " *** Scanning Programs in Computer Memory ***\n");

    if (!EnablePrivilege(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED))
        logg(LOGG_INFO, "---Please login as an Administrator to scan System processes loaded "
                        "in computer memory---\n");

    if (k32_ok)
        walkmodules_th(scanmem_cb, (void *)&data, info);
    else
        walkmodules_psapi(scanmem_cb, (void *)&data, info);
    free_cache(&data.files);

    logg(LOGG_INFO, "\n *** Scanned %lu processes - %lu modules ***\n", data.processes,
         data.modules);
    logg(LOGG_INFO, " *** Computer Memory Scan Completed ***\n\n");
    return data.res;
}
