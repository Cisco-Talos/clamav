/*
 *  Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include "exescanner.h"
#include "scanmem.h"
#include "clamdcom.h"

typedef int (*proc_callback)(PROCESSENTRY32 ProcStruct, MODULEENTRY32 me32, void *data, struct mem_info *info);
int sock;

/* clamd helpers */
static int chkpath(const char *path, struct mem_info *minfo)
{
    const struct optstruct *opt;
    struct optstruct *clamdopts = NULL;

    if ((clamdopts = optparse(optget(minfo->opts, "config-file")->strarg, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
        logg("!Can't parse clamd configuration file %s\n", optget(minfo->opts, "config-file")->strarg);
    }

    if (!path) {
        return 1;
    }

    if ((opt = optget(clamdopts, "ExcludePath"))->enabled) {
        while (opt) {
            if (match_regex(path, opt->strarg) == 1) {
                if (!optget(minfo->opts, "infected")->enabled)
                    logg("~%s: Excluded\n", path);
                return 1;
            }
            opt = opt->nextarg;
        }
    }
    return 0;
}

/* Issues an INSTREAM command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int send_stream(int sockd, const char *filename, struct mem_info *info)
{
    uint32_t buf[BUFSIZ / sizeof(uint32_t)];
    int fd, len;

    struct optstruct *clamdopts = NULL;

    if ((clamdopts = optparse(optget(info->opts, "config-file")->strarg, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
        logg("!Can't parse clamd configuration file %s\n", optget(info->opts, "config-file")->strarg);
    }
    unsigned long int maxstream = optget(clamdopts, "StreamMaxLength")->numarg;
    unsigned long int todo      = maxstream;
    const char zINSTREAM[]      = "zINSTREAM";

    if (filename) {
        if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) < 0) {
            logg("~%s: Failed to open file. ERROR\n", filename);
            return 0;
        }
    } else {
        /* Read stream from STDIN */
        fd = 0;
    }

    if (sendln(sockd, zINSTREAM, sizeof(zINSTREAM))) {
        close(fd);
        return -1;
    }

    while ((len = read(fd, &buf[1], sizeof(buf) - sizeof(uint32_t))) > 0) {
        if ((unsigned int)len > todo) len = todo;
        buf[0] = htonl(len);
        if (sendln(sockd, (const char *)buf, len + sizeof(uint32_t))) {
            close(fd);
            return -1;
        }
        todo -= len;
        if (!todo) {
            len = 0;
            break;
        }
    }
    close(fd);
    if (len) {
        logg("!Failed to read from %s.\n", filename ? filename : "STDIN");
        return 0;
    }
    *buf = 0;
    sendln(sockd, (const char *)buf, 4);
    return 1;
}

/* Connects to clamd
 * Returns a FD or -1 on error */
int connect_clamd(struct mem_info *minfo)
{
    int sockd, res;
    const struct optstruct *opt;
    struct addrinfo hints, *info, *p;
    char port[10];
    char *ipaddr;
    struct optstruct *clamdopts = NULL;

    if ((clamdopts = optparse(optget(minfo->opts, "config-file")->strarg, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
        logg("!Can't parse clamd configuration file %s\n", optget(minfo->opts, "config-file")->strarg);
    }

    snprintf(port, sizeof(port), "%lld", optget(clamdopts, "TCPSocket")->numarg);

    opt = optget(clamdopts, "TCPAddr");
    while (opt) {
        if (opt->enabled) {
            ipaddr = NULL;
            if (opt->strarg)
                ipaddr = (!strcmp(opt->strarg, "any") ? NULL : opt->strarg);

            memset(&hints, 0x00, sizeof(struct addrinfo));
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;

            if ((res = getaddrinfo(ipaddr, port, &hints, &info))) {
                logg("!Could not lookup %s: %s\n", ipaddr ? ipaddr : "", gai_strerror(res));
                opt = opt->nextarg;
                continue;
            }

            for (p = info; p != NULL; p = p->ai_next) {
                if ((sockd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
                    logg("!Can't create the socket: %s\n", strerror(errno));
                    continue;
                }

                if (connect(sockd, p->ai_addr, p->ai_addrlen) < 0) {
                    logg("!Could not connect to clamd on %s: %s\n", opt->strarg, strerror(errno));
                    closesocket(sockd);
                    continue;
                }

                freeaddrinfo(info);
                return sockd;
            }

            freeaddrinfo(info);
        }
        opt = opt->nextarg;
    }

    return -1;
}

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in non IDSESSION mode
 * Returns the number of infected files or -1 on error
 * NOTE: filename may be NULL for STREAM scantype. */
int dresult(int sockd, const char *filename, const char *virname, struct mem_info *info)
{
    int infected = 0, len = 0, beenthere = 0;
    char *bol, *eol;
    struct RCVLN rcv;
    STATBUF sb;

    if (filename) {
        if (1 == chkpath(filename, info)) {
            goto done;
        }
    }

    recvlninit(&rcv, sockd);

    //scantype
    if (optget(info->opts, "allmatch")->enabled) {
        if (!filename) {
            logg("Filename cannot be NULL for ALLMATCHSCAN.\n");
            infected = -1;
            goto done;
        }
        len = strlen(filename) + strlen("ALLMATCHSCAN") + 3;
        if (!(bol = malloc(len))) {
            logg("!Cannot allocate a command buffer: %s\n", strerror(errno));
            infected = -1;
            goto done;
        }
        sprintf(bol, "z%s %s", "ALLMATCHSCAN", filename);
        if (sendln(sockd, bol, len)) {
            free(bol);
            infected = -1;
            goto done;
        }
        free(bol);
    } else if (optget(info->opts, "stream")->enabled) {
        /* NULL filename safe in send_stream() */
        len = send_stream(sockd, filename, info);
    } else {
        if (!filename) {
            logg("Filename cannot be NULL.\n");
            infected = -1;
            goto done;
        }
        len = strlen(filename) + strlen("SCAN") + 3;
        if (!(bol = malloc(len))) {
            logg("!Cannot allocate a command buffer: %s\n", strerror(errno));
            infected = -1;
            goto done;
        }
        sprintf(bol, "z%s %s", "SCAN", filename);
        if (sendln(sockd, bol, len)) {
            free(bol);
            infected = -1;
            goto done;
        }
        free(bol);
    }

    if (len <= 0) {
        if (info->errors)
            (info->errors)++;
        infected = len;
        goto done;
    }

    while ((len = recvln(&rcv, &bol, &eol))) {
        if (len == -1) {
            infected = -1;
            goto done;
        }
        beenthere = 1;
        if (!filename) logg("~%s\n", bol);
        if (len > 7) {
            char *colon = strrchr(bol, ':');
            if (colon && colon[1] != ' ') {
                char *br;
                *colon = 0;
                br     = strrchr(bol, '(');
                if (br)
                    *br = 0;
                colon = strrchr(bol, ':');
            }
            if (!colon) {
                char *unkco = "UNKNOWN COMMAND";
                if (!strncmp(bol, unkco, sizeof(unkco) - 1))
                    logg("clamd replied \"UNKNOWN COMMAND\"");
                else
                    logg("Failed to parse reply: \"%s\"\n", bol);
                infected = -1;
                goto done;
            } else if (!memcmp(eol - 7, " FOUND", 6)) {
                static char last_filename[PATH_MAX + 1] = {'\0'};
                *(eol - 7)                              = 0;
                if (!optget(info->opts, "allmatch")->enabled) {
                    infected++;
                } else {
                    if (filename != NULL && strcmp(filename, last_filename)) {
                        infected++;
                        strncpy(last_filename, filename, PATH_MAX);
                        last_filename[PATH_MAX] = '\0';
                    }
                }
                if (filename) {
                    logg("~%s%s FOUND\n", filename, colon);
                    if (action) action(filename);
                }
            } else if (!memcmp(eol - 7, " ERROR", 6)) {
                if (info->errors)
                    (info->errors)++;
                if (filename) {
                    logg("~%s%s\n", filename, colon);
                }
                return -1;
            }
        }
    }
    if (!beenthere) {
        if (!filename) {
            logg("STDIN: noreply from clamd\n.");
            infected = -1;
            goto done;
        }
        if (CLAMSTAT(filename, &sb) == -1) {
            logg("~%s: stat() failed with %s, clamd may not be responding\n",
                 filename, strerror(errno));
            infected = -1;
            goto done;
        }
        if (!S_ISDIR(sb.st_mode)) {
            logg("~%s: no reply from clamd\n", filename);
            infected = -1;
            goto done;
        }
    }

done:
    return infected;
}

static inline int lookup_cache(filelist_t **list, const char *filename)
{
    filelist_t *current = *list;
    while (current) {
        /* Cache hit */
        if (!_stricmp(filename, current->filename)) {
            /* cli_dbgmsg("ScanMem Cache [Hit]: %s (%s)\n", current->filename,
       * cl_strerror(current->res)); */
            return current->res;
        }
        current = current->next;
    }
    /* cli_dbgmsg("ScanMem Cache [Miss]: %s\n", filename); */
    return -1;
}

static inline void insert_cache(filelist_t **list, const char *filename,
                                int res)
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
        logg("^EnablePrivilege functions are missing\n");
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

    logg(" *** Memory Scan: using ToolHelp ***\n\n");

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
        /* if (ps.szExeFile[0] != 'c') continue; */
        /* if (!strstr(ps.szExeFile, "clam.exe")) continue; */
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
        if (GetModuleFileNameEx) {
            HANDLE hFile = CreateFile(
                me32.szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, NULL);

            if (hFile == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                wchar_t name[MAX_PATH + 1];
                char *converted = NULL;
                HANDLE p;

                if (err == ERROR_BAD_NETPATH) {
                    logg("^Warning scanning files on non-ansi network paths is not "
                         "supported\n");
                    logg("^File: %s\n", me32.szExePath);
                    continue;
                }

                if ((err != ERROR_INVALID_NAME) && (err != ERROR_PATH_NOT_FOUND)) {
                    logg("^Expected ERROR_INVALID_NAME/ERROR_PATH_NOT_FOUND but got %d\n",
                         err);
                    continue;
                }

                p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                                ps.th32ProcessID);
                if (!GetModuleFileNameEx(p, NULL, name, MAX_PATH)) {
                    logg("^GetModuleFileNameExW() failed %d\n", GetLastError());
                    CloseHandle(p);
                    continue;
                }
                CloseHandle(p);

                if (!(converted = getaltpath(name))) {
                    logg("^Cannot map filename to ANSI codepage\n");
                    continue;
                }
                strcpy(me32.szExePath, converted);
                free(converted);
            } else
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

    logg(" *** Memory Scan: using PsApi ***\n\n");

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

        if (!GetModuleBaseName(hProc, mods[0], ps.szExeFile,
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
        logg("^Don't want to kill myself\n");
        return 1;
    }

    if ((hProc = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid))) {
        TerminateProcess(hProc, 0);
        if (WaitForSingleObject(hProc, TIMEOUT_MODULE) != WAIT_OBJECT_0)
            logg("^Unable to unload process from memory\n");
        CloseHandle(hProc);
    } else
        logg("^OpenProcess() failed %lu\n", GetLastError());
    return 1; /* Skip to next process anyway */
}

/* Not so safe ;) */
int unload_module(DWORD pid, HANDLE hModule)
{
    DWORD rc = 1;
    HANDLE ht;
    HANDLE hProc;

    if (GetCurrentProcessId() == pid) {
        logg("^Don't want to unload modules from myself\n");
        return 1;
    }

    hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                            PROCESS_VM_WRITE | PROCESS_VM_READ,
                        FALSE, pid);

    if (!hProc) {
        logg("^OpenProcess() failed %lu\n", GetLastError());
        return 1; /* Skip to next process */
    }

    if ((ht = CreateRemoteThread(
             hProc, 0, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, hModule, 0,
             &rc))) {
        if (WaitForSingleObject(ht, TIMEOUT_MODULE) == WAIT_TIMEOUT) {
            CloseHandle(ht);
            CloseHandle(hProc);
            logg("The module may trying to trick us, killing the process, please "
                 "rescan\n");
            return kill_process(pid);
        }
        CloseHandle(ht);
        rc = 0; /* Continue scanning this process */
    } else {
        DWORD res = GetLastError();
        if (res == ERROR_CALL_NOT_IMPLEMENTED) {
            logg("^Module unloading is not supported on this OS\n");
            rc = -1; /* Don't complain about removing/moving the file */
        } else {
            logg("!CreateRemoteThread() failed %lu\n", res);
            rc = 1; /* Skip to next process */
        }
    }

    CloseHandle(hProc);
    return rc;
}

#define FILLBYTES(dst)                            \
    if (IsBadReadPtr(seek, sizeof(dst))) {        \
        logg("!ScanMem Align: Bad pointer!!!\n"); \
        return 1;                                 \
    }                                             \
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

    hFile = CreateFile(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        logg("Error creating %s\n", filename);
        free(buffer);
        return ret;
    }

    if (WriteFile(hFile, buffer, (DWORD)bytesread, &byteswrite, NULL))
        ret = _open_osfhandle((intptr_t)hFile, O_RDONLY | O_BINARY);
    free(buffer);
    return ret;
}

static inline int excluded(const char *filename, const struct optstruct *opts)
{
    const struct optstruct *opt;

    if ((opt = optget(opts, "exclude"))->enabled) {
        while (opt) {
            /* cli_dbgmsg("Matching %s vs %s\n", filename, opt->strarg); */
            if (cli_matchregex(filename, opt->strarg) == 1) {
                logg("~%s: Excluded\n", filename);
                return 1;
            }
            opt = opt->nextarg;
        }
    }
    return 0;
}

int scanfile(const char *filename, scanmem_data *scan_data, struct mem_info *info)
{
    int fd;
    int ret             = CL_CLEAN;
    const char *virname = NULL;

    logg("*Scanning %s\n", filename);

    if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) == -1) {
        logg("^Can't open file %s, %s\n", filename, strerror(errno));
        return -1;
    }

    if (info->d) { //clamdscan
        if ((sock = connect_clamd(info)) < 0) {
            info->errors++;
            return -1;
        }
        if (dresult(sock, filename, virname, info) > 0) {
            info->ifiles++;
            ret = CL_VIRUS;
        } else if (scan_data->printclean) {
            logg("~%s: OK    \n", filename);
        }
    } else { //clamscan
        ret = cl_scandesc(fd, filename, &virname, &info->blocks, info->engine, info->options);
        if (ret == CL_VIRUS) {
            logg("~%s: %s FOUND\n", filename, virname);
            info->ifiles++;
        } else if (scan_data->printclean) {
            logg("~%s: OK    \n", filename);
        }
    }

    close(fd);
    return ret;
}

int scanmem_cb(PROCESSENTRY32 ProcStruct, MODULEENTRY32 me32, void *data, struct mem_info *info)
{
    scanmem_data *scan_data     = data;
    int rc                      = 0;
    int isprocess               = 0;
    char modulename[MAX_PATH]   = "";
    char expandmodule[MAX_PATH] = "";

    if (!scan_data)
        return 0;
    scan_data->res = CL_CLEAN;

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
        ExpandEnvironmentStrings(expandmodule, modulename, MAX_PATH - 1);
        modulename[MAX_PATH - 1] = 0;
    }

    if (!modulename[0]) {
        if ((strlen(me32.szExePath) > 4) &&
            PATH_ISUN2(me32.szExePath)) /* \\??\ <-- wtf */
            strncpy(modulename, UNC_OFFSET(me32.szExePath), MAX_PATH - 1);
        else
            strncpy(modulename, me32.szExePath, MAX_PATH - 1);
        modulename[MAX_PATH - 1] = 0;
    }

    scan_data->res = lookup_cache(&scan_data->files, modulename);
    isprocess      = !_stricmp(ProcStruct.szExeFile, modulename) ||
                !_stricmp(ProcStruct.szExeFile, me32.szModule);

    if (scan_data->res == -1) {
        if (isprocess)
            scan_data->processes++;
        else
            scan_data->modules++;

        info->files++;

        /* check for module exclusion */
        scan_data->res = CL_CLEAN;
        if (!(scan_data->exclude && excluded(modulename, info->opts)))
            scan_data->res = scanfile(modulename, scan_data, info);

        if ((scan_data->res != CL_VIRUS) && is_packed(modulename)) {
            char *dumped = cli_gentemp(NULL);
            int fd       = -1;
            if ((fd = dump_pe(dumped, ProcStruct, me32)) > 0) {
                close(fd);
                scan_data->res = scanfile(dumped, scan_data, info);
                DeleteFile(dumped);
            }
            free(dumped);
        }
        insert_cache(&scan_data->files, modulename, scan_data->res);
    }

    if (scan_data->res == CL_VIRUS) {
        if (isprocess && scan_data->kill) {
            logg("Unloading program %s from memory\n", modulename);
            rc = kill_process(ProcStruct.th32ProcessID);
        } else if (scan_data->unload) {
            logg("Unloading module %s from %s\n", me32.szModule, modulename);
            if ((rc = unload_module(ProcStruct.th32ProcessID, me32.hModule)) == -1)
                /* CreateProcessThread() is not implemented */
                return 0;
        }

        if (action)
            action(modulename);
        return rc;
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

    HMODULE psapi_ok = LoadLibrary("psapi.dll");
    HMODULE k32_ok   = LoadLibrary("kernel32.dll");

    if (!(psapi_ok || k32_ok)) {
        logg(" *** Memory Scanning is not supported on this OS ***\n\n");
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

    /*connect to clamd*/
    if (info->d == 1) {
        if ((sock = connect_clamd(info)) < 0) {
            info->errors++;
            return -1;
        }
    }

    logg(" *** Scanning Programs in Computer Memory ***\n");

    if (!EnablePrivilege(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED))
        logg("---Please login as an Administrator to scan System processes loaded "
             "in computer memory---\n");

    if (k32_ok)
        walkmodules_th(scanmem_cb, (void *)&data, info);
    else
        walkmodules_psapi(scanmem_cb, (void *)&data, info);
    free_cache(&data.files);

    logg("\n *** Scanned %lu processes - %lu modules ***\n", data.processes,
         data.modules);
    logg(" *** Computer Memory Scan Completed ***\n\n");
    return data.res;
}