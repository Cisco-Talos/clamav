/*
 * Copyright (C) 2010 Sourcefire, Inc.
 * Authors: aCaB <acab@clamav.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 */

#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "clupdate.h"
#include "flog.h"

struct my_f {
    HANDLE h;
    char buf[1024];
    char *next;
    unsigned int len;
};

static void init_myf(struct my_f *f, HANDLE h) {
    f->next = f->buf;
    f->len = 0;
    f->h = h;
}

static char *my_fgets(struct my_f *f) {
    int stripping = 0;
    char *cur = f->next;
    while(1) {
	if(!f->len) {
	    if(f->next == &f->buf[sizeof(f->buf)-1]) {
		if(cur == f->buf) {
		    *f->next = '\0';
		    f->next = f->buf;
		    return f->buf;
		}
		memmove(f->buf, cur, f->next - cur);
		f->next -= cur - f->buf;
		cur = f->buf;
	    }
	    if(!ReadFile(f->h, f->next, sizeof(f->buf) - 1 - (f->next - f->buf), &f->len, NULL)) {
		DWORD er = GetLastError();
		if(er != ERROR_BROKEN_PIPE) {
		    flog("ERROR: Cannot read from pipe: ReadFile failed (%u)", er);
		    return NULL;
		}
		f->len = 0;
	    }
	    if(!f->len) {
		*f->next = '\0';
		return cur != f->next ? cur : NULL;
	    }
	    continue;
	}
	if(*f->next == '\n' || *f->next == '\r') {
	    *f->next = '\0';
	    stripping = 1;
	} else if(stripping)
	    return cur;
	f->len--;
	f->next++;
    }
}

PROCESS_INFORMATION pinfo;
HANDLE updpipe, write_event;
char datadir[4096];

static void cleanup(char *path) {
    WIN32_FIND_DATA wfd;
    char delme[4096];
    HANDLE findh;

    if(!path)
	_snprintf(delme, sizeof(delme), "%s\\clamav-????????????????????????????????", datadir);
    else
	_snprintf(delme, sizeof(delme), "%s\\*.*", path);
    delme[sizeof(delme) - 1] = '\0';
    findh = FindFirstFile(delme, &wfd);
    if(findh == INVALID_HANDLE_VALUE)
	return;
    do {
	if(wfd.cFileName[0] == '.' && (!wfd.cFileName[1] || (wfd.cFileName[1] == '.' && !wfd.cFileName[2])))
	    continue;
	if(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
	    if(!path)
		_snprintf(delme, sizeof(delme), "%s\\%s", datadir, wfd.cFileName);
	    else
		_snprintf(delme, sizeof(delme), "%s\\%s", path, wfd.cFileName);
	    flog_dbg("recursing %s", delme);
	    cleanup(delme);
	    RemoveDirectory(delme);
	} else if(path) {
	    _snprintf(delme, sizeof(delme), "%s\\%s", path, wfd.cFileName);
	    flog_dbg("deleting %s", delme);
	    SetFileAttributes(delme, FILE_ATTRIBUTE_NORMAL);
	    DeleteFile(delme);
	}
    } while(FindNextFile(findh, &wfd));
    FindClose(findh);
}


static void kill_freshclam(void) {
    TerminateProcess(pinfo.hProcess, 1337);
    WaitForSingleObject(pinfo.hProcess, 30*1000);
}

static void send_pipe(AV_UPD_STATUS *updstatus, int state, int fail) {
    DWORD got;
    const char *phases[] = {
	"UPD_CHECK",
	"UPD_NEWER_FOUND",
	"UPD_NONE",
	"UPD_DOWNLOAD_BEGIN",
	"UPD_DOWNLOAD_COMPLETE",
	"UPD_PAUSE",
	"UPD_ABORT",
	"UPD_DONE",
	"UPD_INSTALL_BEGIN",
	"UPD_INSTALL_COMPLETE",
	"UPD_FILE_BEGIN",
	"UPD_FILE_COMPLETE",
	"UPD_FILE_PROGRESS",
    };
    OVERLAPPED o;

    memset(&o, 0, sizeof(o)); /* kb110148 */
    o.hEvent = write_event;
    flog_dbg("SEND: state: %s - status: %s - file: %S - pct: %u%%",
	(unsigned int)state < sizeof(phases) / sizeof(*phases) ? phases[state] : "INVALID",
	fail ? "fail" : "success", updstatus->fileName, updstatus->percentDownloaded);
    updstatus->state = state;
    updstatus->status = fail;
    if(!WriteFile(updpipe, updstatus, sizeof(*updstatus), NULL, &o)) {
	DWORD er = GetLastError();
	if(er != ERROR_IO_PENDING)
	    flog("WARNING: cannot write to pipe (%u)", er);
	else if(!GetOverlappedResult(updpipe, &o, &got, TRUE))
	    flog("WARNING: cannot write to pipe (overlapped failure)");
    }
}

#define SENDFAIL_AND_QUIT(phase)	    \
    do {				    \
	send_pipe(&st, (phase), 1);	    \
	CloseHandle(updpipe);		    \
	CloseHandle(write_event);	    \
	cleanup(NULL);			    \
	flog_close();			    \
	return 1;			    \
    } while(0)

#define SENDOK(phase)			    \
    do {				    \
	send_pipe(&st, (phase), 0);\
    } while(0)

enum fresh_states {
    FRESH_PRE,
    FRESH_IDLE,
    FRESH_DOWN,
    FRESH_RELOAD
};

const char *fstates[] = {
    "FRESH_PRE",
    "FRESH_IDLE",
    "FRESH_DOWN",
    "FRESH_RELOAD"
};

static void log_state(enum fresh_states s) {
    flog_dbg("state is now: %s", (s < FRESH_PRE || s > FRESH_RELOAD) ? "INVALID" : fstates[s]);
}


DWORD WINAPI watch_stop(LPVOID x) {
    AV_UPD_STATUS st;
    DWORD got;
    OVERLAPPED o;
    HANDLE read_event = CreateEvent(NULL, TRUE, FALSE, NULL);

    if(!read_event) {
	flog("ERROR: failed to create pipe read event");
	return 0;
    }

    memset(&o, 0, sizeof(o));
    o.hEvent = read_event;
    while(1) {
	if(!ReadFile(updpipe, &st, sizeof(st), NULL, NULL)) {
	    if(GetLastError() != ERROR_IO_PENDING || !GetOverlappedResult(updpipe, &o, &got, TRUE)) {
		flog("ERROR: failed to read stop event from pipe");
		return 0;
	    }
	}
	if(st.state == UPD_STOP)
	    break;
	flog("WARNING: received bogus message (%d)", st.state);
    }
    flog("STOP event received, killing freshclam");
    kill_freshclam();
    cleanup(NULL);
    return 0;
}


#define FRESH_PRE_START_S "ClamAV update process started at "
#define FRESH_DOWN_S "Downloading "
#define FRESH_DOWN_FAIL_S "ERROR: Verification: Can't verify database integrity"
#define FRESH_UPDATED_S " updated (version: "
#define FRESH_UPTODATE_S " is up to date "
#define FRESH_DONE_S "Database updated "

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    HANDLE cld_r, cld_w2, cld_w;
    STARTUPINFO sinfo;
    enum fresh_states fstate = FRESH_PRE;
    AV_UPD_STATUS st = {UPD_CHECK, 0, 0, 0, L""};
    DWORD dw;
    struct my_f spam;
    char command[8192], *ptr;
    int updated_files = 0;
    char *cmdl = GetCommandLineA();

    //DebugBreak();

    /* Locate myself */
    dw = GetModuleFileName(NULL, datadir, sizeof(datadir));
    if(!dw || dw >= sizeof(datadir)-2)
	return 1;
    ptr = strrchr(datadir, '\\');
    if(!ptr)
	return 1;
    *ptr = '\0';

    /* Log file */
    flog_open(datadir);

    _snprintf(command, sizeof(command)-1, "freshclam.exe --stdout --config-file=\"%s\\freshclam.conf\" --datadir=\"%s\"%s", datadir, datadir, (cmdl && strstr(cmdl, " --mindefs=1")) ? " --update-db=daily" : "");
    command[sizeof(command)-1] = '\0';

    /* Connect to master */
    updpipe = CreateFile("\\\\.\\pipe\\IMMUNET_AVUPDATE", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if(updpipe == INVALID_HANDLE_VALUE) {
	flog("ERROR: failed to connect pipe");
	flog_close();
	return 1;
    }
    dw = PIPE_READMODE_MESSAGE;
    if(!SetNamedPipeHandleState(updpipe, &dw, NULL, NULL)) {
	CloseHandle(updpipe);
	flog("ERROR: failed to set pipe to message mode");
    	flog_close();
	return 1;
    }
    if(!(write_event = CreateEvent(NULL, TRUE, FALSE, NULL))) {
	CloseHandle(updpipe);
	flog("ERROR: failed to create write event");
	flog_close();
	return 1;
    }

    /* Make pipe for freshclam stdio */
    if(!CreatePipe(&cld_r, &cld_w, NULL, 0)) {
	flog("ERROR: failed to create pipe");
	SENDFAIL_AND_QUIT(UPD_CHECK);
    }

    if(!DuplicateHandle(GetCurrentProcess(), cld_w, GetCurrentProcess(), &cld_w2, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
	CloseHandle(cld_r);
	CloseHandle(cld_w);
	flog("ERROR: failed to duplicate pipe");
	SENDFAIL_AND_QUIT(UPD_CHECK);
    }
    CloseHandle(cld_w);

    /* init my_fgets */
    init_myf(&spam, cld_r);

    /* Redir freshclam stdio */
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    sinfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    sinfo.hStdOutput = cld_w2;
    sinfo.hStdError = cld_w2;
    sinfo.dwFlags = STARTF_FORCEOFFFEEDBACK|STARTF_USESTDHANDLES;
    if(!CreateProcess(NULL, command, NULL, NULL, TRUE, DETACHED_PROCESS, NULL, datadir, &sinfo, &pinfo)) {
	CloseHandle(cld_w2);
	CloseHandle(cld_r);
	flog("ERROR: failed to execute '%s'", command);
	SENDFAIL_AND_QUIT(UPD_CHECK);
    }
    CloseHandle(pinfo.hThread);
    CloseHandle(cld_w2);

    flog_dbg("Executing '%s'", command);

    /* Create STOP watcher */
    if(!CreateThread(NULL, 0, watch_stop, NULL, 0, &dw)) {
	flog("ERROR: failed to create watch_stop thread");
	CloseHandle(cld_r);
	CloseHandle(pinfo.hProcess);
	SENDFAIL_AND_QUIT(UPD_CHECK);
    }

    log_state(fstate);
    /* Spam parsing */
    while(1) {
	char *buf;
	buf = my_fgets(&spam);
	flog_dbg("GOT: %s", buf);
	if(!buf)
	    break;

	if(fstate == FRESH_PRE && !strncmp(buf, FRESH_PRE_START_S, sizeof(FRESH_PRE_START_S)-1)) {
	    SENDOK(UPD_CHECK);
	    fstate = FRESH_IDLE;
	    log_state(fstate);
	    continue;
	}

	if((fstate == FRESH_IDLE || fstate == FRESH_DOWN) && !strncmp(buf, FRESH_DOWN_S, sizeof(FRESH_DOWN_S)-1)) {
	    unsigned int pct, fnamelen;
	    unsigned char *partname = buf + 12, *partend, *pctend;
	    wchar_t nuname[AV_UPD_FILE_NAME_MAX];

	    if(!updated_files) {
		SENDOK(UPD_NEWER_FOUND);
		SENDOK(UPD_DOWNLOAD_BEGIN);
	    }
	    updated_files++;
	    partend = strchr(partname, ' ');
	    if(!partend)
		break;
	    *partend = '\0';
	    fnamelen = partend - partname;
	    partend = strchr(partend + 1, '[');
	    if(!partend)
		break;
	    partend++;
	    pct = strtol(partend, &pctend, 10);
	    if(pctend == partend || *pctend != '%')
		break;
	    fnamelen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, partname, (fnamelen < AV_UPD_FILE_NAME_MAX-1) ? fnamelen : AV_UPD_FILE_NAME_MAX-1, nuname, sizeof(nuname));
	    if(!fnamelen)
		break;
	    nuname[fnamelen] = L'\0';
	    if(fstate == FRESH_DOWN && wcscmp(nuname, st.fileName)) {
		st.percentDownloaded = 100;
		SENDOK(UPD_FILE_COMPLETE);
		fstate = FRESH_IDLE;
		log_state(fstate);
	    }
	    if(fstate == FRESH_IDLE) {
		wcscpy(st.fileName, nuname);
		st.percentDownloaded = 0;
		SENDOK(UPD_FILE_BEGIN);
		fstate = FRESH_DOWN;
		log_state(fstate);
	    }
	    st.percentDownloaded = pct;
	    SENDOK(UPD_FILE_PROGRESS);
	    continue;
	}

	if(fstate == FRESH_IDLE) {
	    if(strstr(buf, FRESH_UPTODATE_S))
		continue;
	    if(!strncmp(buf, FRESH_DONE_S, sizeof(FRESH_DONE_S) - 1)) {
		fstate = FRESH_RELOAD;
		log_state(fstate);
		continue;
	    }
	}
	if(fstate == FRESH_DOWN) {
	    if(!strcmp(buf, FRESH_DOWN_FAIL_S)) {
		flog("ERROR: sigcheck verification failed");
#if 0
		// FIXME: ask prashant
		send_pipe(&st, UPD_FILE_COMPLETE, 1);
#else
		SENDOK(UPD_FILE_COMPLETE);
#endif
		fstate = FRESH_IDLE;
		log_state(fstate);
		continue;
	    }
	    if(strstr(buf, FRESH_UPDATED_S)) {
		SENDOK(UPD_FILE_COMPLETE);
		fstate = FRESH_IDLE;
		log_state(fstate);
		continue;
	    }
	    if(strlen(buf) > sizeof(FRESH_DOWN_S)-1 && strstr(buf, FRESH_DOWN_S)) 
		continue;
	}
    }
    CloseHandle(cld_r);
    WaitForSingleObject(pinfo.hProcess, 30*1000);
    if(!GetExitCodeProcess(pinfo.hProcess, &dw)) {
	CloseHandle(pinfo.hProcess);
	flog("ERROR: failed to retrieve freshclam return code");
	SENDFAIL_AND_QUIT(UPD_ABORT);
    }
    CloseHandle(pinfo.hProcess);
    if(dw) {
	if(dw == STILL_ACTIVE) {
	    flog("WARNING: freshclam didn't exit, killing it...");
	    kill_freshclam();
	} else
	    flog("ERROR: freshclam exit code %u", dw);
	if(st.state == UPD_CHECK)
	    st.state = UPD_ABORT;
	SENDFAIL_AND_QUIT(st.state);
    }
    if((updated_files && fstate != FRESH_RELOAD) || (!updated_files && fstate != FRESH_IDLE)) {
	flog("ERROR: log parse failure. Freshclam exit value: %u", dw);
	SENDFAIL_AND_QUIT(st.state);
    }

    /* Send complete fin seq */
    if(updated_files) {
	SENDOK(UPD_DOWNLOAD_COMPLETE);
	SENDOK(UPD_INSTALL_BEGIN);
	SENDOK(UPD_INSTALL_COMPLETE);
	SENDOK(UPD_DONE);
    } else
	SENDOK(UPD_NONE);

    CloseHandle(updpipe);
    CloseHandle(write_event);
    flog_close();
    return 0;
}
