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
	    if(!ReadFile(f->h, f->next, sizeof(f->buf) - 1 - (f->next - f->buf), &f->len, NULL))
		return NULL;
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


static void send_pipe(HANDLE pipe, AV_UPD_STATUS *updstatus, int state, int fail) {
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
    "UPD_FILE_COMPLETE"
    };

    flog("SEND: state: %s - status: %s", (unsigned int)state < sizeof(phases) / sizeof(*phases) ? phases[state] : "INVALID", fail ? "fail" : "success");
    updstatus->state = state;
    updstatus->status = fail;
    if(!WriteFile(pipe, updstatus, sizeof(*updstatus), &got, NULL))
	flog("WARNING: cannot write to pipe");
}

#define SENDFAIL_AND_QUIT(phase)	    \
    do {				    \
	send_pipe(updpipe, &st, (phase), 1);\
	CloseHandle(updpipe);		    \
	flog_close();		    \
	return 1;			    \
    } while(0)

#define SENDOK(phase)			    \
    do {				    \
	send_pipe(updpipe, &st, (phase), 0);\
    } while(0)

enum fresh_states {
    FRESH_PRE,
    FRESH_IDLE,
    FRESH_DOWN
};

const char *fstates[] = {
    "FRESH_PRE",
    "FRESH_IDLE",
    "FRESH_DOWN"
};

static void log_state(enum fresh_states s) {
    flog("state is now: %s", (s < FRESH_PRE || s > FRESH_DOWN) ? "INVALID" : fstates[s]);
}

#define FRESH_PRE_START_S "ClamAV update process started at "
#define FRESH_DOWN_S "Downloading "
#define FRESH_UPDATED_S " updated (version: "
#define FRESH_UPTODATE_S " is up to date "
#define FRESH_DONE_S "Database updated "

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    HANDLE cld_r, cld_w2, cld_w, updpipe;
    PROCESS_INFORMATION pinfo;
    STARTUPINFO sinfo;
    enum fresh_states fstate = FRESH_PRE;
    AV_UPD_STATUS st = {UPD_CHECK, 0, 100, 0, 3};
    DWORD dw;
    struct my_f spam;
    char buf[4096], command[8192], *ptr;
    int updated_files = 0;
    wchar_t *cmdl = GetCommandLineW();

//    DebugBreak();

    /* Locate myself */
    dw = GetModuleFileName(NULL, buf, sizeof(buf));
    if(!dw || dw >= sizeof(buf)-2)
	return 1;
    ptr = strrchr(buf, '\\');
    if(!ptr)
	return 1;
    *ptr = '\0';

    /* Log file */
    _snprintf(command, sizeof(command)-1, "%s\\update.log", buf);
    command[sizeof(command)-1] = '\0';
    flog_open(command);

    _snprintf(command, sizeof(command)-1, "freshclam.exe --stdout --config-file=\"%s\\freshclam.conf\" --datadir=\"%s\"", buf, buf);
    command[sizeof(command)-1] = '\0';

    /* Connect to master */
    updpipe = CreateFile("\\\\.\\pipe\\IMMUNET_AVUPDATE", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
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
    if(!CreateProcess(NULL, command, NULL, NULL, TRUE, DETACHED_PROCESS, NULL, buf, &sinfo, &pinfo)) {
	CloseHandle(cld_w2);
	CloseHandle(cld_r);
	flog("ERROR: failed to execute '%s'", command);
	SENDFAIL_AND_QUIT(UPD_CHECK);
    }
    CloseHandle(pinfo.hThread);
    CloseHandle(cld_w2);

    flog("Executing '%s'", command);
    log_state(fstate);
    /* Spam parsing */
    while(1) {
	char *buf;
	buf = my_fgets(&spam);
	flog("GOT: %s", buf);
	if(!buf)
	    break;
	if(!strncmp(buf, "WARNING: ", 9))
	    continue;
	if(fstate == FRESH_PRE && !strncmp(buf, FRESH_PRE_START_S, sizeof(FRESH_PRE_START_S)-1)) {
	    SENDOK(UPD_CHECK);
	    fstate = FRESH_IDLE;
	    log_state(fstate);
	    continue;
	}
	if(fstate == FRESH_IDLE) {
	    if(!strncmp(buf, FRESH_DOWN_S, sizeof(FRESH_DOWN_S)-1)) {
		if(!updated_files) {
		    SENDOK(UPD_NEWER_FOUND);
		    SENDOK(UPD_DOWNLOAD_BEGIN);
		}
		updated_files++;
		SENDOK(UPD_FILE_BEGIN);
		fstate = FRESH_DOWN;
		log_state(fstate);
		continue;
	    }
	    if(strstr(buf, FRESH_UPTODATE_S))
		continue;
	    if(!strncmp(buf, FRESH_DONE_S, sizeof(FRESH_DONE_S) - 1))
		continue;
	}
	if(fstate == FRESH_DOWN) {
	    if(strstr(buf, FRESH_UPDATED_S)) {
		SENDOK(UPD_FILE_COMPLETE);
		fstate = FRESH_IDLE;
		log_state(fstate);
		continue;
	    }
	    if(strlen(buf) > sizeof(FRESH_DOWN_S)-1 && strstr(buf, FRESH_DOWN_S)) 
		continue;
	}
	break;
    }
    CloseHandle(cld_r);
    WaitForSingleObject(pinfo.hProcess, 30*1000);
    if(!GetExitCodeProcess(pinfo.hProcess, &dw)) {
	CloseHandle(pinfo.hProcess);
	flog("ERROR: failed to retrieve freshclam return code");
	SENDFAIL_AND_QUIT(st.state);
    }
    CloseHandle(pinfo.hProcess);
    if(dw) {
	flog("ERROR: freshclam exitted with %u\n", dw);
	SENDFAIL_AND_QUIT(st.state);
    }
    if(fstate != FRESH_IDLE) {
	flog("ERROR: freshclam exited with %u\n", dw);
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
    flog_close();
    return 0;
}
