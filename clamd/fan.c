/*
 *  Copyright (C) 2011 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef FANOTIFY

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include <sys/fanotify.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "fan.h"

#include "libclamav/clamav.h"
#include "libclamav/scanners.h"

#include "shared/optparser.h"
#include "shared/output.h"

#include "server.h"
#include "others.h"
#include "scanner.h"

static void fan_exit(int sig)
{

    logg("*ScanOnAccess: fan_exit(), signal %d\n", sig);
    pthread_exit(NULL);
    logg("ScanOnAccess: stopped\n");
}

static int fan_scanfile(int fan_fd, const char *fname, struct fanotify_event_metadata *fmd, int scan, int extinfo, struct thrarg *tharg)
{
	struct fanotify_response res;
	struct cb_context context;
	const char *virname;
	int ret = 0;

    res.fd = fmd->fd;
    res.response = FAN_ALLOW;
    context.filename = fname;
    context.virsize = 0;
    if(scan && cl_scandesc_callback(fmd->fd, &virname, NULL, tharg->engine, tharg->options, &context) == CL_VIRUS) {
	if(extinfo && context.virsize)
	    logg("ScanOnAccess: %s: %s(%s:%llu) FOUND\n", fname, virname, context.virhash, context.virsize);
	else
	    logg("ScanOnAccess: %s: %s FOUND\n", fname, virname);
	virusaction(fname, virname, tharg->opts);
	res.response = FAN_DENY;
    }

    if(fmd->mask & FAN_ALL_PERM_EVENTS) {
	ret = write(fan_fd, &res, sizeof(res));
	if(ret == -1)
	    logg("!ScanOnAccess: Internal error (can't write to fanotify)\n");
    }

    return ret;
}

void *fan_th(void *arg)
{
	struct thrarg *tharg = (struct thrarg *) arg;
	sigset_t sigset;
        struct sigaction act;
	const struct optstruct *pt;
	short int scan;
	int sizelimit = 0, extinfo;
	STATBUF sb;
        uint64_t fan_mask = FAN_ACCESS | FAN_EVENT_ON_CHILD;
	int fan_fd;
        fd_set rfds;
	char buf[4096];
	ssize_t bread;
	struct fanotify_event_metadata *fmd;
	char fname[1024];
	int ret, len;
	char err[128];

    /* ignore all signals except SIGUSR1 */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR1);
    /* The behavior of a process is undefined after it ignores a 
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS    
    sigdelset(&sigset, SIGBUS);
#endif
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = fan_exit;
    sigfillset(&(act.sa_mask));
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);

    fan_fd = fanotify_init(0, O_RDONLY);
    if(fan_fd < 0) {
	logg("!ScanOnAccess: fanotify_init failed: %s\n", cli_strerror(errno, err, sizeof(err)));
	if(errno == EPERM)
	    logg("ScanOnAccess: clamd must be started by root\n");
	return NULL;
    }

    if((pt = optget(tharg->opts, "OnAccessIncludePath"))->enabled) {
	while(pt) {
	    if(fanotify_mark(fan_fd, FAN_MARK_ADD, fan_mask, fan_fd, pt->strarg) != 0) {
		logg("!ScanOnAccess: Can't include path '%s'\n", pt->strarg);
		return NULL;
	    } else
		logg("ScanOnAccess: Protecting directory '%s'\n", pt->strarg);
	    pt = (struct optstruct *) pt->nextarg;
	}
    } else {
	logg("!ScanOnAccess: Please specify at least one path with OnAccessIncludePath\n");
	return NULL;
    }

    if((pt = optget(tharg->opts, "OnAccessExcludePath"))->enabled) {
	while(pt) {
            if(fanotify_mark(fan_fd, FAN_MARK_REMOVE, fan_mask, fan_fd, pt->strarg) != 0) {
		logg("!ScanOnAccess: Can't exclude path %s\n", pt->strarg);
		return NULL;
	    } else
		logg("ScanOnAccess: Excluded path %s\n", pt->strarg);
	    pt = (struct optstruct *) pt->nextarg;
	}
    }

    sizelimit = optget(tharg->opts, "OnAccessMaxFileSize")->numarg;
    if(sizelimit)
	logg("ScanOnAccess: Max file size limited to %d bytes\n", sizelimit);
    else
	logg("ScanOnAccess: File size limit disabled\n");

    extinfo = optget(tharg->opts, "ExtendedDetectionInfo")->enabled;

    FD_ZERO(&rfds);
    FD_SET(fan_fd, &rfds);
    do {
        ret = select(fan_fd + 1, &rfds, NULL, NULL, NULL);
    } while(ret == -1 && errno == EINTR);

    while((bread = read(fan_fd, buf, sizeof(buf))) > 0) {
	fmd = (struct fanotify_event_metadata *) buf;
	while(FAN_EVENT_OK(fmd, bread)) {
	    scan = 1;
	    if(fmd->fd >= 0) {
		sprintf(fname, "/proc/self/fd/%d", fmd->fd);
		len = readlink(fname, fname, sizeof(fname) - 1);
		if(len == -1) {
		    close(fmd->fd);
		    logg("!ScanOnAccess: Internal error (readlink() failed)\n");
		    return NULL;
		}
		fname[len] = 0;

		if(fan_checkowner(fmd->pid, tharg->opts)) {
		    scan = 0;
		    logg("*ScanOnAccess: %s skipped (excluded UID)\n", fname);
		}

		if(sizelimit) {
		    if(FSTAT(fmd->fd, &sb) != 0 || sb.st_size > sizelimit) {
			scan = 0;
			/* logg("*ScanOnAccess: %s skipped (size > %d)\n", fname, sizelimit); */
		    }
		}

		if(fan_scanfile(fan_fd, fname, fmd, scan, extinfo, tharg) == -1) {
		    close(fmd->fd);
		    return NULL;
		}

		if(close(fmd->fd) == -1) {
		    printf("!ScanOnAccess: Internal error (close(%d) failed)\n", fmd->fd);
		    close(fmd->fd);
		    return NULL;
		}
	    }
	    fmd = FAN_EVENT_NEXT(fmd, bread);
	}
	do {
	    ret = select(fan_fd + 1, &rfds, NULL, NULL, NULL);
	} while(ret == -1 && errno == EINTR);
    }

    if(bread < 0)
	logg("!ScanOnAccess: Internal error (failed to read data)\n");

    return NULL;
}

#elif defined(CLAMAUTH)

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "libclamav/clamav.h"
#include "libclamav/scanners.h"

#include "shared/optparser.h"
#include "shared/output.h"

#include "server.h"
#include "others.h"
#include "scanner.h"

#define SUPPORTED_PROTOCOL  2

static int cauth_fd = -1;

struct ClamAuthEvent {
    unsigned int action;
    char path[1024];
    unsigned int pid;
};

static void cauth_exit(int sig)
{
    logg("*ScanOnAccess: cauth_exit(), signal %d\n", sig);
    if(cauth_fd > 0)
	close(cauth_fd);
    pthread_exit(NULL);
    logg("ScanOnAccess: stopped\n");
}

static int cauth_scanfile(const char *fname, int extinfo, struct thrarg *tharg)
{
	struct cb_context context;
	const char *virname;
	int ret = 0, fd;

    context.filename = fname;
    context.virsize = 0;

    fd = open(fname, O_RDONLY);
    if(fd == -1)
	return -1;

    if(cl_scandesc_callback(fd, &virname, NULL, tharg->engine, tharg->options, &context) == CL_VIRUS) {
	if(extinfo && context.virsize)
	    logg("ScanOnAccess: %s: %s(%s:%llu) FOUND\n", fname, virname, context.virhash, context.virsize);
	else
	    logg("ScanOnAccess: %s: %s FOUND\n", fname, virname);
	virusaction(fname, virname, tharg->opts);
    }
    close(fd);
    return ret;
}

void *fan_th(void *arg)
{
	struct thrarg *tharg = (struct thrarg *) arg;
	sigset_t sigset;
        struct sigaction act;
	int eventcnt = 1, extinfo;
	char err[128];
	struct ClamAuthEvent event;

    /* ignore all signals except SIGUSR1 */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR1);
    /* The behavior of a process is undefined after it ignores a 
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS    
    sigdelset(&sigset, SIGBUS);
#endif
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = cauth_exit;
    sigfillset(&(act.sa_mask));
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);

    extinfo = optget(tharg->opts, "ExtendedDetectionInfo")->enabled;

    cauth_fd = open("/dev/clamauth", O_RDONLY);
    if(cauth_fd == -1) {
	logg("!ScanOnAccess: Can't open /dev/clamauth\n");
	if(errno == ENOENT)
	    logg("!ScanOnAccess: Please make sure ClamAuth.kext is loaded\n");
	else if(errno == EACCES)
	    logg("!ScanOnAccess: This application requires root privileges\n");
	else
	    logg("!ScanOnAccess: /dev/clamauth: %s\n", cli_strerror(errno, err, sizeof(err)));

	return NULL;
    }

    while(1) {
	if(read(cauth_fd, &event, sizeof(event)) > 0) {
	    if(eventcnt == 1) {
		if(event.action != SUPPORTED_PROTOCOL) {
		    logg("!ScanOnAccess: Protocol version mismatch (tool: %d, driver: %d)\n", SUPPORTED_PROTOCOL, event.action);
		    close(cauth_fd);
		    return NULL;
		}
		if(strncmp(event.path, "ClamAuth", 8)) {
		    logg("!ScanOnAccess: Invalid version event\n");
		    close(cauth_fd);
		    return NULL;
		}
		logg("ScanOnAccess: Driver version: %s, protocol version: %d\n", &event.path[9], event.action);
	    } else {
		cauth_scanfile(event.path, extinfo, tharg);
	    }
	    eventcnt++;
	} else {
	    if(errno == ENODEV) {
		printf("^ScanOnAccess: ClamAuth module deactivated, terminating\n");
		close(cauth_fd);
		return NULL;
	    }
	}
	usleep(200);
    }
}
#endif
