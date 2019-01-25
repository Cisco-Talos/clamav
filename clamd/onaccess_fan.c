/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Mickey Sola
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

#if defined(FANOTIFY)

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/fanotify.h>

#include "libclamav/clamav.h"
#include "libclamav/scanners.h"

#include "shared/optparser.h"
#include "shared/output.h"

#include "onaccess_others.h"
#include "server.h"

#include "onaccess_fan.h"
#include "onaccess_hash.h"
#include "onaccess_ddd.h"

static pthread_t ddd_pid;
static int onas_fan_fd;

static void onas_fan_exit(int sig)
{
	logg("*ScanOnAccess: onas_fan_exit(), signal %d\n", sig);

	close(onas_fan_fd);

	if (ddd_pid > 0) {
		pthread_kill(ddd_pid, SIGUSR1);
		pthread_join(ddd_pid, NULL);
	}

	pthread_exit(NULL);
	logg("ScanOnAccess: stopped\n");
}

static int onas_fan_scanfile(int fan_fd, const char *fname, struct fanotify_event_metadata *fmd, int scan, int extinfo, struct thrarg *tharg)
{
	struct fanotify_response res;
	const char *virname = NULL;
	int ret = 0;

    res.fd = fmd->fd;
    res.response = FAN_ALLOW;

    if (scan) {
        if (onas_scan(fname, fmd->fd, &virname, tharg->engine, tharg->options, extinfo) == CL_VIRUS) {
            /* TODO : FIXME? virusaction forks. This could be extraordinarily problematic, lead to deadlocks, 
             * or at the very least lead to extreme memory consumption. Leaving disabled for now.*/ 
            //virusaction(fname, virname, tharg->opts);
            res.response = FAN_DENY;
        }
    }

    if(fmd->mask & FAN_ALL_PERM_EVENTS) {
	ret = write(fan_fd, &res, sizeof(res));
	if(ret == -1)
	    logg("!ScanOnAccess: Internal error (can't write to fanotify)\n");
    }

    return ret;
}

void *onas_fan_th(void *arg)
{
	struct thrarg *tharg = (struct thrarg *) arg;
	sigset_t sigset;
        struct sigaction act;
	const struct optstruct *pt;
	short int scan;
	unsigned int sizelimit = 0, extinfo;
	STATBUF sb;
        uint64_t fan_mask = FAN_EVENT_ON_CHILD | FAN_CLOSE;
        fd_set rfds;
	char buf[4096];
	ssize_t bread;
	struct fanotify_event_metadata *fmd;
	char fname[1024];
	int ret, len, check;
	char err[128];

	pthread_attr_t ddd_attr;
	struct ddd_thrarg *ddd_tharg = NULL;

	ddd_pid = 0;

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
    act.sa_handler = onas_fan_exit;
    sigfillset(&(act.sa_mask));
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);

    /* Initialize fanotify */
    onas_fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS, O_LARGEFILE | O_RDONLY);
    if(onas_fan_fd < 0) {
	logg("!ScanOnAccess: fanotify_init failed: %s\n", cli_strerror(errno, err, sizeof(err)));
	if(errno == EPERM)
	    logg("ScanOnAccess: clamd must be started by root\n");
	return NULL;
    }

    if (!tharg) {
	logg("!Unable to start on-access scanner. Bad thread args.\n");
	return NULL;
    }


    if (optget(tharg->opts, "OnAccessPrevention")->enabled && !optget(tharg->opts, "OnAccessMountPath")->enabled) {
	    logg("ScanOnAccess: preventing access attempts on malicious files.\n");
	    fan_mask |= FAN_ACCESS_PERM | FAN_OPEN_PERM;
    } else {
	    logg("ScanOnAccess: notifying only for access attempts.\n");
	    fan_mask |= FAN_ACCESS | FAN_OPEN;
    }

    if ((pt = optget(tharg->opts, "OnAccessMountPath"))->enabled) {
	    while(pt) {
		    if(fanotify_mark(onas_fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, fan_mask, onas_fan_fd, pt->strarg) != 0) {
			    logg("!ScanOnAccess: Can't include mountpoint '%s'\n", pt->strarg);
			    return NULL;
		    } else
			    logg("ScanOnAccess: Protecting '%s' and rest of mount.\n", pt->strarg);
		    pt = (struct optstruct *) pt->nextarg;
	    }

    } else if (!optget(tharg->opts, "OnAccessDisableDDD")->enabled) {
		int thread_started = 1;
	    do {
		    if(pthread_attr_init(&ddd_attr)) break;
		    pthread_attr_setdetachstate(&ddd_attr, PTHREAD_CREATE_JOINABLE);

			/* Allocate memory for arguments. Thread is responsible for freeing it. */
		    if (!(ddd_tharg = (struct ddd_thrarg *) calloc(sizeof(struct ddd_thrarg), 1))) break;
			if (!(ddd_tharg->options = (struct cl_scan_options *) calloc(sizeof(struct cl_scan_options), 1))) break;

			(void) memcpy(ddd_tharg->options, tharg->options, sizeof(struct cl_scan_options));
		    ddd_tharg->fan_fd = onas_fan_fd;
		    ddd_tharg->fan_mask = fan_mask;
		    ddd_tharg->opts = tharg->opts;
		    ddd_tharg->engine = tharg->engine;

		    thread_started = pthread_create(&ddd_pid, &ddd_attr, onas_ddd_th, ddd_tharg);
	    } while(0);

		if (0 != thread_started) {
			/* Failed to create thread. Free anything we may have allocated. */
			logg("!Unable to start dynamic directory determination.\n");
			if (NULL != ddd_tharg) {
				if (NULL != ddd_tharg->options) {
					free(ddd_tharg->options);
					ddd_tharg->options = NULL;
				}
				free(ddd_tharg);
				ddd_tharg = NULL;
			}
		}

    } else {
	    if((pt = optget(tharg->opts, "OnAccessIncludePath"))->enabled) {
		    while(pt) {
			    if(fanotify_mark(onas_fan_fd, FAN_MARK_ADD, fan_mask, onas_fan_fd, pt->strarg) != 0) {
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
    }

    /* Load other options. */
    sizelimit = optget(tharg->opts, "OnAccessMaxFileSize")->numarg;
    if(sizelimit)
	logg("ScanOnAccess: Max file size limited to %u bytes\n", sizelimit);
    else
	logg("ScanOnAccess: File size limit disabled\n");

    extinfo = optget(tharg->opts, "ExtendedDetectionInfo")->enabled;

    FD_ZERO(&rfds);
    FD_SET(onas_fan_fd, &rfds);
    do {
	if (reload) sleep(1);
        ret = select(onas_fan_fd + 1, &rfds, NULL, NULL, NULL);
    } while((ret == -1 && errno == EINTR) || reload);


    time_t start = time(NULL) - 30;
    while(((bread = read(onas_fan_fd, buf, sizeof(buf))) > 0) || errno == EOVERFLOW) {

	if (errno == EOVERFLOW) {
		if (time(NULL) - start >= 30) {
			logg("!ScanOnAccess: Internal error (failed to read data) ... %s\n", strerror(errno));
			logg("!ScanOnAccess: File too large for fanotify ... recovering and continuing scans...\n");
			start = time(NULL);
		}

		errno = 0;
		continue;
	}

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

		if((check = onas_fan_checkowner(fmd->pid, tharg->opts))) {
		    scan = 0;
	/* TODO: Re-enable OnAccessExtraScanning once the thread resource consumption issue is resolved. */
	#if 0
			if ((check != CHK_SELF) || !(optget(tharg->opts, "OnAccessExtraScanning")->enabled)) {
	#else
			if (check != CHK_SELF) {
	#endif
				logg("*ScanOnAccess: %s skipped (excluded UID)\n", fname);
			}
		}

		if(sizelimit) {
		    if(FSTAT(fmd->fd, &sb) != 0 || sb.st_size > sizelimit) {
			scan = 0;
			/* logg("*ScanOnAccess: %s skipped (size > %d)\n", fname, sizelimit); */
		    }
		}

		if(onas_fan_scanfile(onas_fan_fd, fname, fmd, scan, extinfo, tharg) == -1) {
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
	    if (reload) sleep(1);
	    ret = select(onas_fan_fd + 1, &rfds, NULL, NULL, NULL);
	} while((ret == -1 && errno == EINTR) || reload);
    }

    if(bread < 0)
	logg("!ScanOnAccess: Internal error (failed to read data) ... %s\n", strerror(errno));

    return NULL;
}


/* CLAMAUTH is deprecated */
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
	const char *virname = NULL;
	int ret = 0, fd;

    context.filename = fname;
    context.virsize = 0;
    context.scandata = NULL;

    fd = open(fname, O_RDONLY);
    if(fd == -1)
	return -1;

    if(cl_scandesc_callback(fd, fname, &virname, NULL, tharg->engine, tharg->options, &context) == CL_VIRUS) {
	if(extinfo && context.virsize)
	    logg("ScanOnAccess: %s: %s(%s:%llu) FOUND\n", fname, virname, context.virhash, context.virsize);
	else
	    logg("ScanOnAccess: %s: %s FOUND\n", fname, virname);
	virusaction(fname, virname, tharg->opts);
    }
    close(fd);
    return ret;
}

void *onas_fan_th(void *arg)
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
