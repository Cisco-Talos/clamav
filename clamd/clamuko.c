/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
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

#ifdef CLAMUKO

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>

#include "libclamav/clamav.h"
#include "libclamav/scanners.h"

#include "shared/optparser.h"
#include "shared/output.h"

#include "server.h"
#include "others.h"
#include "dazukoio.h"
#include "clamukofs.h"
#include "clamuko.h"
#include "scanner.h"

struct dazuko_access *acc;
short int clamuko_scanning;
static void clamuko_exit(int sig)
{

    logg("*Clamuko: clamuko_exit(), signal %d\n", sig);

    if(clamuko_scanning) {
	logg("*Clamuko: stopped while scanning %s\n", acc->filename);
	acc->deny = 0;
	dazukoReturnAccess(&acc); /* is it needed ? */
    }

    if(dazukoUnregister())
	logg("!Can't unregister with Dazuko\n");

    logg("Clamuko stopped.\n");

    pthread_exit(NULL);
}

static void *clamukolegacyth(void *arg)
{
	struct thrarg *tharg = (struct thrarg *) arg;
	sigset_t sigset;
	const char *virname;
        struct sigaction act;
	unsigned long mask = 0;
	const struct optstruct *pt;
	short int scan;
	int sizelimit = 0, extinfo;
	struct stat sb;
	struct cb_context context;


    clamuko_scanning = 0;

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
    act.sa_handler = clamuko_exit;
    sigfillset(&(act.sa_mask));
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);

    /* register */
    if(dazukoRegister("ClamAV", "r+")) {
	logg("!Clamuko: Can't register with Dazuko\n");
	return NULL;
    } else
	logg("Clamuko: Correctly registered with Dazuko.\n");

    /* access mask */
    if(optget(tharg->opts, "ClamukoScanOnOpen")->enabled) {
	logg("Clamuko: Scan-on-open mode activated.\n");
	mask |= DAZUKO_ON_OPEN;
    }
    if(optget(tharg->opts, "ClamukoScanOnClose")->enabled) {
	logg("Clamuko: Scan-on-close mode activated.\n");
	mask |= DAZUKO_ON_CLOSE;
    }
    if(optget(tharg->opts, "ClamukoScanOnExec")->enabled) {
	logg("Clamuko: Scan-on-exec mode activated.\n");
	mask |= DAZUKO_ON_EXEC;
    }

    if(!mask) {
	logg("!Access mask is not configured properly.\n");
	dazukoUnregister();
	return NULL;
    }

    if(dazukoSetAccessMask(mask)) {
	logg("!Clamuko: Can't set access mask in Dazuko.\n");
	dazukoUnregister();
	return NULL;
    }

    if((pt = optget(tharg->opts, "ClamukoIncludePath"))->enabled) {
	while(pt) {
	    if((dazukoAddIncludePath(pt->strarg))) {
		logg("!Clamuko: Dazuko -> Can't include path %s\n", pt->strarg);
		dazukoUnregister();
		return NULL;
	    } else
		logg("Clamuko: Included path %s\n", pt->strarg);

	    pt = (struct optstruct *) pt->nextarg;
	}
    } else {
	logg("!Clamuko: please include at least one path.\n");
	dazukoUnregister();
	return NULL;
    }

    if((pt = optget(tharg->opts, "ClamukoExcludePath"))->enabled) {
	while(pt) {
	    if((dazukoAddExcludePath(pt->strarg))) {
		logg("!Clamuko: Dazuko -> Can't exclude path %s\n", pt->strarg);
		dazukoUnregister();
		return NULL;
	    } else
		logg("Clamuko: Excluded path %s\n", pt->strarg);

	    pt = (struct optstruct *) pt->nextarg;
	}
    }

    sizelimit = optget(tharg->opts, "ClamukoMaxFileSize")->numarg;
    if(sizelimit)
	logg("Clamuko: Max file size limited to %d bytes.\n", sizelimit);
    else
	logg("Clamuko: File size limit disabled.\n");

    extinfo = optget(tharg->opts, "ExtendedDetectionInfo")->enabled;

    while(1) {

	if(dazukoGetAccess(&acc) == 0) {
	    clamuko_scanning = 1;
	    scan = 1;

	    if(sizelimit) {
		stat(acc->filename, &sb);
		if(sb.st_size > sizelimit) {
		    scan = 0;
		    logg("*Clamuko: %s skipped (too big)\n", acc->filename);
		}
	    }

	    if(clamuko_checkowner(acc->pid, tharg->opts)) {
		scan = 0;
		logg("*Clamuko: %s skipped (excluded UID)\n", acc->filename);
	    }

	    context.filename = acc->filename;
	    context.virsize = 0;
	    if(scan && cl_scanfile_callback(acc->filename, &virname, NULL, tharg->engine, tharg->options, &context) == CL_VIRUS) {
		if(context.virsize)
		    detstats_add(virname, acc->filename, context.virsize, context.virhash);
		if(extinfo && context.virsize)
		    logg("Clamuko: %s: %s(%s:%llu) FOUND\n", acc->filename, virname, context.virhash, context.virsize);
		else
		    logg("Clamuko: %s: %s FOUND\n", acc->filename, virname);
		virusaction(acc->filename, virname, tharg->opts);
		acc->deny = 1;
	    } else
		acc->deny = 0;

	    if(dazukoReturnAccess(&acc)) {
		logg("!Can't return access to Dazuko.\n");
		logg("Clamuko stopped.\n");
		dazukoUnregister();
		clamuko_scanning = 0;
		return NULL;
	    }

	    clamuko_scanning = 0;
	}
    }

    /* can't be ;) */
    return NULL;
}

void *clamukoth(void *arg)
{
	struct stat s;

    /* we use DazukoFS if /dev/dazukofs.ctrl exists and it is a
     * character device, otherwise we use Dazuko */
    if(stat("/dev/dazukofs.ctrl", &s) != 0) return clamukolegacyth(arg);
    if(!S_ISCHR(s.st_mode)) return clamukolegacyth(arg);
    return clamukofsth(arg);
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
    logg("*ClamAuth: cauth_exit(), signal %d\n", sig);
    if(cauth_fd > 0)
	close(cauth_fd);
    pthread_exit(NULL);
    logg("ClamAuth: stopped\n");
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
	if(context.virsize)
	    detstats_add(virname, fname, context.virsize, context.virhash);
	if(extinfo && context.virsize)
	    logg("ClamAuth: %s: %s(%s:%llu) FOUND\n", fname, virname, context.virhash, context.virsize);
	else
	    logg("ClamAuth: %s: %s FOUND\n", fname, virname);
	virusaction(fname, virname, tharg->opts);
    }
    close(fd);
    return ret;
}

void *clamukoth(void *arg)
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
	logg("!ClamAuth: Can't open /dev/clamauth\n");
	if(errno == ENOENT)
	    logg("!ClamAuth: Please make sure ClamAuth.kext is loaded\n");
	else if(errno == EACCES)
	    logg("!ClamAuth: This application requires root privileges\n");
	else
	    logg("!ClamAuth: /dev/clamauth: %s\n", cli_strerror(errno, err, sizeof(err)));

	return NULL;
    }

    while(1) {
	if(read(cauth_fd, &event, sizeof(event)) > 0) {
	    if(eventcnt == 1) {
		if(event.action != SUPPORTED_PROTOCOL) {
		    logg("!ClamAuth: Protocol version mismatch (tool: %d, driver: %d)\n", SUPPORTED_PROTOCOL, event.action);
		    close(cauth_fd);
		    return NULL;
		}
		if(strncmp(event.path, "ClamAuth", 8)) {
		    logg("!ClamAuth: Invalid version event\n");
		    close(cauth_fd);
		    return NULL;
		}
		logg("ClamAuth: Driver version: %s, protocol version: %d\n", &event.path[9], event.action);
	    } else {
		cauth_scanfile(event.path, extinfo, tharg);
	    }
	    eventcnt++;
	} else {
	    if(errno == ENODEV) {
		printf("^ClamAuth: ClamAuth module deactivated, terminating\n");
		close(cauth_fd);
		return NULL;
	    }
	}
	usleep(200);
    }
}
#endif
