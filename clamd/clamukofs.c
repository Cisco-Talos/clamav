/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
 *    Author: Tomasz Kojm
 *    Author: John Ogness <dazukocode@ogness.net>
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

#include "libclamav/clamav.h"

#include "shared/optparser.h"
#include "shared/output.h"

#include "server.h"
#include "others.h"
#include "dazukofs.h"
#include "clamuko.h"

static pthread_mutex_t running_mutex = PTHREAD_MUTEX_INITIALIZER;
static dazukofs_handle_t shutdown_hndl;
static pthread_cond_t shutdown_cond;

static void clamuko_exit(int sig)
{
    pthread_cond_signal(&shutdown_cond);
}

static int setup_shutdown_handle(const char *groupname)
{
    /* is another server thread is already running? */
    if(shutdown_hndl) return -1;

    if(pthread_cond_init(&shutdown_cond, NULL)) return -1;

    /* handle used for shutdown by signal */
    shutdown_hndl = dazukofs_open(groupname, DAZUKOFS_TRACK_GROUP);
    if(!shutdown_hndl) {
	logg("!Clamuko: Can't register with DazukoFS\n");
	return -1;
    }
    return 0;
}

static void shutdown_clamuko(void)
{
	dazukofs_handle_t hndl = shutdown_hndl;

    /* Set shutdown_hndl before closing because the close will
     * immediately cause the scan threads to be interrupted.
     * But they will only abort if shutdown_hndl is NULL. */
    shutdown_hndl = NULL;

    if(hndl) dazukofs_close(hndl, DAZUKOFS_REMOVE_GROUP);
}

static void *clamuko_scanth(void *arg)
{
	struct thrarg *tharg = (struct thrarg *) arg;
	sigset_t sigset;
	unsigned int sizelimit = 0;
	struct stat sb;
	dazukofs_handle_t scan_hndl;
	struct dazukofs_access acc;
	const char *groupname = "ClamAV";
	int skip_scan = 0;
	const char *virname;
	char filename[4096];

    /* ignore all signals */
    sigfillset(&sigset);
    /* The behavior of a process is undefined after it ignores a
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS
    sigdelset(&sigset, SIGBUS);
#endif
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);

    /* register */
    scan_hndl = dazukofs_open(groupname, DAZUKOFS_TRACK_GROUP);
    if(!scan_hndl) {
	logg("!Clamuko: Can't register with DazukoFS\n");
	return NULL;
    } else {
	logg("Clamuko: Correctly registered with DazukoFS.\n");
    }

    /* access mask (not used by DazukoFS) */
    if(optget(tharg->opts, "ClamukoScanOnOpen")->enabled)
	logg("!Clamuko: ClamukoScanOnOpen ignored when using DazukoFS.\n");
    if(optget(tharg->opts, "ClamukoScanOnClose")->enabled)
	logg("!Clamuko: ClamukoScanOnClose ignored when using DazukoFS.\n");
    if(optget(tharg->opts, "ClamukoScanOnExec")->enabled)
	logg("!Clamuko: ClamukoScanOnExec ignored when using DazukoFS.\n");
    if(optget(tharg->opts, "ClamukoIncludePath")->enabled)
	logg("!Clamuko: ClamukoIncludePath ignored when using DazukoFS.\n");
    if(optget(tharg->opts, "ClamukoExcludePath")->enabled)
	logg("!Clamuko: ClamukoExcludePath ignored when using DazukoFS.\n");

    sizelimit = optget(tharg->opts, "ClamukoMaxFileSize")->numarg;
    if(sizelimit)
	logg("Clamuko: Max file size limited to %u bytes.\n", sizelimit);
    else
	logg("Clamuko: File size limit disabled.\n");

    while(1) {
	if(dazukofs_get_access(scan_hndl, &acc)) {
	    if(!shutdown_hndl)
		break;
	    continue;
	}

	if(!fstat(acc.fd, &sb)) {
	    if(S_ISDIR(sb.st_mode)) {
		/* don't try to scan directories */
		skip_scan = 1;
	    } else if(sb.st_size > sizelimit) {
		dazukofs_get_filename(&acc, filename, sizeof(filename));
		logg("*Clamuko: %s skipped (too big)\n", filename);
		skip_scan = 1;
	    }
	}

	if(skip_scan) {
	    acc.deny = 0;
	    /* reset skip flag */
	    skip_scan = 0;
	} else if(cl_scandesc(acc.fd, &virname, NULL, tharg->engine,
			      tharg->options) == CL_VIRUS) {
	    dazukofs_get_filename(&acc, filename, sizeof(filename));
	    logg("Clamuko: %s: %s FOUND\n", filename, virname);
	    /* we can not perform any special action because it will
	     * trigger DazukoFS recursively */
	    acc.deny = 1;
	} else {
	    acc.deny = 0;
	}

	if(dazukofs_return_access(scan_hndl, &acc)) {
	    if(shutdown_hndl)
	        logg("!Clamuko: Can't return access to DazukoFS.\n");
	    break;
	}
    }

    dazukofs_close(scan_hndl, 0);

    if(shutdown_hndl)
        logg("!Clamuko: A scanner thread has unexpectedly shutdown.\n");

    return NULL;
}

void *clamukofsth(void *arg)
{
	struct thrarg *tharg = (struct thrarg *) arg;
	sigset_t sigset;
        struct sigaction act;
	pthread_t *clamuko_pids = NULL;
	const char *groupname = "ClamAV";
	int count;
	int started;

    /* is another server thread already working? */
    if(pthread_mutex_trylock(&running_mutex))
	return NULL;

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

    count = optget(tharg->opts, "ClamukoScannerCount")->numarg;
    if(count < 1) goto out;

    clamuko_pids = calloc(count, sizeof(pthread_t));
    if(!clamuko_pids) goto out;

    if(setup_shutdown_handle(groupname)) goto out;

    act.sa_handler = clamuko_exit;
    sigfillset(&(act.sa_mask));
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);

    for(started = 0; started < count; started++) {
	pthread_attr_t clamuko_attr;

	if(pthread_attr_init(&clamuko_attr)) break;
	pthread_attr_setdetachstate(&clamuko_attr, PTHREAD_CREATE_JOINABLE);
	if(pthread_create(&clamuko_pids[started], &clamuko_attr,
			  clamuko_scanth, tharg)) break;
	logg("Clamuko: Started scanner thread %d.\n", started);
    }

    pthread_cond_wait(&shutdown_cond, &running_mutex);
    logg("Clamuko: Stop signal received.\n");

    shutdown_clamuko();

    for(started-- ; started >= 0; started--) {
	logg("Clamuko: Waiting for scanner thread %d to finish.\n", started);
	pthread_join(clamuko_pids[started], NULL);
    }

    logg("Clamuko: Stopped.\n");
out:
    if(clamuko_pids) free(clamuko_pids);
    pthread_mutex_unlock(&running_mutex);
    return NULL;
}

#endif
