/*
 *  Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Mickey Sola
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
#include <string.h>
#include <fcntl.h>
#include <fts.h>
#include <signal.h>
#include <pthread.h>

#include "shared/optparser.h"
#include "shared/output.h"

#include "others.h"

#include "onaccess_scth.h"

static void onas_scth_handle_dir(const char *pathname);
static void onas_scth_handle_file(const char *pathname);

static void onas_scth_exit(int sig);

static void onas_scth_exit(int sig) {
	logg("*ScanOnAccess: onas_scth_exit(), signal %d\n", sig);

	pthread_exit(NULL);
}

static void onas_scth_handle_dir(const char *pathname) {
	FTS *ftsp = NULL;
	int ftspopts = FTS_PHYSICAL | FTS_XDEV;
	FTSENT *curr = NULL;

	char *const pathargv[] = { (char *) pathname, NULL };
	if (!(ftsp = fts_open(pathargv, ftspopts, NULL))) return;

	/* Offload scanning work to fanotify thread to avoid potential deadlocks. */
	while ((curr = fts_read(ftsp))) {
		if (curr->fts_info != FTS_D) {
			int fd = open(curr->fts_path, O_RDONLY);
			if (fd > 0) close(fd);
		}
	}

	return;
}


static void onas_scth_handle_file(const char *pathname) {
	if (!pathname) return;

	/* Offload scanning work to fanotify thread to avoid potential deadlocks. */
	int fd = open(pathname, O_RDONLY);
	if (fd > 0) close(fd);

	return;
}

void *onas_scan_th(void *arg) {
	struct scth_thrarg *tharg = (struct scth_thrarg *) arg;
	sigset_t sigset;
	struct sigaction act;

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
	act.sa_handler = onas_scth_exit;
	sigfillset(&(act.sa_mask));
	sigaction(SIGUSR1, &act, NULL);
	sigaction(SIGSEGV, &act, NULL);


	if (tharg->options & ONAS_SCTH_ISDIR) {
		logg("ScanOnAccess: Performing additional scanning on directory '%s'\n", tharg->pathname);
		onas_scth_handle_dir(tharg->pathname);
	} else if (tharg->options & ONAS_SCTH_ISFILE) {
		logg("ScanOnAccess: Performing additional scanning on file '%s'\n", tharg->pathname);
		onas_scth_handle_file(tharg->pathname);
	}

	free(tharg->pathname);
	tharg->pathname = NULL;

	return NULL;
}
#endif
