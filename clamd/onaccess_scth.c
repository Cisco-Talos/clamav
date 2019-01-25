/*
 *  Copyright (C) 2015-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <signal.h>
#include <pthread.h>

#include "shared/optparser.h"
#include "shared/output.h"

#include "others.h"
#include "priv_fts.h"
#include "onaccess_others.h"
#include "onaccess_scth.h"
#include "onaccess_others.h"

#include "libclamav/clamav.h"


static int onas_scth_scanfile(const char *fname, int fd, int extinfo, struct scth_thrarg *tharg);
static int onas_scth_handle_dir(const char *pathname, struct scth_thrarg *tharg);
static int onas_scth_handle_file(const char *pathname, struct scth_thrarg *tharg);

static void onas_scth_exit(int sig);

static void onas_scth_exit(int sig) {
	logg("*ScanOnAccess: onas_scth_exit(), signal %d\n", sig);

	pthread_exit(NULL);
}

static int onas_scth_scanfile(const char *fname, int fd, int extinfo, struct scth_thrarg *tharg)
{
    int ret = 0;
    const char *virname = NULL;

    return onas_scan(fname, fd, &virname, tharg->engine, tharg->options, extinfo);
}

static int onas_scth_handle_dir(const char *pathname, struct scth_thrarg *tharg) {
	FTS *ftsp = NULL;
	int fd;
	int ftspopts = FTS_PHYSICAL | FTS_XDEV;
	int extinfo;
	int ret;
	FTSENT *curr = NULL;

	extinfo = optget(tharg->opts, "ExtendedDetectionInfo")->enabled;

	char *const pathargv[] = { (char *) pathname, NULL };
	if (!(ftsp = _priv_fts_open(pathargv, ftspopts, NULL))) return CL_EOPEN;

	while ((curr = _priv_fts_read(ftsp))) {
		if (curr->fts_info != FTS_D) {
			if ((fd = safe_open(curr->fts_path, O_RDONLY | O_BINARY)) == -1)
                            return CL_EOPEN;

                        if (onas_scth_scanfile(curr->fts_path, fd, extinfo, tharg) == CL_VIRUS);
                            ret = CL_VIRUS;

			close(fd);
		}
	}

	return ret;
}


static int onas_scth_handle_file(const char *pathname, struct scth_thrarg *tharg) {
	int fd;
	int extinfo;
	int ret;

	if (!pathname) return CL_ENULLARG;

	extinfo = optget(tharg->opts, "ExtendedDetectionInfo")->enabled;

	if ((fd = safe_open(pathname, O_RDONLY | O_BINARY)) == -1)
		return CL_EOPEN;
	ret = onas_scth_scanfile(pathname, fd, extinfo, tharg);

	close(fd);

	return ret;
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

	if (NULL == tharg || NULL == tharg->pathname || NULL == tharg->opts || NULL == tharg->engine) {
		logg("ScanOnAccess: Invalid thread arguments for extra scanning\n");
		goto done;
	}

	if (tharg->extra_options & ONAS_SCTH_ISDIR) {
		logg("*ScanOnAccess: Performing additional scanning on directory '%s'\n", tharg->pathname);
		onas_scth_handle_dir(tharg->pathname, tharg);
	} else if (tharg->extra_options & ONAS_SCTH_ISFILE) {
		logg("*ScanOnAccess: Performing additional scanning on file '%s'\n", tharg->pathname);
		onas_scth_handle_file(tharg->pathname, tharg);
	}

done:
	if (NULL != tharg->pathname){
		free(tharg->pathname);
		tharg->pathname = NULL;
	}
	if (NULL != tharg->options) {
		free(tharg->options);
		tharg->options = NULL;
	}
	if (NULL != tharg) {
		free(tharg);
	}

	return NULL;
}
#endif
