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

#include "../misc/onaccess_others.h"
#include "clamd/server.h"

#include "onaccess_fan.h"
#include "../inotif/onaccess_hash.h"
#include "../inotif/onaccess_ddd.h"

#include "../client/onaccess_client.h"

extern pthread_t ddd_pid;
extern int reload;

/*static void onas_fan_exit(int sig)
{
	logg("*ClamFanotif: onas_fan_exit(), signal %d\n", sig);

    close(onas_fan_fd);

    if (ddd_pid > 0) {
        pthread_kill(ddd_pid, SIGUSR1);
        pthread_join(ddd_pid, NULL);
    }

    pthread_exit(NULL);
	logg("ClamFanotif: stopped\n");
}*/

static int onas_fan_scanfile(const char *fname, struct fanotify_event_metadata *fmd, STATBUF sb, int scan, struct onas_context **ctx)
{
    struct fanotify_response res;
    const char *virname = NULL;
        int infected = 0;
        int err = 0;
    int ret             = 0;
	int i = 0;
	int scan_failed = 0;

    res.fd       = fmd->fd;
    res.response = FAN_ALLOW;


        logg("*scan: %d\n", scan);
    if (scan) {
		ret = onas_client_scan(ctx, fname, sb, &infected, &err);

		if (err) {
			logg("!ClamFanotif: Internal error (client failed to scan)\n");
			if ((*ctx)->retry_on_error) {
				logg("!ClamFanotif: reattempting scan ... \n");
				while (err) {
					ret = onas_client_scan(ctx, fname, sb, &infected, &err);

					i++;
					if (err && i == (*ctx)->retry_attempts) {
						err = 0;
						scan_failed = 1;
					}
				}
			} else {
				scan_failed = 1;
			}
		}

		if (scan_failed) {
			logg("*ClamFanotif: Scan failed with error code %d\n", err);
		}

		if ((scan_failed && (*ctx)->deny_on_scanfail) || infected) {
            res.response = FAN_DENY;
        }
    }

    if (fmd->mask & FAN_ALL_PERM_EVENTS) {
		ret = write((*ctx)->fan_fd, &res, sizeof(res));
        if (ret == -1)
			logg("!ClamFanotif: Internal error (can't write to fanotify)\n");
    }

    return ret;
}

cl_error_t onas_setup_fanotif(struct onas_context **ctx) {

    const struct optstruct *pt;
    short int scan;
    unsigned int sizelimit = 0, extinfo;
	int onas_fan_fd;
    uint64_t fan_mask = FAN_EVENT_ON_CHILD | FAN_CLOSE;
    char err[128];

    pthread_attr_t ddd_attr;
    struct ddd_thrarg *ddd_tharg = NULL;

    ddd_pid = 0;

    /* Initialize fanotify */
    onas_fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS, O_LARGEFILE | O_RDONLY);
    if (onas_fan_fd < 0) {
		logg("!ClamFanotif: fanotify_init failed: %s\n", cli_strerror(errno, err, sizeof(err)));
        if (errno == EPERM)
			logg("!ClamFanotif: clamonacc must have elevated permissions ... exiting ...\n");
		return CL_EOPEN;
    }


	if (!ctx || !*ctx) {
		logg("!ClamFanotif: unable to start clamonacc. (bad context)\n");
		return CL_EARG;
    }

	(*ctx)->fan_fd = onas_fan_fd;
	(*ctx)->fan_mask = fan_mask;

	if (optget((*ctx)->clamdopts, "OnAccessPrevention")->enabled && !optget((*ctx)->clamdopts, "OnAccessMountPath")->enabled) {
		logg("*ClamFanotif: kernel-level blocking feature enabled ... preventing malicious files access attempts\n");
        fan_mask |= FAN_ACCESS_PERM | FAN_OPEN_PERM;
    } else {
		logg("*ClamFanotif: kernel-level blocking feature disabled ...\n");
		if (optget((*ctx)->clamdopts, "OnAccessPrevention")->enabled && optget((*ctx)->clamdopts, "OnAccessMountPath")->enabled) {
			logg("*ClamFanotif: feature not available when watching mounts ... \n");
		}
        fan_mask |= FAN_ACCESS | FAN_OPEN;
    }

	if ((pt = optget((*ctx)->clamdopts, "OnAccessMountPath"))->enabled) {
        while (pt) {
            if (fanotify_mark(onas_fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, fan_mask, onas_fan_fd, pt->strarg) != 0) {
				logg("!ClamFanotif: can't include mountpoint '%s'\n", pt->strarg);
				return CL_EARG;
            } else
				logg("*ClamFanotif: recursively watching the mount point '%s'\n", pt->strarg);
            pt = (struct optstruct *)pt->nextarg;
        }

	} else if (!optget((*ctx)->clamdopts, "OnAccessDisableDDD")->enabled) {
		(*ctx)->ddd_enabled = 1;
    } else {
		if((pt = optget((*ctx)->clamdopts, "OnAccessIncludePath"))->enabled) {
            while (pt) {
                if (fanotify_mark(onas_fan_fd, FAN_MARK_ADD, fan_mask, onas_fan_fd, pt->strarg) != 0) {
					logg("!ClamFanotif: can't include path '%s'\n", pt->strarg);
					return CL_EARG;
                } else
					logg("*ClamFanotif: watching directory '%s' (non-recursively)\n", pt->strarg);
                pt = (struct optstruct *)pt->nextarg;
            }
        } else {
			logg("!ClamFanotif: Please specify at least one path with OnAccessIncludePath\n");
			return CL_EARG;
        }
    }

    /* Load other options. */
	(*ctx)->sizelimit = optget((*ctx)->clamdopts, "OnAccessMaxFileSize")->numarg;
	if((*ctx)->sizelimit)
		logg("*ClamFanotif: Max file size limited to %lu bytes\n", (*ctx)->sizelimit);
    else
		logg("*ClamFanotif: File size limit disabled\n");

	extinfo = optget((*ctx)->clamdopts, "ExtendedDetectionInfo")->enabled;

	//(*ctx)->sizelimit = sizelimit;
	(*ctx)->extinfo = extinfo;

	return CL_SUCCESS;
}

int onas_fan_eloop(struct onas_context **ctx) {
	int ret = 0;
	short int scan;
	STATBUF sb;
	fd_set rfds;
	char buf[4096];
	ssize_t bread;
	struct fanotify_event_metadata *fmd;
	char fname[1024];
	int len, check, fres;
	char err[128];

    FD_ZERO(&rfds);
	FD_SET((*ctx)->fan_fd, &rfds);
    do {
        if (reload) sleep(1);
		ret = select((*ctx)->fan_fd + 1, &rfds, NULL, NULL, NULL);
    } while ((ret == -1 && errno == EINTR) || reload);

    time_t start = time(NULL) - 30;
	while(((bread = read((*ctx)->fan_fd, buf, sizeof(buf))) > 0) || errno == EOVERFLOW) {

        if (errno == EOVERFLOW) {
            if (time(NULL) - start >= 30) {
				logg("!ClamFanotif: Internal error (failed to read data) ... %s\n", strerror(errno));
				logg("!ClamFanotif: File too large for fanotify ... recovering and continuing scans...\n");
                start = time(NULL);
            }

            errno = 0;
            continue;
        }

        fmd = (struct fanotify_event_metadata *)buf;
        while (FAN_EVENT_OK(fmd, bread)) {
            scan = 1;
            if (fmd->fd >= 0) {
                sprintf(fname, "/proc/self/fd/%d", fmd->fd);
                len = readlink(fname, fname, sizeof(fname) - 1);
                if (len == -1) {
                    close(fmd->fd);
					logg("!ClamFanotif: Internal error (readlink() failed)\n");
					return 2;
                }
				fname[len] = '\0';

				logg("fname = %s\n", fname);
				if((check = onas_fan_checkowner(fmd->pid, (*ctx)->clamdopts))) {
					logg("*ClamFanotif: no scan today, fam\n");
                    scan = 0;
/* TODO: Re-enable OnAccessExtraScanning once the thread resource consumption issue is resolved. */
#if 0
					if ((check != CHK_SELF) || !(optget(tharg->opts, "OnAccessExtraScanning")->enabled))
#else
                    if (check != CHK_SELF) {
#endif
							logg("*ClamFanotif: %s skipped (excluded UID)\n", fname);
                }
            }

                                fres = FSTAT(fmd->fd, &sb);
					if((*ctx)->sizelimit) {
					if(fres != 0 || sb.st_size > (*ctx)->sizelimit) {
                    scan = 0;
						logg("*ClamFanotif: %s skipped (size > %ld)\n", fname, (*ctx)->sizelimit);
                }
            }

				logg("SCASDFASDNNNN\n");
                                logg("%d\n", fres);
				if (onas_fan_scanfile(fname, fmd, sb, scan, ctx) == -1) {
                close(fmd->fd);
					logg("!ClamFanotif: Error when stating and/or scanning??\n");
						return 2;
            }

				logg("???????????\n");

            if (close(fmd->fd) == -1) {
						printf("!ClamFanotif: Internal error (close(%d) failed)\n", fmd->fd);
						return 2;
            }
        }
        fmd = FAN_EVENT_NEXT(fmd, bread);
    }
    do {
        if (reload) sleep(1);
				ret = select((*ctx)->fan_fd + 1, &rfds, NULL, NULL, NULL);
    } while ((ret == -1 && errno == EINTR) || reload);
}

		if(bread < 0) {
			logg("!ClamFanotif: Internal error (failed to read data) ... %s\n", strerror(errno));
                        return 2;
                }


	return ret;
}
#endif
