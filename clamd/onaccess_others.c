/*
 *  Copyright (C) 2017-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
//#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
//#include <limits.h>
#include "libclamav/clamav.h"
//#include "libclamav/scanners.h"
#include "shared/optparser.h"
#include "shared/output.h"
//#include "shared/misc.h"
//#include "libclamav/others.h"

//#include "others.h"

#include "onaccess_others.h"
#include "scanner.h"

static pthread_mutex_t onas_scan_lock = PTHREAD_MUTEX_INITIALIZER;

int onas_fan_checkowner(int pid, const struct optstruct *opts)
{
    char path[32];
    STATBUF sb;
    const struct optstruct *opt = NULL;
    const struct optstruct *opt_root = NULL;

    /* always ignore ourselves */
    if (pid == (int) getpid()) {
        return CHK_SELF;
    }

    /* look up options */
    opt = optget (opts, "OnAccessExcludeUID");
    opt_root = optget (opts, "OnAccessExcludeRootUID");

    /* we can return immediately if no uid exclusions were requested */
    if (!(opt->enabled || opt_root->enabled))
        return CHK_CLEAN;

    /* perform exclusion checks if we can stat OK */
    snprintf (path, sizeof (path), "/proc/%u", pid);
    if (CLAMSTAT (path, &sb) == 0) {
        /* check all our non-root UIDs first */
        if (opt->enabled) {
            while (opt)
            {
                if (opt->numarg == (long long) sb.st_uid)
                    return CHK_FOUND;
                opt = opt->nextarg;
            }
        }
        /* finally check root UID */
        if (opt_root->enabled) {
            if (0 == (long long) sb.st_uid)
                return CHK_FOUND;
        }
    } else if (errno == EACCES) {
        logg("*Permission denied to stat /proc/%d to exclude UIDs... perhaps SELinux denial?\n", pid);
    } else if (errno == ENOENT) {
        /* FIXME: should this be configurable? */
        logg("$/proc/%d vanished before UIDs could be excluded; scanning anyway\n", pid);
    }

    return CHK_CLEAN;
}

int onas_scan(const char *fname, int fd, const char **virname, const struct cl_engine *engine, struct cl_scan_options *options, int extinfo)
{
    int ret = 0;
    struct cb_context context;

    pthread_mutex_lock(&onas_scan_lock);

    context.filename = fname;
    context.virsize = 0;
    context.scandata = NULL;
 
    ret = cl_scandesc_callback(fd, fname, virname, NULL, engine, options, &context);

    if (ret) {
        if (extinfo && context.virsize)
            logg("ScanOnAccess: %s: %s(%s:%llu) FOUND\n", fname, *virname, context.virhash, context.virsize);
        else
            logg("ScanOnAccess: %s: %s FOUND\n", fname, *virname);
    }

    pthread_mutex_unlock(&onas_scan_lock);

    return ret;
}
#endif
