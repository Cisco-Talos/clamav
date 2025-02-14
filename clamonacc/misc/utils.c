/*
 *  Copyright (C) 2019-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <pwd.h>

// libclamav
#include "clamav.h"

// common
#include "optparser.h"
#include "output.h"

// clamd
#include "scanner.h"

#include "utils.h"
#include "../clamonacc.h"
#include "../client/client.h"
#include "../scan/onas_queue.h"

#if defined(HAVE_SYS_FANOTIFY_H)

extern pthread_cond_t onas_scan_queue_empty_cond;

int onas_fan_checkowner(int pid, const struct optstruct *opts)
{
    struct passwd *pwd;
    char path[32];
    STATBUF sb;
    const struct optstruct *opt       = NULL;
    const struct optstruct *opt_root  = NULL;
    const struct optstruct *opt_uname = NULL;
    int retry                         = 0;

    /* always ignore ourselves */
    if (pid == (int)getpid()) {
        return CHK_SELF;
    }

    /* look up options */
    opt       = optget(opts, "OnAccessExcludeUID");
    opt_root  = optget(opts, "OnAccessExcludeRootUID");
    opt_uname = optget(opts, "OnAccessExcludeUname");

    /* we can return immediately if no uid exclusions were requested */
    if (!(opt->enabled || opt_root->enabled || opt_uname->enabled))
        return CHK_CLEAN;

    /* perform exclusion checks if we can stat OK */
    snprintf(path, sizeof(path), "/proc/%u", pid);
    if (CLAMSTAT(path, &sb) == 0) {
        /* check all our non-root UIDs first */
        if (opt->enabled) {
            while (opt) {
                if (opt->numarg == (long long)sb.st_uid)
                    return CHK_FOUND;
                opt = opt->nextarg;
            }
        }
        /* then check our unames */
        if (opt_uname->enabled) {
            while (opt_uname) {
                errno = 0;
                pwd   = getpwuid(sb.st_uid);
                if (NULL == pwd) {
                    if (errno) {
                        logg(LOGG_DEBUG, "ClamMisc: internal error (failed to exclude event) ... %s\n", strerror(errno));
                        switch (errno) {
                            case EIO:
                                logg(LOGG_DEBUG, "ClamMisc: system i/o failed while retrieving username information (excluding for safety)\n");
                                return CHK_FOUND;
                                break;
                            case EINTR:
                                logg(LOGG_DEBUG, "ClamMisc: caught signal while retrieving username information from system (excluding for safety)\n");
                                return CHK_FOUND;
                                break;
                            case EMFILE:
                            case ENFILE:
                                if (3 >= retry) {
                                    logg(LOGG_DEBUG, "ClamMisc: waiting for consumer thread to catch up then retrying ...\n");
                                    sleep(6);
                                    retry += 1;
                                    continue;
                                } else {
                                    logg(LOGG_DEBUG, "ClamMisc: fds have been exhausted ... attempting to force the consumer thread to catch up ... (excluding for safety)\n");
                                    pthread_cond_signal(&onas_scan_queue_empty_cond);
                                    sleep(6);
                                    return CHK_FOUND;
                                }
                            case ERANGE:
                            default:
                                logg(LOGG_DEBUG, "ClamMisc: unknown error occurred (excluding for safety)\n");
                                return CHK_FOUND;
                                break;
                        }
                    }
                } else {
                    if (!strncmp(opt_uname->strarg, pwd->pw_name, strlen(opt_uname->strarg))) {
                        return CHK_FOUND;
                    }
                }
                opt_uname = opt_uname->nextarg;
            }
        }
        /* finally check root UID */
        if (opt_root->enabled) {
            if (0 == (long long)sb.st_uid)
                return CHK_FOUND;
        }
    } else if (errno == EACCES) {
        logg(LOGG_DEBUG, "ClamMisc: permission denied to stat /proc/%d to exclude UIDs... perhaps SELinux denial?\n", pid);
    } else if (errno == ENOENT) {
        /* TODO: should this be configurable? */
        logg(LOGG_DEBUG, "ClamMisc: $/proc/%d vanished before UIDs could be excluded; scanning anyway\n", pid);
    }

    return CHK_CLEAN;
}

#endif

char **onas_get_opt_list(const char *fname, int *num_entries, cl_error_t *err)
{

    FILE *opt_file = 0;
    STATBUF sb;
    char **opt_list = NULL;
    char **rlc_ptr  = NULL;
    uint64_t len    = 0;
    int32_t ret     = 0;

    *num_entries = 0;

    opt_list = malloc(sizeof(char *));
    if (NULL == opt_list) {
        *err = CL_EMEM;
        return NULL;
    }
    opt_list[*num_entries] = NULL;

    errno    = 0;
    opt_file = fopen(fname, "r");

    if (NULL == opt_file) {
        logg(LOGG_ERROR, "ClamMisc: could not open path list file `%s', %s\n", fname, errno ? strerror(errno) : "");
        *err = CL_EARG;
        free(opt_list);
        return NULL;
    }

    while ((ret = getline(opt_list + *num_entries, &len, opt_file)) != -1) {

        opt_list[*num_entries][strlen(opt_list[*num_entries]) - 1] = '\0';
        errno                                                      = 0;
        if (0 != CLAMSTAT(opt_list[*num_entries], &sb)) {
            logg(LOGG_DEBUG, "ClamMisc: when parsing path list ... could not stat '%s' ... %s ... skipping\n", opt_list[*num_entries], strerror(errno));
            len = 0;
            free(opt_list[*num_entries]);
            opt_list[*num_entries] = NULL;
            continue;
        }

        if (!S_ISDIR(sb.st_mode)) {
            logg(LOGG_DEBUG, "ClamMisc: when parsing path list ... '%s' is not a directory ... skipping\n", opt_list[*num_entries]);
            len = 0;
            free(opt_list[*num_entries]);
            opt_list[*num_entries] = NULL;
            continue;
        }

        if (strcmp(opt_list[*num_entries], "/") == 0) {
            logg(LOGG_DEBUG, "ClamMisc: when parsing path list ... ignoring path '%s' while DDD is enabled ... skipping\n", opt_list[*num_entries]);
            logg(LOGG_DEBUG, "ClamMisc: use the OnAccessMountPath configuration option to watch '%s'\n", opt_list[*num_entries]);
            len = 0;
            free(opt_list[*num_entries]);
            opt_list[*num_entries] = NULL;
            continue;
        }

        (*num_entries)++;
        rlc_ptr = cli_safer_realloc(opt_list, sizeof(char *) * (*num_entries + 1));
        if (rlc_ptr) {
            opt_list               = rlc_ptr;
            opt_list[*num_entries] = NULL;
        } else {
            *err = CL_EMEM;
            fclose(opt_file);
            free_opt_list(opt_list, *num_entries);
            return NULL;
        }

        len = 0;
    }

    opt_list[*num_entries] = NULL;
    fclose(opt_file);
    return opt_list;
}

void free_opt_list(char **opt_list, int entries)
{

    int i = 0;
    for (i = 0; i < entries; i++) {
        if (opt_list[i]) {
            free(opt_list[i]);
            opt_list[i] = NULL;
        }
    }

    free(opt_list);
    opt_list = NULL;

    return;
}
