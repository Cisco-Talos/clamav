/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB
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
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_LIMITS_H
#include <sys/limits.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <utime.h>
#endif
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

// libclamav
#include "clamav.h"
#include "str.h"
#include "others.h"

// common
#include "optparser.h"
#include "output.h"
#include "misc.h"
#include "actions.h"
#include "clamdcom.h"

#ifdef _WIN32
#include "scanmem.h"
#endif

#include "client.h"
#include "proto.h"

unsigned long int maxstream;
extern struct optstruct *clamdopts;

/* Inits the communication layer
 * Returns 0 if clamd is local, non zero if clamd is remote */
static int isremote(const struct optstruct *opts)
{
    int s, ret;
    const struct optstruct *opt;
    char *ipaddr, port[10];
    struct addrinfo hints, *info, *p;
    int res;

    UNUSEDPARAM(opts);

#ifndef _WIN32
    if ((opt = optget(clamdopts, "LocalSocket"))->enabled) {
        memset((void *)&nixsock, 0, sizeof(nixsock));
        nixsock.sun_family = AF_UNIX;
        strncpy(nixsock.sun_path, opt->strarg, sizeof(nixsock.sun_path));
        nixsock.sun_path[sizeof(nixsock.sun_path) - 1] = '\0';
        return 0;
    }
#endif
    if (!(opt = optget(clamdopts, "TCPSocket"))->enabled)
        return 0;

    snprintf(port, sizeof(port), "%lld", optget(clamdopts, "TCPSocket")->numarg);

    opt = optget(clamdopts, "TCPAddr");
    while (opt) {
        ipaddr = NULL;
        if (opt->strarg)
            ipaddr = (!strcmp(opt->strarg, "any") ? NULL : opt->strarg);

        memset(&hints, 0x00, sizeof(struct addrinfo));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_PASSIVE;

        if ((res = getaddrinfo(ipaddr, port, &hints, &info))) {
            logg(LOGG_ERROR, "Can't lookup clamd hostname: %s\n", gai_strerror(res));
            opt = opt->nextarg;
            continue;
        }

        for (p = info; p != NULL; p = p->ai_next) {
            if ((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
                logg(LOGG_INFO, "isremote: socket() returning: %s.\n", strerror(errno));
                continue;
            }

            switch (p->ai_family) {
                case AF_INET:
                    ((struct sockaddr_in *)(p->ai_addr))->sin_port = htons(INADDR_ANY);
                    break;
                case AF_INET6:
                    ((struct sockaddr_in6 *)(p->ai_addr))->sin6_port = htons(INADDR_ANY);
                    break;
                default:
                    break;
            }

            ret = bind(s, p->ai_addr, p->ai_addrlen);
            if (ret) {
                if (errno == EADDRINUSE) {
                    /*
                     * If we can't bind, then either we're attempting to listen on an IP that isn't
                     * ours or that clamd is already listening on.
                     */
                    closesocket(s);
                    freeaddrinfo(info);
                    return 0;
                }

                closesocket(s);
                freeaddrinfo(info);
                return 1;
            }

            closesocket(s);
        }

        freeaddrinfo(info);

        opt = opt->nextarg;
    }

    return 0;
}

/* pings clamd at the specified interval the number of time specified
 * return 0 on a successful connection, 1 upon timeout, -1 on error */
int16_t ping_clamd(const struct optstruct *opts)
{

    uint64_t attempts           = 0;
    uint64_t interval           = 0;
    char *attempt_str           = NULL;
    char *interval_str          = NULL;
    char *errchk                = NULL;
    uint64_t i                  = 0;
    const struct optstruct *opt = NULL;
    int64_t sockd               = -1;
    struct RCVLN rcv;
    uint16_t ret = 0;

    if (opts == NULL) {
        logg(LOGG_ERROR, "null parameter was passed\n");
        ret = -1;
        goto done;
    }

    /* ping command takes the form --ping [attempts[:interval]] */
    if (NULL != (opt = optget(opts, "ping"))) {
        if (NULL != opt->strarg) {
            if (NULL == (attempt_str = cli_safer_strdup(opt->strarg))) {
                logg(LOGG_ERROR, "could not allocate memory for string\n");
                ret = -1;
                goto done;
            }
            interval_str = strchr(attempt_str, ':');
            if ((NULL != interval_str) && (interval_str[0] != '\0')) {
                interval_str[0] = '\0';
                interval_str++;
                interval = cli_strntoul(interval_str, strlen(interval_str), &errchk, 10);
                if (interval_str + strlen(interval_str) > errchk) {
                    logg(LOGG_WARNING, "interval_str would go past end of buffer\n");
                    ret = -1;
                    goto done;
                }
            } else {
                interval = CLAMDSCAN_DEFAULT_PING_INTERVAL;
            }
            attempts = cli_strntoul(attempt_str, strlen(attempt_str), &errchk, 10);
            if (attempt_str + strlen(attempt_str) > errchk) {
                logg(LOGG_WARNING, "attempt_str would go past end of buffer\n");
                ret = -1;
                goto done;
            }
        } else {
            attempts = CLAMDSCAN_DEFAULT_PING_ATTEMPTS;
            interval = CLAMDSCAN_DEFAULT_PING_INTERVAL;
        }
    }

    isremote(opts);
    do {
        if ((sockd = dconnect(clamdopts)) >= 0) {
            const char zPING[] = "zPING";
            recvlninit(&rcv, sockd);

            if (sendln(sockd, zPING, sizeof(zPING))) {
                logg(LOGG_DEBUG, "PING failed...\n");
                closesocket(sockd);
                sockd = -1;
            } else {
                if (!optget(opts, "wait")->enabled) {
                    logg(LOGG_INFO, "PONG\n");
                }
                ret = 0;
                goto done;
            }
        }

        if (i + 1 < attempts) {
            if (optget(opts, "wait")->enabled) {
                if (interval == 1)
                    logg(LOGG_DEBUG, "Could not connect, will try again in %lu second\n", interval);
                else
                    logg(LOGG_DEBUG, "Could not connect, will try again in %lu seconds\n", interval);
            } else {
                if (interval == 1)
                    logg(LOGG_INFO, "Could not connect, will PING again in %lu second\n", interval);
                else
                    logg(LOGG_INFO, "Could not connect, will PING again in %lu seconds\n", interval);
            }
            sleep(interval);
        }
        i++;
    } while (i < attempts);

    /* timed out */
    ret = 1;
    if (optget(opts, "wait")->enabled) {
        logg(LOGG_INFO, "Wait timeout exceeded; Could not connect to clamd\n");
    } else {
        logg(LOGG_INFO, "PING timeout exceeded; No response from clamd\n");
    }

done:
    if (sockd >= 0) {
        closesocket(sockd);
    }
    if (attempt_str) {
        free(attempt_str);
    }
    attempt_str  = NULL;
    interval_str = NULL;
    errchk       = NULL;

    return ret;
}

/* Turns a relative path into an absolute one
 * Returns a pointer to the path (which must be
 * freed by the caller) or NULL on error */
static char *makeabs(const char *basepath)
{
    int namelen;
    char *ret;

    if (!(ret = malloc(PATH_MAX + 1))) {
        logg(LOGG_WARNING, "Can't make room for fullpath.\n");
        return NULL;
    }
    if (!cli_is_abspath(basepath)) {
        if (!getcwd(ret, PATH_MAX)) {
            logg(LOGG_WARNING, "Can't get absolute pathname of current working directory.\n");
            free(ret);
            return NULL;
        }
#ifdef _WIN32
        if (*basepath == '\\') {
            namelen = 2;
            basepath++;
        } else
#endif
            namelen = strlen(ret);
        snprintf(&ret[namelen], PATH_MAX - namelen, PATHSEP "%s", basepath);
    } else {
        strncpy(ret, basepath, PATH_MAX);
    }
    ret[PATH_MAX] = '\0';
    return ret;
}

/* Recursively scans a path with the given scantype
 * Returns non zero for serious errors, zero otherwise */
static int client_scan(const char *file, int scantype, int *infected, int *err, int maxlevel, int session, int flags)
{
    int ret;
    char *real_path = NULL;
    char *fullpath  = NULL;

    /* Convert relative path to fullpath */
    fullpath = makeabs(file);

    /* Convert fullpath to the real path (evaluating symlinks and . and ..).
       Doing this early on will ensure that the scan results will appear consistent
       across regular scans, --fdpass scans, and --stream scans. */
    if (CL_SUCCESS != cli_realpath(fullpath, &real_path)) {
        logg(LOGG_DEBUG, "client_scan: Failed to determine real filename of %s.\n", fullpath);
    } else {
        free(fullpath);
        fullpath = real_path;
    }

    if (!fullpath)
        return 0;
    if (!session)
        ret = serial_client_scan(fullpath, scantype, infected, err, maxlevel, flags);
    else
        ret = parallel_client_scan(fullpath, scantype, infected, err, maxlevel, flags);
    free(fullpath);
    return ret;
}

int get_clamd_version(const struct optstruct *opts)
{
    char *buff;
    int len, sockd;
    struct RCVLN rcv;
    const char zVERSION[] = "zVERSION";

    isremote(opts);
    if ((sockd = dconnect(clamdopts)) < 0) return 2;
    recvlninit(&rcv, sockd);

    if (sendln(sockd, zVERSION, sizeof(zVERSION))) {
        closesocket(sockd);
        return 2;
    }

    while ((len = recvln(&rcv, &buff, NULL))) {
        if (len == -1) {
            logg(LOGG_ERROR, "Error occurred while receiving version information.\n");
            break;
        }

        /* Check if the response was "COMMAND UNAVAILABLE", which means that
           clamd has the VERSION command disabled. */
        if (len >= 19 && memcmp(buff, "COMMAND UNAVAILABLE", 19) == 0) {
            logg(LOGG_WARNING, "VERSION command disabled in clamd, printing the local version.\n");
            closesocket(sockd);
            return 2;
        }

        printf("%s\n", buff);
    }

    closesocket(sockd);
    return 0;
}

int reload_clamd_database(const struct optstruct *opts)
{
    char *buff;
    int len, sockd;
    struct RCVLN rcv;
    const char zRELOAD[] = "zRELOAD";

    isremote(opts);
    if ((sockd = dconnect(clamdopts)) < 0) return 2;
    recvlninit(&rcv, sockd);

    if (sendln(sockd, zRELOAD, sizeof(zRELOAD))) {
        closesocket(sockd);
        return 2;
    }

    if (!(len = recvln(&rcv, &buff, NULL)) || len < 10 || memcmp(buff, "RELOADING", 9)) {
        logg(LOGG_ERROR, "Clamd did not reload the database\n");
        closesocket(sockd);
        return 2;
    }
    closesocket(sockd);
    return 0;
}

int client(const struct optstruct *opts, int *infected, int *err)
{
    int remote, scantype, session = 0, errors = 0, scandash = 0, maxrec, flags = 0;
    const char *fname;

    if (optget(opts, "wait")->enabled) {
        int16_t ping_result = ping_clamd(opts);
        switch (ping_result) {
            case 0:
                break;
            case 1:
                return (int)CL_ETIMEOUT;
            default:
                return (int)CL_ERROR;
        }
    }

    scandash = (opts->filename && opts->filename[0] && !strcmp(opts->filename[0], "-") && !optget(opts, "file-list")->enabled && !opts->filename[1]);
    remote   = isremote(opts) | optget(opts, "stream")->enabled;
#ifdef HAVE_FD_PASSING
    if (!remote && optget(clamdopts, "LocalSocket")->enabled && (optget(opts, "fdpass")->enabled || scandash)) {
        scantype = FILDES;
        session  = optget(opts, "multiscan")->enabled;
    } else
#endif
        if (remote || scandash) {
        scantype = STREAM;
        session  = optget(opts, "multiscan")->enabled;
    } else if (optget(opts, "multiscan")->enabled)
        scantype = MULTI;
    else if (optget(opts, "allmatch")->enabled)
        scantype = ALLMATCH;
    else
        scantype = CONT;

    maxrec    = optget(clamdopts, "MaxDirectoryRecursion")->numarg;
    maxstream = optget(clamdopts, "StreamMaxLength")->numarg;
    if (optget(clamdopts, "FollowDirectorySymlinks")->enabled)
        flags |= CLI_FTW_FOLLOW_DIR_SYMLINK;
    if (optget(clamdopts, "FollowFileSymlinks")->enabled)
        flags |= CLI_FTW_FOLLOW_FILE_SYMLINK;
    flags |= CLI_FTW_TRIM_SLASHES;

    *infected = 0;

    if (scandash) {
        int sockd, ret;
        STATBUF sb;
        if (FSTAT(0, &sb) < 0) {
            logg(LOGG_INFO, "client.c: fstat failed for file name \"%s\", with %s\n",
                 opts->filename[0], strerror(errno));
            return 2;
        }
        if ((sb.st_mode & S_IFMT) != S_IFREG) scantype = STREAM;
        if ((sockd = dconnect(clamdopts)) >= 0 && (ret = dsresult(sockd, scantype, NULL, &ret, NULL, clamdopts)) >= 0)
            *infected = ret;
        else
            errors = 1;
        if (sockd >= 0) closesocket(sockd);
    } else if (opts->filename || optget(opts, "file-list")->enabled) {
        if (opts->filename && optget(opts, "file-list")->enabled)
            logg(LOGG_WARNING, "Only scanning files from --file-list (files passed at cmdline are ignored)\n");

        while ((fname = filelist(opts, NULL))) {
            if (!strcmp(fname, "-")) {
                logg(LOGG_ERROR, "Scanning from standard input requires \"-\" to be the only file argument\n");
                continue;
            }
            errors += client_scan(fname, scantype, infected, err, maxrec, session, flags);
            /* this may be too strict
            if(errors >= 10) {
                logg(LOGG_ERROR, "Too many errors\n");
                break;
            }
            */
        }
    }
#ifdef _WIN32
    else if (optget(opts, "memory")->enabled) {
        struct mem_info minfo;
        minfo.d      = 1;
        minfo.opts   = opts;
        minfo.ifiles = *infected;
        minfo.errors = errors;
        int res      = scanmem(&minfo);
        *infected    = minfo.ifiles;
        *err         = minfo.errors;
    }
#endif
    else {
        errors = client_scan("", scantype, infected, err, maxrec, session, flags);
    }
    return *infected ? 1 : (errors ? 2 : 0);
}
