/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#if defined(C_SOLARIS)
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif
#endif

/* must be first because it may define _XOPEN_SOURCE */
#include "fdpassing.h"
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#endif

// libclamav
#include "clamav.h"
#include "others.h"

// shared
#include "actions.h"
#include "output.h"
#include "misc.h"
#include "clamdcom.h"

#include "proto.h"
#include "client.h"

extern unsigned long int maxstream;
int printinfected;
extern struct optstruct *clamdopts;
#ifndef _WIN32
extern struct sockaddr_un nixsock;
#endif

static const char *scancmd[] = {"CONTSCAN", "MULTISCAN", "INSTREAM", "FILDES", "ALLMATCHSCAN"};

/* Connects to clamd
 * Returns a FD or -1 on error */
int dconnect()
{
    int sockd, res;
    const struct optstruct *opt;
    struct addrinfo hints, *info, *p;
    char port[10];
    char *ipaddr;

#ifndef _WIN32
    opt = optget(clamdopts, "LocalSocket");
    if (opt->enabled) {
        if ((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0) {
            if (connect(sockd, (struct sockaddr *)&nixsock, sizeof(nixsock)) == 0)
                return sockd;
            else {
                logg("!Could not connect to clamd on LocalSocket %s: %s\n", opt->strarg, strerror(errno));
                close(sockd);
            }
        }
    }
#endif

    snprintf(port, sizeof(port), "%lld", optget(clamdopts, "TCPSocket")->numarg);

    opt = optget(clamdopts, "TCPAddr");
    while (opt) {
        if (opt->enabled) {
            ipaddr = NULL;
            if (opt->strarg)
                ipaddr = (!strcmp(opt->strarg, "any") ? NULL : opt->strarg);

            memset(&hints, 0x00, sizeof(struct addrinfo));
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;

            if ((res = getaddrinfo(ipaddr, port, &hints, &info))) {
                logg("!Could not lookup %s: %s\n", ipaddr ? ipaddr : "", gai_strerror(res));
                opt = opt->nextarg;
                continue;
            }

            for (p = info; p != NULL; p = p->ai_next) {
                if ((sockd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
                    logg("!Can't create the socket: %s\n", strerror(errno));
                    continue;
                }

                if (connect(sockd, p->ai_addr, p->ai_addrlen) < 0) {
                    logg("!Could not connect to clamd on %s: %s\n", opt->strarg, strerror(errno));
                    closesocket(sockd);
                    continue;
                }

                freeaddrinfo(info);
                return sockd;
            }

            freeaddrinfo(info);
        }
        opt = opt->nextarg;
    }

    return -1;
}

/* Issues an INSTREAM command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int send_stream(int sockd, const char *filename)
{
    uint32_t buf[BUFSIZ / sizeof(uint32_t)];
    int fd, len;
    unsigned long int todo = maxstream;

    if (filename) {
        if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) < 0) {
            logg("~%s: Failed to open file. ERROR\n", filename);
            return 0;
        }
    } else {
        /* Read stream from STDIN */
        fd = 0;
    }

    if (sendln(sockd, "zINSTREAM", 10)) {
        close(fd);
        return -1;
    }

    while ((len = read(fd, &buf[1], sizeof(buf) - sizeof(uint32_t))) > 0) {
        if ((unsigned int)len > todo) len = todo;
        buf[0] = htonl(len);
        if (sendln(sockd, (const char *)buf, len + sizeof(uint32_t))) {
            close(fd);
            return -1;
        }
        todo -= len;
        if (!todo) {
            len = 0;
            break;
        }
    }
    close(fd);
    if (len) {
        logg("!Failed to read from %s.\n", filename ? filename : "STDIN");
        return 0;
    }
    *buf = 0;
    sendln(sockd, (const char *)buf, 4);
    return 1;
}

#ifdef HAVE_FD_PASSING
/* Issues a FILDES command and pass a FD to clamd
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int send_fdpass(int sockd, const char *filename)
{
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[] = "";
    int fd;

    if (filename) {
        if ((fd = open(filename, O_RDONLY)) < 0) {
            logg("~%s: Failed to open file\n", filename);
            return 0;
        }
    } else
        fd = 0;
    if (sendln(sockd, "zFILDES", 8)) {
        close(fd);
        return -1;
    }

    iov[0].iov_base = dummy;
    iov[0].iov_len  = 1;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control         = fdbuf;
    msg.msg_iov             = iov;
    msg.msg_iovlen          = 1;
    msg.msg_controllen      = CMSG_LEN(sizeof(int));
    cmsg                    = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len          = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level        = SOL_SOCKET;
    cmsg->cmsg_type         = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = fd;
    if (sendmsg(sockd, &msg, 0) == -1) {
        logg("!FD send failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 1;
}
#endif

/* 0: scan, 1: skip */
static int chkpath(const char *path)
{
    int status = 0;
    const struct optstruct *opt;
    char *real_path = NULL;

    if (!path) {
        status = 1;
        goto done;
    }

    if ((opt = optget(clamdopts, "ExcludePath"))->enabled) {
        while (opt) {
            if (match_regex(path, opt->strarg) == 1) {
                if (printinfected != 1)
                    logg("~%s: Excluded\n", path);
                status = 1;
                goto done;
            }
            opt = opt->nextarg;
        }
    }

done:
    if (NULL != real_path) {
        free(real_path);
    }
    return status;
}

static int ftw_chkpath(const char *path, struct cli_ftw_cbdata *data)
{
    UNUSEDPARAM(data);
    return chkpath(path);
}

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in non IDSESSION mode
 * Returns the number of infected files or -1 on error
 * NOTE: filename may be NULL for STREAM scantype. */
int dsresult(int sockd, int scantype, const char *filename, int *printok, int *errors)
{
    int infected = 0, len = 0, beenthere = 0;
    char *bol, *eol;
    struct RCVLN rcv;
    STATBUF sb;

    if (filename) {
        if (1 == chkpath(filename)) {
            goto done;
        }
    }

    recvlninit(&rcv, sockd);

    switch (scantype) {
        case MULTI:
        case CONT:
        case ALLMATCH:
            if (!filename) {
                logg("Filename cannot be NULL for MULTISCAN or CONTSCAN.\n");
                infected = -1;
                goto done;
            }
            len = strlen(filename) + strlen(scancmd[scantype]) + 3;
            if (!(bol = malloc(len))) {
                logg("!Cannot allocate a command buffer: %s\n", strerror(errno));
                infected = -1;
                goto done;
            }
            sprintf(bol, "z%s %s", scancmd[scantype], filename);
            if (sendln(sockd, bol, len)) {
                free(bol);
                infected = -1;
                goto done;
            }
            free(bol);
            break;

        case STREAM:
            /* NULL filename safe in send_stream() */
            len = send_stream(sockd, filename);
            break;
#ifdef HAVE_FD_PASSING
        case FILDES:
            /* NULL filename safe in send_fdpass() */
            len = send_fdpass(sockd, filename);
            break;
#endif
    }

    if (len <= 0) {
        *printok = 0;
        if (errors)
            (*errors)++;
        infected = len;
        goto done;
    }

    while ((len = recvln(&rcv, &bol, &eol))) {
        if (len == -1) {
            infected = -1;
            goto done;
        }
        beenthere = 1;
        if (!filename) logg("~%s\n", bol);
        if (len > 7) {
            char *colon = strrchr(bol, ':');
            if (colon && colon[1] != ' ') {
                char *br;
                *colon = 0;
                br     = strrchr(bol, '(');
                if (br)
                    *br = 0;
                colon = strrchr(bol, ':');
            }
            if (!colon) {
                char *unkco = "UNKNOWN COMMAND";
                if (!strncmp(bol, unkco, sizeof(unkco) - 1))
                    logg("clamd replied \"UNKNOWN COMMAND\". Command was %s\n",
                         (scantype < 0 || scantype > MAX_SCANTYPE) ? "unidentified" : scancmd[scantype]);
                else
                    logg("Failed to parse reply: \"%s\"\n", bol);
                infected = -1;
                goto done;
            } else if (!memcmp(eol - 7, " FOUND", 6)) {
                static char last_filename[PATH_MAX + 1] = {'\0'};
                *(eol - 7)                              = 0;
                *printok                                = 0;
                if (scantype != ALLMATCH) {
                    infected++;
                } else {
                    if (filename != NULL && strcmp(filename, last_filename)) {
                        infected++;
                        strncpy(last_filename, filename, PATH_MAX);
                        last_filename[PATH_MAX] = '\0';
                    }
                }
                if (filename) {
                    if (scantype >= STREAM) {
                        logg("~%s%s FOUND\n", filename, colon);
                        if (action) action(filename);
                    } else {
                        logg("~%s FOUND\n", bol);
                        *colon = '\0';
                        if (action)
                            action(bol);
                    }
                }
            } else if (!memcmp(eol - 7, " ERROR", 6)) {
                if (errors)
                    (*errors)++;
                *printok = 0;
                if (filename) {
                    if (scantype >= STREAM)
                        logg("~%s%s\n", filename, colon);
                    else
                        logg("~%s\n", bol);
                }
            }
        }
    }
    if (!beenthere) {
        if (!filename) {
            logg("STDIN: noreply from clamd\n.");
            infected = -1;
            goto done;
        }
        if (CLAMSTAT(filename, &sb) == -1) {
            logg("~%s: stat() failed with %s, clamd may not be responding\n",
                 filename, strerror(errno));
            infected = -1;
            goto done;
        }
        if (!S_ISDIR(sb.st_mode)) {
            logg("~%s: no reply from clamd\n", filename);
            infected = -1;
            goto done;
        }
    }

done:
    return infected;
}

/* Used by serial_callback() */
struct client_serial_data {
    int infected;
    int scantype;
    int printok;
    int files;
    int errors;
};

/* FTW callback for scanning in non IDSESSION mode
 * Returns SUCCESS or BREAK on success, CL_EXXX on error */
static cl_error_t serial_callback(STATBUF *sb, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data)
{
    int status = CL_EOPEN;

    struct client_serial_data *c = (struct client_serial_data *)data->data;
    int sockd, ret;
    const char *f       = filename;
    char *real_filename = NULL;

    UNUSEDPARAM(sb);

    if (reason != visit_directory_toplev) {
        if (CL_SUCCESS != cli_realpath((const char *)path, &real_filename)) {
            logg("*Failed to determine real filename of %s.\n", path);
            logg("*Quarantine of the file may fail if file path contains symlinks.\n");
        } else {
            path = real_filename;
        }
    }

    if (chkpath(path)) {
        /* Exclude the path */
        status = CL_SUCCESS;
        goto done;
    }
    c->files++;
    switch (reason) {
        case error_stat:
            logg("!Can't access file %s\n", path);
            c->errors++;
            status = CL_SUCCESS;
            goto done;
        case error_mem:
            logg("!Memory allocation failed in ftw\n");
            c->errors++;
            status = CL_EMEM;
            goto done;
        case warning_skipped_dir:
            logg("^Directory recursion limit reached\n");
            /* fall-through */
        case warning_skipped_link:
            status = CL_SUCCESS;
            goto done;
        case warning_skipped_special:
            logg("^%s: Not supported file type\n", path);
            c->errors++;
            status = CL_SUCCESS;
            goto done;
        case visit_directory_toplev:
            if (c->scantype >= STREAM) {
                status = CL_SUCCESS;
                goto done;
            }
            f = path;
        case visit_file:
            break;
    }

    if ((sockd = dconnect()) < 0) {
        c->errors++;
        goto done;
    }
    ret = dsresult(sockd, c->scantype, f, &c->printok, &c->errors);
    closesocket(sockd);
    if (ret < 0) {
        c->errors++;
        goto done;
    }
    c->infected += ret;
    if (reason == visit_directory_toplev) {
        status = CL_BREAK;
        goto done;
    }

    status = CL_SUCCESS;
done:
    if (NULL != real_filename) {
        free(real_filename);
    }
    free(filename);
    return status;
}

/* Non-IDSESSION handler
 * Returns non zero for serious errors, zero otherwise */
int serial_client_scan(char *file, int scantype, int *infected, int *err, int maxlevel, int flags)
{
    struct cli_ftw_cbdata data;
    struct client_serial_data cdata;
    int ftw;

    cdata.infected = 0;
    cdata.files    = 0;
    cdata.errors   = 0;
    cdata.printok  = printinfected ^ 1;
    cdata.scantype = scantype;
    data.data      = &cdata;

    ftw = cli_ftw(file, flags, maxlevel ? maxlevel : INT_MAX, serial_callback, &data, ftw_chkpath);
    *infected += cdata.infected;
    *err += cdata.errors;

    if (!cdata.errors && (ftw == CL_SUCCESS || ftw == CL_BREAK)) {
        if (cdata.printok)
            logg("~%s: OK\n", file);
        return 0;
    } else if (!cdata.files) {
        logg("~%s: No files scanned\n", file);
        return 0;
    }
    return 1;
}

/* Used in IDSESSION mode */
struct client_parallel_data {
    int infected;
    int files;
    int errors;
    int scantype;
    int sockd;
    int lastid;
    int printok;
    struct SCANID {
        unsigned int id;
        const char *file;
        struct SCANID *next;
    } * ids;
};

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in IDSESSION mode
 * Returns 0 on success, 1 on hard failures, 2 on len == 0 (bb#1717) */
static int dspresult(struct client_parallel_data *c)
{
    const char *filename;
    char *bol, *eol;
    unsigned int rid;
    int len;
    struct SCANID **id = NULL;
    struct RCVLN rcv;

    recvlninit(&rcv, c->sockd);
    do {
        len = recvln(&rcv, &bol, &eol);
        if (len < 0) return 1;
        if (!len) return 2;
        if ((rid = atoi(bol))) {
            id = &c->ids;
            while (*id) {
                if ((*id)->id == rid) break;
                id = &((*id)->next);
            }
            if (!*id) id = NULL;
        }
        if (!id) {
            logg("!Bogus session id from clamd\n");
            return 1;
        }
        filename = (*id)->file;
        if (len > 7) {
            char *colon = strrchr(bol, ':');
            if (!colon) {
                logg("!Failed to parse reply\n");
                free((void *)filename);
                return 1;
            } else if (!memcmp(eol - 7, " FOUND", 6)) {
                c->infected++;
                c->printok = 0;
                logg("~%s%s\n", filename, colon);
                if (action) action(filename);
            } else if (!memcmp(eol - 7, " ERROR", 6)) {
                c->errors++;
                c->printok = 0;
                logg("~%s%s\n", filename, colon);
            }
        }
        free((void *)filename);
        bol = (char *)*id;
        *id = (*id)->next;
        free(bol);
    } while (rcv.cur != rcv.buf); /* clamd sends whole lines, so, on partial lines, we just assume
				    more data can be recv()'d with close to zero latency */
    return 0;
}

/* FTW callback for scanning in IDSESSION mode
 * Returns SUCCESS on success, CL_EXXX or BREAK on error */
static cl_error_t parallel_callback(STATBUF *sb, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data)
{
    cl_error_t status = CL_EOPEN;

    struct client_parallel_data *c = (struct client_parallel_data *)data->data;
    struct SCANID *cid             = NULL;
    int res                        = CL_CLEAN;

    char *real_filename = NULL;

    UNUSEDPARAM(sb);
    UNUSEDPARAM(path);

    if (reason != visit_directory_toplev) {
        if (CL_SUCCESS != cli_realpath((const char *)filename, &real_filename)) {
            logg("*Failed to determine real filename of %s.\n", filename);
            logg("*Quarantine of the file may fail if file path contains symlinks.\n");
        } else {
            free(filename); /* callback is responsible for free'ing filename parameter. */
            filename = real_filename;
        }
    }

    if (chkpath(filename)) {
        /* Exclude the path */
        status = CL_SUCCESS;
        goto done;
    }
    c->files++;
    switch (reason) {
        case error_stat:
            logg("!Can't access file %s\n", filename);
            c->errors++;
            status = CL_SUCCESS;
            goto done;
        case error_mem:
            logg("!Memory allocation failed in ftw\n");
            c->errors++;
            status = CL_EMEM;
            goto done;
        case warning_skipped_dir:
            logg("^Directory recursion limit reached\n");
            status = CL_SUCCESS;
            goto done;
        case warning_skipped_special:
            logg("^%s: Not supported file type\n", filename);
            c->errors++;
            /* fall-through */
        case warning_skipped_link:
        case visit_directory_toplev:
            status = CL_SUCCESS;
            goto done;
        case visit_file:
            break;
    }

    while (1) {
        /* consume all the available input to let some of the clamd
	     * threads blocked on send() to be dead.
	     * by doing so we shouldn't deadlock on the next recv() */
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_SET(c->sockd, &rfds);
        FD_ZERO(&wfds);
        FD_SET(c->sockd, &wfds);
        if (select(c->sockd + 1, &rfds, &wfds, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            logg("!select() failed during session: %s\n", strerror(errno));
            status = CL_BREAK;
            goto done;
        }
        if (FD_ISSET(c->sockd, &rfds)) {
            if (dspresult(c)) {
                status = CL_BREAK;
                goto done;
            } else
                continue;
        }
        if (FD_ISSET(c->sockd, &wfds)) break;
    }

    switch (c->scantype) {
#ifdef HAVE_FD_PASSING
        case FILDES:
            res = send_fdpass(c->sockd, filename);
            break;
#endif
        case STREAM:
            res = send_stream(c->sockd, filename);
            break;
    }
    if (res <= 0) {
        c->printok = 0;
        c->errors++;
        status = res ? CL_BREAK : CL_SUCCESS;
        goto done;
    }

    cid = (struct SCANID *)malloc(sizeof(struct SCANID));
    if (!cid) {
        logg("!Failed to allocate scanid entry: %s\n", strerror(errno));
        status = CL_BREAK;
        goto done;
    }

    cid->id   = ++c->lastid;
    cid->file = filename;
    cid->next = c->ids;
    c->ids    = cid;

    /* Give up ownership of the filename to the client parralel scan ID list */
    filename = NULL;

    status = CL_SUCCESS;

done:
    if (NULL != filename) {
        free(filename);
    }
    return status;
}

/* IDSESSION handler
 * Returns non zero for serious errors, zero otherwise */
int parallel_client_scan(char *file, int scantype, int *infected, int *err, int maxlevel, int flags)
{
    struct cli_ftw_cbdata data;
    struct client_parallel_data cdata;
    int ftw;

    if ((cdata.sockd = dconnect()) < 0)
        return 1;

    if (sendln(cdata.sockd, "zIDSESSION", 11)) {
        closesocket(cdata.sockd);
        return 1;
    }

    cdata.infected = 0;
    cdata.files    = 0;
    cdata.errors   = 0;
    cdata.scantype = scantype;
    cdata.lastid   = 0;
    cdata.ids      = NULL;
    cdata.printok  = printinfected ^ 1;
    data.data      = &cdata;

    ftw = cli_ftw(file, flags, maxlevel ? maxlevel : INT_MAX, parallel_callback, &data, ftw_chkpath);

    if (ftw != CL_SUCCESS) {
        *err += cdata.errors;
        *infected += cdata.infected;
        closesocket(cdata.sockd);
        return 1;
    }

    sendln(cdata.sockd, "zEND", 5);
    while (cdata.ids && !dspresult(&cdata)) continue;
    closesocket(cdata.sockd);

    *infected += cdata.infected;
    *err += cdata.errors;

    if (cdata.ids) {
        logg("!Clamd closed the connection before scanning all files.\n");
        return 1;
    }
    if (cdata.errors)
        return 1;

    if (!cdata.files)
        return 0;

    if (cdata.printok)
        logg("~%s: OK\n", file);
    return 0;
}
