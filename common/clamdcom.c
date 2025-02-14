/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Author: aCaB
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
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#endif

#include "clamav.h"
#include "actions.h"
#include "output.h"
#include "clamdcom.h"

#ifndef _WIN32
struct sockaddr_un nixsock;
#endif

static const char *scancmd[] = {"CONTSCAN", "MULTISCAN", "INSTREAM", "FILDES", "ALLMATCHSCAN"};

/* Sends bytes over a socket
 * Returns 0 on success */
int sendln(int sockd, const char *line, unsigned int len)
{
    while (len) {
        int sent = send(sockd, line, len, 0);
        if (sent <= 0) {
            if (sent && errno == EINTR) continue;
            logg(LOGG_ERROR, "Can't send to clamd: %s\n", strerror(errno));
            return 1;
        }
        line += sent;
        len -= sent;
    }
    return 0;
}

/* Inits a RECVLN struct before it can be used in recvln() - see below */
void recvlninit(struct RCVLN *s, int sockd)
{
    s->sockd = sockd;
    s->bol = s->cur = s->buf;
    s->r            = 0;
}

/* Receives a full (terminated with \0) line from a socket
 * Sets rbol to the begin of the received line, and optionally
 * reol to the end of line.
 * Should be called repeatedly until all input is consumed
 * Returns:
 * - the length of the line (a positive number) on success
 * - 0 if the connection is closed
 * - -1 on error
 */
int recvln(struct RCVLN *s, char **rbol, char **reol)
{
    char *eol;

    while (1) {
        if (!s->r) {
            s->r = recv(s->sockd, s->cur, sizeof(s->buf) - (s->cur - s->buf), 0);
            if (s->r <= 0) {
                if (s->r && errno == EINTR) {
                    s->r = 0;
                    continue;
                }
                if (s->r || s->cur != s->buf) {
                    *s->cur = '\0';
                    if (strcmp(s->buf, "UNKNOWN COMMAND\n"))
                        logg(LOGG_ERROR, "Communication error\n");
                    else
                        logg(LOGG_ERROR, "Command rejected by clamd (wrong clamd version?)\n");
                    return -1;
                }
                return 0;
            }
        }
        if ((eol = memchr(s->cur, 0, s->r))) {
            int ret = 0;
            eol++;
            s->r -= eol - s->cur;
            *rbol = s->bol;
            if (reol) *reol = eol;
            ret = eol - s->bol;
            if (s->r)
                s->bol = s->cur = eol;
            else
                s->bol = s->cur = s->buf;
            return ret;
        }
        s->r += s->cur - s->bol;
        if (!eol && s->r == sizeof(s->buf)) {
            logg(LOGG_ERROR, "Overlong reply from clamd\n");
            return -1;
        }
        if (!eol) {
            if (s->buf != s->bol) { /* old memmove sux */
                memmove(s->buf, s->bol, s->r);
                s->bol = s->buf;
            }
            s->cur = &s->bol[s->r];
            s->r   = 0;
        }
    }
}

/* Determines if a path should be excluded
 * 0: scan, 1: skip */
int chkpath(const char *path, struct optstruct *clamdopts)
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
                logg(LOGG_DEBUG, "%s: Excluded\n", path);
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

#ifdef HAVE_FD_PASSING
/* Issues a FILDES command and pass a FD to clamd
 * Returns >0 on success, 0 soft fail, -1 hard fail */
int send_fdpass(int sockd, const char *filename)
{
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[] = "";
    int fd;
    const char zFILDES[] = "zFILDES";

    if (filename) {
        if ((fd = open(filename, O_RDONLY)) < 0) {
            logg(LOGG_INFO, "%s: Failed to open file\n", filename);
            return 0;
        }
    } else
        fd = 0;
    if (sendln(sockd, zFILDES, sizeof(zFILDES))) {
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
        logg(LOGG_ERROR, "FD send failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 1;
}
#endif

/* Issues an INSTREAM command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
int send_stream(int sockd, const char *filename, struct optstruct *clamdopts)
{
    uint32_t buf[BUFSIZ / sizeof(uint32_t)];
    int fd, len;
    unsigned long int todo = optget(clamdopts, "StreamMaxLength")->numarg;
    const char zINSTREAM[] = "zINSTREAM";

    if (filename) {
        if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) < 0) {
            logg(LOGG_INFO, "%s: Failed to open file. ERROR\n", filename);
            return 0;
        }
    } else {
        /* Read stream from STDIN */
        fd = 0;
    }

    if (sendln(sockd, zINSTREAM, sizeof(zINSTREAM))) {
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
        logg(LOGG_ERROR, "Failed to read from %s.\n", filename ? filename : "STDIN");
        return 0;
    }
    *buf = 0;
    sendln(sockd, (const char *)buf, 4);
    return 1;
}

/* Connects to clamd
 * Returns a FD or -1 on error */
int dconnect(struct optstruct *clamdopts)
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
                logg(LOGG_ERROR, "Could not connect to clamd on LocalSocket %s: %s\n", opt->strarg, strerror(errno));
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
                logg(LOGG_ERROR, "Could not lookup %s: %s\n", ipaddr ? ipaddr : "", gai_strerror(res));
                opt = opt->nextarg;
                continue;
            }

            for (p = info; p != NULL; p = p->ai_next) {
                if ((sockd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
                    logg(LOGG_ERROR, "Can't create the socket: %s\n", strerror(errno));
                    continue;
                }

                if (connect(sockd, p->ai_addr, p->ai_addrlen) < 0) {
                    logg(LOGG_ERROR, "Could not connect to clamd on %s: %s\n", opt->strarg, strerror(errno));
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

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in non IDSESSION mode
 * Returns the number of infected files or -1 on error
 * NOTE: filename may be NULL for STREAM scantype. */
int dsresult(int sockd, int scantype, const char *filename, int *printok, int *errors, struct optstruct *clamdopts)
{
    int infected = 0, len = 0, beenthere = 0;
    char *bol, *eol;
    struct RCVLN rcv;
    STATBUF sb;

    if (filename) {
        if (1 == chkpath(filename, clamdopts)) {
            goto done;
        }
    }

    recvlninit(&rcv, sockd);

    switch (scantype) {
        case MULTI:
        case CONT:
        case ALLMATCH:
            if (!filename) {
                logg(LOGG_INFO, "Filename cannot be NULL for MULTISCAN or CONTSCAN.\n");
                infected = -1;
                goto done;
            }
            len = strlen(filename) + strlen(scancmd[scantype]) + 3;
            if (!(bol = malloc(len))) {
                logg(LOGG_ERROR, "Cannot allocate a command buffer: %s\n", strerror(errno));
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
            len = send_stream(sockd, filename, clamdopts);
            break;
#ifdef HAVE_FD_PASSING
        case FILDES:
            /* NULL filename safe in send_fdpass() */
            len = send_fdpass(sockd, filename);
            break;
#endif
    }

    if (len <= 0) {
        if (printok)
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
        if (!filename) logg(LOGG_INFO, "%s\n", bol);
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
                    logg(LOGG_INFO, "clamd replied \"UNKNOWN COMMAND\". Command was %s\n",
                         (scantype < 0 || scantype > MAX_SCANTYPE) ? "unidentified" : scancmd[scantype]);
                else
                    logg(LOGG_INFO, "Failed to parse reply: \"%s\"\n", bol);
                infected = -1;
                goto done;
            } else if (!memcmp(eol - 7, " FOUND", 6)) {
                static char last_filename[PATH_MAX + 1] = {'\0'};
                *(eol - 7)                              = 0;
                if (printok)
                    *printok = 0;
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
                        logg(LOGG_INFO, "%s%s FOUND\n", filename, colon);
                        if (action) action(filename);
                    } else {
                        logg(LOGG_INFO, "%s FOUND\n", bol);
                        *colon = '\0';
                        if (action)
                            action(bol);
                    }
                }
            } else if (!memcmp(eol - 7, " ERROR", 6)) {
                if (errors)
                    (*errors)++;
                if (printok)
                    *printok = 0;
                if (filename) {
                    if (scantype >= STREAM)
                        logg(LOGG_INFO, "%s%s\n", filename, colon);
                    else
                        logg(LOGG_INFO, "%s\n", bol);
                }
            }
        }
    }
    if (!beenthere) {
        if (!filename) {
            logg(LOGG_INFO, "STDIN: noreply from clamd\n.");
            infected = -1;
            goto done;
        }
        if (CLAMSTAT(filename, &sb) == -1) {
            logg(LOGG_INFO, "%s: stat() failed with %s, clamd may not be responding\n",
                 filename, strerror(errno));
            infected = -1;
            goto done;
        }
        if (!S_ISDIR(sb.st_mode)) {
            logg(LOGG_INFO, "%s: no reply from clamd\n", filename);
            infected = -1;
            goto done;
        }
    }

done:
    return infected;
}
