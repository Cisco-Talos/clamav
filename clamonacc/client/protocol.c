/*
 *  Copyright (C) 2015-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB, Mickey Sola
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
#include <curl/curl.h>
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

// common
#include "actions.h"
#include "output.h"
#include "misc.h"
#include "clamdcom.h"

#include "communication.h"
#include "protocol.h"
#include "client.h"
#include "socket.h"

static const char *scancmd[] = {"CONTSCAN", "MULTISCAN", "INSTREAM", "FILDES", "ALLMATCHSCAN"};

/* Issues an INSTREAM command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int onas_send_stream(CURL *curl, const char *filename, int fd, int64_t timeout, uint64_t maxstream)
{
    uint32_t buf[BUFSIZ / sizeof(uint32_t)];
    uint64_t len;
    int ret        = 1;
    int close_flag = 0;
    STATBUF statbuf;
    uint64_t bytesRead     = 0;
    const char zINSTREAM[] = "zINSTREAM";

    if (-1 == fd) {
        if (NULL == filename) {
            logg(LOGG_ERROR, "onas_send_stream: Invalid args, a filename or file descriptor must be provided.\n");
            return 0;
        } else {
            if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) < 0) {
                logg(LOGG_DEBUG, "%s: Failed to open file. ERROR\n", filename);
                return 0;
            }
            // logg(LOGG_INFO, "DEBUG: >>>>> fd is %d\n", fd);
            close_flag = 1;
        }
    }

    if (FSTAT(fd, &statbuf)) {
        logg(LOGG_ERROR, "onas_send_stream: Invalid args, bad file descriptor.\n");
        ret = -1;
        goto strm_out;
    }

    if (S_ISDIR(statbuf.st_mode)) {
        ret = 0;
        goto strm_out;
    }

    if ((uint64_t)statbuf.st_size > maxstream) {
        ret = 0;
        goto strm_out;
    }

    if (onas_sendln(curl, zINSTREAM, sizeof(zINSTREAM), timeout)) {
        ret = -1;
        goto strm_out;
    }

    len    = statbuf.st_size;
    buf[0] = htonl(len);
    if (onas_sendln(curl, (const char *)buf, sizeof(uint32_t), timeout)) {
        ret = -1;
        goto strm_out;
    }

    while (bytesRead < len) {
        ssize_t ret = read(fd, buf, sizeof(buf));
        if (ret < 0) {
            logg(LOGG_ERROR, "Failed to read from %s.\n", filename ? filename : "FD");
            ret = -1;
            goto strm_out;
        } else if (0 == ret) {
            break;
        }
        bytesRead += ret;

        if (onas_sendln(curl, (const char *)buf, ret, timeout)) {
            ret = -1;
            goto strm_out;
        }
    }

    *buf = 0;
    onas_sendln(curl, (const char *)buf, 4, timeout);

strm_out:
    if (close_flag) {
        close(fd);
    }
    return ret;
}

#ifdef HAVE_FD_PASSING
static int onas_send_fdpass(int sockd, int fd)
{

    char dummy[] = "";
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    const char zFILDES[] = "zFILDES";

    if (sendln(sockd, zFILDES, sizeof(zFILDES))) {
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
        return -1;
    }

    return 1;
}

/* Issues a FILDES command and pass a FD to clamd
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int onas_fdpass(const char *filename, int fd, int sockd)
{
    int ret        = 1;
    int close_flag = 0;

    if (-1 == fd) {
        if (filename) {
            if ((fd = open(filename, O_RDONLY)) < 0) {
                logg(LOGG_DEBUG, "%s: Failed to open file. ERROR\n", filename);
                return 0;
            }
            close_flag = 1;
        } else {
            fd = -1;
        }
    }

    if (sockd == -1) {
        logg(LOGG_DEBUG, "ClamProto: error when getting socket descriptor\n");
        ret = -1;
        goto fd_out;
    }

    ret = onas_send_fdpass(sockd, fd);

    if (ret < 0) {
        logg(LOGG_DEBUG, "ClamProto: error when fdpassing\n");
        ret = -1;
        goto fd_out;
    }

fd_out:
    if (close_flag) {
        close(fd);
    }
    return ret;
}
#endif

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in non IDSESSION mode
 * Returns the number of infected files or -1 on error
 * NOTE: filename may be NULL for STREAM scantype. */
int onas_dsresult(CURL *curl, int scantype, uint64_t maxstream, const char *filename, int fd, int64_t timeout, int *printok, int *errors, cl_error_t *ret_code)
{
    int infected = 0, len = 0, beenthere = 0;
    char *bol, *eol;
    struct onas_rcvln rcv;
    STATBUF sb;
    int sockd                                                        = -1;
    int (*recv_func)(struct onas_rcvln *, char **, char **, int64_t) = NULL;

    sockd = onas_get_sockd();

    onas_recvlninit(&rcv, curl, sockd);
    if (rcv.sockd > 0) {
        recv_func = &onas_fd_recvln;
    } else {
        recv_func = &onas_recvln;
    }

    switch (scantype) {
        case MULTI:
        case CONT:
        case ALLMATCH:
            if (!filename) {
                logg(LOGG_INFO, "Filename cannot be NULL for MULTISCAN or CONTSCAN.\n");
                if (ret_code) {
                    *ret_code = CL_ENULLARG;
                }
                infected = -1;
                goto done;
            }
            len = strlen(filename) + strlen(scancmd[scantype]) + 3;
            if (!(bol = malloc(len))) {
                logg(LOGG_ERROR, "Cannot allocate a command buffer: %s\n", strerror(errno));
                if (ret_code) {
                    *ret_code = CL_EMEM;
                }
                infected = -1;
                goto done;
            }
            sprintf(bol, "z%s %s", scancmd[scantype], filename);
            if (onas_sendln(curl, bol, len, timeout)) {
                if (ret_code) {
                    *ret_code = CL_EWRITE;
                }
                free(bol);
                infected = -1;
                goto done;
            }
            free(bol);
            break;

        case STREAM:
            /* NULL filename safe in send_stream() */
            len = onas_send_stream(curl, filename, fd, timeout, maxstream);
            break;
#ifdef HAVE_FD_PASSING
        case FILDES:
            /* NULL filename safe in send_fdpass() */
            len = onas_fdpass(filename, fd, sockd);
            break;
#endif
    }

    if (len <= 0) {
        *printok = 0;
        if (errors && len < 0) {
            /* Ignore error if len == 0 to reduce verbosity from file open()
               "errors" where the file has been deleted before we have a chance
               to scan it. */
            (*errors)++;
        }
        infected = len;
        goto done;
    }

    while ((len = (*recv_func)(&rcv, &bol, &eol, timeout))) {

        if (len == -1) {

            if (ret_code) {
                *ret_code = CL_EREAD;
            }
            infected = -1;
            goto done;
        }
        beenthere = 1;
        if (!filename) {
            logg(LOGG_INFO, "%s\n", bol);
        }
        if (len > 7) {
            char *colon = strrchr(bol, ':');

            if (colon && colon[1] != ' ') {
                char *br;
                *colon = 0;

                br = strrchr(bol, '(');
                if (br) {
                    *br = 0;
                }
                colon = strrchr(bol, ':');
            }

            if (!colon) {
                char *unkco = "UNKNOWN COMMAND";
                if (!strncmp(bol, unkco, sizeof(unkco) - 1)) {
                    logg(LOGG_DEBUG, "clamd replied \"UNKNOWN COMMAND\". Command was %s\n",
                         (scantype < 0 || scantype > MAX_SCANTYPE) ? "unidentified" : scancmd[scantype]);
                } else {
                    logg(LOGG_DEBUG, "Failed to parse reply: \"%s\"\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_EPARSE;
                }
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
                        logg(LOGG_INFO, "%s%s FOUND\n", filename, colon);
                        if (action) {
                            action(filename);
                        }
                    } else {
                        logg(LOGG_INFO, "%s FOUND\n", bol);
                        *colon = '\0';
                        if (action) {
                            action(bol);
                        }
                    }
                }

                if (ret_code) {
                    *ret_code = CL_VIRUS;
                }

            } else if ((len > 32 && !memcmp(eol - 33, "No such file or directory. ERROR", 32)) ||
                       (len > 34 && !memcmp(eol - 35, "Can't open file or directory ERROR", 34))) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (filename) {
                    (scantype >= STREAM) ? logg(LOGG_DEBUG, "%s%s\n", filename, colon) : logg(LOGG_DEBUG, "%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_ESTAT;
                }
            } else if ((len > 21 && !memcmp(eol - 22, " Access denied. ERROR", 21)) ||
                       (len > 23 && !memcmp(eol - 24, "Can't access file ERROR", 23)) ||
                       (len > 41 && !memcmp(eol - 42, " lstat() failed: Permission denied. ERROR", 41))) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (filename) {
                    (scantype >= STREAM) ? logg(LOGG_INFO, "%s%s\n", filename, colon) : logg(LOGG_INFO, "%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_EACCES;
                }
            } else if (len > 6 && !memcmp(eol - 7, " ERROR", 6)) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (filename) {
                    (scantype >= STREAM) ? logg(LOGG_INFO, "%s%s\n", filename, colon) : logg(LOGG_INFO, "%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_ERROR;
                }
            }
        }
    }
    if (!beenthere) {
        if (!filename) {
            logg(LOGG_INFO, "STDIN: noreply from clamd\n.");
            if (ret_code) {
                *ret_code = CL_EACCES;
            }
            infected = -1;
            goto done;
        }
        if (CLAMSTAT(filename, &sb) == -1) {
            logg(LOGG_INFO, "%s: stat() failed with %s, clamd may not be responding\n",
                 filename, strerror(errno));
            if (ret_code) {
                *ret_code = CL_EACCES;
            }
            infected = -1;
            goto done;
        }
        if (!S_ISDIR(sb.st_mode)) {
            logg(LOGG_INFO, "%s: no reply from clamd\n", filename);
            if (ret_code) {
                *ret_code = CL_EACCES;
            }
            infected = -1;
            goto done;
        }
    }

done:
    if (sockd > 0) {
        closesocket(sockd);
    }
    return infected;
}
