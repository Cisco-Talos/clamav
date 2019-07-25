/*
 *  Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include "shared/fdpassing.h"
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

#include "libclamav/clamav.h"
#include "shared/actions.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "communication.h"
#include "protocol.h"
#include "client.h"

static const char *scancmd[] = {"CONTSCAN", "MULTISCAN", "INSTREAM", "FILDES", "ALLMATCHSCAN"};

/* Issues an INSTREAM command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int onas_send_stream(CURL *curl, const char *filename, int fd, int64_t timeout, uint64_t maxstream)
{
    uint32_t buf[BUFSIZ / sizeof(uint32_t)];
    uint64_t len;
    uint64_t todo  = maxstream;
    int ret        = 1;
    int close_flag = 0;

    if (0 == fd) {
        if (filename) {
            if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) < 0) {
                logg("~%s: Access denied. ERROR\n", filename);
                return 0;
            }
            //logg("DEBUG: >>>>> fd is %d\n", fd);
            close_flag = 1;
        } else {
            fd = 0;
        }
    }

    if (onas_sendln(curl, "zINSTREAM", 10, timeout)) {
        ret = -1;
        goto strm_out;
    }

    while ((len = read(fd, &buf[1], sizeof(buf) - sizeof(uint32_t))) > 0) {
        if ((uint64_t)len > todo) len = todo;
        buf[0] = htonl(len);
        if (onas_sendln(curl, (const char *)buf, len + sizeof(uint32_t), timeout)) {
            ret = -1;
            goto strm_out;
        }
        todo -= len;
        if (!todo) {
            len = 0;
            break;
        }
    }

    if (len) {
        logg("!Failed to read from %s.\n", filename ? filename : "STDIN");
        ret = 0;
        goto strm_out;
    }
    *buf = 0;
    onas_sendln(curl, (const char *)buf, 4, timeout);

strm_out:
    if (close_flag) {
        //logg("DEBUG: >>>>> closed fd %d\n", fd);
        close(fd);
    }
    return ret;
}

#ifdef HAVE_FD_PASSING
/* Issues a FILDES command and pass a FD to clamd
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int onas_send_fdpass(CURL *curl, const char *filename, int fd, int64_t timeout)
{
    CURLcode result;
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[]   = "";
    int ret        = 1;
    int close_flag = 0;

    if (0 == fd) {
        if (filename) {
            if ((fd = open(filename, O_RDONLY)) < 0) {
                logg("~%s: Access denied. ERROR\n", filename);
                return 0;
            }
            close_flag = 1;
        } else {
            fd = 0;
        }
    }
    if (result = onas_sendln(curl, "zFILDES", 8, timeout)) {
        logg("*ClamProto: error sending w/ curl, %s\n", curl_easy_strerror(result));
        ret = -1;
        goto fd_out;
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
    if (onas_sendln(curl, &msg, 0, timeout) == -1) {
        logg("!FD send failed: %s\n", strerror(errno));
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
    struct RCVLN rcv;
    STATBUF sb;

    onas_recvlninit(&rcv, curl);

    if (ret_code) {
        *ret_code = CL_SUCCESS;
    }

    switch (scantype) {
        case MULTI:
        case CONT:
        case ALLMATCH:
            if (!filename) {
                logg("Filename cannot be NULL for MULTISCAN or CONTSCAN.\n");
                if (ret_code) {
                    *ret_code = CL_ENULLARG;
                }
                return -1;
            }
            len = strlen(filename) + strlen(scancmd[scantype]) + 3;
            if (!(bol = malloc(len))) {
                logg("!Cannot allocate a command buffer: %s\n", strerror(errno));
                if (ret_code) {
                    *ret_code = CL_EMEM;
                }
                return -1;
            }
            sprintf(bol, "z%s %s", scancmd[scantype], filename);
            if (onas_sendln(curl, bol, len, timeout)) {
                if (ret_code) {
                    *ret_code = CL_EWRITE;
                }
                free(bol);
                return -1;
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
            len = onas_send_fdpass(curl, filename, fd, timeout);
            break;
#endif
    }

    if (len <= 0) {
        *printok = 0;
        if (errors)
            (*errors)++;
        return len;
    }

    while ((len = onas_recvln(&rcv, &bol, &eol, timeout))) {
        if (len == -1) {
            if (ret_code) {
                *ret_code = CL_EREAD;
            }
            return -1;
        }
        beenthere = 1;
        if (!filename) {
            logg("~%s\n", bol);
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
                    logg("*clamd replied \"UNKNOWN COMMAND\". Command was %s\n",
                         (scantype < 0 || scantype > MAX_SCANTYPE) ? "unidentified" : scancmd[scantype]);
                } else {
                    logg("*Failed to parse reply: \"%s\"\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_EPARSE;
                }
                return -1;

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
                        if (action) {
                            action(filename);
                        }
                    } else {
                        logg("~%s FOUND\n", bol);
                        *colon = '\0';
                        if (action) {
                            action(bol);
                        }
                    }
                }

                if (ret_code) {
                    *ret_code = CL_VIRUS;
                }

            } else if (len > 49 && !memcmp(eol - 50, " lstat() failed: No such file or directory. ERROR", 49)) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (filename) {
                    (scantype >= STREAM) ? logg("*%s%s\n", filename, colon) : logg("*%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_ESTAT;
                }
            } else if (len > 41 && !memcmp(eol - 42, " lstat() failed: Permission denied. ERROR", 41)) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (filename) {
                    (scantype >= STREAM) ? logg("*%s%s\n", filename, colon) : logg("*%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_ESTAT;
                }
            } else if (len > 21 && !memcmp(eol - 22, " Access denied. ERROR", 21)) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (filename) {
                    (scantype >= STREAM) ? logg("*%s%s\n", filename, colon) : logg("*%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_EACCES;
                }
            } else if (!memcmp(eol - 7, " ERROR", 6)) {
                if (errors) {
                    (*errors)++;
                }
                *printok = 0;

                if (filename) {
                    (scantype >= STREAM) ? logg("~%s%s\n", filename, colon) : logg("~%s\n", bol);
                }

                if (ret_code) {
                    *ret_code = CL_ESTATE;
                }
            }
        }
    }
    if (!beenthere) {
        if (!filename) {
            logg("STDIN: noreply from clamd\n.");
            if (ret_code) {
                *ret_code = CL_EACCES;
            }
            return -1;
        }
        if (CLAMSTAT(filename, &sb) == -1) {
            logg("~%s: stat() failed with %s, clamd may not be responding\n",
                 filename, strerror(errno));
            if (ret_code) {
                *ret_code = CL_EACCES;
            }
            return -1;
        }
        if (!S_ISDIR(sb.st_mode)) {
            logg("~%s: no reply from clamd\n", filename);
            if (ret_code) {
                *ret_code = CL_EACCES;
            }
            return -1;
        }
    }
    return infected;
}
