/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>

#if !defined(_WIN32)
#include <sys/socket.h>
#endif

#include "shared/output.h"
#include "shared/clamdcom.h"

/* Sends bytes over a socket
 * Returns 0 on success */
int sendln(int sockd, const char *line, unsigned int len) {
    while(len) {
	int sent = send(sockd, line, len, 0);
	if(sent <= 0) {
	    if(sent && errno == EINTR) continue;
	    logg("!Can't send to clamd: %s\n", strerror(errno));
	    return 1;
	}
	line += sent;
	len -= sent;
    }
    return 0;
}

/* Inits a RECVLN struct before it can be used in recvln() - see below */
void recvlninit(struct RCVLN *s, int sockd) {
    s->sockd = sockd;
    s->bol = s->cur = s->buf;
    s->r = 0;
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
int recvln(struct RCVLN *s, char **rbol, char **reol) {
    char *eol;

    while(1) {
	if(!s->r) {
	    s->r = recv(s->sockd, s->cur, sizeof(s->buf) - (s->cur - s->buf), 0);
	    if(s->r<=0) {
		if(s->r && errno == EINTR) {
		    s->r = 0;
		    continue;
		}
		if(s->r || s->cur!=s->buf) {
		    *s->cur = '\0';
		    if(strcmp(s->buf, "UNKNOWN COMMAND\n"))
			logg("!Communication error\n");
		    else
			logg("!Command rejected by clamd (wrong clamd version?)\n");
		    return -1;
		}
	        return 0;
	    }
	}
	if((eol = memchr(s->cur, 0, s->r))) {
	    int ret = 0;
	    eol++;
	    s->r -= eol - s->cur;
	    *rbol = s->bol;
	    if(reol) *reol = eol;
	    ret = eol - s->bol;
	    if(s->r)
		s->bol = s->cur = eol;
	    else
		s->bol = s->cur = s->buf;
	    return ret;
	}
	s->r += s->cur - s->bol;
	if(!eol && s->r==sizeof(s->buf)) {
	    logg("!Overlong reply from clamd\n");
	    return -1;
	}
	if(!eol) {
	    if(s->buf != s->bol) { /* old memmove sux */
		memmove(s->buf, s->bol, s->r);
		s->bol = s->buf;
	    }
	    s->cur = &s->bol[s->r];
	    s->r = 0;
	}
    }
}

