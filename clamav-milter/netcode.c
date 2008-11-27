/*
 *  Copyright (C)2008 Sourcefire, Inc.
 *
 *  Author: aCaB <acab@clamav.net>
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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/select.h>
#include <time.h>
#include <errno.h>

#include "shared/output.h"
#include "netcode.h"


/* FIXME: for connect and send */
#define TIMEOUT 60
/* for recv */
long readtimeout;


int nc_socket(struct CP_ENTRY *cpe) {
    int flags, s = socket(cpe->server->sa_family, SOCK_STREAM, 0);

    if (s == -1) return -1;
    flags = fcntl(s, F_GETFL, 0);
    if (flags == -1) {
	close(s);
	return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(s, F_SETFL, flags) == -1) {
	close(s);
	return -1;
    }
    return s;
}


int nc_connect(int s, struct CP_ENTRY *cpe) {
    time_t timeout = time(NULL) + TIMEOUT;
    int res = connect(s, cpe->server, cpe->socklen);
    struct timeval tv;

    if (!res) return 0;
    if (errno != EINPROGRESS) {
	close(s);
	return -1;
    }

    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    while(1) {
	fd_set fds;
	int s_err;
	socklen_t s_len = sizeof(s_err);

	FD_ZERO(&fds);
	FD_SET(s, &fds);
	res = select(s+1, NULL, &fds, NULL, &tv);
	if(res < 1) {
	    time_t now;
	    if (res == -1 && errno == EINTR && ((now = time(NULL)) < timeout)) {
		tv.tv_sec = timeout - now;
		tv.tv_usec = 0;
		continue;
	    }
	    close(s);
	    return -1;
	}
	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &s_err, &s_len) || s_err) {
	    logg("!getsockopt failed: %s\n", strerror(s_err));
	    close(s);
	    return -1;
	}
	return 0;
    }
}


int nc_send(int s, const void *buf, size_t len) {
    while(len) {
	int res = send(s, buf, len, 0);
	time_t timeout = time(NULL) + TIMEOUT;
	struct timeval tv;

	if(res!=-1) {
	    len-=res;
	    buf+=res;
	    timeout = time(NULL) + TIMEOUT;
	    continue;
	}
	if(errno != EAGAIN && errno != EWOULDBLOCK) {
	    close(s);
	    return 1;
	}

	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;
	while(1) {
	    fd_set fds;
	    int s_err;
	    socklen_t s_len = sizeof(s_err);

	    FD_ZERO(&fds);
	    FD_SET(s, &fds);
	    res = select(s+1, NULL, &fds, NULL, &tv);
	    if(res < 1) {
		time_t now;
		if (res == -1 && errno == EINTR && ((now = time(NULL)) < timeout)) {
		    tv.tv_sec = timeout - now;
		    tv.tv_usec = 0;
		    continue;
		}
		close(s);
		return 1;
	    }
	    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &s_err, &s_len)) {
		close(s);
		return 1;
	    }
	    len-=s_len;
	    buf+=s_len;
	    break;
	}
    }
    return 0;
}


char *nc_recv(int s) {
    char buf[BUFSIZ], *ret=NULL;
    time_t timeout = time(NULL) + readtimeout;
    struct timeval tv;
    fd_set fds;
    int res;

    tv.tv_sec = readtimeout;
    tv.tv_usec = 0;

    FD_ZERO(&fds);
    FD_SET(s, &fds);
    while(1) {
	res = select(s+1, &fds, NULL, NULL, &tv);
	if(res<1) {
	    time_t now;
	    if (res == -1 && errno == EINTR && ((now = time(NULL)) < timeout)) {
		tv.tv_sec = timeout - now;
		tv.tv_usec = 0;
	    continue;
	    }
	    close(s);
	    return NULL;
	}
	break;
    }
    /* FIXME: check for EOL@EObuf ? */
    res = recv(s, buf, sizeof(buf), 0);
    if (res==-1 || !(ret = (char *)malloc(res+1))) {
	close(s);
	return NULL;
    }
    memcpy(ret, buf, res);
    ret[res]='\0';
    return ret;
}


int nc_connect_entry(struct CP_ENTRY *cpe) {
    int s = nc_socket(cpe);
    if(s==-1) return -1;
    return nc_connect(s, cpe) ? -1 : s;
}


void nc_ping_entry(struct CP_ENTRY *cpe) {
    int s = nc_connect_entry(cpe);
    char *reply;
    if (s!=-1 && !nc_send(s, "nPING\n", 6) && (reply = nc_recv(s))) {
	cpe->dead = strcmp(reply, "PONG\n")!=0;
	free(reply);
	close(s);
    } else cpe->dead = 1;
}


int nc_connect_rand(int *main, int *alt, int *local) {
    struct CP_ENTRY *cpe = cpool_get_rand();

    if(!cpe) return 1;
    *local = cpe->local;
    if ((*main = nc_connect_entry(cpe)) == -1) return 1; /* FIXME : this should be delayed till eom if local */
    if(*local) {
	char tmpn[] = "/tmp/clamav-milter-XXXXXX"; 
	if((*alt = mkstemp(tmpn))==-1) { /* FIXME */
	    logg("!Failed to create temporary file\n");
	    close(*main);
	    return 1;
	}
	unlink(tmpn);
    } else {
	char *reply=NULL, *port;
	int nport;
	struct CP_ENTRY new_cpe;
	union {
	    struct sockaddr_in sa4;
	    struct sockaddr_in6 sa6;
	} sa;

	if(nc_send(*main, "nSTREAM\n", 8) || !(reply = nc_recv(*main)) || !(port = strstr(reply, "PORT"))) {
	    logg("!Failed to communicate with clamd\n");
	    if(reply) free(reply);
	    close(*main);
	    return 1;
	}
	port+=5;
	sscanf(port, "%d", &nport);
	free(reply);
	if(cpe->server->sa_family == AF_INET && cpe->socklen == sizeof(struct sockaddr_in)) {
	    memcpy(&sa, cpe->server, sizeof(struct sockaddr_in));
	    sa.sa4.sin_port = htons(nport);
	    new_cpe.socklen = sizeof(struct sockaddr_in);
	} else if(cpe->server->sa_family == AF_INET6 && cpe->socklen == sizeof(struct sockaddr_in6)) {
	    memcpy(&sa, cpe->server, sizeof(struct sockaddr_in6));
	    sa.sa6.sin6_port = htons(nport);
	    new_cpe.socklen = sizeof(struct sockaddr_in6);
	} else {
	    logg("!WTF WHY AM I DOING HERE???");
	    close(*main);
	    return 1;
	}
	new_cpe.server = (struct sockaddr *)&sa;
	if ((*alt = nc_connect_entry(&new_cpe)) == -1) {
	    logg("!Failed to communicate with clamd for streaming\n");
	    close(*main);
	    return 1;
	}
    }
    return 0;
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * tab-width: 8
 * End: 
 * vim: set cindent smartindent autoindent softtabstop=4 shiftwidth=4 tabstop=8: 
 */
