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
#include <netdb.h>

#include "shared/output.h"
#include "netcode.h"


/* FIXME: for connect and send */
#define TIMEOUT 60
/* for recv */
long readtimeout;

int nc_socket(struct CP_ENTRY *cpe) {
    int flags, s = socket(cpe->server->sa_family, SOCK_STREAM, 0);
    char er[256];

    if (s == -1) {
	strerror_r(errno, er, sizeof(er));
	logg("!Failed to create socket: %s\n", er);
	return -1;
    }
    flags = fcntl(s, F_GETFL, 0);
    if (flags == -1) {
	strerror_r(errno, er, sizeof(er));
	logg("!fcntl_get failed: %s\n", er);
	close(s);
	return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(s, F_SETFL, flags) == -1) {
	strerror_r(errno, er, sizeof(er));
	logg("!fcntl_set failed: %s\n", er);
	close(s);
	return -1;
    }
    return s;
}


int nc_connect(int s, struct CP_ENTRY *cpe) {
    time_t timeout = time(NULL) + TIMEOUT;
    int res = connect(s, cpe->server, cpe->socklen);
    struct timeval tv;
    char er[256];

    if (!res) return 0;
    if (errno != EINPROGRESS) {
	strerror_r(errno, er, sizeof(er));
	logg("!connect failed: %s\n", er);
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
	    logg("!Failed to establish a connection to clamd\n");
	    close(s);
	    return -1;
	}
	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &s_err, &s_len) || s_err) {
	    logg("!Failed to establish a connection to clamd\n");
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
	char er[256];

	if(res!=-1) {
	    len-=res;
	    buf+=res;
	    timeout = time(NULL) + TIMEOUT;
	    continue;
	}
	if(errno != EAGAIN && errno != EWOULDBLOCK) {
	    strerror_r(errno, er, sizeof(er));
	    logg("!send failed: %s\n", er);
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
		logg("!Failed stream to clamd\n");
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


int nc_sendmsg(int s, int fd) {
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    int ret;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[]="";

    iov[0].iov_base = dummy;
    iov[0].iov_len = 1;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = fdbuf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_controllen = CMSG_LEN(sizeof(int));
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = fd;
    /* FIXME: nonblock code needed (?) */

    if((ret = sendmsg(s, &msg, 0)) == -1) {
	char er[256];
	strerror_r(errno, er, sizeof(er));
	logg("!clamfi_eom: FD send failed (%s)\n", er);
	close(s);
    }
    return ret;
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
	    logg("!Failed to read clamd reply\n");
	    close(s);
	    return NULL;
	}
	break;
    }
    /* FIXME: check for EOL@EObuf ? */
    res = recv(s, buf, sizeof(buf), 0);
    if (res==-1) {
	char er[256];
	strerror_r(errno, er, sizeof(er));
	logg("!recv failed after successful select: %s\n", er);
	close(s);
	return NULL;
    }
    if(!(ret = (char *)malloc(res+1))) {
	logg("!malloc(%d) failed\n", res+1);
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
    } else cpe->dead = 1;
    return;
}


int nc_connect_rand(int *main, int *alt, int *local) {
    struct CP_ENTRY *cpe = cpool_get_rand(main);

    if(!cpe) return 1;
    *local = (cpe->server->sa_family == AF_UNIX);
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
	    if(reply) {
		free(reply);
		close(*main);
	    }
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
	    logg("!WTF WHY AM I DOING HERE???\n");
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



enum {
    NON_SMTP,
    INET_HOST,
    INET6_HOST
};

int resolve(char *name, uint32_t *family, uint32_t *host) {
    struct addrinfo hints, *res;

    if(!strcasecmp("local", name)) {
	*family = NON_SMTP;
	return 0;
    }

    memset(&hints, 0, sizeof(hints));
#ifdef SUPPORT_IPv6
    hints.ai_family = AF_UNSPEC;
#else
    hints.ai_family = AF_INET;
#endif
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(name, NULL, &hints, &res)) {
	logg("!Can't resolve LocalNet hostname %s\n", name);
	return 1;
    }
    if(res->ai_addrlen == sizeof(struct sockaddr_in) && res->ai_addr->sa_family == AF_INET) {
	struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;

	*family = INET_HOST;
	host[0] = htonl(sa->sin_addr.s_addr);
	host[1] = host[2] = host[3] = 0;
    } else if(res->ai_addrlen == sizeof(struct sockaddr_in6) && res->ai_addr->sa_family == AF_INET6) {
	struct sockaddr_in6 *sa = (struct sockaddr_in6 *)res->ai_addr;
	unsigned int i, j;
	uint32_t u = 0;

	*family = INET6_HOST;
	for(i=0, j=0; i<16; i++) {
	    u += (sa->sin6_addr.s6_addr[i] << (8*j));
	    if(++j == 4) {
		host[3-(i>>2)] = u;
		j = u = 0;
	    }
	}
    } else {
	logg("!Unsupported address type for LocalNet %s\n", name);
	freeaddrinfo(res);
	return 1;
    }
    freeaddrinfo(res);
    return 0;
}


struct LOCALNET {
    struct LOCALNET *next;
    uint32_t basehost[4];
    uint32_t mask[4];
    uint32_t family;
};


void applymask(uint32_t *host, uint32_t *mask) {
    host[0] &= mask[0];
    host[1] &= mask[1];
    host[2] &= mask[2];
    host[3] &= mask[3];
}


struct LOCALNET* localnet(char *name, char *mask) {
    struct LOCALNET *l = (struct LOCALNET *)malloc(sizeof(*l));
    uint32_t nmask;
    unsigned int i;

    if(!l) {
	logg("!Out of memory while resolving LocalNet\n");
	return NULL;
    }

    l->next = NULL;
    if(resolve(name, &l->family, l->basehost)) {
	free(l);
	return NULL;
    }

    if(l->family == NON_SMTP) {
	l->mask[0] = l->mask[1] = l->mask[2] = l->mask[3] = 0;
	l->basehost[0] = l->basehost[1] = l->basehost[2] = l->basehost[3] = 0;
	return l;
    }
    if(!*mask) nmask = 32;
    else nmask = atoi(mask);

    if((l->family == INET6_HOST && nmask > 128) || (l->family == INET_HOST && nmask > 32)) {
	logg("!Bad netmask '/%s' for LocalNet %s\n", mask, name);
	free(l);
	return NULL;
    }
    l->mask[0] = l->mask[1] = l->mask[2] = l->mask[3] = 0;
    for(i=0; i<nmask; i++)
	l->mask[i>>5] |= 1<<(i&0x1f);
    applymask(l->basehost, l->mask);
    return l;
}


int belongto(struct LOCALNET* l, char *name) {
    uint32_t host[4], family;

    if(resolve(name, &family, host)) {
	logg("^Cannot resolv %s\n", name);
	return 0;
    }
    while(l) {
	if (
	    (l->family == family) &&
	    (l->basehost[0] == (host[0] & l->mask[0])) && (l->basehost[1] == (host[1] & l->mask[1])) &&
	    (l->basehost[2] == (host[2] & l->mask[2])) && (l->basehost[3] == (host[3] & l->mask[3]))
	    ) return 1;
	l=l->next;
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
