/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
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

/* for Solaris, so that both FDPassing and IPV6 work */
#if !defined(__EXTENSIONS__)
#define __EXTENSIONS__
#endif
/* must be first because it may define _XOPEN_SOURCE */
#include "shared/fdpassing.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <sys/uio.h>

#include "libclamav/clamav.h"
#include "shared/output.h"
#include "shared/optparser.h"
#include "libclamav/others.h"
#include "netcode.h"

#define strerror_print(msg) logg(msg": %s\n", cli_strerror(errno, er, sizeof(er)))

enum {
    NON_SMTP,
    INET_HOST,
    INET6_HOST
};

struct LOCALNET {
    struct LOCALNET *next;
    /* most significant first */
    uint32_t basehost[4];
    uint32_t mask[4];
    uint32_t family;
};

struct LOCALNET *lnet = NULL;
char *tempdir = NULL;

/* for connect and send */
#define TIMEOUT 30
/* for recv */
long readtimeout;


static int nc_socket(struct CP_ENTRY *cpe) {
    int flags, s = socket(cpe->server->sa_family, SOCK_STREAM, 0);
    char er[256];

    if (s == -1) {
	strerror_print("!Failed to create socket");
	return -1;
    }
    flags = fcntl(s, F_GETFL, 0);
    if (flags == -1) {
	strerror_print("!fcntl_get failed");
	close(s);
	return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(s, F_SETFL, flags) == -1) {
	strerror_print("!fcntl_set failed");
	close(s);
	return -1;
    }
    return s;
}


static int nc_connect(int s, struct CP_ENTRY *cpe) {
    time_t timeout = time(NULL) + TIMEOUT;
    int res = connect(s, cpe->server, cpe->socklen);
    struct timeval tv;
    char er[256];

    if (!res) return 0;
    if (errno != EINPROGRESS) {
	strerror_print("*connect failed");
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
	    logg("*Failed to establish a connection to clamd\n");
	    close(s);
	    return -1;
	}
	if(getsockopt(s, SOL_SOCKET, SO_ERROR, &s_err, (socklen_t *)&s_len) || s_err) {
	    logg("*Failed to establish a connection to clamd\n");
	    close(s);
	    return -1;
	}
	return 0;
    }
}


int nc_send(int s, const void *buff, size_t len) {
    char *buf = (char *)buff;

    while(len) {
	int res = send(s, buf, len, 0);
	time_t timeout = time(NULL) + TIMEOUT;
	struct timeval tv;
	char er[256];

	if(!res) {
	    logg("!Connection closed while sending data\n");
	    close(s);
	    return 1;
	}
	if(res!=-1) {
	    len-=res;
	    buf+=res;
	    continue;
	}
	if(errno != EAGAIN && errno != EWOULDBLOCK) {
	    strerror_print("!send failed");
	    close(s);
	    return 1;
	}

	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;
	while(1) {
	    fd_set fds;

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
		logg("!Failed to stream to clamd\n");
		close(s);
		return 1;
	    }
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
	strerror_print("!clamfi_eom: FD send failed");
	close(s);
    }
    return ret;
}

char *nc_recv(int s) {
    char buf[128], *ret=NULL;
    time_t now, timeout = time(NULL) + readtimeout;
    struct timeval tv;
    fd_set fds;
    int res;
    unsigned int len = 0;

    while(1) {
	now = time(NULL);
	if(now >= timeout) {
	    logg("!Timed out while reading clamd reply\n");
	    close(s);
	    return NULL;
	}
	tv.tv_sec = timeout - now;
	tv.tv_usec = 0;

	FD_ZERO(&fds);
	FD_SET(s, &fds);

	res = select(s+1, &fds, NULL, NULL, readtimeout ? &tv : NULL);
	if(res<1) {
	    if (res != -1 || errno != EINTR)
		timeout = 0;
	    continue;
	}

	res = recv(s, &buf[len], sizeof(buf) - len, 0);
	if(!res) {
	    logg("!Connection closed while reading from socket\n");
	    close(s);
	    return NULL;
	}
	if(res==-1) {
	    char er[256];
	    if (errno == EAGAIN)
		continue;
	    strerror_print("!recv failed after successful select");
	    close(s);
	    return NULL;
	}
	len += res;
	if(len && buf[len-1] == '\n') break;
	if(len >= sizeof(buf)) {
	    logg("!Overlong reply from clamd\n");
	    close(s);
	    return NULL;
	}
    }
    if(!(ret = (char *)malloc(len+1))) {
	logg("!malloc(%d) failed\n", len+1);
	close(s);
	return NULL;
    }
    memcpy(ret, buf, len);
    ret[len]='\0';
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

    if(s>=0) {
	if(!nc_send(s, "nPING\n", 6) && (reply = nc_recv(s))) {
	    cpe->dead = strcmp(reply, "PONG\n")!=0;
	    free(reply);
	    close(s);
	    return;
	}
	close(s);
    }
    cpe->dead = 1;
}


int nc_connect_rand(int *main, int *alt, int *local) {
    struct CP_ENTRY *cpe = cpool_get_rand(main);

    if(!cpe) return 1;
    *local = (cpe->server->sa_family == AF_UNIX);
    if(*local) {
	char *unlinkme;
	if(cli_gentempfd(tempdir, &unlinkme, alt) != CL_SUCCESS) {
	    logg("!Failed to create temporary file\n");
	    close(*main);
	    return 1;
	}
	unlink(unlinkme);
	free(unlinkme);
	if(nc_send(*main, "nFILDES\n", 8)) {
	    logg("!FD scan request failed\n");
	    close(*alt);
	    close(*main);
	    return 1;
	}
    } else {
	if(nc_send(*main, "nINSTREAM\n", 10)) {
	    logg("!Failed to communicate with clamd\n");
	    close(*main);
	    return 1;
	}
    }
    return 0;
}


static int resolve(char *name, uint32_t *family, uint32_t *host) {
    struct addrinfo hints, *res;

    if(!name) {
	/* 	l->basehost[0] = l->basehost[1] = l->basehost[2] = l->basehost[3] = 0; DONT BOTHER*/
	*family = NON_SMTP;
	return 0;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(name, NULL, &hints, &res)) {
	logg("!Can't resolve LocalNet hostname %s\n", name);
	return 1;
    }
    if(res->ai_addrlen == sizeof(struct sockaddr_in) && res->ai_addr->sa_family == AF_INET) {
	struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;

	*family = INET_HOST;
	host[0] = htonl(sa->sin_addr.s_addr);
	/* 	host[1] = host[2] = host[3] = 0; DONT BOTHER*/
    } else if(res->ai_addrlen == sizeof(struct sockaddr_in6) && res->ai_addr->sa_family == AF_INET6) {
	struct sockaddr_in6 *sa = (struct sockaddr_in6 *)res->ai_addr;
	unsigned int i, j;
	uint32_t u = 0;

	*family = INET6_HOST;
	for(i=0, j=0; i<16; i++) {
	    u += (sa->sin6_addr.s6_addr[i] << (8*j));
	    if(++j == 4) {
		host[i>>2] = u;
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


static struct LOCALNET *localnet(char *name, char *mask) {
    struct LOCALNET *l = (struct LOCALNET *)malloc(sizeof(*l));
    uint32_t nmask;
    unsigned int i;

    if(!l) {
	logg("!Out of memory while resolving LocalNet\n");
	return NULL;
    }

    if(resolve(name, &l->family, l->basehost)) {
	free(l);
	return NULL;
    }

    if(l->family == NON_SMTP) {
	l->mask[0] = l->mask[1] = l->mask[2] = l->mask[3] = 0x0;
	return l;
    }

    if(!mask || !*mask) nmask = 32 + 96*(l->family == INET6_HOST);
    else nmask = atoi(mask);

    if((l->family == INET6_HOST && nmask > 128) || (l->family == INET_HOST && nmask > 32)) {
	logg("!Bad netmask '/%s' for LocalNet %s\n", mask, name);
	free(l);
	return NULL;
    }

    l->mask[0] = l->mask[1] = l->mask[2] = l->mask[3] = 0;
    for(i=0; i<nmask; i++)
	l->mask[i>>5] |= 1<<(31-(i & 31));

    l->basehost[0] &= l->mask[0];
    l->basehost[1] &= l->mask[1];
    l->basehost[2] &= l->mask[2];
    l->basehost[3] &= l->mask[3];

    return l;
}


static int islocalnet(uint32_t family, uint32_t *host) {
    struct LOCALNET* l = lnet;

    if(!l) return 0;
    while(l) {
	if(
	   (l->family == family) &&
	   (l->basehost[0] == (host[0] & l->mask[0])) && (l->basehost[1] == (host[1] & l->mask[1])) &&
	   (l->basehost[2] == (host[2] & l->mask[2])) && (l->basehost[3] == (host[3] & l->mask[3]))
	   ) return 1;
	l=l->next;
    }
    return 0;
}


int islocalnet_name(char *name) {
    uint32_t host[4], family;

    if(!lnet) return 0;
    if(resolve(name, &family, host)) {
	logg("*Cannot resolv %s\n", name);
	return 0;
    }
    return islocalnet(family, host);
}


int islocalnet_sock(struct sockaddr *sa) {
    uint32_t host[4], family;

    if(!lnet) return 0;

    if(sa->sa_family == AF_INET) {
	struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;

	family = INET_HOST;
	host[0] = htonl(sa4->sin_addr.s_addr);
    } else if(sa->sa_family == AF_INET6) {
	struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
	unsigned int i, j;
	uint32_t u = 0;

	family = INET6_HOST;
	for(i=0, j=0; i<16; i++) {
	    u += (sa6->sin6_addr.s6_addr[i] << (8*j));
	    if(++j == 4) {
		host[i>>2] = u;
		j = u = 0;
	    }
	}
    } else return 0;
    return islocalnet(family, host);
}


void localnets_free(void) {
    while(lnet) {
	struct LOCALNET *l = lnet->next;

	free(lnet);
	lnet = l;
    }   
}


int localnets_init(struct optstruct *opts) {
    const struct optstruct *opt;

    if((opt = optget(opts, "LocalNet"))->enabled) {
	while(opt) {
	    char *lnetname = opt->strarg;
	    struct LOCALNET *l;
	    char *mask = strrchr(lnetname, *PATHSEP);

	    if(mask) {
		*mask='\0';
		mask++;
	    }
	    if(!strcasecmp(lnetname, "local")) lnetname = NULL;
	    if((l = localnet(lnetname, mask)) == NULL) {
		localnets_free();
		return 1;
	    }
	    l->next = lnet;
	    lnet = l;
	    opt = opt->nextarg;
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
