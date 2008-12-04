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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>

#include "shared/cfgparser.h"
#include "shared/output.h"

#include "connpool.h"
#include "netcode.h"

#ifdef HAVE_GETADDRINFO
#define SETGAI(k, v) {(k)->gai = (void *)(v);} while(0)
#define FREESRV(k) { if((k).gai) freeaddrinfo((k).gai); else if((k).server) free((k).server); } while(0)
#else
#include <netdb.h>
#define SETGAI
#define FREESRV(k) { if ((k).server) free((k).server); } while(0)
#endif

struct CPOOL *cp = NULL;

static int cpool_addunix(char *path) {
    struct sockaddr_un *srv;
    struct CP_ENTRY *cpe = &cp->pool[cp->entries-1];

    if(strlen(path)<2 || *path!='/') {
	logg("!Unix clamd socket must be an absolute path\n");
	return 1;
    }
    if(!(srv = (struct sockaddr_un *)malloc(sizeof(*srv)))) {
	logg("!Out of memory allocating unix socket space\n");
	return 1;
    }

    srv->sun_family = AF_UNIX;
    strncpy(srv->sun_path, path, sizeof(srv->sun_path));
    srv->sun_path[sizeof(srv->sun_path)-1]='\0';
    cpe->type = 0;
    cpe->dead = 1;
    cpe->local = 1;
    cpe->last_poll = 0;
    cpe->server = (struct sockaddr *)srv;
    cpe->socklen = sizeof(*srv);
    SETGAI(cpe, NULL);
    if(!cp->local_cpe) cp->local_cpe = cpe;
    logg("*Local socket unix:%s added to the pool (slot %d)\n", srv->sun_path, cp->entries);
    return 0;
}


static int islocal(struct sockaddr *sa, socklen_t addrlen) {
    int s = socket(sa->sa_family, SOCK_STREAM, 0);
    int ret;
    if (!s) return 0;
    ret = (bind(s, sa, addrlen) == 0);
    close(s);
    return ret;
}


#ifdef HAVE_GETADDRINFO
static int cpool_addtcp(char *addr, char *port) {
    struct addrinfo hints, *res, *res2;;
    struct CP_ENTRY *cpe = (struct CP_ENTRY *)&cp->pool[cp->entries-1];

    memset(&hints, 0, sizeof(hints));
#ifdef SUPPORT_IPv6
    hints.ai_family = AF_UNSPEC;
#else
    hints.ai_family = AF_INET;
#endif
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(addr, port ? port : "3310", &hints, &res)) {
	logg("^Can't resolve hostname %s\n", addr ? addr : "");
	return 1;
    }
    cpe->type = 1;
    cpe->dead = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
#ifdef SUPPORT_IPv6
    hints.ai_family = AF_UNSPEC;
#else
    hints.ai_family = AF_INET;
#endif
    if(!getaddrinfo(addr, NULL, &hints, &res2)) {
	cpe->local = islocal(res2->ai_addr, res2->ai_addrlen);
	freeaddrinfo(res2);
    } else cpe->local = 0;
    cpe->last_poll = 0;
    cpe->server = res->ai_addr;
    cpe->socklen = res->ai_addrlen;
    SETGAI(cpe, res);
    logg("*%s socket tcp:%s:%s added to the pool (slot %d)\n", cpe->local ? "Local" : "Remote", addr ? addr : "localhost", port ? port : "3310", cp->entries);
    return 0;
}
#else
static int cpool_addtcp(char *addr, char *port) {
    struct sockaddr_in *srv;
    struct CP_ENTRY *cpe = (struct CP_ENTRY *)&cp->pool[cp->entries-1];
    int nport = 3310;

    if(port) {
	nport = atoi(port);
	if (nport<=0 || nport>65535) {
	    logg("!Bad port for clamd socket (%d)\n", nport);
	    return 1;
	}
    }
    if(!(srv = malloc(sizeof(*srv)))) {
	logg("!Out of memory allocating unix socket space\n");
	return 1;
    }

    srv->sin_family = AF_INET;

    if (addr) {
	struct hostent *h;
	if(!(h=gethostbyname(addr))) {
	    logg("^Can't resolve tcp socket hostname %s\n", addr);
	    free(srv);
	    return 1;
	}
	memcpy(&srv->sin_addr.s_addr, h->h_addr_list[0], 4);
    } else {
	srv->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    cpe->type = 1;
    cpe->dead = 1;
    srv->sin_port = htons(INADDR_ANY);
    cpe->local = islocal(srv, sizeof(srv));
    srv->sin_port = htons(nport);
    cpe->last_poll = 0;
    cpe->server = (struct sockaddr *)srv;
    cpe->socklen = sizeof(*srv);
    logg("*%s socket tcp:%s:%u added to the pool (slot %d)\n", cpe->local ? "Local" : "Remote", addr ? addr : "localhost", nport, cp->entries);
    return 0;
}    
#endif


int addslot(void) {
    struct CP_ENTRY *cpe;

    if(!(cpe = realloc(cp->pool, (cp->entries + 1) * sizeof(struct CP_ENTRY)))) {
	logg("!Out of memory while initializing the connection pool\n");
	cpool_free();
	return 1;
    }
    if(cp->local_cpe)
	cp->local_cpe = (struct CP_ENTRY *)((char *)cp->local_cpe + ((char *)cpe - (char *)cp->pool));
    memset(&cpe[cp->entries], 0, sizeof(*cpe));
    cp->pool = cpe;
    cp->entries++;
    return 0;
}
    

void cpool_probe(void) {
    unsigned int i, dead=0;
    struct CP_ENTRY *cpe = cp->pool;
    time_t lastpoll = time(NULL) - 5*60;

    for(i=1; i<=cp->entries; i++) {
	if(cpe->dead && lastpoll > cpe->last_poll) {
	    nc_ping_entry(cpe);
	    logg("*Probe for slot %u returned: %s\n", i, cpe->dead ? "failed" : "success");
	}
	dead += cpe->dead;
	cpe++;
    }
    cp->alive = cp->entries - dead;
    if(!cp->alive)
	logg("^No clamd server appears to be available, trying again in 5 minutes.\n");
}


void cpool_init(struct cfgstruct *copt) {
    const struct cfgstruct *cpt;
    int failed = 0;

    if(!(cp=calloc(sizeof(*cp), 1))) {
	logg("!Out of memory while initializing the connection pool");
	return;
    }

    cp->local_cpe = NULL;

    if((cpt = cfgopt(copt, "ClamdSocket"))->enabled) {
	while(cpt) {
	    char *socktype = cpt->strarg;

	    if(addslot()) return;
	    if(!strncasecmp(socktype, "unix:", 5)) {
		failed = cpool_addunix(socktype+5);
	    } else if(!strncasecmp(socktype, "tcp:", 4)) {
		char *port = strrchr(socktype+4, ':');
		if(port) {
		    *port='\0';
		    port++;
		}
		failed = cpool_addtcp(socktype+4, port);
	    } else {
		logg("!Failed to parse ClamdSocket directive '%s'\n", socktype);
		failed = 1;
	    }
	    if(failed) break;
	    cpt = (struct cfgstruct *) cpt->nextarg;
	}
	if(failed) {
	    cpool_free();
	    return;
	}
    }

#ifdef MILTER_LEGACY
    if((cpt = cfgopt(copt, "LocalSocket"))->enabled) {
	if(addslot()) return;
	if(cpool_addunix(cpt->strarg)) {
	    cpool_free();
	    return;
	}
    }

    if((cpt = cfgopt(copt, "TCPSocket"))->enabled) {
	char *addr = NULL;
	char port[5];

	if(addslot()) return;
	snprintf(port, 5, "%d", cpt->numarg);
	port[5] = 0;
	if((cpt = cfgopt(copt, "TCPAddr"))->enabled)
	    addr = cpt->strarg;
	if(cpool_addtcp(addr, port)) {
	    cpool_free();
	    return;
	}
    }
#endif

    if(!cp->entries) {
	logg("!No ClamdSocket specified\n");
	cpool_free();
	return;
    }
    cpool_probe();
    srand(time(NULL)); /* FIXME: naive ? */
}


void cpool_free(void) {
    unsigned int i;
    for(i=0; i<cp->entries; i++)
	FREESRV(cp->pool[i]);
    free(cp->pool);
    free(cp);
}


struct CP_ENTRY *cpool_get_rand(void) {
    unsigned int start, i;
    struct CP_ENTRY *cpe;

    if(!cp->alive) {
	logg("!No sockets are alive. Probe forced...\n");
	/* FIXME: yeah, actually do force smthng here */
	return NULL;
    }
    start = rand() % cp->entries;
    for(i=0; i<cp->entries; i++) {
	cpe = &cp->pool[(i+start) % cp->entries];
	if(cpe->dead) continue;
	if(cpe->local && cp->local_cpe && !cp->local_cpe->dead)
	    return cp->local_cpe;
	return cpe;
    }
    return NULL;
}


/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * tab-width: 8
 * End: 
 * vim: set cindent smartindent autoindent softtabstop=4 shiftwidth=4 tabstop=8: 
 */
