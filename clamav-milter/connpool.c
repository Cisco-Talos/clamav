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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "connpool.h"
#include "netcode.h"

#define SETGAI(k, v) {(k)->gai = (void *)(v);} while(0)
#define FREESRV(k) { if((k).gai) freeaddrinfo((k).gai); else if((k).server) free((k).server); } while(0)

#if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#define _UNUSED_ __attribute__ ((__unused__))
#else
#define _UNUSED_
#endif

struct CPOOL *cp = NULL;
static pthread_cond_t mon_cond = PTHREAD_COND_INITIALIZER;
static int quitting = 1;
static pthread_t probe_th;

static int cpool_addunix(char *path) {
    struct sockaddr_un *srv;
    struct CP_ENTRY *cpe = &cp->pool[cp->entries-1];

    if(!cli_is_abspath(path)) {
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
    if (s < 0) return 0;
    ret = (bind(s, sa, addrlen) == 0);
    close(s);
    return ret;
}


static int cpool_addtcp(char *addr, char *port) {
    struct addrinfo hints, *res, *res2;
    struct CP_ENTRY *cpe = (struct CP_ENTRY *)&cp->pool[cp->entries-1];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
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
    hints.ai_family = AF_UNSPEC;
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


static int addslot(void) {
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


/* Probe strategy:
- wake up every minute
- probe alive if last check > 15 min
- probe dead if (last check > 2 min || no clamd available)
*/

static void cpool_probe(void) {
    unsigned int i, dead=0;
    struct CP_ENTRY *cpe = cp->pool;
    time_t now = time(NULL);

    for(i=1; i<=cp->entries; i++) {
	if((cpe->dead && (cpe->last_poll < now - 120 || !cp->alive)) || cpe->last_poll < now - 15*60*60) {
	    cpe->last_poll = time(NULL);
	    nc_ping_entry(cpe);
	    logg("*Probe for slot %u returned: %s\n", i, cpe->dead ? "failed" : "success");
	}
	dead += cpe->dead;
	cpe++;
    }
    cp->alive = cp->entries - dead;

    if(!cp->alive)
	logg("^No clamd server appears to be available\n");
}


static void *cpool_mon(_UNUSED_ void *v) {
    pthread_mutex_t conv;

    pthread_mutex_init(&conv, NULL);
    pthread_mutex_lock(&conv);

    while(!quitting) {
	struct timespec t;

	cpool_probe();
	t.tv_sec = time(NULL) + 60;
	t.tv_nsec = 0;
	pthread_cond_timedwait(&mon_cond, &conv, &t);
    }
    pthread_mutex_unlock(&conv);
    pthread_mutex_destroy(&conv);
    return NULL;
}


void cpool_init(struct optstruct *opts) {
    const struct optstruct *opt;
    int failed = 0;

    if(!(cp=calloc(sizeof(*cp), 1))) {
	logg("!Out of memory while initializing the connection pool");
	return;
    }

    cp->local_cpe = NULL;

    if((opt = optget(opts, "ClamdSocket"))->enabled) {
	while(opt) {
	    char *socktype = opt->strarg;

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
	    opt = opt->nextarg;
	}
	if(failed) {
	    cpool_free();
	    return;
	}
    }

    if(!cp->entries) {
	logg("!No ClamdSocket specified\n");
	cpool_free();
	return;
    }
    quitting = 0;
    pthread_create(&probe_th, NULL, cpool_mon, NULL);
    srand(time(NULL));
}


void cpool_free(void) {
    unsigned int i;

    if(!quitting) {
	logg("*Killing the monitor and stopping\n");
	quitting = 1;
	pthread_cond_signal(&mon_cond);
	pthread_join(probe_th, NULL);
    }

    if(cp) {
	if(cp->pool) {
	    for(i=0; i<cp->entries; i++)
		FREESRV(cp->pool[i]);
	    free(cp->pool);
	}
	free(cp);
	cp = NULL;
    }
}


struct CP_ENTRY *cpool_get_rand(int *s) {
    unsigned int start, i;
    struct CP_ENTRY *cpe;

    if(cp->alive) {
	start = rand() % cp->entries;
	for(i=0; i<cp->entries; i++) {
	    cpe = &cp->pool[(i+start) % cp->entries];
	    if(cpe->dead) continue;
	    if(cpe->local && cp->local_cpe && !cp->local_cpe->dead)
		cpe = cp->local_cpe;
	    if((*s = nc_connect_entry(cpe)) == -1) {
		cpe->dead = 1;
		continue;
	    }
	    return cpe;
	}
    }
    pthread_cond_signal(&mon_cond);
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
