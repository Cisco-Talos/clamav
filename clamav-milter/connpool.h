#ifndef _CONNPOOL_H
#define _CONNPOOL_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>

#include "shared/cfgparser.h"

struct CP_ENTRY {
    uint8_t type;
    uint8_t dead;
    uint8_t local;
    time_t last_poll;
    struct sockaddr *server;
    socklen_t socklen;
#ifdef HAVE_GETADDRINFO
    void *gai;
#endif
};

struct CPOOL {
    unsigned int entries;
    unsigned int alive;
    struct CP_ENTRY *local_cpe;
    struct CP_ENTRY *pool;
};

void cpool_init(struct cfgstruct *copt);
void cpool_free(void);
struct CP_ENTRY *cpool_get_rand(int *s);

extern struct CPOOL *cp;

#endif

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * tab-width: 8
 * End: 
 * vim: set cindent smartindent autoindent softtabstop=4 shiftwidth=4 tabstop=8: 
 */
