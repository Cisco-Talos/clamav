#ifndef _NETCODE_H
#define _NETCODE_H

#include <sys/types.h>
#include <sys/socket.h>

#include "shared/optparser.h"
#include "connpool.h"

void nc_ping_entry(struct CP_ENTRY *cpe);
int nc_connect_rand(int *main, int *alt, int *local);
int nc_send(int s, const void *buf, size_t len);
char *nc_recv(int s);
int nc_sendmsg(int s, int fd);
int nc_connect_entry(struct CP_ENTRY *cpe);
int localnets_init(struct optstruct *opts);
void localnets_free(void);
int islocalnet_name(char *name);
int islocalnet_sock(struct sockaddr *sa);

extern long readtimeout;
extern char *tempdir;

#endif
