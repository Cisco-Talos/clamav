#ifndef _NETCODE_H
#define _NETCODE_H

#include "connpool.h"

void nc_ping_entry(struct CP_ENTRY *cpe);
int nc_connect_rand(int *main, int *alt, int *local);
int nc_send(int s, const void *buf, size_t len);
char *nc_recv(int s);
int nc_sendmsg(int s, int fd);

extern long readtimeout;

#endif
