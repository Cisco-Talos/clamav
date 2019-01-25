/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#ifndef __NET_H
#define __NET_H

typedef int socklen_t;
typedef int ssize_t;

#define F_GETFL 1
#define F_SETFL 2
#define O_NONBLOCK 1

int w32_socket(int domain, int type, int protocol);
int w32_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int w32_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int w32_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int w32_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t w32_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t w32_recv(int sockfd, void *buf, size_t len, int flags);
int w32_closesocket(int sockfd);
struct servent *w32_getservbyname(const char *name, const char *proto);
#define endservent()
int w32_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
void w32_freeaddrinfo(struct addrinfo *res);
const char *w32_inet_ntop(int af, const void *src, char *dst, socklen_t size);
int w32_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int poll_with_event(struct pollfd *fds, int nfds, int timeout, HANDLE event);
int w32_accept(SOCKET sockfd, const struct sockaddr *addr, socklen_t *addrlen);
int w32_listen(int sockfd, int backlog);
int w32_shutdown(int sockfd, int how);
int w32_getpeername(int sd, struct sockaddr *name, int *namelen);
char *w32_inet_ntoa(struct in_addr in);
int fcntl(int fd, int cmd, ...);

#endif
